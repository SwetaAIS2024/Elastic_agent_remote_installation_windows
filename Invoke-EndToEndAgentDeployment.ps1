#Requires -Version 5.1

<#
.SYNOPSIS
Runs the full remote Elastic Agent deployment flow end-to-end: WinRM/Fleet
connectivity check, then install and enrollment, then a combined summary.

.DESCRIPTION
Run from an elevated Windows PowerShell prompt on the deployment/controller
machine. This wrapper calls, in order:
1. multi-windows-winrm-check.ps1  - verifies WinRM and Fleet Server reachability
2. Install-ElasticAgentsRemote.ps1 - copies, installs, and enrolls Elastic Agent

If the connectivity check fails for a target, the install step is not run and
the overall exit code reflects the failure. Use -SkipConnectivityCheck to jump
straight to installation if you already validated connectivity separately.

.EXAMPLE
.\Invoke-EndToEndAgentDeployment.ps1 `
    -FleetServer 10.50.128.61 `
    -FleetPort 8220 `
    -TargetsFile .\windows-targets.txt `
    -CredentialFile .\winrm-credential.xml `
    -EnrollmentTokenFile .\fleet-enrollment-token.xml `
    -AgentZip .\elastic-agent-8.18.8-windows-x86_64.zip `
    -Insecure

.EXAMPLE
# Converts a plaintext token file (e.g. windows_enrollment_token.txt) automatically.
.\Invoke-EndToEndAgentDeployment.ps1 `
    -FleetServer 10.50.128.61 `
    -TargetsFile .\windows-targets.txt `
    -CredentialFile .\winrm-credential.xml `
    -EnrollmentTokenTextFile .\windows_enrollment_token.txt `
    -AgentZip .\elastic-agent-8.18.8-windows-x86_64.zip `
    -Insecure

.EXAMPLE
.\Invoke-EndToEndAgentDeployment.ps1 `
    -FleetServer 10.50.128.61 `
    -TargetsFile .\windows-targets.txt `
    -CredentialFile .\winrm-credential.xml `
    -KibanaUrl https://my-kibana-host:5601 `
    -KibanaApiKeyFile .\kibana-api-key.xml `
    -PolicyId 2b820230-4b54-11ed-b107-4bfe66d759e4 `
    -AgentZip .\elastic-agent-8.18.8-windows-x86_64.zip `
    -Insecure
#>

[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [Parameter()]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]*$')]
    [string] $FleetServer = '10.50.128.61',

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int] $FleetPort = 8220,

    [Parameter(Mandatory = $true, ParameterSetName = 'File')]
    [Alias('TargetFile')]
    [string] $TargetsFile,

    [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
    [ValidateNotNullOrEmpty()]
    [string[]] $Targets,

    [Parameter(Mandatory = $true)]
    [string] $CredentialFile,

    [Parameter()]
    [string] $EnrollmentTokenFile,

    [Parameter()]
    [string] $EnrollmentTokenTextFile,

    [Parameter()]
    [string] $KibanaUrl,

    [Parameter()]
    [string] $KibanaApiKeyFile,

    [Parameter()]
    [string] $PolicyId,

    [Parameter()]
    [switch] $KibanaInsecure,

    [Parameter(Mandatory = $true)]
    [string] $AgentZip,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string] $ExpectedVersion = '8.18.8',

    [Parameter()]
    [string] $FleetCaCertificate,

    [Parameter()]
    [switch] $Insecure,

    [Parameter()]
    [switch] $Unprivileged,

    [Parameter()]
    [string] $RemoteStagingRoot = 'C:\ProgramData\Elastic\Staging',

    [Parameter()]
    [switch] $KeepStagingFiles,

    [Parameter()]
    [switch] $SkipConnectivityCheck,

    [Parameter()]
    [string] $LogDirectory
)

$ErrorActionPreference = 'Stop'
$script:GeneratedTokenFile = $null

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Message,

        [ValidateSet('INFO', 'PASS', 'WARN', 'FAIL')]
        [string] $Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $color = switch ($Level) {
        'PASS' { 'Green' }
        'WARN' { 'Yellow' }
        'FAIL' { 'Red' }
        default { 'Cyan' }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function ConvertTo-EnrollmentTokenXml {
    param(
        [Parameter(Mandatory = $true)]
        [string] $TextFilePath
    )

    if (-not (Test-Path -LiteralPath $TextFilePath -PathType Leaf)) {
        throw "Enrollment token text file does not exist: $TextFilePath"
    }

    $rawToken = (Get-Content -LiteralPath $TextFilePath -Raw).Trim()
    if ([string]::IsNullOrWhiteSpace($rawToken)) {
        throw "Enrollment token text file is empty: $TextFilePath"
    }

    $secureToken = ConvertTo-SecureString -String $rawToken -AsPlainText -Force
    $generatedPath = Join-Path -Path $env:TEMP -ChildPath "fleet-enrollment-token-$([Guid]::NewGuid().ToString('N')).xml"
    $secureToken | Export-Clixml -LiteralPath $generatedPath -Force
    Remove-Variable rawToken, secureToken -ErrorAction SilentlyContinue

    return $generatedPath
}

$scriptRoot = $PSScriptRoot
$winrmCheckScript = Join-Path -Path $scriptRoot -ChildPath 'multi-windows-winrm-check.ps1'
$installScript = Join-Path -Path $scriptRoot -ChildPath 'Install-ElasticAgentsRemote.ps1'

foreach ($requiredScript in @($winrmCheckScript, $installScript)) {
    if (-not (Test-Path -LiteralPath $requiredScript -PathType Leaf)) {
        Write-Log "Required companion script not found: $requiredScript" 'FAIL'
        exit 2
    }
}

if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
    $LogDirectory = Get-Location
}

if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
    Write-Log "Log directory does not exist: $LogDirectory" 'FAIL'
    exit 2
}

if (-not [string]::IsNullOrWhiteSpace($EnrollmentTokenTextFile)) {
    if (-not [string]::IsNullOrWhiteSpace($EnrollmentTokenFile)) {
        Write-Log 'Use either -EnrollmentTokenFile or -EnrollmentTokenTextFile, not both.' 'FAIL'
        exit 2
    }

    try {
        Write-Log "Converting enrollment token text file to a protected XML: $EnrollmentTokenTextFile"
        $script:GeneratedTokenFile = ConvertTo-EnrollmentTokenXml -TextFilePath $EnrollmentTokenTextFile
        $EnrollmentTokenFile = $script:GeneratedTokenFile
        Write-Log 'Enrollment token conversion completed.' 'PASS'
    }
    catch {
        Write-Log "Enrollment token conversion failed: $($_.Exception.Message)" 'FAIL'
        exit 2
    }
}

$runTimestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$connectivityLog = Join-Path -Path $LogDirectory -ChildPath "e2e-$runTimestamp-01-connectivity.log"
$installLog = Join-Path -Path $LogDirectory -ChildPath "e2e-$runTimestamp-02-install.log"

$targetSelection = if ($PSCmdlet.ParameterSetName -eq 'File') {
    @{ TargetsFile = $TargetsFile }
}
else {
    @{ Targets = $Targets }
}

Write-Log '=== Stage 1/2: WinRM and Fleet connectivity check ==='

$connectivityExitCode = 0
$installExitCode = 2
$skipInstallStage = $false

try {
    if ($SkipConnectivityCheck) {
        Write-Log 'Skipping connectivity check (-SkipConnectivityCheck).' 'WARN'
    }
    else {
        $connectivityParameters = @{
            FleetServer    = $FleetServer
            FleetPort      = $FleetPort
            CredentialFile = $CredentialFile
            LogFile        = $connectivityLog
        } + $targetSelection

        & $winrmCheckScript @connectivityParameters
        $connectivityExitCode = $LASTEXITCODE

        if ($connectivityExitCode -ne 0) {
            Write-Log "Connectivity check failed (exit code $connectivityExitCode). See: $connectivityLog" 'FAIL'
            Write-Log 'Installation was not attempted because connectivity checks failed.' 'FAIL'
            $installExitCode = $connectivityExitCode
            $skipInstallStage = $true
        }
        else {
            Write-Log "Connectivity check passed. Log: $connectivityLog" 'PASS'
        }
    }

    if (-not $skipInstallStage) {
        Write-Log '=== Stage 2/2: Elastic Agent install and enrollment ==='

        $installParameters = @{
            FleetServer       = $FleetServer
            FleetPort         = $FleetPort
            CredentialFile    = $CredentialFile
            AgentZip          = $AgentZip
            ExpectedVersion   = $ExpectedVersion
            RemoteStagingRoot = $RemoteStagingRoot
            LogFile           = $installLog
        } + $targetSelection

        if (-not [string]::IsNullOrWhiteSpace($EnrollmentTokenFile)) {
            $installParameters['EnrollmentTokenFile'] = $EnrollmentTokenFile
        }
        if (-not [string]::IsNullOrWhiteSpace($KibanaUrl)) {
            $installParameters['KibanaUrl'] = $KibanaUrl
        }
        if (-not [string]::IsNullOrWhiteSpace($KibanaApiKeyFile)) {
            $installParameters['KibanaApiKeyFile'] = $KibanaApiKeyFile
        }
        if (-not [string]::IsNullOrWhiteSpace($PolicyId)) {
            $installParameters['PolicyId'] = $PolicyId
        }
        if (-not [string]::IsNullOrWhiteSpace($FleetCaCertificate)) {
            $installParameters['FleetCaCertificate'] = $FleetCaCertificate
        }
        if ($KibanaInsecure) { $installParameters['KibanaInsecure'] = $true }
        if ($Insecure) { $installParameters['Insecure'] = $true }
        if ($Unprivileged) { $installParameters['Unprivileged'] = $true }
        if ($KeepStagingFiles) { $installParameters['KeepStagingFiles'] = $true }

        & $installScript @installParameters
        $installExitCode = $LASTEXITCODE
    }
}
finally {
    if ($script:GeneratedTokenFile -and (Test-Path -LiteralPath $script:GeneratedTokenFile -PathType Leaf)) {
        Remove-Item -LiteralPath $script:GeneratedTokenFile -Force -ErrorAction SilentlyContinue
        Write-Log "Removed the temporary generated enrollment token file: $script:GeneratedTokenFile"
    }
}

Write-Log '=== End-to-end deployment summary ==='
Write-Log "Connectivity check: $(if ($SkipConnectivityCheck) { 'SKIPPED' } elseif ($connectivityExitCode -eq 0) { 'PASSED' } else { 'FAILED' }) $(if (-not $SkipConnectivityCheck) { "(log: $connectivityLog)" })"
Write-Log "Install and enrollment: $(if ($installExitCode -eq 0) { 'PASSED' } else { 'FAILED' }) (log: $installLog)"

if ($installExitCode -ne 0) {
    Write-Log 'End-to-end deployment finished with failures.' 'FAIL'
}
else {
    Write-Log 'End-to-end deployment finished successfully.' 'PASS'
}

exit $installExitCode
