#Requires -Version 5.1

<#
.SYNOPSIS
Checks WinRM access to multiple Windows machines and verifies that each target
can reach an Elastic Fleet Server.

.DESCRIPTION
Run this script from an elevated Windows PowerShell prompt on the Fleet or
deployment computer. The script:

1. Starts the local WinRM service if required.
2. Adds only the supplied targets to the existing TrustedHosts list.
3. Tests TCP 5985 and WS-Man on each target.
4. Executes a remote PowerShell command using one administrator credential.
5. Tests Fleet Server port connectivity from each remote machine.
6. Prints a final table and saves the complete session to a log file.

.EXAMPLE
.\multi-windows-winrm-check.ps1 `
    -FleetServer 10.50.128.61 `
    -FleetPort 8220 `
    -TargetsFile .\windows-targets.txt `
    -CredentialFile .\winrm-credential.xml `
    -LogFile .\Log_server.txt

.EXAMPLE
.\multi-windows-winrm-check.ps1 `
    -FleetServer 10.50.128.61 `
    -Targets 10.50.130.29, 10.50.130.30
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

    [Parameter()]
    [string] $LogFile,

    [Parameter()]
    [System.Management.Automation.PSCredential] $Credential,

    [Parameter()]
    [string] $CredentialFile
)

$ErrorActionPreference = 'Stop'
$script:TranscriptStarted = $false
$script:UseTargetsFile = -not [string]::IsNullOrWhiteSpace($TargetsFile)

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

function Get-NormalizedTargets {
    $suppliedTargets = @()

    if ($script:UseTargetsFile) {
        if (-not (Test-Path -LiteralPath $TargetsFile -PathType Leaf)) {
            throw "Targets file does not exist: $TargetsFile"
        }

        foreach ($line in (Get-Content -LiteralPath $TargetsFile)) {
            $cleanLine = (($line -replace '#.*$', '').Trim())
            if ($cleanLine) {
                $suppliedTargets += $cleanLine
            }
        }
    }
    else {
        $suppliedTargets = @($Targets)
    }

    $normalizedTargets = @()
    foreach ($target in $suppliedTargets) {
        $cleanTarget = $target.Trim()

        if (-not $cleanTarget) {
            continue
        }

        if ($cleanTarget -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') {
            throw "Invalid target IP address or hostname: $cleanTarget"
        }

        if ($normalizedTargets -notcontains $cleanTarget) {
            $normalizedTargets += $cleanTarget
        }
    }

    if ($normalizedTargets.Count -eq 0) {
        throw 'No valid Windows targets were supplied.'
    }

    return $normalizedTargets
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Set-ControllerTrustedHosts {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $ComputerNames
    )

    Write-Log 'Checking the WinRM service on this controller.'
    $winRMService = Get-Service -Name WinRM

    if ($winRMService.Status -ne 'Running') {
        Write-Log 'Starting the WinRM service on this controller.'
        Start-Service -Name WinRM
    }

    Import-Module Microsoft.WSMan.Management -ErrorAction Stop

    $trustedHostsPath = 'WSMan:\localhost\Client\TrustedHosts'
    $currentValue = (Get-Item -LiteralPath $trustedHostsPath).Value
    $trustedHosts = @()

    if ($currentValue) {
        $trustedHosts = @(
            $currentValue.Split(',') |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ }
        )
    }

    foreach ($computerName in $ComputerNames) {
        if ($trustedHosts -notcontains $computerName) {
            $trustedHosts += $computerName
        }
    }

    $updatedValue = $trustedHosts -join ','
    Set-Item -LiteralPath $trustedHostsPath -Value $updatedValue -Force

    Write-Log "TrustedHosts: $((Get-Item -LiteralPath $trustedHostsPath).Value)"

    if ($trustedHosts -contains '*') {
        Write-Log 'TrustedHosts already contains *, which trusts every host.' 'WARN'
    }
}

function Invoke-MultiMachineCheck {
    if (-not (Test-IsAdministrator)) {
        Write-Log 'Open PowerShell with Run as Administrator, then run the script again.' 'FAIL'
        return 2
    }

    try {
        $computerNames = @(Get-NormalizedTargets)
    }
    catch {
        Write-Log $_.Exception.Message 'FAIL'
        return 2
    }

    Write-Log "Fleet Server: ${FleetServer}:$FleetPort"
    Write-Log "Targets ($($computerNames.Count)): $($computerNames -join ', ')"

    try {
        Set-ControllerTrustedHosts -ComputerNames $computerNames
    }
    catch {
        Write-Log "Controller WinRM configuration failed: $($_.Exception.Message)" 'FAIL'
        return 2
    }

    if (($null -ne $Credential) -and -not [string]::IsNullOrWhiteSpace($CredentialFile)) {
        Write-Log 'Both -Credential and -CredentialFile were supplied; using -Credential.' 'WARN'
    }

    if (($null -eq $Credential) -and -not [string]::IsNullOrWhiteSpace($CredentialFile)) {
        try {
            if (-not (Test-Path -LiteralPath $CredentialFile -PathType Leaf)) {
                throw "Credential file does not exist: $CredentialFile"
            }

            $loadedCredential = Import-Clixml -LiteralPath $CredentialFile
            if ($loadedCredential -isnot [System.Management.Automation.PSCredential]) {
                throw 'The credential file does not contain a PowerShell PSCredential object.'
            }

            $Credential = $loadedCredential
            $credentialPath = (Resolve-Path -LiteralPath $CredentialFile).Path
            Write-Log "Loaded the protected credential file: $credentialPath"
        }
        catch {
            Write-Log "Could not load the credential file: $($_.Exception.Message)" 'FAIL'
            return 2
        }
    }

    if ($null -eq $Credential) {
        Write-Log 'Waiting for an administrator credential valid on all target machines.' 'WARN'
        $Credential = Get-Credential -Message 'Administrator credential for the Windows targets'
    }

    if ($null -eq $Credential) {
        Write-Log 'No credential was supplied.' 'FAIL'
        return 2
    }

    $results = @()

    foreach ($computerName in $computerNames) {
        Write-Log "Checking target: $computerName"

        $result = [ordered]@{
            Target         = $computerName
            Status         = 'FAILED'
            WinRM5985      = $false
            WSMan          = $false
            RemoteCommand  = $false
            FleetReachable = $false
            RemoteHost     = ''
            RemoteUser     = ''
            Error          = ''
        }

        try {
            Write-Log "Testing ${computerName}:5985."
            $result['WinRM5985'] = [bool](
                Test-NetConnection `
                    -ComputerName $computerName `
                    -Port 5985 `
                    -InformationLevel Quiet `
                    -WarningAction SilentlyContinue
            )

            if (-not $result['WinRM5985']) {
                throw 'TCP port 5985 is not reachable.'
            }

            Write-Log "Testing WS-Man on $computerName."
            Test-WSMan -ComputerName $computerName -ErrorAction Stop | Out-Null
            $result['WSMan'] = $true

            Write-Log "Executing the remote connectivity check on $computerName."
            $invokeParameters = @{
                ComputerName   = $computerName
                Credential     = $Credential
                Authentication = 'Negotiate'
                ErrorAction    = 'Stop'
                ArgumentList   = @($FleetServer, $FleetPort)
                ScriptBlock    = {
                    param($FleetAddress, $Port)

                    [pscustomobject]@{
                        HostName = [Environment]::MachineName
                        UserName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                        FleetReachable = [bool](
                            Test-NetConnection `
                                -ComputerName $FleetAddress `
                                -Port $Port `
                                -InformationLevel Quiet `
                                -WarningAction SilentlyContinue
                        )
                    }
                }
            }

            $remoteResult = Invoke-Command @invokeParameters | Select-Object -First 1

            $result['RemoteCommand'] = $true
            $result['RemoteHost'] = $remoteResult.HostName
            $result['RemoteUser'] = $remoteResult.UserName
            $result['FleetReachable'] = [bool]$remoteResult.FleetReachable

            if (-not $result['FleetReachable']) {
                throw "The remote machine cannot reach ${FleetServer}:$FleetPort."
            }

            $result['Status'] = 'PASSED'
            Write-Log "$computerName passed WinRM and Fleet connectivity checks." 'PASS'
        }
        catch {
            $result['Error'] = $_.Exception.Message
            Write-Log "$computerName failed: $($result['Error'])" 'FAIL'
        }

        $results += [pscustomobject]$result
    }

    Write-Log 'Final per-machine summary:'
    $summaryTable = $results |
        Select-Object `
            Target,
            Status,
            WinRM5985,
            WSMan,
            RemoteCommand,
            FleetReachable,
            RemoteHost |
        Format-Table -AutoSize |
        Out-String -Width 220
    Write-Host $summaryTable

    $failed = @($results | Where-Object { $_.Status -ne 'PASSED' })
    $passedCount = $results.Count - $failed.Count

    Write-Log "Passed: $passedCount / $($results.Count)"
    Write-Log "Failed: $($failed.Count) / $($results.Count)"

    if ($failed.Count -gt 0) {
        Write-Log 'Failure details:' 'WARN'
        foreach ($failedTarget in $failed) {
            Write-Host "  $($failedTarget.Target): $($failedTarget.Error)"
        }
        return 1
    }

    Write-Log 'All Windows targets passed.' 'PASS'
    return 0
}

if ([string]::IsNullOrWhiteSpace($LogFile)) {
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $LogFile = Join-Path -Path (Get-Location) -ChildPath "winrm-check-$timestamp.log"
}

if ([IO.Path]::IsPathRooted($LogFile)) {
    $absoluteLogPath = [IO.Path]::GetFullPath($LogFile)
}
else {
    $absoluteLogPath = [IO.Path]::GetFullPath(
        (Join-Path -Path (Get-Location).Path -ChildPath $LogFile)
    )
}
$logDirectory = Split-Path -Parent $absoluteLogPath

if (-not (Test-Path -LiteralPath $logDirectory -PathType Container)) {
    Write-Error "Log directory does not exist: $logDirectory"
    exit 2
}

$finalExitCode = 2

try {
    Start-Transcript -Path $absoluteLogPath -Append | Out-Null
    $script:TranscriptStarted = $true

    Write-Log 'Starting multi-machine WinRM check.'
    Write-Log "Full log: $absoluteLogPath"
    $finalExitCode = Invoke-MultiMachineCheck
}
catch {
    Write-Log "Unexpected script error: $($_.Exception.Message)" 'FAIL'
    $finalExitCode = 2
}
finally {
    if ($script:TranscriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
            Write-Warning "Could not stop the transcript cleanly: $($_.Exception.Message)"
        }
    }
}

exit $finalExitCode
