#Requires -Version 5.1

<#
.SYNOPSIS
Starts, stops, restarts, or reports the status of the Elastic Agent Windows
service on one or more remote machines.

.DESCRIPTION
Run from an elevated Windows PowerShell prompt on the deployment/controller
machine. Opens a WinRM session per target and controls the 'Elastic Agent'
Windows service. Use -Action Status to just check current state without
changing anything. Fleet itself cannot start/stop/restart the underlying OS
service (it only manages enrollment, policy, upgrades, and tags), so this
host-level control has to happen over WinRM.

.EXAMPLE
.\Manage-ElasticAgentService.ps1 -Action Status -TargetsFile .\windows-targets.txt -CredentialFile .\winrm-credential.xml

.EXAMPLE
.\Manage-ElasticAgentService.ps1 -Action Restart -Targets 10.50.130.29 -CredentialFile .\winrm-credential.xml

.EXAMPLE
# Also fixes StartType back to Automatic if a reboot or image change reverted it.
.\Manage-ElasticAgentService.ps1 -Action Start -TargetsFile .\windows-targets.txt -CredentialFile .\winrm-credential.xml -EnsureAutomaticStartup
#>

[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Start', 'Stop', 'Restart', 'Status')]
    [string] $Action,

    [Parameter(Mandatory = $true, ParameterSetName = 'File')]
    [Alias('TargetFile')]
    [string] $TargetsFile,

    [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
    [ValidateNotNullOrEmpty()]
    [string[]] $Targets,

    [Parameter(Mandatory = $true)]
    [string] $CredentialFile,

    [Parameter()]
    [switch] $EnsureAutomaticStartup
)

$ErrorActionPreference = 'Stop'
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
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    Write-Log 'Open PowerShell with Run as Administrator, then run the script again.' 'FAIL'
    exit 2
}

try {
    $computerNames = @(Get-NormalizedTargets)
    if (-not (Test-Path -LiteralPath $CredentialFile -PathType Leaf)) {
        throw "WinRM credential file does not exist: $CredentialFile"
    }
    $winRMCredential = Import-Clixml -LiteralPath $CredentialFile
    if ($winRMCredential -isnot [System.Management.Automation.PSCredential]) {
        throw 'The WinRM credential file does not contain a PSCredential object.'
    }
}
catch {
    Write-Log $_.Exception.Message 'FAIL'
    exit 2
}

Write-Log "Action: $Action"
Write-Log "Targets ($($computerNames.Count)): $($computerNames -join ', ')"

$results = @()

foreach ($computerName in $computerNames) {
    $result = [ordered]@{
        Target        = $computerName
        Status        = 'FAILED'
        ServiceStatus = ''
        StartType     = ''
        Error         = ''
    }

    try {
        $serviceState = Invoke-Command -ComputerName $computerName -Credential $winRMCredential -Authentication Negotiate -ScriptBlock {
            param($RequestedAction, $ForceAutomaticStartup)

            $ErrorActionPreference = 'Stop'
            $service = Get-Service -Name 'Elastic Agent' -ErrorAction Stop

            if ($ForceAutomaticStartup) {
                Set-Service -Name 'Elastic Agent' -StartupType Automatic
            }

            switch ($RequestedAction) {
                'Start' { if ($service.Status -ne 'Running') { Start-Service -Name 'Elastic Agent' } }
                'Stop' { if ($service.Status -ne 'Stopped') { Stop-Service -Name 'Elastic Agent' -Force } }
                'Restart' { Restart-Service -Name 'Elastic Agent' -Force }
                'Status' { }
            }

            $service.Refresh()
            $wmiService = Get-CimInstance -ClassName Win32_Service -Filter "Name='Elastic Agent'"

            [pscustomobject]@{
                ServiceStatus = $service.Status.ToString()
                StartType     = $wmiService.StartMode
            }
        } -ArgumentList $Action, ([bool]$EnsureAutomaticStartup)

        $result['Status'] = 'SUCCEEDED'
        $result['ServiceStatus'] = $serviceState.ServiceStatus
        $result['StartType'] = $serviceState.StartType
        Write-Log "$computerName -> $($serviceState.ServiceStatus) (StartType: $($serviceState.StartType))" 'PASS'
    }
    catch {
        $result['Error'] = $_.Exception.Message
        Write-Log "$computerName failed: $($result['Error'])" 'FAIL'
    }

    $results += [pscustomobject]$result
}

Write-Log 'Summary:'
$summaryTable = $results |
    Select-Object Target, Status, ServiceStatus, StartType, Error |
    Format-Table -AutoSize |
    Out-String -Width 200
Write-Host $summaryTable

$failed = @($results | Where-Object { $_.Status -ne 'SUCCEEDED' })
if ($failed.Count -gt 0) {
    exit 1
}
exit 0
