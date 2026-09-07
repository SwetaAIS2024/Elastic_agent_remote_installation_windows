#Requires -Version 5.1

<#
.SYNOPSIS
Uninstalls Elastic Agent from multiple remote Windows machines.

.DESCRIPTION
Run from an elevated Windows PowerShell prompt on the deployment/controller
machine. For each target, opens a WinRM session and runs
elastic-agent.exe uninstall --non-interactive. Notifies Fleet before removal
(handled internally by the agent) and prints a per-machine summary.

Targets where Elastic Agent is not installed are reported and skipped.

.EXAMPLE
.\Uninstall-ElasticAgentsRemote.ps1 `
    -TargetsFile .\windows-targets.txt `
    -CredentialFile .\winrm-credential.xml `
    -LogFile .\Elastic-Agent-Uninstall.log

.EXAMPLE
.\Uninstall-ElasticAgentsRemote.ps1 `
    -Targets 10.50.130.29, 10.50.130.30 `
    -CredentialFile .\winrm-credential.xml
#>

[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'File')]
    [Alias('TargetFile')]
    [string] $TargetsFile,

    [Parameter(Mandatory = $true, ParameterSetName = 'Direct')]
    [ValidateNotNullOrEmpty()]
    [string[]] $Targets,

    [Parameter(Mandatory = $true)]
    [string] $CredentialFile,

    [Parameter()]
    [string] $LogFile
)

$ErrorActionPreference = 'Stop'
$script:UseTargetsFile = -not [string]::IsNullOrWhiteSpace($TargetsFile)
$script:TranscriptStarted = $false

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

function Resolve-RequiredFile {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description does not exist: $Path"
    }

    return (Resolve-Path -LiteralPath $Path).Path
}

function Get-NormalizedTargets {
    $suppliedTargets = @()

    if ($script:UseTargetsFile) {
        $resolvedTargetsFile = Resolve-RequiredFile `
            -Path $TargetsFile `
            -Description 'Targets file'

        foreach ($line in (Get-Content -LiteralPath $resolvedTargetsFile)) {
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
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Set-ControllerTrustedHosts {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $ComputerNames
    )

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

    Set-Item `
        -LiteralPath $trustedHostsPath `
        -Value ($trustedHosts -join ',') `
        -Force

    Write-Log "TrustedHosts: $((Get-Item -LiteralPath $trustedHostsPath).Value)"
}

function Invoke-ElasticAgentUninstall {
    if (-not (Test-IsAdministrator)) {
        Write-Log 'Open PowerShell with Run as Administrator, then run the script again.' 'FAIL'
        return 2
    }

    try {
        $computerNames = @(Get-NormalizedTargets)
        $resolvedCredentialFile = Resolve-RequiredFile `
            -Path $CredentialFile `
            -Description 'WinRM credential file'

        $winRMCredential = Import-Clixml -LiteralPath $resolvedCredentialFile
        if ($winRMCredential -isnot [System.Management.Automation.PSCredential]) {
            throw 'The WinRM credential file does not contain a PSCredential object.'
        }

        Set-ControllerTrustedHosts -ComputerNames $computerNames
    }
    catch {
        Write-Log "Uninstall preparation failed: $($_.Exception.Message)" 'FAIL'
        return 2
    }

    Write-Log "Targets ($($computerNames.Count)): $($computerNames -join ', ')"

    $results = @()

    foreach ($computerName in $computerNames) {
        Write-Log "Starting uninstall check for $computerName."

        $result = [ordered]@{
            Target     = $computerName
            RemoteHost = ''
            Status     = 'FAILED'
            Error      = ''
        }

        $session = $null

        try {
            Write-Log "Testing ${computerName}:5985."
            $winRMReachable = [bool](
                Test-NetConnection `
                    -ComputerName $computerName `
                    -Port 5985 `
                    -InformationLevel Quiet `
                    -WarningAction SilentlyContinue
            )

            if (-not $winRMReachable) {
                throw 'WinRM TCP port 5985 is not reachable.'
            }

            Write-Log "Creating a PowerShell session to $computerName."
            $session = New-PSSession `
                -ComputerName $computerName `
                -Credential $winRMCredential `
                -Authentication Negotiate `
                -ErrorAction Stop

            $precheck = Invoke-Command -Session $session -ScriptBlock {
                $installedAgentPath = 'C:\Program Files\Elastic\Agent\elastic-agent.exe'
                $service = Get-Service -Name 'Elastic Agent' -ErrorAction SilentlyContinue

                [pscustomobject]@{
                    HostName  = [Environment]::MachineName
                    Installed = (
                        (Test-Path -LiteralPath $installedAgentPath -PathType Leaf) -or
                        ($null -ne $service)
                    )
                    AgentPath = $installedAgentPath
                }
            }

            $result['RemoteHost'] = $precheck.HostName

            if (-not $precheck.Installed) {
                $result['Status'] = 'NOT_INSTALLED'
                Write-Log "$computerName has no Elastic Agent installation; uninstall skipped." 'WARN'
                $results += [pscustomobject]$result
                continue
            }

            Write-Log "Uninstalling Elastic Agent on $computerName."
            Invoke-Command -Session $session -ScriptBlock {
                param($AgentPath)

                $ErrorActionPreference = 'Stop'
                $uninstallOutput = (
                    & $AgentPath uninstall --non-interactive --force 2>&1 | Out-String
                ).Trim()
                $uninstallExitCode = $LASTEXITCODE

                if ($uninstallExitCode -ne 0) {
                    throw "Elastic Agent uninstall exited with code ${uninstallExitCode}: $uninstallOutput"
                }
            } -ArgumentList $precheck.AgentPath

            $result['Status'] = 'UNINSTALLED'
            Write-Log "$computerName uninstalled successfully." 'PASS'
        }
        catch {
            $result['Status'] = 'FAILED'
            $result['Error'] = $_.Exception.Message
            Write-Log "$computerName failed: $($result['Error'])" 'FAIL'
        }
        finally {
            if ($session) {
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            }
        }

        $results += [pscustomobject]$result
    }

    Write-Log 'Final Elastic Agent uninstall summary:'
    $summaryTable = $results |
        Select-Object Target, RemoteHost, Status |
        Format-Table -AutoSize |
        Out-String -Width 200
    Write-Host $summaryTable

    $failed = @($results | Where-Object { $_.Status -eq 'FAILED' })
    $uninstalled = @($results | Where-Object { $_.Status -eq 'UNINSTALLED' })
    $notInstalled = @($results | Where-Object { $_.Status -eq 'NOT_INSTALLED' })

    Write-Log "Uninstalled: $($uninstalled.Count)"
    Write-Log "Not installed: $($notInstalled.Count)"
    Write-Log "Failed: $($failed.Count)"

    if ($failed.Count -gt 0) {
        Write-Log 'Failure details:' 'WARN'
        foreach ($failedTarget in $failed) {
            Write-Host "  $($failedTarget.Target): $($failedTarget.Error)"
        }
        return 1
    }

    Write-Log 'All target machines completed without uninstall failures.' 'PASS'
    return 0
}

if ([string]::IsNullOrWhiteSpace($LogFile)) {
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $LogFile = Join-Path `
        -Path (Get-Location).Path `
        -ChildPath "elastic-agent-uninstall-$timestamp.log"
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

    Write-Log 'Starting multi-machine Elastic Agent uninstall.'
    Write-Log "Full log: $absoluteLogPath"
    $finalExitCode = Invoke-ElasticAgentUninstall
}
catch {
    Write-Log "Unexpected uninstall error: $($_.Exception.Message)" 'FAIL'
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
