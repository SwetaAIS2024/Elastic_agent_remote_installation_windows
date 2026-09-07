#!/usr/bin/env bash

# Validate WinRM access from a Windows Fleet/deployment PC to multiple
# Windows machines, then verify that every remote machine can reach Fleet.
# Run from an elevated Git Bash or WSL terminal on the Fleet/deployment PC.

set -uo pipefail
shopt -s extglob

DEFAULT_FLEET_SERVER="10.50.128.61"
DEFAULT_FLEET_PORT="8220"

usage() {
    cat <<'USAGE'
Usage:
  ./multi-windows-winrm-check.sh [options] HOST [HOST ...]
  ./multi-windows-winrm-check.sh [options] --targets-file FILE

Options:
  --fleet-server ADDRESS  Fleet Server address (default: 10.50.128.61)
  --fleet-port PORT       Fleet Server port (default: 8220)
  --targets-file FILE     File containing one Windows IP/hostname per line
  --log-file FILE         Save output here (default: timestamped .log file)
  -h, --help              Show this help

Examples:
  ./multi-windows-winrm-check.sh 10.50.130.29 10.50.130.30

  ./multi-windows-winrm-check.sh \
      --fleet-server 10.50.128.61 \
      --fleet-port 8220 \
      --targets-file windows-targets.txt

Blank lines and lines beginning with # are ignored in the targets file.
The script prompts once for an administrator credential used on all targets.
USAGE
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 2
}

trim() {
    local value="$1"
    value="${value//$'\r'/}"
    value="${value##+([[:space:]])}"
    value="${value%%+([[:space:]])}"
    printf '%s' "$value"
}

to_windows_path() {
    local path="$1"

    if [[ -r /proc/version ]] && grep -qi microsoft /proc/version 2>/dev/null; then
        command -v wslpath >/dev/null 2>&1 || die "wslpath is required under WSL."
        wslpath -w "$path"
    elif command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$path"
    else
        printf '%s' "$path"
    fi
}

fleet_server="$DEFAULT_FLEET_SERVER"
fleet_port="$DEFAULT_FLEET_PORT"
targets_file=""
log_file=""
declare -a supplied_targets=()

while (($#)); do
    case "$1" in
        --fleet-server)
            (($# >= 2)) || die "--fleet-server requires an address."
            fleet_server="$2"
            shift 2
            ;;
        --fleet-port)
            (($# >= 2)) || die "--fleet-port requires a port."
            fleet_port="$2"
            shift 2
            ;;
        --targets-file)
            (($# >= 2)) || die "--targets-file requires a file path."
            targets_file="$2"
            shift 2
            ;;
        --log-file)
            (($# >= 2)) || die "--log-file requires a file path."
            log_file="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --)
            shift
            supplied_targets+=("$@")
            break
            ;;
        -* )
            die "Unknown option: $1"
            ;;
        *)
            supplied_targets+=("$1")
            shift
            ;;
    esac
done

[[ "$fleet_port" =~ ^[0-9]+$ ]] || die "Fleet port must be numeric."
((fleet_port >= 1 && fleet_port <= 65535)) || die "Fleet port must be between 1 and 65535."
[[ "$fleet_server" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || die "Invalid Fleet Server address: $fleet_server"

if [[ -n "$targets_file" ]]; then
    [[ -r "$targets_file" ]] || die "Cannot read targets file: $targets_file"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="$(trim "$line")"
        [[ -n "$line" ]] && supplied_targets+=("$line")
    done < "$targets_file"
fi

((${#supplied_targets[@]} > 0)) || {
    usage >&2
    die "Provide at least one Windows target."
}

declare -a targets=()
declare -A seen=()
for target in "${supplied_targets[@]}"; do
    target="$(trim "$target")"
    [[ -n "$target" ]] || continue
    [[ "$target" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || die "Invalid target address: $target"
    if [[ -z "${seen[$target]+present}" ]]; then
        targets+=("$target")
        seen[$target]=1
    fi
done

((${#targets[@]} > 0)) || die "No valid Windows targets were found."

command -v powershell.exe >/dev/null 2>&1 || {
    die "powershell.exe was not found. Run this from Git Bash or WSL on Windows."
}

if [[ -z "$log_file" ]]; then
    log_file="winrm-check-$(date '+%Y%m%d-%H%M%S').log"
fi

log_dir="$(dirname "$log_file")"
[[ -d "$log_dir" ]] || die "Log directory does not exist: $log_dir"
touch "$log_file" || die "Cannot write log file: $log_file"

# Display all subsequent output live and retain the same output in the log.
exec > >(tee -a "$log_file") 2>&1

printf '[%s] Starting multi-machine WinRM check.\n' "$(date '+%Y-%m-%d %H:%M:%S')"
printf '[%s] Fleet Server: %s:%s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$fleet_server" "$fleet_port"
printf '[%s] Targets (%d): %s\n' \
    "$(date '+%Y-%m-%d %H:%M:%S')" "${#targets[@]}" "${targets[*]}"
printf '[%s] Full log: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$log_file"

temp_dir="$(mktemp -d)" || die "Could not create a temporary directory."
ps_script="$temp_dir/multi-winrm-check.ps1"
normalized_targets="$temp_dir/windows-targets.txt"

cleanup() {
    rm -f -- "$ps_script" "$normalized_targets"
    rmdir -- "$temp_dir" 2>/dev/null || true
}
trap cleanup EXIT

printf '%s\n' "${targets[@]}" > "$normalized_targets"

cat > "$ps_script" <<'POWERSHELL'
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $FleetServer,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int] $FleetPort,

    [Parameter(Mandatory = $true)]
    [string] $TargetFile
)

$ErrorActionPreference = 'Stop'

function Write-Heading {
    param([string] $Text)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "`n[$timestamp] === $Text ===" -ForegroundColor Cyan
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdministrator) {
    Write-Error 'Run Git Bash or WSL from an elevated (Run as Administrator) Windows terminal.'
    exit 2
}

$targets = @(
    Get-Content -LiteralPath $TargetFile |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
)

if ($targets.Count -eq 0) {
    Write-Error 'The target list is empty.'
    exit 2
}

Write-Heading 'Controller configuration'
Write-Host "Fleet Server : ${FleetServer}:$FleetPort"
Write-Host "Target count  : $($targets.Count)"

try {
    $winrmService = Get-Service -Name WinRM
    if ($winrmService.Status -ne 'Running') {
        Start-Service -Name WinRM
    }

    Import-Module Microsoft.WSMan.Management -ErrorAction Stop

    $trustedHostsPath = 'WSMan:\localhost\Client\TrustedHosts'
    $currentValue = (Get-Item -LiteralPath $trustedHostsPath).Value
    $trustedHosts = [System.Collections.Generic.List[string]]::new()

    if ($currentValue) {
        foreach ($entry in ($currentValue -split ',')) {
            $entry = $entry.Trim()
            if ($entry -and -not $trustedHosts.Contains($entry)) {
                $trustedHosts.Add($entry)
            }
        }
    }

    foreach ($target in $targets) {
        if (-not $trustedHosts.Contains($target)) {
            $trustedHosts.Add($target)
        }
    }

    Set-Item -LiteralPath $trustedHostsPath -Value ($trustedHosts -join ',') -Force
    Write-Host "TrustedHosts : $((Get-Item -LiteralPath $trustedHostsPath).Value)"
}
catch {
    Write-Error "Controller WinRM configuration failed: $($_.Exception.Message)"
    exit 2
}

Write-Heading 'Remote credentials'
Write-Host 'WAITING: Enter an administrator credential valid on all target machines.' -ForegroundColor Yellow
Write-Host 'If no prompt is visible, check for a Windows credential dialog behind the terminal.' -ForegroundColor Yellow
$credential = Get-Credential -Message 'Administrator credential for the Windows targets'

if ($null -eq $credential) {
    Write-Error 'No credential was supplied.'
    exit 2
}

$results = foreach ($target in $targets) {
    Write-Heading "Checking $target"

    $result = [ordered]@{
        Target         = $target
        WinRM5985      = $false
        WSMan          = $false
        RemoteCommand  = $false
        FleetReachable = $false
        RemoteHost     = ''
        RemoteUser     = ''
        Status         = 'FAILED'
        Error          = ''
    }

    try {
        $result.WinRM5985 = [bool](
            Test-NetConnection -ComputerName $target -Port 5985 `
                -InformationLevel Quiet -WarningAction SilentlyContinue
        )

        if (-not $result.WinRM5985) {
            throw 'TCP port 5985 is not reachable.'
        }

        Test-WSMan -ComputerName $target -ErrorAction Stop | Out-Null
        $result.WSMan = $true

        $invokeParameters = @{
            ComputerName = $target
            Credential = $credential
            Authentication = 'Negotiate'
            ErrorAction = 'Stop'
            ArgumentList = @($FleetServer, $FleetPort)
            ScriptBlock = {
                param($FleetAddress, $Port)

                [pscustomobject]@{
                    HostName = [Environment]::MachineName
                    UserName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                    FleetReachable = [bool](
                        Test-NetConnection -ComputerName $FleetAddress -Port $Port `
                            -InformationLevel Quiet -WarningAction SilentlyContinue
                    )
                }
            }
        }

        $remoteResult = Invoke-Command @invokeParameters

        $result.RemoteCommand = $true
        $result.RemoteHost = $remoteResult.HostName
        $result.RemoteUser = $remoteResult.UserName
        $result.FleetReachable = [bool]$remoteResult.FleetReachable

        if (-not $result.FleetReachable) {
            throw "Remote machine cannot reach ${FleetServer}:$FleetPort."
        }

        $result.Status = 'PASSED'
        Write-Host "PASS: $target ($($result.RemoteHost)) can reach Fleet Server." -ForegroundColor Green
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-Host "FAIL: $target - $($result.Error)" -ForegroundColor Red
    }

    [pscustomobject]$result
}

Write-Heading 'Summary'
$results |
    Select-Object Target, Status, WinRM5985, WSMan, RemoteCommand, FleetReachable, RemoteHost |
    Format-Table -AutoSize |
    Out-Host

$failed = @($results | Where-Object { $_.Status -ne 'PASSED' })
$passedCount = $results.Count - $failed.Count

Write-Host "Passed: $passedCount / $($results.Count)"
Write-Host "Failed: $($failed.Count) / $($results.Count)"

if ($failed.Count -gt 0) {
    Write-Host "`nFailure details:" -ForegroundColor Yellow
    foreach ($item in $failed) {
        Write-Host "  $($item.Target): $($item.Error)"
    }
    exit 1
}

Write-Host "`nAll Windows targets passed the WinRM and Fleet connectivity checks." -ForegroundColor Green
exit 0
POWERSHELL

ps_script_windows="$(to_windows_path "$ps_script")"
targets_windows="$(to_windows_path "$normalized_targets")"

printf 'Checking %d Windows target(s)...\n' "${#targets[@]}"
printf 'PowerShell is starting. The next expected message is "Controller configuration".\n'

set +e
powershell.exe \
    -NoLogo \
    -NoProfile \
    -ExecutionPolicy Bypass \
    -File "$ps_script_windows" \
    -FleetServer "$fleet_server" \
    -FleetPort "$fleet_port" \
    -TargetFile "$targets_windows"
exit_code=$?

case "$exit_code" in
    0)
        printf '[%s] RESULT: SUCCESS - all targets passed.\n' "$(date '+%Y-%m-%d %H:%M:%S')"
        ;;
    1)
        printf '[%s] RESULT: PARTIAL FAILURE - review the summary above.\n' "$(date '+%Y-%m-%d %H:%M:%S')"
        ;;
    *)
        printf '[%s] RESULT: SCRIPT ERROR (exit code %d).\n' \
            "$(date '+%Y-%m-%d %H:%M:%S')" "$exit_code"
        ;;
esac
printf '[%s] Log saved to: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$log_file"

exit "$exit_code"
