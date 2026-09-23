#Requires -Version 5.1

<#
.SYNOPSIS
Installs and enrolls Elastic Agent on multiple remote Windows machines.

.DESCRIPTION
Run from an elevated Windows PowerShell prompt on the deployment/controller
machine. The script copies a local Elastic Agent Windows ZIP over WinRM,
verifies its SHA-256 hash after transfer, extracts it, installs it as a Windows
service, enrolls it in Fleet, and prints a per-machine summary.

Existing Elastic Agent installations are detected and skipped. The script does
not use --force.

.EXAMPLE
.\Install-ElasticAgentsRemote.ps1 `
    -FleetServer 10.50.128.61 `
    -FleetPort 8220 `
    -TargetsFile .\windows-targets.txt `
    -CredentialFile .\winrm-credential.xml `
    -EnrollmentTokenFile .\fleet-enrollment-token.xml `
    -AgentZip .\elastic-agent-8.18.8-windows-x86_64.zip `
    -ExpectedVersion 8.18.8 `
    -Insecure `
    -LogFile .\Elastic-Agent-Deployment.log

.EXAMPLE
.\Install-ElasticAgentsRemote.ps1 `
    -FleetServer fleet.example.local `
    -Targets 10.50.130.29, 10.50.130.30 `
    -CredentialFile .\winrm-credential.xml `
    -EnrollmentTokenFile .\fleet-enrollment-token.xml `
    -AgentZip .\elastic-agent-8.18.8-windows-x86_64.zip `
    -FleetCaCertificate .\fleet-ca.crt

.EXAMPLE
# Fetches a live enrollment token from the Fleet API instead of a static file.
.\Install-ElasticAgentsRemote.ps1 `
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
    [string] $LogFile
)

$ErrorActionPreference = 'Stop'
$script:UseTargetsFile = -not [string]::IsNullOrWhiteSpace($TargetsFile)
$script:TranscriptStarted = $false
$script:ManageServiceScript = Join-Path -Path $PSScriptRoot -ChildPath 'Manage-ElasticAgentService.ps1'
$script:TokenBstr = [IntPtr]::Zero
$script:PlainEnrollmentToken = $null

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

function Invoke-KibanaRestGet {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Uri,

        [Parameter(Mandatory = $true)]
        [hashtable] $Headers,

        [Parameter()]
        [switch] $AllowInsecureTls
    )

    # PS 5.1 has no Invoke-RestMethod -SkipCertificateCheck; toggle the callback instead.
    $originalCallback = [Net.ServicePointManager]::ServerCertificateValidationCallback
    try {
        if ($AllowInsecureTls) {
            [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
        return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -ErrorAction Stop
    }
    finally {
        [Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
    }
}

function Get-FleetEnrollmentToken {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ResolvedKibanaApiKeyFile,

        [Parameter(Mandatory = $true)]
        [string] $KibanaBaseUrl,

        [Parameter(Mandatory = $true)]
        [string] $TargetPolicyId,

        [Parameter()]
        [switch] $AllowInsecureTls
    )

    $secureApiKey = Import-Clixml -LiteralPath $ResolvedKibanaApiKeyFile
    if ($secureApiKey -isnot [Security.SecureString]) {
        throw 'The Kibana API key file does not contain a SecureString.'
    }

    $apiKeyBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureApiKey)
    try {
        $plainApiKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($apiKeyBstr)
        if ([string]::IsNullOrWhiteSpace($plainApiKey)) {
            throw 'The Kibana API key is empty.'
        }

        $kuery = "policy_id:`"$TargetPolicyId`""
        $uri = '{0}/api/fleet/enrollment_api_keys?kuery={1}' -f `
            $KibanaBaseUrl.TrimEnd('/'), [Uri]::EscapeDataString($kuery)
        $headers = @{
            Authorization = "ApiKey $plainApiKey"
            'kbn-xsrf'    = 'true'
        }

        $response = Invoke-KibanaRestGet -Uri $uri -Headers $headers -AllowInsecureTls:$AllowInsecureTls
        $activeKey = $response.items | Where-Object { $_.active } | Select-Object -First 1

        if ($null -eq $activeKey) {
            throw "No active Fleet enrollment token was found for policy: $TargetPolicyId"
        }

        return $activeKey.api_key
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($apiKeyBstr)
    }
}

function Get-DeploymentSecrets {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ResolvedCredentialFile,

        [Parameter()]
        [string] $ResolvedTokenFile,

        [Parameter()]
        [string] $ResolvedKibanaApiKeyFile
    )

    $winRMCredential = Import-Clixml -LiteralPath $ResolvedCredentialFile
    if ($winRMCredential -isnot [System.Management.Automation.PSCredential]) {
        throw 'The WinRM credential file does not contain a PSCredential object.'
    }

    if ($ResolvedTokenFile) {
        $secureToken = Import-Clixml -LiteralPath $ResolvedTokenFile
        if ($secureToken -isnot [Security.SecureString]) {
            throw 'The enrollment token file does not contain a SecureString.'
        }

        $script:TokenBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
        $script:PlainEnrollmentToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
            $script:TokenBstr
        )
    }
    else {
        Write-Log "Fetching a live enrollment token from Fleet for policy: $PolicyId"
        $script:PlainEnrollmentToken = Get-FleetEnrollmentToken `
            -ResolvedKibanaApiKeyFile $ResolvedKibanaApiKeyFile `
            -KibanaBaseUrl $KibanaUrl `
            -TargetPolicyId $PolicyId `
            -AllowInsecureTls:$KibanaInsecure
    }

    if ([string]::IsNullOrWhiteSpace($script:PlainEnrollmentToken)) {
        throw 'The enrollment token is empty.'
    }

    return $winRMCredential
}

function Invoke-ElasticAgentDeployment {
    if (-not (Test-IsAdministrator)) {
        Write-Log 'Open PowerShell with Run as Administrator, then run the script again.' 'FAIL'
        return 2
    }

    if ($Insecure -and -not [string]::IsNullOrWhiteSpace($FleetCaCertificate)) {
        Write-Log 'Use either -Insecure or -FleetCaCertificate, not both.' 'FAIL'
        return 2
    }

    $usingTokenFile = -not [string]::IsNullOrWhiteSpace($EnrollmentTokenFile)
    $usingKibanaApi = -not [string]::IsNullOrWhiteSpace($KibanaUrl) -or `
        -not [string]::IsNullOrWhiteSpace($KibanaApiKeyFile) -or `
        -not [string]::IsNullOrWhiteSpace($PolicyId)

    if ($usingTokenFile -and $usingKibanaApi) {
        Write-Log 'Use either -EnrollmentTokenFile or the -KibanaUrl/-KibanaApiKeyFile/-PolicyId set, not both.' 'FAIL'
        return 2
    }

    if (-not $usingTokenFile -and -not $usingKibanaApi) {
        Write-Log 'Provide -EnrollmentTokenFile, or all of -KibanaUrl, -KibanaApiKeyFile, and -PolicyId.' 'FAIL'
        return 2
    }

    if ($usingKibanaApi -and (
            [string]::IsNullOrWhiteSpace($KibanaUrl) -or
            [string]::IsNullOrWhiteSpace($KibanaApiKeyFile) -or
            [string]::IsNullOrWhiteSpace($PolicyId)
        )) {
        Write-Log '-KibanaUrl, -KibanaApiKeyFile, and -PolicyId must all be supplied together.' 'FAIL'
        return 2
    }

    try {
        $computerNames = @(Get-NormalizedTargets)
        $resolvedCredentialFile = Resolve-RequiredFile `
            -Path $CredentialFile `
            -Description 'WinRM credential file'
        $resolvedTokenFile = $null
        if ($usingTokenFile) {
            $resolvedTokenFile = Resolve-RequiredFile `
                -Path $EnrollmentTokenFile `
                -Description 'Fleet enrollment token file'
        }
        $resolvedKibanaApiKeyFile = $null
        if ($usingKibanaApi) {
            $resolvedKibanaApiKeyFile = Resolve-RequiredFile `
                -Path $KibanaApiKeyFile `
                -Description 'Kibana API key file'
        }
        $resolvedAgentZip = Resolve-RequiredFile `
            -Path $AgentZip `
            -Description 'Elastic Agent ZIP'

        if ([IO.Path]::GetExtension($resolvedAgentZip) -ne '.zip') {
            throw 'AgentZip must be an Elastic Agent Windows ZIP file.'
        }

        $resolvedCaCertificate = $null
        if (-not [string]::IsNullOrWhiteSpace($FleetCaCertificate)) {
            $resolvedCaCertificate = Resolve-RequiredFile `
                -Path $FleetCaCertificate `
                -Description 'Fleet CA certificate'
        }

        $winRMCredential = Get-DeploymentSecrets `
            -ResolvedCredentialFile $resolvedCredentialFile `
            -ResolvedTokenFile $resolvedTokenFile `
            -ResolvedKibanaApiKeyFile $resolvedKibanaApiKeyFile

        $localZipHash = (Get-FileHash -LiteralPath $resolvedAgentZip -Algorithm SHA256).Hash
        $localZipName = Split-Path -Leaf $resolvedAgentZip
        $localZipSizeMB = [Math]::Round(
            (Get-Item -LiteralPath $resolvedAgentZip).Length / 1MB,
            2
        )

        Set-ControllerTrustedHosts -ComputerNames $computerNames
    }
    catch {
        Write-Log "Deployment preparation failed: $($_.Exception.Message)" 'FAIL'
        return 2
    }

    $fleetUrl = "https://${FleetServer}:$FleetPort"
    Write-Log "Fleet URL: $fleetUrl"
    Write-Log "Elastic Agent package: $localZipName ($localZipSizeMB MB)"
    Write-Log "Expected agent version: $ExpectedVersion"
    Write-Log "Targets ($($computerNames.Count)): $($computerNames -join ', ')"

    if ($Insecure) {
        Write-Log 'TLS certificate verification is disabled for enrollment.' 'WARN'
    }
    elseif ($resolvedCaCertificate) {
        Write-Log "Fleet CA certificate: $(Split-Path -Leaf $resolvedCaCertificate)"
    }
    else {
        Write-Log 'Using the Windows trusted CA store for Fleet TLS verification.'
    }

    $results = @()

    foreach ($computerName in $computerNames) {
        Write-Log "Starting deployment check for $computerName."

        $result = [ordered]@{
            Target         = $computerName
            RemoteHost     = ''
            Status         = 'FAILED'
            AgentVersion   = ''
            ServiceStatus  = ''
            FleetReachable = $false
            StagingPath    = ''
            Error          = ''
        }

        $session = $null
        $remoteStagingPath = $null
        $installationSucceeded = $false

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
                param($FleetAddress, $Port)

                $installedAgentPath = 'C:\Program Files\Elastic\Agent\elastic-agent.exe'
                $lockFilePath = 'C:\Program Files\Elastic\Agent\elastic-agent.lock'
                $service = Get-Service -Name 'Elastic Agent' -ErrorAction SilentlyContinue
                $versionOutput = ''

                if (Test-Path -LiteralPath $installedAgentPath -PathType Leaf) {
                    # version can try to reach a running daemon over RPC; --binary-only avoids that,
                    # and a relaxed EAP keeps stray stderr text from becoming a terminating error.
                    $previousEap = $ErrorActionPreference
                    $ErrorActionPreference = 'Continue'
                    $versionOutput = (
                        & $installedAgentPath version --binary-only 2>&1 | Out-String
                    ).Trim()
                    $ErrorActionPreference = $previousEap
                }

                [pscustomobject]@{
                    HostName = [Environment]::MachineName
                    Installed = (
                        (Test-Path -LiteralPath $installedAgentPath -PathType Leaf) -or
                        ($null -ne $service)
                    )
                    # A stale lock survives only when a prior install/uninstall crashed mid-run.
                    StaleLockFound = (
                        (Test-Path -LiteralPath $lockFilePath -PathType Leaf) -and
                        (-not (Test-Path -LiteralPath $installedAgentPath -PathType Leaf)) -and
                        ($null -eq $service)
                    )
                    LockFilePath = $lockFilePath
                    Version = $versionOutput
                    ServiceStatus = if ($service) { $service.Status.ToString() } else { '' }
                    FleetReachable = [bool](
                        Test-NetConnection `
                            -ComputerName $FleetAddress `
                            -Port $Port `
                            -InformationLevel Quiet `
                            -WarningAction SilentlyContinue
                    )
                }
            } -ArgumentList $FleetServer, $FleetPort

            $result['RemoteHost'] = $precheck.HostName
            $result['FleetReachable'] = [bool]$precheck.FleetReachable

            if (-not $result['FleetReachable']) {
                throw "The remote machine cannot reach ${FleetServer}:$FleetPort."
            }

            if ($precheck.Installed) {
                $result['Status'] = 'ALREADY_INSTALLED'
                $result['AgentVersion'] = $precheck.Version
                $result['ServiceStatus'] = $precheck.ServiceStatus

                if ($precheck.ServiceStatus -ne 'Running' -and (Test-Path -LiteralPath $script:ManageServiceScript -PathType Leaf)) {
                    Write-Log "$computerName has Elastic Agent installed but not running (StartType issue after a reboot?); attempting to start it." 'WARN'
                    try {
                        & $script:ManageServiceScript -Action Start -Targets $computerName -CredentialFile $CredentialFile -EnsureAutomaticStartup | Out-Null
                        if ($LASTEXITCODE -eq 0) {
                            $result['ServiceStatus'] = 'Running'
                            Write-Log "$computerName service started successfully." 'PASS'
                        }
                        else {
                            Write-Log "$computerName service start attempt did not report success (exit code $LASTEXITCODE); check manually." 'WARN'
                        }
                    }
                    catch {
                        Write-Log "$computerName automatic service start failed: $($_.Exception.Message)" 'WARN'
                    }
                }

                Write-Log "$computerName already has Elastic Agent; installation skipped." 'WARN'
                $results += [pscustomobject]$result
                continue
            }

            if ($precheck.StaleLockFound) {
                throw "A stale install lock was found at $($precheck.LockFilePath) from a previous failed run; remove it on $computerName before retrying."
            }

            # Keyed by the ZIP's own hash (not a random GUID) so a retry reuses a prior
            # successful copy on this host instead of re-uploading 200+ MB every run.
            $deploymentId = $localZipHash.Substring(0, 16).ToLowerInvariant()
            $remoteStagingPath = Join-Path `
                -Path $RemoteStagingRoot `
                -ChildPath "elastic-agent-$deploymentId"
            $result['StagingPath'] = $remoteStagingPath

            Invoke-Command -Session $session -ScriptBlock {
                param($StagingPath)
                New-Item -ItemType Directory -Path $StagingPath -Force | Out-Null
            } -ArgumentList $remoteStagingPath

            $remoteZipPath = Join-Path -Path $remoteStagingPath -ChildPath $localZipName

            $remoteZipHash = Invoke-Command -Session $session -ScriptBlock {
                param($ZipPath)
                if (Test-Path -LiteralPath $ZipPath -PathType Leaf) {
                    (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash
                }
            } -ArgumentList $remoteZipPath

            if ($remoteZipHash -eq $localZipHash) {
                Write-Log "$computerName already has a verified copy of $localZipName; skipping upload." 'PASS'
            }
            else {
                Write-Log "Copying $localZipName to $computerName ($localZipSizeMB MB); this may take several minutes."
                Copy-Item `
                    -LiteralPath $resolvedAgentZip `
                    -Destination $remoteZipPath `
                    -ToSession $session `
                    -Force
                Write-Log "Package copy completed for $computerName."

                $remoteZipHash = Invoke-Command -Session $session -ScriptBlock {
                    param($ZipPath)
                    (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash
                } -ArgumentList $remoteZipPath

                if ($remoteZipHash -ne $localZipHash) {
                    throw 'SHA-256 verification failed after copying the Elastic Agent ZIP.'
                }
                Write-Log "Package SHA-256 verified on $computerName."
            }

            $remoteCaPath = $null
            if ($resolvedCaCertificate) {
                $remoteCaName = Split-Path -Leaf $resolvedCaCertificate
                $remoteCaPath = Join-Path -Path $remoteStagingPath -ChildPath $remoteCaName
                Copy-Item `
                    -LiteralPath $resolvedCaCertificate `
                    -Destination $remoteCaPath `
                    -ToSession $session `
                    -Force
                Write-Log "Fleet CA certificate copied to $computerName."
            }

            Write-Log "Extracting and installing Elastic Agent on $computerName."
            $installResult = Invoke-Command -Session $session -ScriptBlock {
                param(
                    $ZipPath,
                    $StagingPath,
                    $FleetUrl,
                    $EnrollmentToken,
                    $UseInsecure,
                    $CaCertificatePath,
                    $RequiredVersion,
                    $UseUnprivileged
                )

                $ErrorActionPreference = 'Stop'
                $extractPath = Join-Path -Path $StagingPath -ChildPath 'extracted'

                # Avoids depending on the Microsoft.PowerShell.Archive module, which can fail
                # to load on some remote hosts due to execution-policy/module-path issues.
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $extractPath)

                $agentExecutable = Get-ChildItem `
                    -Path $extractPath `
                    -Filter 'elastic-agent.exe' `
                    -File `
                    -Recurse |
                    Select-Object -First 1

                if ($null -eq $agentExecutable) {
                    throw 'elastic-agent.exe was not found in the extracted package.'
                }

                # --binary-only skips the running-daemon RPC check (none exists pre-install);
                # a relaxed EAP also stops any stray stderr line from aborting the block.
                $previousEap = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                $packageVersion = (
                    & $agentExecutable.FullName version --binary-only 2>&1 | Out-String
                ).Trim()
                $ErrorActionPreference = $previousEap

                if ($packageVersion -notmatch [Regex]::Escape($RequiredVersion)) {
                    throw "Package version mismatch. Expected $RequiredVersion; found: $packageVersion"
                }

                $agentArguments = @(
                    'install',
                    "--url=$FleetUrl",
                    "--enrollment-token=$EnrollmentToken",
                    '--non-interactive'
                )

                if ($UseInsecure) {
                    $agentArguments += '--insecure'
                }
                elseif ($CaCertificatePath) {
                    $agentArguments += "--certificate-authorities=$CaCertificatePath"
                }

                if ($UseUnprivileged) {
                    $agentArguments += '--unprivileged'
                }

                # elastic-agent writes routine JSON log lines (e.g. WARN "SSL/TLS verifications
                # disabled") to stderr; a relaxed EAP stops those from aborting the install as a
                # terminating error, leaving the real success/failure signal to the exit code.
                $previousEap = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                $installOutput = (
                    & $agentExecutable.FullName @agentArguments 2>&1 | Out-String
                ).Trim()
                $installExitCode = $LASTEXITCODE
                $ErrorActionPreference = $previousEap

                if ($installExitCode -ne 0) {
                    $safeOutput = $installOutput.Replace($EnrollmentToken, '[REDACTED]')
                    throw "Elastic Agent install exited with code ${installExitCode}: $safeOutput"
                }

                Start-Sleep -Seconds 3

                $installedAgentPath = 'C:\Program Files\Elastic\Agent\elastic-agent.exe'
                if (-not (Test-Path -LiteralPath $installedAgentPath -PathType Leaf)) {
                    throw 'Installation returned success, but the installed executable was not found.'
                }

                $service = Get-Service -Name 'Elastic Agent' -ErrorAction Stop
                # A relaxed EAP stops stray stderr text (e.g. from a still-starting daemon) from
                # aborting the block; version/status failures here are non-fatal reporting only.
                $previousEap = $ErrorActionPreference
                $ErrorActionPreference = 'Continue'
                $installedVersion = (
                    & $installedAgentPath version --binary-only 2>&1 | Out-String
                ).Trim()
                $statusOutput = (
                    & $installedAgentPath status 2>&1 | Out-String
                ).Trim()
                $ErrorActionPreference = $previousEap

                [pscustomobject]@{
                    Version = $installedVersion
                    ServiceStatus = $service.Status.ToString()
                    AgentStatus = $statusOutput
                }
            } -ArgumentList `
                $remoteZipPath,
                $remoteStagingPath,
                $fleetUrl,
                $script:PlainEnrollmentToken,
                ([bool]$Insecure),
                $remoteCaPath,
                $ExpectedVersion,
                ([bool]$Unprivileged)

            $result['AgentVersion'] = $installResult.Version
            $result['ServiceStatus'] = $installResult.ServiceStatus
            $result['Status'] = 'INSTALLED'
            $installationSucceeded = $true

            Write-Log "$computerName installed and enrolled successfully." 'PASS'
            Write-Log "Remote service status: $($installResult.ServiceStatus)"

            if (-not $KeepStagingFiles) {
                try {
                    Invoke-Command -Session $session -ScriptBlock {
                        param($StagingPath)
                        Remove-Item -LiteralPath $StagingPath -Recurse -Force
                    } -ArgumentList $remoteStagingPath | Out-Null
                    $result['StagingPath'] = ''
                    Write-Log "Removed deployment staging files from $computerName."
                }
                catch {
                    Write-Log "Agent installation succeeded, but staging cleanup failed: $($_.Exception.Message)" 'WARN'
                }
            }
        }
        catch {
            $result['Status'] = 'FAILED'
            $result['Error'] = $_.Exception.Message
            Write-Log "$computerName failed: $($result['Error'])" 'FAIL'

            if ($remoteStagingPath -and -not $installationSucceeded) {
                Write-Log "Staging files retained for troubleshooting: $remoteStagingPath" 'WARN'
            }
        }
        finally {
            if ($session) {
                Remove-PSSession -Session $session -ErrorAction SilentlyContinue
            }
        }

        $results += [pscustomobject]$result
    }

    Write-Log 'Final Elastic Agent deployment summary:'
    $summaryTable = $results |
        Select-Object `
            Target,
            RemoteHost,
            Status,
            ServiceStatus,
            FleetReachable,
            AgentVersion |
        Format-Table -AutoSize |
        Out-String -Width 240
    Write-Host $summaryTable

    $failed = @($results | Where-Object { $_.Status -eq 'FAILED' })
    $installed = @($results | Where-Object { $_.Status -eq 'INSTALLED' })
    $existing = @($results | Where-Object { $_.Status -eq 'ALREADY_INSTALLED' })

    Write-Log "Installed: $($installed.Count)"
    Write-Log "Already installed: $($existing.Count)"
    Write-Log "Failed: $($failed.Count)"

    if ($failed.Count -gt 0) {
        Write-Log 'Failure details:' 'WARN'
        foreach ($failedTarget in $failed) {
            Write-Host "  $($failedTarget.Target): $($failedTarget.Error)"
        }
        return 1
    }

    Write-Log 'All target machines completed without deployment failures.' 'PASS'
    return 0
}

if ([string]::IsNullOrWhiteSpace($LogFile)) {
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $LogFile = Join-Path `
        -Path (Get-Location).Path `
        -ChildPath "elastic-agent-deployment-$timestamp.log"
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

    Write-Log 'Starting multi-machine Elastic Agent deployment.'
    Write-Log "Full log: $absoluteLogPath"
    $finalExitCode = Invoke-ElasticAgentDeployment
}
catch {
    Write-Log "Unexpected deployment error: $($_.Exception.Message)" 'FAIL'
    $finalExitCode = 2
}
finally {
    if ($script:TokenBstr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($script:TokenBstr)
        $script:TokenBstr = [IntPtr]::Zero
    }
    $script:PlainEnrollmentToken = $null

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
