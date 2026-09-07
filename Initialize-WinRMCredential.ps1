#Requires -Version 5.1

<#
.SYNOPSIS
Creates a DPAPI-protected WinRM credential file for multi-machine deployment.

.DESCRIPTION
Run this script once on the Windows deployment/controller machine, using the
same Windows account that will later run the WinRM validation and Elastic Agent
deployment scripts.

The saved credential can be used to connect to multiple remote Windows
machines when the entered account is authorized on all of those machines.
The credential file is encrypted for the current Windows user and current
computer and must not be copied to another controller.

.EXAMPLE
.\Initialize-WinRMCredential.ps1 `
    -CredentialFile .\winrm-credential.xml `
    -UserName 'DOMAIN\elastic-deploy'

.EXAMPLE
.\Initialize-WinRMCredential.ps1 `
    -CredentialFile .\winrm-credential.xml `
    -Force
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string] $CredentialFile = '.\winrm-credential.xml',

    [Parameter()]
    [string] $UserName,

    [Parameter()]
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

function Write-Status {
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

try {
    if ($env:OS -ne 'Windows_NT') {
        throw 'This credential helper must be run on Windows.'
    }

    if ([IO.Path]::IsPathRooted($CredentialFile)) {
        $absoluteCredentialPath = [IO.Path]::GetFullPath($CredentialFile)
    }
    else {
        $absoluteCredentialPath = [IO.Path]::GetFullPath(
            (Join-Path -Path (Get-Location).Path -ChildPath $CredentialFile)
        )
    }

    $credentialDirectory = Split-Path -Parent $absoluteCredentialPath
    if (-not (Test-Path -LiteralPath $credentialDirectory -PathType Container)) {
        throw "Credential directory does not exist: $credentialDirectory"
    }

    if ((Test-Path -LiteralPath $absoluteCredentialPath -PathType Leaf) -and -not $Force) {
        throw "Credential file already exists: $absoluteCredentialPath. Use -Force only when you intend to replace it."
    }

    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Status "Creating a credential for controller user: $($currentIdentity.Name)"
    Write-Status "Credential destination: $absoluteCredentialPath"

    if ([string]::IsNullOrWhiteSpace($UserName)) {
        $credential = Get-Credential -Message 'WinRM administrator credential for the remote Windows machines'
    }
    else {
        $credential = Get-Credential `
            -UserName $UserName `
            -Message 'WinRM administrator credential for the remote Windows machines'
    }

    if ($null -eq $credential) {
        throw 'Credential entry was cancelled.'
    }

    $credential | Export-Clixml -LiteralPath $absoluteCredentialPath -Force

    # Remove inherited and explicit access entries, then grant only the current
    # Windows identity full control over the encrypted credential file.
    $fileAcl = Get-Acl -LiteralPath $absoluteCredentialPath
    $fileAcl.SetAccessRuleProtection($true, $false)

    foreach ($existingRule in @($fileAcl.Access)) {
        [void]$fileAcl.RemoveAccessRuleSpecific($existingRule)
    }

    $currentUserRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $currentIdentity.User,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    )
    [void]$fileAcl.AddAccessRule($currentUserRule)
    Set-Acl -LiteralPath $absoluteCredentialPath -AclObject $fileAcl

    # Verify that the file can be decrypted now, before it is used by another
    # deployment script.
    $verifiedCredential = Import-Clixml -LiteralPath $absoluteCredentialPath
    if ($verifiedCredential -isnot [System.Management.Automation.PSCredential]) {
        throw 'Verification failed: the saved object is not a PSCredential.'
    }

    if ($verifiedCredential.UserName -ne $credential.UserName) {
        throw 'Verification failed: the saved username does not match.'
    }

    Write-Status "Protected credential created for: $($verifiedCredential.UserName)" 'PASS'
    Write-Status 'The credential can be used for multiple targets where this account is authorized.' 'PASS'
    Write-Status 'Run the validation or deployment script with:'
    Write-Host "  -CredentialFile `"$absoluteCredentialPath`""
    Write-Status 'Do not copy this file to another user account or controller machine.' 'WARN'

    Remove-Variable credential, verifiedCredential -ErrorAction SilentlyContinue
    exit 0
}
catch {
    Write-Status $_.Exception.Message 'FAIL'
    exit 1
}
