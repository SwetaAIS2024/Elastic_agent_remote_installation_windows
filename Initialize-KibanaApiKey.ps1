#Requires -Version 5.1

<#
.SYNOPSIS
Creates a DPAPI-protected Kibana API key file used to fetch live Fleet
enrollment tokens.

.DESCRIPTION
Run this script once on the Windows deployment/controller machine, using the
same Windows account that will later run Install-ElasticAgentsRemote.ps1 with
-KibanaUrl/-KibanaApiKeyFile/-PolicyId. The API key must have the Fleet and
Integrations privileges required to read enrollment tokens (Fleet "Agents:
Read" at minimum).

The saved file is encrypted for the current Windows user and current
computer and must not be copied to another controller.

.EXAMPLE
.\Initialize-KibanaApiKey.ps1 -ApiKeyFile .\kibana-api-key.xml
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string] $ApiKeyFile = '.\kibana-api-key.xml',

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
        throw 'This helper must be run on Windows.'
    }

    if ([IO.Path]::IsPathRooted($ApiKeyFile)) {
        $absoluteApiKeyPath = [IO.Path]::GetFullPath($ApiKeyFile)
    }
    else {
        $absoluteApiKeyPath = [IO.Path]::GetFullPath(
            (Join-Path -Path (Get-Location).Path -ChildPath $ApiKeyFile)
        )
    }

    $apiKeyDirectory = Split-Path -Parent $absoluteApiKeyPath
    if (-not (Test-Path -LiteralPath $apiKeyDirectory -PathType Container)) {
        throw "Destination directory does not exist: $apiKeyDirectory"
    }

    if ((Test-Path -LiteralPath $absoluteApiKeyPath -PathType Leaf) -and -not $Force) {
        throw "API key file already exists: $absoluteApiKeyPath. Use -Force only when you intend to replace it."
    }

    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Status "Creating a Kibana API key file for controller user: $($currentIdentity.Name)"
    Write-Status "Destination: $absoluteApiKeyPath"
    Write-Status 'Paste the base64 Kibana API key value (id:api_key encoded form).'

    $secureApiKey = Read-Host -AsSecureString -Prompt 'Kibana API key'
    $apiKeyBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureApiKey)
    try {
        $plainApiKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($apiKeyBstr)
        if ([string]::IsNullOrWhiteSpace($plainApiKey)) {
            throw 'No API key was entered.'
        }
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($apiKeyBstr)
    }

    $secureApiKey | Export-Clixml -LiteralPath $absoluteApiKeyPath -Force

    # Remove inherited and explicit access entries, then grant only the current
    # Windows identity full control over the encrypted API key file.
    $fileAcl = Get-Acl -LiteralPath $absoluteApiKeyPath
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
    Set-Acl -LiteralPath $absoluteApiKeyPath -AclObject $fileAcl

    # Verify that the file can be decrypted now, before it is used by another script.
    $verifiedSecureApiKey = Import-Clixml -LiteralPath $absoluteApiKeyPath
    if ($verifiedSecureApiKey -isnot [Security.SecureString]) {
        throw 'Verification failed: the saved object is not a SecureString.'
    }

    Write-Status 'Protected Kibana API key file created.' 'PASS'
    Write-Status 'Run Install-ElasticAgentsRemote.ps1 with:'
    Write-Host "  -KibanaUrl <https://kibana-host:5601> -KibanaApiKeyFile `"$absoluteApiKeyPath`" -PolicyId <policy-id>"
    Write-Status 'Do not copy this file to another user account or controller machine.' 'WARN'

    Remove-Variable secureApiKey, verifiedSecureApiKey -ErrorAction SilentlyContinue
    exit 0
}
catch {
    Write-Status $_.Exception.Message 'FAIL'
    exit 1
}
