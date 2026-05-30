param(
    [string]$PackagePath = ".quarantine\splunk-mcp-server_120.tgz",
    [string]$Container = "breachlens-splunk",
    [string]$SplunkUser = "admin"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $PackagePath)) {
    throw "Package not found: $PackagePath. Download the Splunk MCP Server app from https://splunkbase.splunk.com/app/7931 first."
}

$resolvedPackage = Resolve-Path -LiteralPath $PackagePath
$hash = Get-FileHash -LiteralPath $resolvedPackage -Algorithm SHA256
Write-Host "Package: $resolvedPackage"
Write-Host "SHA256:  $($hash.Hash.ToLowerInvariant())"

$password = $env:SPLUNK_PASSWORD
if (-not $password) {
    $securePassword = Read-Host "Splunk password for $SplunkUser" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    try {
        $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

$remotePackage = "/tmp/splunk-mcp-server.tgz"
docker cp $resolvedPackage "${Container}:$remotePackage"
if ($LASTEXITCODE -ne 0) {
    throw "docker cp failed with exit code $LASTEXITCODE"
}

docker exec -e SPLUNK_PASSWORD="$password" -u splunk $Container sh -lc '/opt/splunk/bin/splunk install app "$1" -update 1 -auth "$2:$SPLUNK_PASSWORD"' sh "$remotePackage" "$SplunkUser"
if ($LASTEXITCODE -ne 0) {
    throw "docker exec install failed with exit code $LASTEXITCODE"
}

Write-Host ""
Write-Host "Installed the package. Restart Splunk if prompted, then open the Splunk MCP Server app in Splunk Web."
Write-Host "Next manual steps:"
Write-Host "1. Grant mcp_tool_execute to the demo role/user."
Write-Host "2. Grant mcp_tool_admin plus edit_tokens_own only to the user generating the encrypted token."
Write-Host "3. Generate the encrypted MCP token in the Splunk MCP Server app."
Write-Host "4. Copy the MCP endpoint and token into .env as SPLUNK_MCP_URL and SPLUNK_MCP_TOKEN."
