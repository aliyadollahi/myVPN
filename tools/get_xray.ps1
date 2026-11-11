# Downloads the official Xray-core for Windows x64 from github.com/XTLS/Xray-core,
# verifies its SHA2-256 against the release .dgst file, and extracts it to ..\xray
# Usage:  powershell -ExecutionPolicy Bypass -File tools\get_xray.ps1 [-Version v25.x.x]
param([string]$Version = "latest")
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $root "xray"
$tmp  = Join-Path $env:TEMP ("xray_dl_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

$api = if ($Version -eq "latest") { "https://api.github.com/repos/XTLS/Xray-core/releases/latest" }
       else { "https://api.github.com/repos/XTLS/Xray-core/releases/tags/$Version" }
$rel = Invoke-RestMethod -Uri $api -Headers @{ "User-Agent" = "vpngate-guardian-setup" }
$zipAsset  = $rel.assets | Where-Object { $_.name -eq "Xray-windows-64.zip" }
$dgstAsset = $rel.assets | Where-Object { $_.name -eq "Xray-windows-64.zip.dgst" }
if (-not $zipAsset -or -not $dgstAsset) { throw "Release $($rel.tag_name) has no Xray-windows-64.zip/.dgst" }

$zip  = Join-Path $tmp $zipAsset.name
$dgst = Join-Path $tmp $dgstAsset.name
Write-Host "Downloading Xray $($rel.tag_name) ..."
Invoke-WebRequest -Uri $zipAsset.browser_download_url  -OutFile $zip  -UseBasicParsing
Invoke-WebRequest -Uri $dgstAsset.browser_download_url -OutFile $dgst -UseBasicParsing

$expected = (Select-String -Path $dgst -Pattern '^SHA2-256=\s*([0-9a-fA-F]{64})').Matches[0].Groups[1].Value.ToLower()
$actual   = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
if (-not $expected -or $expected -ne $actual) { throw "SHA256 mismatch! expected=$expected actual=$actual" }
Write-Host "SHA256 OK: $actual"

if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
Expand-Archive -Path $zip -DestinationPath $dest
Remove-Item -Recurse -Force $tmp
& (Join-Path $dest "xray.exe") version
Write-Host "Installed to $dest"
