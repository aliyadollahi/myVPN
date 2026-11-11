# Builds ONE self-contained VPNGateGuardian.exe
#   - Xray-core (official XTLS release, SHA256 verified)
#   - SoftEther VPN Client engine (official, Authenticode signature verified)
#   - last known VPN Gate server list (seed, for when every mirror is blocked)
# Usage:  powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$bundle = Join-Path $PSScriptRoot "bundle"
New-Item -ItemType Directory -Force -Path $bundle | Out-Null

# ---------- 1. Xray ----------
if (-not (Test-Path "xray\xray.exe")) { & powershell -ExecutionPolicy Bypass -File tools\get_xray.ps1 }
$bx = Join-Path $bundle "xray"
New-Item -ItemType Directory -Force -Path $bx | Out-Null
foreach ($f in "xray.exe","geoip.dat","geosite.dat","wintun.dll") { Copy-Item "xray\$f" $bx -Force }
Write-Host "[ok] Xray bundled"

# ---------- 2. SoftEther engine ----------
$seSrc = @("C:\Program Files\SoftEther VPN Client", "C:\Program Files (x86)\SoftEther VPN Client") |
         Where-Object { Test-Path (Join-Path $_ "vpnclient_x64.exe") } | Select-Object -First 1
if (-not $seSrc) {
    throw "SoftEther VPN Client must be installed on the BUILD machine (official installer from github.com/SoftEtherVPN/SoftEtherVPN_Stable/releases)."
}
$bs = Join-Path $bundle "softether"
New-Item -ItemType Directory -Force -Path $bs | Out-Null
foreach ($f in "vpnclient_x64.exe","vpncmd_x64.exe") {
    $p = Join-Path $seSrc $f
    $sig = Get-AuthenticodeSignature $p
    if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "SoftEther") {
        throw "Bad signature on $p : $($sig.Status) $($sig.SignerCertificate.Subject)"
    }
    Copy-Item $p $bs -Force
}
Copy-Item (Join-Path $seSrc "hamcore.se2") $bs -Force
Write-Host "[ok] SoftEther $((Get-Item (Join-Path $bs 'vpnclient_x64.exe')).VersionInfo.FileVersion) bundled (signature valid)"

# ---------- 3. Seed server list ----------
python -I -c @"
import sys, json; sys.path.insert(0, r'$PSScriptRoot')
from vpngate_fetcher import VpnGateFetcher
try:
    s = VpnGateFetcher().get_servers()
    json.dump([x.to_dict() for x in s], open(r'$bundle\seed_servers.json', 'w'))
    print('[ok] seed list:', len(s), 'servers')
except Exception as e:
    print('[warn] seed list not refreshed:', e)
"@

# ---------- 4. PyInstaller ----------
python -m pip install --quiet --upgrade pyinstaller customtkinter requests qrcode pillow
python -m PyInstaller --noconfirm --clean VPNGateGuardian.spec
$exe = Get-Item "dist\VPNGateGuardian.exe"
Write-Host ("[ok] Built {0}  ({1:N1} MB)" -f $exe.FullName, ($exe.Length / 1MB))
