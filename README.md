# VPN Gate Guardian (Anti-Censorship Client)

A Windows client for **VPN Gate** servers with built-in **Xray-core**: real ping from your own system, automatic switching to the fastest server, IP change, kill switch, and a local proxy.

## Architecture

```
            [Xray Front - optional]                [VPN Gate]                [Xray Gateway - optional]
Apps ──► 127.0.0.1:10809 ──► tunnel adapter ──► SoftEther/OpenVPN ──► (127.0.0.1:10810 ──► your VLESS/VMess server) ──► VPN Gate server ──► internet
                └─ Iranian sites ──► direct
```

| Feature | What it does |
|---|---|
| **Your ping** | Measures real TCP latency from **your** system to every server (the Ping VPN Gate publishes is measured from its own side). |
| **Best (Ping + Speed)** | Default sort: actual latency + a penalty for low bandwidth. Unreachable servers go to the bottom; Iranian servers are hidden. |
| **🚀 Connect Best** | Connects to the first server in the list. |
| **🔀 Change IP** | Moves the connection to the next good server without dropping the kill switch. |
| **Auto-Switch** | If a connection fails or drops, it goes straight to the next fastest server. |
| **Xray Front (anti-filter)** | Your link (vless/vmess/trojan/ss or JSON) carries the VPN Gate connection inside itself. The filter only sees Xray traffic; your exit IP is still the VPN Gate server's IP. |
| **Xray Gateway** | Once the tunnel is up, an HTTP proxy `127.0.0.1:10809` / SOCKS `10808` is set as the Windows proxy. Traffic is bound to the tunnel IP so it never leaks to the ISP. |
| **Iran sites direct** | `.ir` domains and Iranian IPs bypass the VPN (needs geoip/geosite, which come with Xray). Disabled when the kill switch is on. |
| **Share on LAN** | SOCKS5 with a random username and password on port `10818` for your phone and other devices. |
| **Kill Switch** (Admin) | Windows Firewall rules on the physical adapter: only VPN Gate servers, the Xray server and the LAN are allowed. If the VPN drops, the internet is blocked. DNS to the router/ISP and IPv6 are also blocked (no DNS/IPv6 leaks). |

## Security
- `.ovpn` configs are **sanitized**: `up`, `down`, `script-security`, `plugin` and every other directive that can run commands are removed, and OpenVPN runs with `--script-security 1`.
- The server list is downloaded with TLS verification (the old `verify=False` was removed).
- Your Xray link is stored encrypted with Windows DPAPI (`%APPDATA%\VPNGateGuardian\settings.json`).
- The QR share server only runs while its window is open, and only accepts requests with a random token.
- After a crash, the next launch restores the proxy, kill switch and Xray processes. If you're stuck: `emergency_unblock.bat` (Run as administrator).

## For the end user (just one file)
Give `dist\VPNGateGuardian.exe` to anyone. On first run (after UAC approval):
1. Xray is unpacked into `%LOCALAPPDATA%\VPNGateGuardian\bin`.
2. If SoftEther isn't installed, the VPN engine is installed **silently** into `%ProgramFiles%\VPNGateGuardian\SoftEther` and its virtual network adapter is created.
3. The server list is fetched in this order: GitHub raw ← github.com ← jsDelivr ← vpngate.net → DoH if DNS is poisoned → through the user's Xray servers → finally, the list bundled inside the exe.

No Python or other installation is needed.

## «My Xray Servers» tab
- Add `vless:// vmess:// trojan:// ss://` links or a **subscription URL** (paste or clipboard).
- **Test Delay**: real latency through each server (like v2rayN).
- **Connect**: connects directly through Xray (system proxy, Iranian sites go direct).
- **★ Use as Front**: VPN Gate connections go through this server (bypassing the filter).

## Build (developer only)
On the build machine: Python 3.10+ and the official SoftEther VPN Client installed (the engine files are taken from there after their signature is checked).
```bash
powershell -ExecutionPolicy Bypass -File build.ps1
```
Output: `dist\VPNGateGuardian.exe` (~70 MB) containing Xray (SHA256-verified), SoftEther (signature-verified), and the latest server list.
