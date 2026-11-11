"""
Windows networking helpers:
- app paths / persistent state (crash recovery)
- admin detection & elevation
- physical interface / IP discovery
- Windows system proxy (HKCU, no admin needed)
- Kill switch via Windows Firewall rules scoped to the physical adapters
"""

import ctypes
import ipaddress
import json
import os
import socket
import subprocess
import sys

CREATE_NO_WINDOW = 0x08000000
APP_NAME = "VPNGateGuardian"
FW_GROUP = "VPNGateGuardian"
FW_RULE_V4 = "VPNGateGuardian KillSwitch v4"
FW_RULE_V6 = "VPNGateGuardian KillSwitch v6"
FW_RULE_DNS_UDP = "VPNGateGuardian DNS-Leak UDP"
FW_RULE_DNS_TCP = "VPNGateGuardian DNS-Leak TCP"

VIRTUAL_ADAPTER_PATTERN = r"VPN Client Adapter|TAP-Windows|Wintun|OpenVPN|WireGuard|SoftEther|Loopback|Hyper-V Virtual|VirtualBox|VMware"

LAN_NETWORKS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32",
]


# ---------------- paths ----------------
def app_dir() -> str:
    """Folder of the .exe (frozen) or of the scripts - writable, persistent."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def data_dir() -> str:
    d = os.path.join(os.environ.get("APPDATA", app_dir()), APP_NAME)
    os.makedirs(d, exist_ok=True)
    return d


def resource_candidates(*parts) -> list[str]:
    roots = [app_dir()]
    if hasattr(sys, "_MEIPASS"):
        roots.insert(0, sys._MEIPASS)
    return [os.path.join(r, *parts) for r in roots]


def find_resource(*parts) -> str | None:
    for p in resource_candidates(*parts):
        if os.path.exists(p):
            return p
    return None


STATE_FILE = os.path.join(data_dir(), "state.json")


def load_state() -> dict:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(state: dict):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f)
    except Exception:
        pass


def update_state(**kw):
    st = load_state()
    for k, v in kw.items():
        if v is None:
            st.pop(k, None)
        else:
            st[k] = v
    save_state(st)


# ---------------- admin ----------------
def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, " ".join(f'"{a}"' for a in sys.argv[1:] + ["--elevated"])
    else:
        exe = sys.executable
        params = " ".join(f'"{a}"' for a in [os.path.abspath(sys.argv[0])] + sys.argv[1:] + ["--elevated"])
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, app_dir(), 1)
    return rc > 32


# ---------------- shell helpers ----------------
def run_ps(script: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW,
    )


def _ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _ps_array(items) -> str:
    return "@(" + ",".join(_ps_quote(i) for i in items) + ")"


# ---------------- interfaces ----------------
def get_local_ip() -> str:
    """IP the OS would use to reach the internet right now."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def physical_interfaces() -> list[str]:
    """Aliases of real uplink adapters (plus whatever carries the default route)."""
    script = (
        f"$virt = {_ps_quote(VIRTUAL_ADAPTER_PATTERN)};"
        "$a = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch $virt -and $_.Name -notmatch $virt } | ForEach-Object Name);"
        "$r = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | ForEach-Object { Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue } | Where-Object { $_.InterfaceDescription -notmatch $virt -and $_.Name -notmatch $virt } | ForEach-Object Name);"
        "($a + $r) | Sort-Object -Unique | ConvertTo-Json -Compress"
    )
    res = run_ps(script)
    try:
        data = json.loads(res.stdout or "[]")
    except Exception:
        return []
    return [data] if isinstance(data, str) else list(data or [])


def resolve_ipv4(host: str) -> str | None:
    try:
        ipaddress.IPv4Address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


# ---------------- system proxy ----------------
_INET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _refresh_wininet():
    try:
        inet = ctypes.windll.wininet
        inet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        inet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
    except Exception:
        pass


def _read_proxy() -> dict:
    import winreg
    out = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_KEY) as k:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL"):
            try:
                out[name] = winreg.QueryValueEx(k, name)
            except FileNotFoundError:
                out[name] = None
    return out


def set_system_proxy(http_port: int):
    import winreg
    st = load_state()
    if "proxy_backup" not in st:
        backup = {k: (list(v) if v else None) for k, v in _read_proxy().items()}
        update_state(proxy_backup=backup)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{http_port}")
        winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ,
                          "localhost;127.*;10.*;172.16.*;192.168.*;*.local;<local>")
        try:
            winreg.DeleteValue(k, "AutoConfigURL")
        except FileNotFoundError:
            pass
    _refresh_wininet()


def restore_system_proxy():
    import winreg
    st = load_state()
    backup = st.get("proxy_backup")
    if not backup:
        return
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_KEY, 0, winreg.KEY_SET_VALUE) as k:
        for name, val in backup.items():
            if val is None:
                try:
                    winreg.DeleteValue(k, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(k, name, 0, val[1], val[0])
    update_state(proxy_backup=None)
    _refresh_wininet()


# ---------------- kill switch ----------------
def _complement_ranges(allowed: list[str]) -> list[str]:
    """IPv4 ranges covering everything EXCEPT the allowed networks/IPs."""
    intervals = []
    for item in allowed:
        try:
            net = ipaddress.IPv4Network(item, strict=False)
        except ValueError:
            continue
        intervals.append((int(net.network_address), int(net.broadcast_address)))
    intervals.sort()
    merged = []
    for a, b in intervals:
        if merged and a <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    ranges, cur = [], 0
    for a, b in merged:
        if a > cur:
            ranges.append((cur, a - 1))
        cur = b + 1
    if cur <= 0xFFFFFFFF:
        ranges.append((cur, 0xFFFFFFFF))
    fmt = lambda x: str(ipaddress.IPv4Address(x))
    return [f"{fmt(a)}-{fmt(b)}" for a, b in ranges]


def firewall_enabled() -> bool:
    res = run_ps("(Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | Measure-Object).Count")
    return (res.stdout or "").strip() == "0"


def enable_kill_switch(allowed_ips: list[str], interfaces: list[str]) -> tuple[bool, str]:
    """Blocks all traffic on the physical adapters except to the VPN servers / LAN.

    Traffic inside the tunnel uses the virtual adapter, so it is unaffected.
    If the tunnel drops, Windows falls back to the physical adapter and everything is blocked.
    DNS to LAN resolvers (router/ISP) is blocked too, preventing DNS leaks.
    """
    if not is_admin():
        return False, "Kill switch needs Administrator rights."
    if not interfaces:
        return False, "No physical network adapter found."
    allow = sorted(set(LAN_NETWORKS + [f"{ip}/32" for ip in allowed_ips if ip]))
    v4_block = _complement_ranges(allow)
    v6_block = [
        "::-fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",      # everything below link-local
        "fec0::-feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",  # between link-local and multicast
    ]
    lan_dns = [n for n in LAN_NETWORKS if not n.startswith(("127.", "224.", "255."))]
    ifs = _ps_array(interfaces)
    script = f"""
$ErrorActionPreference = 'Stop'
Remove-NetFirewallRule -Group {_ps_quote(FW_GROUP)} -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName {_ps_quote(FW_RULE_V4)} -Group {_ps_quote(FW_GROUP)} -Direction Outbound -Action Block -InterfaceAlias {ifs} -RemoteAddress {_ps_array(v4_block)} | Out-Null
New-NetFirewallRule -DisplayName {_ps_quote(FW_RULE_V6)} -Group {_ps_quote(FW_GROUP)} -Direction Outbound -Action Block -InterfaceAlias {ifs} -RemoteAddress {_ps_array(v6_block)} | Out-Null
New-NetFirewallRule -DisplayName {_ps_quote(FW_RULE_DNS_UDP)} -Group {_ps_quote(FW_GROUP)} -Direction Outbound -Action Block -InterfaceAlias {ifs} -Protocol UDP -RemotePort 53 -RemoteAddress {_ps_array(lan_dns)} | Out-Null
New-NetFirewallRule -DisplayName {_ps_quote(FW_RULE_DNS_TCP)} -Group {_ps_quote(FW_GROUP)} -Direction Outbound -Action Block -InterfaceAlias {ifs} -Protocol TCP -RemotePort 53 -RemoteAddress {_ps_array(lan_dns)} | Out-Null
'OK'
"""
    try:
        res = run_ps(script, timeout=60)
    except subprocess.TimeoutExpired:
        disable_kill_switch()
        return False, "Firewall command timed out."
    if "OK" not in (res.stdout or ""):
        disable_kill_switch()
        return False, (res.stderr or res.stdout or "Unknown firewall error").strip()[:300]
    update_state(killswitch=True)
    warn = "" if firewall_enabled() else " (warning: a Windows Firewall profile is OFF, rules may not apply)"
    return True, "Kill switch active" + warn


def disable_kill_switch() -> bool:
    if not is_admin():
        return not load_state().get("killswitch")
    run_ps(f"Remove-NetFirewallRule -Group {_ps_quote(FW_GROUP)} -ErrorAction SilentlyContinue")
    update_state(killswitch=None)
    return True


# ---------------- processes ----------------
def kill_pid_if_name(pid: int, image_name: str):
    try:
        res = subprocess.run(["tasklist", "/FI", f"PID eq {int(pid)}", "/NH"],
                             capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
        if image_name.lower() in res.stdout.lower():
            subprocess.run(["taskkill", "/PID", str(int(pid)), "/F"],
                           capture_output=True, creationflags=CREATE_NO_WINDOW)
    except Exception:
        pass


def recover_after_crash() -> list[str]:
    """Undo anything a previous crashed run left behind. Returns notes for the UI."""
    notes = []
    st = load_state()
    for pid in st.get("xray_pids", []):
        kill_pid_if_name(pid, "xray.exe")
    update_state(xray_pids=None)
    if st.get("proxy_backup"):
        restore_system_proxy()
        notes.append("Restored Windows proxy settings left by a previous session.")
    if st.get("killswitch"):
        if disable_kill_switch() and is_admin():
            notes.append("Removed kill-switch rules left by a previous session.")
        else:
            notes.append("Kill-switch rules from a previous session are still active. "
                         "Run as Administrator (or emergency_unblock.bat) to remove them.")
    return notes


# ---------------- secrets at rest (Windows DPAPI, per-user) ----------------
class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, protect: bool) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    if protect:
        ok = fn(ctypes.byref(blob_in), "VPNGateGuardian", None, None, None, 0, ctypes.byref(blob_out))
    else:
        ok = fn(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise OSError("DPAPI failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def protect_str(text: str) -> str:
    import base64
    if not text:
        return ""
    return base64.b64encode(_dpapi(text.encode("utf-8"), True)).decode("ascii")


def unprotect_str(token: str) -> str:
    import base64
    if not token:
        return ""
    try:
        return _dpapi(base64.b64decode(token), False).decode("utf-8")
    except Exception:
        return ""


def public_ip(timeout: float = 8) -> str | None:
    import requests
    for url in ("https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"):
        try:
            r = requests.get(url, timeout=timeout)
            ip = r.text.strip()
            ipaddress.ip_address(ip)
            return ip
        except Exception:
            continue
    return None
