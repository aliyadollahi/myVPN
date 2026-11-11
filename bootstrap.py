"""
First-run installer: makes the single .exe self-sufficient.

Everything the app needs is bundled inside the .exe (PyInstaller) under "bundle/":
  bundle/xray/      xray.exe, geoip.dat, geosite.dat, wintun.dll
  bundle/softether/ vpnclient_x64.exe, vpncmd_x64.exe, hamcore.se2  (official, Authenticode-signed)
  bundle/seed_servers.json  (last known VPN Gate list, used when every mirror is blocked)

On start we copy them to stable locations (a stable path also means Windows Firewall asks only once):
  Xray       -> %LOCALAPPDATA%\\VPNGateGuardian\\bin\\xray
  SoftEther  -> %ProgramFiles%\\VPNGateGuardian\\SoftEther   (needs admin; the exe requests it)
and register the SoftEther client service exactly like the official setup does:
  "<dir>\\vpnclient_x64.exe" /install /silent   -> service SEVPNCLIENT running "<exe> /service"
If SoftEther is already installed on the machine, that installation is used instead.
"""

import filecmp
import os
import shutil
import subprocess
import time

from system_net import CREATE_NO_WINDOW, find_resource, is_admin

LOCAL_BIN = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "VPNGateGuardian", "bin")
XRAY_DIR = os.path.join(LOCAL_BIN, "xray")
SE_DIR = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "VPNGateGuardian", "SoftEther")
SE_SERVICE = "SEVPNCLIENT"
SE_OFFICIAL_DIRS = [r"C:\Program Files\SoftEther VPN Client", r"C:\Program Files (x86)\SoftEther VPN Client"]
SE_FILES = ["vpnclient_x64.exe", "vpncmd_x64.exe", "hamcore.se2"]
XRAY_FILES = ["xray.exe", "geoip.dat", "geosite.dat", "wintun.dll"]


def bundled_dir(name: str) -> str | None:
    return find_resource("bundle", name) or find_resource(name)


def _sync_files(src_dir: str, dst_dir: str, files: list[str]) -> bool:
    os.makedirs(dst_dir, exist_ok=True)
    changed = False
    for f in files:
        src = os.path.join(src_dir, f)
        dst = os.path.join(dst_dir, f)
        if not os.path.exists(src):
            continue
        if os.path.exists(dst) and filecmp.cmp(src, dst, shallow=False):
            continue
        tmp = dst + ".new"
        shutil.copy2(src, tmp)
        os.replace(tmp, dst)
        changed = True
    return changed


# ---------------- Xray ----------------
def ensure_xray() -> str | None:
    """Returns path to xray.exe in a stable location (copies the bundled one if needed)."""
    src = bundled_dir("xray")
    if src and os.path.exists(os.path.join(src, "xray.exe")):
        try:
            _sync_files(src, XRAY_DIR, XRAY_FILES)
        except OSError:
            # xray.exe in use (another instance running) - keep the existing copy
            pass
    p = os.path.join(XRAY_DIR, "xray.exe")
    return p if os.path.exists(p) else None


# ---------------- SoftEther ----------------
def _sc_query(name: str) -> str:
    try:
        return subprocess.run(["sc", "query", name], capture_output=True, text=True,
                              creationflags=CREATE_NO_WINDOW, timeout=15).stdout
    except Exception:
        return ""


def softether_service_state() -> str:
    out = _sc_query(SE_SERVICE)
    if "RUNNING" in out:
        return "running"
    if "STOPPED" in out or "START_PENDING" in out:
        return "stopped"
    return "missing"


def find_vpncmd() -> str | None:
    for d in SE_OFFICIAL_DIRS + [SE_DIR]:
        for exe in ("vpncmd_x64.exe", "vpncmd.exe"):
            p = os.path.join(d, exe)
            if os.path.exists(p):
                return p
    return None


def _start_service(timeout=20) -> bool:
    subprocess.run(["sc", "start", SE_SERVICE], capture_output=True, creationflags=CREATE_NO_WINDOW)
    end = time.time() + timeout
    while time.time() < end:
        if softether_service_state() == "running":
            return True
        time.sleep(1)
    return False


def ensure_softether(progress=lambda msg: None) -> tuple[bool, str]:
    """Makes sure a SoftEther VPN Client service is installed and running."""
    state = softether_service_state()
    if state == "running" and find_vpncmd():
        return True, "SoftEther ready"
    if state == "stopped":
        if not is_admin():
            return False, "SoftEther service is stopped; Administrator rights are needed to start it."
        progress("Starting SoftEther service...")
        return (True, "SoftEther started") if _start_service() else (False, "SoftEther service failed to start")

    # missing -> portable install from the bundle
    src = bundled_dir("softether")
    if not src or not os.path.exists(os.path.join(src, "vpnclient_x64.exe")):
        return False, "SoftEther is not installed and no bundled copy exists."
    if not is_admin():
        return False, "Installing the VPN engine needs Administrator rights."
    try:
        progress("Installing VPN engine (SoftEther)...")
        _sync_files(src, SE_DIR, SE_FILES)
        client = os.path.join(SE_DIR, "vpnclient_x64.exe")
        # Same thing the official setup does (MsInstallServiceW with "<exe> /service").
        subprocess.run([client, "/install", "/silent"], capture_output=True, creationflags=CREATE_NO_WINDOW,
                       timeout=60)
        if softether_service_state() == "missing":
            # fallback: register the service directly
            subprocess.run(["sc", "create", SE_SERVICE, f'binPath= "{client}" /service', "start=", "auto",
                            "DisplayName=", "SoftEther VPN Client"],
                           capture_output=True, creationflags=CREATE_NO_WINDOW)
        if softether_service_state() != "running" and not _start_service(30):
            return False, "SoftEther service could not be started."
        # wait until the management port answers
        vpncmd = os.path.join(SE_DIR, "vpncmd_x64.exe")
        for _ in range(20):
            r = subprocess.run([vpncmd, "localhost", "/CLIENT", "/CMD", "NicList"], capture_output=True,
                               text=True, creationflags=CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, timeout=20)
            if r.returncode == 0:
                break
            time.sleep(1)
        progress("Creating virtual network adapter (first time only, may take a minute)...")
        r = subprocess.run([vpncmd, "localhost", "/CLIENT", "/CMD", "NicCreate", "VPN"], capture_output=True,
                           text=True, creationflags=CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, timeout=180)
        if r.returncode not in (0,) and "already exists" not in (r.stdout or ""):
            # NicCreate returns an error if it exists; NicList is the truth
            pass
        return True, "VPN engine installed"
    except subprocess.TimeoutExpired:
        return False, "VPN engine installation timed out."
    except OSError as e:
        return False, f"VPN engine installation failed: {e}"


def uninstall_portable_softether() -> bool:
    """Removes only OUR portable install (never touches an official SoftEther installation)."""
    client = os.path.join(SE_DIR, "vpnclient_x64.exe")
    if not os.path.exists(client) or not is_admin():
        return False
    vpncmd = os.path.join(SE_DIR, "vpncmd_x64.exe")
    subprocess.run([vpncmd, "localhost", "/CLIENT", "/CMD", "NicDelete", "VPN"], capture_output=True,
                   creationflags=CREATE_NO_WINDOW, stdin=subprocess.DEVNULL, timeout=120)
    subprocess.run([client, "/uninstall", "/silent"], capture_output=True, creationflags=CREATE_NO_WINDOW, timeout=60)
    shutil.rmtree(os.path.dirname(SE_DIR), ignore_errors=True)
    return True


def seed_servers_path() -> str | None:
    return find_resource("bundle", "seed_servers.json")
