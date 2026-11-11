"""
Connection engines for VPN Gate:
1. SoftEther native (vpncmd) - no admin needed, supports an HTTP proxy (Xray front)
2. OpenVPN (needs admin) - TCP mode through the Xray front, DNS-leak blocking
3. On-demand, token-protected HTTP server to share a config to a phone via QR
"""

import os
import secrets
import subprocess
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import qrcode
from PIL import Image

from system_net import CREATE_NO_WINDOW, data_dir, get_local_ip


# ======================= SoftEther =======================
class SoftEtherManager:
    ACCOUNT = "VPN Gate Guardian"
    NIC = "VPN"

    name = "SoftEther"

    def __init__(self):
        self.last_error = ""
        self._cmd_path = None

    @property
    def cmd_path(self):
        # re-detect lazily: the engine may be installed by bootstrap after the app started
        if not self._cmd_path or not os.path.exists(self._cmd_path):
            from bootstrap import find_vpncmd, softether_service_state
            p = find_vpncmd()
            self._cmd_path = p if p and softether_service_state() == "running" else None
        return self._cmd_path

    def is_available(self) -> bool:
        return self.cmd_path is not None

    @staticmethod
    def can_install() -> bool:
        from bootstrap import bundled_dir, find_vpncmd
        return bool(find_vpncmd() or bundled_dir("softether"))

    def _cmd(self, *args, timeout=20) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.cmd_path, "localhost", "/CLIENT", "/CMD", *args],
            capture_output=True, text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW,
            stdin=subprocess.DEVNULL,
        )

    def ensure_nic(self):
        res = self._cmd("NicList")
        if self.NIC not in res.stdout:
            self._cmd("NicCreate", self.NIC, timeout=90)
        self._cmd("NicEnable", self.NIC)

    def start(self, server, proxy_port: int | None = None) -> bool:
        """Starts connecting (non-blocking on the server side). Use status() to follow."""
        if not self.cmd_path:
            self.last_error = "SoftEther VPN Client not installed."
            return False
        try:
            self.ensure_nic()
            self._cmd("AccountDisconnect", self.ACCOUNT)
            self._cmd("AccountDelete", self.ACCOUNT)
            res = self._cmd("AccountCreate", self.ACCOUNT, f"/SERVER:{server.ip}:{server.port}",
                            "/HUB:VPNGATE", "/USERNAME:vpn", f"/NICNAME:{self.NIC}")
            if res.returncode != 0:
                self.last_error = (res.stdout or res.stderr)[-300:]
                return False
            self._cmd("AccountPasswordSet", self.ACCOUNT, "/PASSWORD:vpn", "/TYPE:standard")
            # We handle failover ourselves - don't let SoftEther retry forever on a dead server.
            self._cmd("AccountRetrySet", self.ACCOUNT, "/NUM:0", "/INTERVAL:5")
            if proxy_port:
                self._cmd("AccountProxyHttp", self.ACCOUNT, f"/SERVER:127.0.0.1:{proxy_port}",
                          "/USERNAME:none", "/PASSWORD:none")
            else:
                self._cmd("AccountProxyNone", self.ACCOUNT)
            res = self._cmd("AccountConnect", self.ACCOUNT)
            if res.returncode != 0:
                self.last_error = (res.stdout or res.stderr)[-300:]
                return False
            return True
        except subprocess.TimeoutExpired:
            self.last_error = "vpncmd timed out."
            return False

    def status(self) -> str:
        """'Connected', 'Connecting' or 'Disconnected'."""
        if not self.cmd_path:
            return "Disconnected"
        try:
            out = self._cmd("AccountStatusGet", self.ACCOUNT, timeout=10).stdout
        except subprocess.TimeoutExpired:
            return "Connecting"
        if "Session Established" in out or "Connection Completed" in out:
            return "Connected"
        if "Connecting" in out or "Negotiation" in out or "Retrying" in out or "Authenticating" in out:
            return "Connecting"
        return "Disconnected"

    def stop(self):
        if not self.cmd_path:
            return
        try:
            self._cmd("AccountDisconnect", self.ACCOUNT)
            self._cmd("AccountDelete", self.ACCOUNT)
        except subprocess.TimeoutExpired:
            pass


# ======================= OpenVPN =======================
class OpenVpnManager:
    name = "OpenVPN"

    def __init__(self):
        self.path = self._detect()
        self.proc: subprocess.Popen | None = None
        self.state = "Disconnected"
        self.last_error = ""
        self._dir = os.path.join(data_dir(), "active_connection")

    @staticmethod
    def _detect():
        for p in (r"C:\Program Files\OpenVPN\bin\openvpn.exe",
                  r"C:\Program Files (x86)\OpenVPN\bin\openvpn.exe",
                  r"C:\OpenVPN\bin\openvpn.exe"):
            if os.path.exists(p):
                return p
        return None

    def is_available(self) -> bool:
        return self.path is not None

    def start(self, server, proxy_port: int | None = None) -> bool:
        self.stop()
        if not self.path:
            self.last_error = "OpenVPN not installed."
            return False
        os.makedirs(self._dir, exist_ok=True)
        cfg = server.get_tcp_ovpn_config() if proxy_port else server.get_ovpn_config()
        if not cfg:
            self.last_error = "Invalid server configuration."
            return False
        cfg_path = os.path.join(self._dir, "connection.ovpn")
        auth_path = os.path.join(self._dir, "auth.txt")
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(cfg)
        with open(auth_path, "w", encoding="utf-8") as f:
            f.write("vpn\nvpn\n")
        cmd = [
            self.path, "--config", cfg_path, "--auth-user-pass", auth_path,
            "--script-security", "1",                   # never run external scripts
            "--data-ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC",
            "--data-ciphers-fallback", "AES-128-CBC",
            "--connect-retry-max", "1", "--connect-timeout", "15",
            "--block-outside-dns",                      # Windows: stop DNS leaks via other adapters
            "--verb", "3",
        ]
        if proxy_port:
            cmd += ["--http-proxy", "127.0.0.1", str(proxy_port)]
        self.state = "Connecting"
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                         encoding="utf-8", errors="replace", creationflags=CREATE_NO_WINDOW)
        except OSError as e:
            self.last_error = str(e)
            self.state = "Disconnected"
            return False
        threading.Thread(target=self._pump, args=(self.proc,), daemon=True).start()
        return True

    def _pump(self, proc):
        for line in proc.stdout:
            if proc is not self.proc:
                return
            if "Initialization Sequence Completed" in line:
                self.state = "Connected"
            elif "AUTH_FAILED" in line or "Exiting due to fatal error" in line:
                self.last_error = line.strip()
        if proc is self.proc:
            self.state = "Disconnected"

    def status(self) -> str:
        if not self.proc or self.proc.poll() is not None:
            return "Disconnected"
        return self.state

    def stop(self):
        proc, self.proc = self.proc, None
        self.state = "Disconnected"
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


# ======================= Mobile share (QR) =======================
class MobileShareServer:
    """Serves ONE sanitized .ovpn to the LAN, only with a random token, only while the dialog is open."""

    def __init__(self):
        self.server: HTTPServer | None = None
        self.port = 0
        self.token = ""
        self.config = ""
        self.filename = "vpngate.ovpn"

    def start(self, ip: str, config_text: str):
        self.stop()
        self.token = secrets.token_urlsafe(16)
        self.config = config_text
        self.filename = f"vpngate_{ip}.ovpn"
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                if q.get("t", [""])[0] == parent.token and parent.config:
                    data = parent.config.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-openvpn-profile")
                    self.send_header("Content-Disposition", f'attachment; filename="{parent.filename}"')
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args):
                pass

        bind_ip = get_local_ip()
        self.server = HTTPServer((bind_ip, 0), Handler)  # random free port, LAN interface only
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
        self.server = None
        self.config = ""

    def get_download_url(self) -> str:
        return f"http://{get_local_ip()}:{self.port}/dl?t={self.token}"

    def generate_qr_image(self) -> Image.Image:
        qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=2)
        qr.add_data(self.get_download_url())
        qr.make(fit=True)
        return qr.make_image(fill_color="black", back_color="white").convert("RGB")
