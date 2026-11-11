"""
VPN Gate Anti-Censorship Fetcher & Manager
- Races several mirrors concurrently (TLS verified).
- Sanitizes every .ovpn config so a tampered list can never run commands.
- Measures *real* latency from this machine (TCP connect) instead of trusting
  the Ping column published by VPN Gate (which is measured from Japan).
"""

import base64
import csv
import io
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

_REPO = "GeorgeXie2333/vpngate-list-mirror"
ACTIVE_SOURCES = [
    {"name": "GitHub raw", "url": f"https://raw.githubusercontent.com/{_REPO}/main/data/vpngate.csv", "timeout": 8},
    {"name": "GitHub web", "url": f"https://github.com/{_REPO}/raw/main/data/vpngate.csv", "timeout": 10},
    {"name": "jsDelivr CDN", "url": f"https://cdn.jsdelivr.net/gh/{_REPO}@main/data/vpngate.csv", "timeout": 10},
    {"name": "VPN Gate API", "url": "https://www.vpngate.net/api/iphone/", "timeout": 8},
    {"name": "VPN Gate API (http)", "url": "http://www.vpngate.net/api/iphone/", "timeout": 8},
]

# ---------------- DNS-over-HTTPS (beats poisoned DNS) ----------------
# Queried by IP so the resolver itself needs no DNS.
_DOH_ENDPOINTS = [
    ("https://1.1.1.1/dns-query", {"accept": "application/dns-json"}),
    ("https://8.8.8.8/resolve", {}),
    ("https://9.9.9.9:5053/dns-query", {"accept": "application/dns-json"}),
    ("https://1.0.0.1/dns-query", {"accept": "application/dns-json"}),
]
_DOH_CACHE: dict[str, str] = {}
_orig_getaddrinfo = socket.getaddrinfo


def _patched_getaddrinfo(host, *args, **kwargs):
    ip = _DOH_CACHE.get(host) if isinstance(host, str) else None
    return _orig_getaddrinfo(ip or host, *args, **kwargs)


socket.getaddrinfo = _patched_getaddrinfo


def doh_resolve(host: str, timeout: float = 5) -> str | None:
    for url, headers in _DOH_ENDPOINTS:
        try:
            r = requests.get(url, params={"name": host, "type": "A"}, headers=headers, timeout=timeout)
            for ans in r.json().get("Answer", []):
                if ans.get("type") == 1:
                    socket.inet_aton(ans["data"])
                    return ans["data"]
        except Exception:
            continue
    return None


def _host_of(url: str) -> str:
    return url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]


# OpenVPN directives that can execute programs, load code, or write files.
# A config downloaded from the internet must never contain them.
DANGEROUS_OVPN_DIRECTIVES = {
    "up", "down", "route-up", "route-pre-down", "ipchange", "client-connect",
    "client-disconnect", "learn-address", "auth-user-pass-verify", "tls-verify",
    "script-security", "plugin", "setenv", "setenv-safe", "management",
    "management-client", "log", "log-append", "writepid", "status", "cd",
    "chroot", "config", "iproute", "tmp-dir", "daemon", "auth-user-pass",
    "askpass", "dhcp-pre-release", "dhcp-renew", "dhcp-release", "tls-crypt-v2-verify",
    "ifconfig-pool-persist", "replay-persist", "http-proxy", "socks-proxy",
    "http-proxy-user-pass", "redirect-private",
}

# Ports SoftEther (and therefore VPN Gate) servers usually listen on with TCP.
SOFTETHER_TCP_PORTS = [443, 992, 1194, 5555]


def _to_int(val, default=0):
    if val is None or val == "":
        return default
    try:
        return int(str(val).strip())
    except (ValueError, TypeError):
        return default


def sanitize_ovpn(config: str) -> str:
    """Remove every directive that could run code or touch the filesystem.

    Inline blocks (<ca>...</ca>, <cert>...) are kept untouched.
    """
    out = []
    in_block = False
    for raw in config.splitlines():
        line = raw.strip()
        if re.match(r"^<[a-z0-9-]+>$", line, re.I):
            in_block = True
            out.append(raw)
            continue
        if re.match(r"^</[a-z0-9-]+>$", line, re.I):
            in_block = False
            out.append(raw)
            continue
        if in_block or not line or line.startswith(("#", ";")):
            out.append(raw)
            continue
        directive = line.split()[0].lower().lstrip("-")
        if directive in DANGEROUS_OVPN_DIRECTIVES:
            out.append(f"# [removed by VPN Gate Guardian] {directive}")
            continue
        out.append(raw)
    return "\n".join(out) + "\n"


class VpnGateServer:
    def __init__(self, data: dict):
        self.hostname = data.get("HostName", "")
        self.ip = data.get("IP", "")
        self.score = _to_int(data.get("Score"), 0)
        self.ping = _to_int(data.get("Ping"), 999)
        self.speed = _to_int(data.get("Speed"), 0)
        self.country_long = data.get("CountryLong", "")
        self.country_short = data.get("CountryShort", "")
        self.num_sessions = _to_int(data.get("NumVpnSessions"), 0)
        self.uptime = _to_int(data.get("Uptime"), 0)
        self.operator = data.get("Operator", "")
        self.ovpn_b64 = data.get("OpenVPN_ConfigData_Base64", "")

        # Filled by measure_latency(): real RTT from this PC and the TCP port that answered.
        self.latency = data.get("_latency")          # ms or None
        self.tcp_port = data.get("_tcp_port")        # int or None
        self.failed = False                           # set when a connect attempt fails

        self._config_cache = None
        self.proto, self.ovpn_port = self._parse_remote()

    # ---------- config ----------
    def _raw_config(self) -> str:
        if self._config_cache is None:
            try:
                self._config_cache = base64.b64decode(self.ovpn_b64).decode("utf-8", errors="ignore") if self.ovpn_b64 else ""
            except Exception:
                self._config_cache = ""
        return self._config_cache

    def _parse_remote(self):
        proto, port = "tcp", 443
        for line in self._raw_config().splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            if parts[0] == "proto" and len(parts) > 1:
                proto = "udp" if parts[1].startswith("udp") else "tcp"
            elif parts[0] == "remote" and len(parts) >= 3 and parts[2].isdigit():
                port = int(parts[2])
        return proto, port

    def get_ovpn_config(self) -> str:
        """Sanitized config (safe to hand to OpenVPN or share)."""
        raw = self._raw_config()
        return sanitize_ovpn(raw) if raw else ""

    def get_tcp_ovpn_config(self) -> str:
        """Sanitized config forced to TCP (required for running OpenVPN through a proxy)."""
        cfg = self.get_ovpn_config()
        if not cfg:
            return ""
        port = self.port
        lines = []
        for line in cfg.splitlines():
            parts = line.strip().split()
            if parts and parts[0] == "proto":
                lines.append("proto tcp")
            elif parts and parts[0] == "remote" and len(parts) >= 2:
                lines.append(f"remote {parts[1]} {port}")
            elif parts and parts[0] == "explicit-exit-notify":
                continue  # UDP only
            else:
                lines.append(line)
        return "\n".join(lines) + "\n"

    @property
    def port(self) -> int:
        """Best TCP port for this server (measured if possible)."""
        if self.tcp_port:
            return int(self.tcp_port)
        if self.proto == "tcp":
            return self.ovpn_port
        return 443

    @property
    def speed_mbps(self) -> float:
        return round(self.speed / (1024 * 1024), 2)

    @property
    def rank(self) -> float:
        """Lower is better. Real latency first, bandwidth as a penalty.

        e.g. 1 Mbps adds ~200 ms, 10 Mbps ~36 ms, 100 Mbps ~4 ms.
        Unmeasured servers fall back to VPN Gate's ping + 1000 so measured ones win.
        """
        speed_penalty = 400.0 / (1.0 + self.speed_mbps)
        if self.latency is not None:
            return self.latency + speed_penalty
        if self.latency is None and self.tcp_port == 0:
            return 1e9  # measured and unreachable
        return 1000 + (self.ping if self.ping > 0 else 999) + speed_penalty

    @property
    def reachable(self) -> bool:
        return self.tcp_port != 0

    def save_ovpn_file(self, output_path: str) -> bool:
        config = self.get_ovpn_config()
        if not config:
            return False
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(config)
        return True

    def to_dict(self) -> dict:
        return {
            "HostName": self.hostname, "IP": self.ip, "Score": self.score,
            "Ping": self.ping, "Speed": self.speed, "CountryLong": self.country_long,
            "CountryShort": self.country_short, "NumVpnSessions": self.num_sessions,
            "Uptime": self.uptime, "Operator": self.operator,
            "OpenVPN_ConfigData_Base64": self.ovpn_b64,
            "_latency": self.latency, "_tcp_port": self.tcp_port,
        }


# ---------------- latency ----------------
def _tcp_rtt(ip: str, port: int, timeout: float) -> float | None:
    start = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return (time.perf_counter() - start) * 1000.0
    except OSError:
        return None


def _probe_server(s: VpnGateServer, timeout: float):
    ports = []
    if s.proto == "tcp":
        ports.append(s.ovpn_port)
    ports += [p for p in SOFTETHER_TCP_PORTS if p not in ports]
    for port in ports:
        first = _tcp_rtt(s.ip, port, timeout)
        if first is None:
            continue
        second = _tcp_rtt(s.ip, port, timeout)
        best = min(x for x in (first, second) if x is not None)
        return round(best), port
    return None, 0


def measure_latency(servers, timeout: float = 1.5, workers: int = 64, progress=None):
    """Measures real TCP latency to every server concurrently (in place)."""
    done = 0
    total = len(servers)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_probe_server, s, timeout): s for s in servers}
        for fut in as_completed(futures):
            s = futures[fut]
            try:
                s.latency, s.tcp_port = fut.result()
            except Exception:
                s.latency, s.tcp_port = None, 0
            done += 1
            if progress:
                progress(done, total)
    return servers


def sort_servers(servers, mode: str = "Best (Ping + Speed)"):
    if mode == "Lowest Ping":
        key = lambda s: (not s.reachable, s.latency if s.latency is not None else 10000 + s.ping, -s.speed)
    elif mode == "Highest Speed":
        key = lambda s: (not s.reachable, -s.speed)
    elif mode == "Most Users":
        key = lambda s: (not s.reachable, -s.num_sessions)
    else:
        key = lambda s: s.rank
    return sorted(servers, key=key)


class VpnGateFetcher:
    """Tries, in order, until one works:
       1. all mirrors in parallel (normal DNS)
       2. all mirrors again with hostnames resolved via DNS-over-HTTPS
       3. all mirrors through a proxy (e.g. a temporary Xray front) if one is given
    The caller falls back to the cached / bundled list if everything fails."""

    def __init__(self, sources=None):
        self.sources = sources or ACTIVE_SOURCES
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
        })
        self.last_source = ""

    def _fetch_single(self, source: dict, proxy: str | None) -> tuple[str, str]:
        try:
            # TLS verification stays ON (the plain-http VPN Gate source is a last resort; configs are sanitized).
            proxies = {"http": proxy, "https": proxy} if proxy else None
            resp = self.session.get(source["url"], timeout=source.get("timeout", 8), proxies=proxies)
            if resp.status_code == 200 and resp.text:
                return source["name"], resp.text
        except Exception:
            pass
        return source["name"], ""

    def _race(self, proxy: str | None = None) -> list[VpnGateServer]:
        with ThreadPoolExecutor(max_workers=len(self.sources)) as executor:
            futures = [executor.submit(self._fetch_single, src, proxy) for src in self.sources]
            for future in as_completed(futures):
                try:
                    name, raw_data = future.result()
                    if raw_data and ("#HostName" in raw_data or "OpenVPN_ConfigData_Base64" in raw_data):
                        servers = self._parse_csv(raw_data)
                        if len(servers) >= 5:
                            self.last_source = name + (" via proxy" if proxy else "")
                            return servers
                except Exception:
                    continue
        return []

    def get_servers(self, proxy: str | None = None, progress=lambda m: None) -> list[VpnGateServer]:
        if proxy:
            progress("Fetching server list through Xray...")
            servers = self._race(proxy)
            if servers:
                return servers
            raise RuntimeError("Server list not reachable even through Xray.")

        progress("Fetching server list from mirrors...")
        servers = self._race()
        if servers:
            return servers

        progress("Mirrors blocked - retrying with DNS-over-HTTPS...")
        hosts = {_host_of(s["url"]) for s in self.sources}
        with ThreadPoolExecutor(max_workers=len(hosts)) as ex:
            for host, ip in zip(hosts, ex.map(doh_resolve, hosts)):
                if ip:
                    _DOH_CACHE[host] = ip
        if _DOH_CACHE:
            servers = self._race()
            if servers:
                self.last_source += " (DoH)"
                return servers

        raise RuntimeError("All server-list mirrors are blocked.")

    def _parse_csv(self, raw_csv: str) -> list[VpnGateServer]:
        lines = [line.strip() for line in raw_csv.splitlines() if line.strip()]
        header_index = next((i for i, l in enumerate(lines) if l.startswith(("#HostName", "HostName"))), -1)
        if header_index == -1:
            return []
        csv_text = "\n".join(l for l in lines[header_index:] if not l.startswith("*"))
        if csv_text.startswith("#"):
            csv_text = csv_text[1:]
        servers = []
        for row in csv.DictReader(io.StringIO(csv_text)):
            ip = (row.get("IP") or "").strip()
            if not ip or not row.get("OpenVPN_ConfigData_Base64"):
                continue
            try:
                socket.inet_aton(ip)  # reject anything that is not an IPv4 literal
            except OSError:
                continue
            servers.append(VpnGateServer(row))
        return sort_servers(servers)
