"""
Xray-core integration.

Two independent roles:
1. FRONT (anti-censorship): Xray connects to *your* server (VLESS/VMess/Trojan/SS),
   and the VPN Gate session (SoftEther/OpenVPN over TCP) is carried inside it through a
   local HTTP CONNECT inbound. The filter only sees your Xray traffic; the exit IP is
   still the VPN Gate server you picked.
2. GATEWAY (local proxy): after the tunnel is up, Xray exposes SOCKS/HTTP on 127.0.0.1,
   sets it as the Windows proxy and routes:
     * Iranian domains/IPs  -> direct (physical adapter)   [optional]
     * everything else      -> bound to the VPN adapter IP (never leaks to the ISP)
   Optionally a password-protected SOCKS inbound for other devices on the LAN.
"""

import base64
import json
import os
import secrets
import subprocess
import threading
import urllib.parse

from system_net import CREATE_NO_WINDOW, data_dir, find_resource, load_state, update_state, resolve_ipv4

FRONT_HTTP_PORT = 10810
GW_SOCKS_PORT = 10808
GW_HTTP_PORT = 10809
LAN_SOCKS_PORT = 10818

PRIVATE_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                 "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128"]


class XrayLinkError(ValueError):
    pass


# ======================= share-link parsing =======================
def _b64decode(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", errors="strict")


def _stream_settings(net: str, security: str, p: dict, host_default: str) -> dict:
    net = (net or "tcp").lower()
    if net == "splithttp":
        net = "xhttp"
    if net in ("h2", "http"):
        net = "http"
    ss = {"network": net}
    security = (security or "none").lower()
    sni = p.get("sni") or p.get("peer") or p.get("serverName") or ""
    fp = p.get("fp") or "chrome"
    alpn = [a for a in (p.get("alpn") or "").split(",") if a]
    host = p.get("host") or ""
    path = p.get("path") or "/"

    if security == "tls":
        tls = {"serverName": sni or host or host_default, "fingerprint": fp}
        if alpn:
            tls["alpn"] = alpn
        if str(p.get("allowInsecure", p.get("insecure", "0"))).lower() in ("1", "true"):
            tls["allowInsecure"] = True
        ss["security"] = "tls"
        ss["tlsSettings"] = tls
    elif security == "reality":
        if not p.get("pbk"):
            raise XrayLinkError("REALITY link is missing the public key (pbk).")
        ss["security"] = "reality"
        ss["realitySettings"] = {
            "serverName": sni, "fingerprint": fp, "publicKey": p["pbk"],
            "shortId": p.get("sid", ""), "spiderX": p.get("spx", "/") or "/",
        }
    else:
        ss["security"] = "none"

    if net == "ws":
        ss["wsSettings"] = {"path": path, "host": host}
    elif net == "grpc":
        ss["grpcSettings"] = {"serviceName": p.get("serviceName") or p.get("path", "").strip("/"),
                              "multiMode": p.get("mode") == "multi"}
    elif net == "httpupgrade":
        ss["httpupgradeSettings"] = {"path": path, "host": host}
    elif net == "xhttp":
        ss["xhttpSettings"] = {"path": path, "host": host, "mode": p.get("mode") or "auto"}
    elif net == "http":
        ss["httpSettings"] = {"path": path, "host": [h for h in host.split(",") if h]}
    elif net == "kcp":
        ss["kcpSettings"] = {"header": {"type": p.get("headerType") or "none"}, "seed": p.get("seed", "")}
    elif net == "tcp" and (p.get("headerType") or p.get("type")) == "http":
        ss["tcpSettings"] = {"header": {"type": "http", "request": {
            "path": [path], "headers": {"Host": [h for h in host.split(",") if h]}}}}
    return ss


def parse_share_link(link: str) -> tuple[dict, str, int, str]:
    """Returns (outbound, server_host, server_port, display_name)."""
    link = link.strip()
    if not link:
        raise XrayLinkError("Empty link.")

    # Raw Xray JSON: a full config or a single outbound
    if link.startswith("{"):
        try:
            obj = json.loads(link)
        except json.JSONDecodeError as e:
            raise XrayLinkError(f"Invalid JSON: {e}")
        if "outbounds" in obj:
            obj = next((o for o in obj["outbounds"]
                        if o.get("protocol") not in ("freedom", "blackhole", "dns")), None)
            if not obj:
                raise XrayLinkError("JSON config has no proxy outbound.")
        if "protocol" not in obj:
            raise XrayLinkError("JSON must be an Xray outbound or full config.")
        settings = obj.get("settings", {})
        srv = (settings.get("vnext") or settings.get("servers") or [{}])[0]
        if not srv.get("address"):
            raise XrayLinkError("Outbound has no server address.")
        return obj, srv["address"], int(srv.get("port", 443)), obj.get("tag", "custom")

    scheme = link.split("://", 1)[0].lower()

    if scheme == "vmess":
        try:
            j = json.loads(_b64decode(link[8:]))
        except Exception:
            raise XrayLinkError("Could not decode vmess:// link.")
        host, port = j.get("add", ""), int(j.get("port", 443))
        p = {"sni": j.get("sni", ""), "host": j.get("host", ""), "path": j.get("path", ""),
             "fp": j.get("fp", ""), "alpn": j.get("alpn", ""), "headerType": j.get("type", ""),
             "serviceName": j.get("path", "")}
        ob = {"protocol": "vmess", "settings": {"vnext": [{"address": host, "port": port, "users": [
            {"id": j.get("id", ""), "alterId": int(j.get("aid", 0) or 0), "security": j.get("scy") or "auto"}]}]},
            "streamSettings": _stream_settings(j.get("net"), "tls" if j.get("tls") == "tls" else "none", p, host)}
        return ob, host, port, j.get("ps", "vmess")

    if scheme == "ss":
        body = link[5:]
        name = ""
        if "#" in body:
            body, name = body.split("#", 1)
            name = urllib.parse.unquote(name)
        body = body.split("?", 1)[0].rstrip("/")
        if "@" not in body:
            body = _b64decode(body)
        userinfo, hostport = body.rsplit("@", 1)
        userinfo = urllib.parse.unquote(userinfo)
        if ":" not in userinfo:
            userinfo = _b64decode(userinfo)
        method, password = userinfo.split(":", 1)
        host, port = hostport.rsplit(":", 1)
        host = host.strip("[]")
        ob = {"protocol": "shadowsocks", "settings": {"servers": [
            {"address": host, "port": int(port), "method": method, "password": password}]}}
        return ob, host, int(port), name or "shadowsocks"

    if scheme in ("vless", "trojan"):
        u = urllib.parse.urlsplit(link)
        if not u.hostname or not u.port:
            raise XrayLinkError("Link has no host/port.")
        p = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        user = urllib.parse.unquote(u.username or "")
        name = urllib.parse.unquote(u.fragment or scheme)
        default_sec = "tls" if scheme == "trojan" else "none"
        ss = _stream_settings(p.get("type"), p.get("security", default_sec), p, u.hostname)
        if scheme == "vless":
            usr = {"id": user, "encryption": p.get("encryption") or "none"}
            if p.get("flow"):
                usr["flow"] = p["flow"]
            ob = {"protocol": "vless", "settings": {"vnext": [
                {"address": u.hostname, "port": u.port, "users": [usr]}]}, "streamSettings": ss}
        else:
            ob = {"protocol": "trojan", "settings": {"servers": [
                {"address": u.hostname, "port": u.port, "password": user}]}, "streamSettings": ss}
        return ob, u.hostname, u.port, name

    raise XrayLinkError(f"Unsupported link type: {scheme}:// (use vless, vmess, trojan, ss or JSON)")


# ======================= config builders =======================
def build_front_config(outbound: dict, server_host: str, server_ip: str, phys_ip: str | None,
                       port: int = FRONT_HTTP_PORT) -> dict:
    ob = json.loads(json.dumps(outbound))
    ob["tag"] = "upstream"
    ss = ob.setdefault("streamSettings", {})
    ss.setdefault("sockopt", {})["domainStrategy"] = "UseIPv4"
    if phys_ip and phys_ip != "127.0.0.1":
        ob["sendThrough"] = phys_ip  # keep Xray's own traffic on the physical NIC (no loop through the tunnel)
    hosts = {}
    if server_host != server_ip:
        hosts[server_host] = server_ip  # pre-resolved before the tunnel/kill switch
    return {
        "log": {"loglevel": "warning"},
        "dns": {"hosts": hosts, "servers": ["localhost"]},
        "inbounds": [{
            "tag": "vpn-front", "listen": "127.0.0.1", "port": port,
            "protocol": "http", "settings": {"allowTransparent": False},
        }],
        "outbounds": [ob, {"tag": "block", "protocol": "blackhole"}],
        "routing": {"rules": [
            {"type": "field", "inboundTag": ["vpn-front"], "outboundTag": "upstream"},
        ]},
    }


def build_gateway_config(vpn_ip: str | None, phys_ip: str | None, split_iran: bool,
                         lan_share: bool, lan_user: str, lan_pass: str, geo_ok: bool,
                         proxy_profile=None) -> dict:
    """vpn_ip: bind the 'vpn' outbound to the tunnel adapter (VPN Gate mode).
    proxy_profile: a FrontProfile -> the 'vpn' outbound IS that Xray server (Xray-only mode)."""
    sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
    inbounds = [
        {"tag": "socks-in", "listen": "127.0.0.1", "port": GW_SOCKS_PORT, "protocol": "socks",
         "settings": {"udp": True, "auth": "noauth"}, "sniffing": sniff},
        {"tag": "http-in", "listen": "127.0.0.1", "port": GW_HTTP_PORT, "protocol": "http",
         "settings": {}, "sniffing": sniff},
    ]
    if lan_share:
        inbounds.append({
            "tag": "lan-in", "listen": "0.0.0.0", "port": LAN_SOCKS_PORT, "protocol": "socks",
            "settings": {"udp": True, "auth": "password", "accounts": [{"user": lan_user, "pass": lan_pass}]},
            "sniffing": sniff,
        })

    hosts = {}
    if proxy_profile is not None:
        vpn_out = json.loads(json.dumps(proxy_profile.outbound))
        vpn_out["tag"] = "vpn"
        vpn_out.setdefault("streamSettings", {}).setdefault("sockopt", {})["domainStrategy"] = "UseIPv4"
        if phys_ip and phys_ip != "127.0.0.1":
            vpn_out["sendThrough"] = phys_ip
        if proxy_profile.host != proxy_profile.ip:
            hosts[proxy_profile.host] = proxy_profile.ip
    else:
        vpn_out = {"tag": "vpn", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}}
        if vpn_ip:
            vpn_out["sendThrough"] = vpn_ip
    direct_out = {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}}
    if phys_ip and phys_ip != "127.0.0.1":
        direct_out["sendThrough"] = phys_ip

    rules = [
        {"type": "field", "inboundTag": ["dns-internal"], "outboundTag": "vpn"},
        {"type": "field", "ip": PRIVATE_CIDRS, "outboundTag": "local"},
        {"type": "field", "protocol": ["bittorrent"], "outboundTag": "vpn"},
    ]
    if split_iran:
        domains = ["regexp:\\.ir$"]
        if geo_ok:
            domains.append("geosite:category-ir")
        rules.append({"type": "field", "domain": domains, "outboundTag": "direct"})
        if geo_ok:
            rules.append({"type": "field", "ip": ["geoip:ir"], "outboundTag": "direct"})
    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "vpn"})

    return {
        "log": {"loglevel": "warning"},
        "dns": {"tag": "dns-internal", "hosts": hosts, "servers": ["1.1.1.1", "8.8.8.8"], "queryStrategy": "UseIPv4"},
        "inbounds": inbounds,
        "outbounds": [vpn_out, direct_out,
                      {"tag": "local", "protocol": "freedom"},
                      {"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }


# ======================= process management =======================
class XrayProcess:
    def __init__(self, role: str):
        self.role = role
        self.proc: subprocess.Popen | None = None
        self.log_tail: list[str] = []
        self.config_path = os.path.join(data_dir(), f"xray_{role}.json")

    @staticmethod
    def binary() -> str | None:
        from bootstrap import XRAY_DIR
        p = os.path.join(XRAY_DIR, "xray.exe")
        if os.path.exists(p):
            return p
        return find_resource("bundle", "xray", "xray.exe") or find_resource("xray", "xray.exe")

    @staticmethod
    def geo_available() -> bool:
        b = XrayProcess.binary()
        if not b:
            return False
        d = os.path.dirname(b)
        return os.path.exists(os.path.join(d, "geoip.dat")) and os.path.exists(os.path.join(d, "geosite.dat"))

    def _write(self, config: dict):
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)

    def test_config(self, config: dict) -> tuple[bool, str]:
        exe = self.binary()
        if not exe:
            return False, "xray.exe not found (put it in the 'xray' folder next to the app)."
        self._write(config)
        res = subprocess.run([exe, "run", "-test", "-c", self.config_path], capture_output=True, text=True,
                             cwd=os.path.dirname(exe), creationflags=CREATE_NO_WINDOW, timeout=20)
        ok = res.returncode == 0
        return ok, (res.stdout + res.stderr).strip()[-600:]

    def start(self, config: dict) -> tuple[bool, str]:
        self.stop()
        exe = self.binary()
        if not exe:
            return False, "xray.exe not found (put it in the 'xray' folder next to the app)."
        self._write(config)
        self.log_tail = []
        env = dict(os.environ, XRAY_LOCATION_ASSET=os.path.dirname(exe))
        self.proc = subprocess.Popen(
            [exe, "run", "-c", self.config_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", cwd=os.path.dirname(exe), env=env,
            creationflags=CREATE_NO_WINDOW,
        )
        pids = set(load_state().get("xray_pids", []))
        pids.add(self.proc.pid)
        update_state(xray_pids=sorted(pids))
        threading.Thread(target=self._pump, daemon=True).start()
        # give it a moment to bind ports / fail on bad config
        try:
            self.proc.wait(timeout=1.5)
            return False, "Xray exited: " + "\n".join(self.log_tail[-8:])
        except subprocess.TimeoutExpired:
            return True, "started"

    def _pump(self):
        p = self.proc
        if not p or not p.stdout:
            return
        for line in p.stdout:
            self.log_tail.append(line.rstrip())
            self.log_tail = self.log_tail[-50:]

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self):
        if self.proc:
            pid = self.proc.pid
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None
            pids = [p for p in load_state().get("xray_pids", []) if p != pid]
            update_state(xray_pids=pids or None)
        try:
            os.remove(self.config_path)  # contains credentials
        except OSError:
            pass


class FrontProfile:
    """A parsed & pre-resolved upstream server."""

    def __init__(self, link: str):
        self.outbound, self.host, self.port, self.name = parse_share_link(link)
        self.ip = resolve_ipv4(self.host)
        if not self.ip:
            raise XrayLinkError(f"Cannot resolve Xray server host: {self.host}")


def random_lan_credentials() -> tuple[str, str]:
    return "vg" + secrets.token_hex(3), secrets.token_urlsafe(12)


# ======================= profiles / subscriptions / delay test =======================
SHARE_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")


def extract_links(text: str) -> list[str]:
    """Finds share links in pasted text or a subscription body (plain or base64)."""
    text = (text or "").strip()
    if text.startswith("{"):
        return [text]
    links = [l.strip() for l in text.splitlines() if l.strip().startswith(SHARE_SCHEMES)]
    if not links:
        try:
            decoded = _b64decode("".join(text.split()))
            links = [l.strip() for l in decoded.splitlines() if l.strip().startswith(SHARE_SCHEMES)]
        except Exception:
            pass
    return links


def fetch_subscription(url: str, timeout: float = 15) -> list[str]:
    import requests
    from vpngate_fetcher import _DOH_CACHE, _host_of, doh_resolve
    headers = {"User-Agent": "v2rayN/7.0"}
    try:
        r = requests.get(url, timeout=timeout, headers=headers)
    except Exception:
        host = _host_of(url)
        ip = doh_resolve(host)
        if not ip:
            raise
        _DOH_CACHE[host] = ip
        r = requests.get(url, timeout=timeout, headers=headers)
    r.raise_for_status()
    return extract_links(r.text)


class XrayProfile:
    """A saved Xray server (one share link)."""

    def __init__(self, link: str, source: str = ""):
        self.link = link.strip()
        self.source = source            # subscription URL, or "" for manual
        self.outbound, self.host, self.port, self.name = parse_share_link(self.link)
        self.ip = None                  # resolved lazily
        self.delay = None               # real delay in ms through the proxy
        self.tested = False
        self.failed = False

    @property
    def reachable(self) -> bool:
        return not self.tested or self.delay is not None

    @property
    def country_short(self) -> str:
        return "XR"

    def resolve(self) -> str | None:
        if not self.ip:
            self.ip = resolve_ipv4(self.host)
            if not self.ip:
                from vpngate_fetcher import doh_resolve
                self.ip = doh_resolve(self.host)
        return self.ip

    def as_front(self) -> "FrontProfile":
        fp = FrontProfile.__new__(FrontProfile)
        fp.outbound, fp.host, fp.port, fp.name = self.outbound, self.host, self.port, self.name
        fp.ip = self.resolve()
        if not fp.ip:
            raise XrayLinkError(f"Cannot resolve {self.host}")
        return fp

    def to_dict(self) -> dict:
        return {"link": self.link, "source": self.source}


def real_delay_test(profiles: list, progress=None, url="https://www.gstatic.com/generate_204",
                    timeout: float = 8, base_port: int = 21000) -> None:
    """v2rayN-style real delay: one Xray process with one local HTTP inbound per profile,
    then an HTTPS request through each. Sets profile.delay (ms) or None."""
    import time as _t
    import requests
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from system_net import get_local_ip
    phys = get_local_ip()
    inbounds, outbounds, rules, hosts, idx = [], [], [], {}, {}
    for i, p in enumerate(profiles):
        p.tested, p.delay = True, None
        ip = p.resolve()
        if not ip:
            continue
        ob = json.loads(json.dumps(p.outbound))
        ob["tag"] = f"o{i}"
        ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["domainStrategy"] = "UseIPv4"
        if phys != "127.0.0.1":
            ob["sendThrough"] = phys
        if p.host != ip:
            hosts[p.host] = ip
        outbounds.append(ob)
        inbounds.append({"tag": f"i{i}", "listen": "127.0.0.1", "port": base_port + i, "protocol": "http"})
        rules.append({"type": "field", "inboundTag": [f"i{i}"], "outboundTag": f"o{i}"})
        idx[i] = p
    if not idx:
        return
    proc = XrayProcess("delaytest")
    ok, msg = proc.start({"log": {"loglevel": "error"}, "dns": {"hosts": hosts, "servers": ["localhost"]},
                          "inbounds": inbounds, "outbounds": outbounds, "routing": {"rules": rules}})
    if not ok:
        proc.stop()
        raise RuntimeError(msg)

    def one(i):
        px = f"http://127.0.0.1:{base_port + i}"
        best = None
        for _ in range(2):  # the first request includes the handshake; keep the better one
            t0 = _t.perf_counter()
            try:
                r = requests.get(url, proxies={"http": px, "https": px}, timeout=timeout)
                if r.status_code in (200, 204):
                    d = (_t.perf_counter() - t0) * 1000
                    best = d if best is None else min(best, d)
            except Exception:
                break
        return i, (round(best) if best is not None else None)

    try:
        done = 0
        with ThreadPoolExecutor(max_workers=16) as ex:
            for fut in as_completed([ex.submit(one, i) for i in idx]):
                i, d = fut.result()
                idx[i].delay = d
                done += 1
                if progress:
                    progress(done, len(idx))
    finally:
        proc.stop()
