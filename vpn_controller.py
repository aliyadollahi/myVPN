"""
Connection orchestrator (runs in a worker thread, talks to the UI through emit()).

Order of operations on Connect:
  1. resolve Xray front server (before anything blocks DNS)
  2. kill switch ON (firewall allows only VPN Gate candidates + Xray server + LAN)
  3. Xray FRONT up (if a link is configured)  -> VPN engine dials through 127.0.0.1:10810
  4. VPN engine (SoftEther / OpenVPN) to the chosen server
  5. Xray GATEWAY up, bound to the tunnel IP, Windows proxy -> 127.0.0.1:10809
  6. monitor; on drop -> next fastest server (auto-switch); "Change IP" -> next server
Disconnect undoes everything in reverse; a crash is undone on next start (system_net.recover_after_crash).
"""

import threading
import time
from dataclasses import dataclass

from connection_engine import OpenVpnManager, SoftEtherManager
from system_net import (disable_kill_switch, enable_kill_switch, get_local_ip, load_state,
                        physical_interfaces, public_ip, restore_system_proxy, set_system_proxy)
from xray_manager import (FRONT_HTTP_PORT, GW_HTTP_PORT, FrontProfile, XrayLinkError, XrayProcess,
                          build_front_config, build_gateway_config, random_lan_credentials)
import bootstrap

CONNECT_TIMEOUT = 30
MAX_KS_ALLOWED = 60


@dataclass
class ConnectOptions:
    front_link: str = ""
    gateway: bool = True
    split_iran: bool = True
    lan_share: bool = False
    kill_switch: bool = False
    auto_switch: bool = True
    engine: str = "auto"  # auto | softether | openvpn


class VpnController:
    def __init__(self, emit):
        self.emit = emit
        self.softether = SoftEtherManager()
        self.openvpn = OpenVpnManager()
        self.front = XrayProcess("front")
        self.gateway = XrayProcess("gateway")
        self.lan_user, self.lan_pass = random_lan_credentials()
        self.current = None
        self.engine = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._switch = threading.Event()
        self._next_server = None
        self._lock = threading.Lock()

    # ---------------- public API (UI thread) ----------------
    @property
    def busy(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def engine_name(self, pref="auto") -> str:
        e = self._pick_engine(pref)
        return e.name if e else "none"

    def connect(self, server, candidates, opts: ConnectOptions):
        if self.busy:
            # Same session: switch server without dropping the kill switch / front.
            with self._lock:
                self._next_server = server
            self._switch.set()
            return
        self._stop = threading.Event()
        self._switch = threading.Event()
        self._next_server = None
        queue = [server] + [c for c in candidates if c is not server and c.reachable and not c.failed]
        target = self._run_xray if hasattr(server, "link") else self._run
        self._thread = threading.Thread(target=target, args=(queue, opts, self._stop, self._switch), daemon=True)
        self._thread.start()

    def change_ip(self):
        if self.busy:
            self._switch.set()

    def disconnect(self):
        self._stop.set()
        self._switch.set()
        if not self.busy and load_state().get("killswitch"):
            threading.Thread(target=self._unblock, daemon=True).start()

    def shutdown(self, timeout=20):
        self.disconnect()
        if self._thread:
            self._thread.join(timeout)
        if load_state().get("killswitch"):
            disable_kill_switch()

    # ---------------- internals ----------------
    def _unblock(self):
        disable_kill_switch()
        self.emit("disconnected", blocked=False)
        self.emit("status", text="● Disconnected (kill switch removed)", color="#94a3b8")

    def _pick_engine(self, pref):
        if pref == "openvpn" and self.openvpn.is_available():
            return self.openvpn
        if pref == "softether" and self.softether.is_available():
            return self.softether
        if self.softether.is_available():
            return self.softether
        if self.openvpn.is_available():
            return self.openvpn
        return None

    def _take_next(self, queue, tried):
        with self._lock:
            nxt, self._next_server = self._next_server, None
        if nxt is not None:
            return nxt
        key = lambda x: getattr(x, "link", None) or x.ip
        for s in queue:
            if key(s) not in tried and not s.failed:
                return s
        # Every server tried once: start another round over the ones that worked.
        if any(not s.failed for s in queue):
            tried.clear()
            for s in queue:
                if not s.failed:
                    return s
        return None

    def _bring_up(self, engine, server, proxy_port, stop, switch) -> str:
        if not engine.start(server, proxy_port):
            return "fail"
        start = time.time()
        down_count = 0
        while time.time() - start < CONNECT_TIMEOUT:
            if stop.is_set() or switch.is_set():
                return "abort"
            st = engine.status()
            if st == "Connected":
                return "ok"
            if st == "Disconnected" and time.time() - start > 3:
                down_count += 1
                if down_count >= 4:
                    return "fail"
            else:
                down_count = 0
            time.sleep(1)
        return "fail"

    @staticmethod
    def _wait_tunnel_ip(phys_ip, stop, timeout=15) -> str | None:
        end = time.time() + timeout
        while time.time() < end and not stop.is_set():
            ip = get_local_ip()
            if ip not in (phys_ip, "127.0.0.1") and not ip.startswith("169.254."):
                return ip
            time.sleep(1)
        return None

    def _monitor(self, engine, stop, switch, profile, gw_cfg) -> str:
        downs = 0
        gw_restarts = 0
        while True:
            for _ in range(4):
                if stop.is_set():
                    return "stop"
                if switch.is_set():
                    return "switch"
                time.sleep(0.5)
            if profile and not self.front.alive():
                return "front_dead"
            if gw_cfg and not self.gateway.alive():
                if gw_restarts >= 3:
                    self.emit("log", text="Xray gateway keeps crashing: " + " | ".join(self.gateway.log_tail[-3:]))
                    return "drop"
                gw_restarts += 1
                self.gateway.start(gw_cfg)
            if engine.status() == "Disconnected":
                downs += 1
                if downs >= 2:
                    return "drop"
            else:
                downs = 0

    def _run(self, queue, opts: ConnectOptions, stop: threading.Event, switch: threading.Event):
        engine = self._pick_engine(opts.engine)
        msg = ""
        if not engine:
            ok, msg = bootstrap.ensure_softether(lambda m: self.emit("status", text="● " + m, color="#f59e0b"))
            self.emit("log", text=msg)
            engine = self._pick_engine(opts.engine) if ok else None
        self.engine = engine
        if not engine:
            self.emit("error", text="VPN engine is not available: " + (msg or "unknown error"))
            self.emit("disconnected")
            return

        phys_ip = get_local_ip()
        profile = None
        ks_active = False
        allowed = set()
        split = opts.split_iran
        try:
            # 1. Xray front profile
            if opts.front_link.strip():
                try:
                    profile = FrontProfile(opts.front_link)
                except XrayLinkError as e:
                    self.emit("error", text=f"Xray link error: {e}")
                    return
                except Exception as e:
                    self.emit("error", text=f"Xray link error: {e}")
                    return

            # 2. kill switch
            if opts.kill_switch:
                self.emit("status", text="● Arming kill switch...", color="#f59e0b")
                allowed = {s.ip for s in queue[:MAX_KS_ALLOWED]}
                if profile:
                    allowed.add(profile.ip)
                ok, msg = enable_kill_switch(sorted(allowed), physical_interfaces())
                if not ok:
                    self.emit("error", text=f"Kill switch failed, not connecting: {msg}")
                    return
                ks_active = True
                self.emit("log", text=msg)
                if split:
                    split = False
                    self.emit("log", text="Iran-direct routing disabled while kill switch is on (everything goes through the VPN).")

            # 3. Xray front
            proxy_port = None
            if profile:
                self.emit("status", text=f"● Starting Xray front ({profile.name})...", color="#f59e0b")
                ok, msg = self.front.start(build_front_config(profile.outbound, profile.host, profile.ip, phys_ip))
                if not ok:
                    self.emit("error", text=f"Xray front failed: {msg}")
                    return
                proxy_port = FRONT_HTTP_PORT

            tried = set()
            while not stop.is_set():
                switch.clear()
                server = self._take_next(queue, tried)
                if server is None:
                    self.emit("error", text="No more reachable servers to try. Refresh the list or test ping again.")
                    break
                tried.add(server.ip)

                if ks_active and server.ip not in allowed:
                    allowed.add(server.ip)
                    enable_kill_switch(sorted(allowed), physical_interfaces())

                via = " via Xray" if profile else ""
                self.emit("status", text=f"● Connecting to {server.country_short} {server.ip}:{server.port}{via} ({engine.name})...",
                          color="#f59e0b")
                self.emit("connecting", server=server)
                res = self._bring_up(engine, server, proxy_port, stop, switch)
                if res != "ok":
                    engine.stop()
                    if res == "abort":
                        continue
                    server.failed = True
                    self.emit("server_failed", server=server, text=getattr(engine, "last_error", ""))
                    if profile and not self.front.alive():
                        self.emit("error", text="Xray front died: " + " | ".join(self.front.log_tail[-3:]))
                        break
                    if not opts.auto_switch:
                        self.emit("error", text=f"Could not connect to {server.ip}. Enable Auto-Switch or pick another server.")
                        break
                    continue

                # 5. gateway
                gw_cfg = None
                if opts.gateway:
                    vpn_ip = self._wait_tunnel_ip(phys_ip, stop)
                    if vpn_ip:
                        gw_cfg = build_gateway_config(vpn_ip, phys_ip, split, opts.lan_share,
                                                      self.lan_user, self.lan_pass, XrayProcess.geo_available())
                        ok, msg = self.gateway.start(gw_cfg)
                        if ok:
                            set_system_proxy(GW_HTTP_PORT)
                        else:
                            gw_cfg = None
                            self.emit("log", text=f"Xray gateway failed (VPN still works without it): {msg}")
                    else:
                        self.emit("log", text="Tunnel IP not detected; Xray gateway skipped.")

                self.current = server
                self.emit("connected", server=server, engine=engine.name, front=profile.name if profile else "",
                          gateway=bool(gw_cfg))
                threading.Thread(target=lambda s=server: self.emit("public_ip", ip=public_ip(), server=s),
                                 daemon=True).start()

                reason = self._monitor(engine, stop, switch, profile, gw_cfg)

                # tear down this hop (kill switch + front stay)
                self.gateway.stop()
                restore_system_proxy()
                engine.stop()
                self.current = None

                if reason == "stop":
                    break
                if reason == "switch":
                    self.emit("log", text="Changing IP: switching to the next server...")
                    continue
                if reason == "front_dead":
                    self.emit("log", text="Xray front crashed, restarting it...")
                    ok, msg = self.front.start(build_front_config(profile.outbound, profile.host, profile.ip, phys_ip))
                    if not ok:
                        self.emit("error", text=f"Xray front failed: {msg}")
                        break
                    tried.discard(server.ip)
                    continue
                # drop
                self.emit("dropped", server=server)
                if not opts.auto_switch:
                    break
        except Exception as e:  # never leave the system half-configured
            self.emit("error", text=f"Unexpected error: {e}")
        finally:
            self.gateway.stop()
            restore_system_proxy()
            engine.stop()
            self.front.stop()
            self.current = None
            if ks_active:
                if stop.is_set():
                    disable_kill_switch()
                else:
                    self.emit("blocked", text="VPN is down - internet is BLOCKED by the kill switch. "
                                              "Press Disconnect to unblock.")
            self.emit("disconnected", blocked=ks_active and not stop.is_set())


    # ======================= Xray-only mode =======================
    def _probe_proxy(self, timeout=10) -> bool:
        import requests
        px = f"http://127.0.0.1:{GW_HTTP_PORT}"
        try:
            r = requests.get("https://www.gstatic.com/generate_204", proxies={"http": px, "https": px},
                             timeout=timeout)
            return r.status_code in (200, 204)
        except Exception:
            return False

    def _run_xray(self, queue, opts: ConnectOptions, stop: threading.Event, switch: threading.Event):
        """Connects straight through the user's Xray servers (no VPN Gate). System proxy + Iran-direct."""
        phys_ip = get_local_ip()
        ks_active = False
        allowed = set()
        split = opts.split_iran
        try:
            if opts.kill_switch:
                self.emit("status", text="● Arming kill switch...", color="#f59e0b")
                for p in queue[:MAX_KS_ALLOWED]:
                    if p.resolve():
                        allowed.add(p.ip)
                ok, msg = enable_kill_switch(sorted(allowed), physical_interfaces())
                if not ok:
                    self.emit("error", text=f"Kill switch failed, not connecting: {msg}")
                    return
                ks_active = True
                split = False
                self.emit("log", text=msg)

            tried = set()
            while not stop.is_set():
                switch.clear()
                prof = self._take_next(queue, tried)
                if prof is None:
                    self.emit("error", text="None of your Xray servers work right now. Run 'Test Delay' or add more.")
                    break
                tried.add(prof.link)
                self.emit("status", text=f"● Connecting via Xray: {prof.name}...", color="#f59e0b")
                self.emit("connecting", server=prof)
                try:
                    front = prof.as_front()
                except XrayLinkError as e:
                    prof.failed = True
                    self.emit("server_failed", server=prof, text=str(e))
                    continue
                if ks_active and front.ip not in allowed:
                    allowed.add(front.ip)
                    enable_kill_switch(sorted(allowed), physical_interfaces())

                cfg = build_gateway_config(None, phys_ip, split, opts.lan_share, self.lan_user, self.lan_pass,
                                           XrayProcess.geo_available(), proxy_profile=front)
                ok, msg = self.gateway.start(cfg)
                if not ok or not self._probe_proxy():
                    self.gateway.stop()
                    prof.failed = True
                    self.emit("server_failed", server=prof, text=msg if not ok else "no internet through this server")
                    if not opts.auto_switch:
                        self.emit("error", text=f"{prof.name} does not work. Enable Auto-Switch or pick another.")
                        break
                    continue

                set_system_proxy(GW_HTTP_PORT)
                self.current = prof
                self.emit("connected", server=prof, engine="Xray", front="", gateway=True)
                threading.Thread(target=lambda p=prof: self.emit("public_ip", ip=public_ip(), server=p),
                                 daemon=True).start()

                reason, fails = None, 0
                while reason is None:
                    for _ in range(20):          # health check every ~10 s
                        if stop.is_set():
                            reason = "stop"
                            break
                        if switch.is_set():
                            reason = "switch"
                            break
                        if not self.gateway.alive():
                            reason = "drop"
                            break
                        time.sleep(0.5)
                    if reason is None:
                        fails = 0 if self._probe_proxy(8) else fails + 1
                        if fails >= 3:
                            reason = "drop"

                self.gateway.stop()
                restore_system_proxy()
                self.current = None
                if reason == "stop":
                    break
                if reason == "drop":
                    self.emit("dropped", server=prof)
                    if not opts.auto_switch:
                        break
        except Exception as e:
            self.emit("error", text=f"Unexpected error: {e}")
        finally:
            self.gateway.stop()
            restore_system_proxy()
            self.current = None
            if ks_active:
                if stop.is_set():
                    disable_kill_switch()
                else:
                    self.emit("blocked", text="Xray is down - internet is BLOCKED by the kill switch. "
                                              "Press Disconnect to unblock.")
            self.emit("disconnected", blocked=ks_active and not stop.is_set())
