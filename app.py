import json
import os
import queue
import sys
import threading
from tkinter import filedialog, messagebox

import customtkinter as ctk
from PIL import ImageTk

import bootstrap
from connection_engine import MobileShareServer
from system_net import (app_dir, data_dir, is_admin, protect_str, recover_after_crash, relaunch_as_admin,
                        unprotect_str)
from vpn_controller import ConnectOptions, VpnController
from vpngate_fetcher import VpnGateFetcher, VpnGateServer, measure_latency, sort_servers
from xray_manager import (GW_HTTP_PORT, GW_SOCKS_PORT, LAN_SOCKS_PORT, XrayLinkError, XrayProcess, XrayProfile,
                          build_front_config, extract_links, fetch_subscription, real_delay_test)

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

APP_VERSION = "2.0"
CACHE_FILE = os.path.join(data_dir(), "cached_servers.json")
SETTINGS_FILE = os.path.join(data_dir(), "settings.json")
SORT_MODES = ["Best (Ping + Speed)", "Lowest Ping", "Highest Speed", "Most Users"]
FETCH_PROXY_PORT = 10811

GREEN, AMBER, RED, GREY = "#10b981", "#f59e0b", "#ef4444", "#94a3b8"


def get_flag(cc: str) -> str:
    cc = (cc or "").upper()
    if len(cc) == 2 and cc.isalpha():
        return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)
    return "🌐"


class VpnApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(f"VPN Gate Guardian {APP_VERSION}")
        self.geometry("1120x780")
        self.minsize(920, 620)

        self.events: queue.Queue = queue.Queue()
        self.controller = VpnController(lambda kind, **kw: self.events.put((kind, kw)))
        self.fetcher = VpnGateFetcher()
        self.mobile_share = MobileShareServer()

        self.servers: list[VpnGateServer] = []
        self.filtered_servers: list[VpnGateServer] = []
        self.display_limit = 25
        self.connected_server = None
        self.connecting_server = None
        self.pinging = False
        self.delay_testing = False
        self.ready = False
        self.settings = self._load_settings()
        self.profiles: list[XrayProfile] = self._load_profiles()

        self._build_ui()
        self.after(100, self._drain_events)

        for note in recover_after_crash():
            self._footer(note)
        self._load_cache()
        self._render_profiles()
        threading.Thread(target=self._first_run_setup, daemon=True).start()

    # ======================= first run =======================
    def _first_run_setup(self):
        """Unpacks bundled Xray and installs the VPN engine if missing (exe = zero dependencies)."""
        put = lambda kind, **kw: self.events.put((kind, kw))
        put("setup", text="Preparing components...")
        xray = bootstrap.ensure_xray()
        ok, msg = bootstrap.ensure_softether(lambda m: put("setup", text=m))
        if not ok and self.controller.openvpn.is_available():
            ok, msg = True, "Using installed OpenVPN"
        put("setup_done", xray=bool(xray), engine_ok=ok, text=msg)

    def _ev_setup(self, text):
        self.status_badge.configure(text=f"● {text}", text_color=AMBER)

    def _ev_setup_done(self, xray, engine_ok, text):
        self.ready = True
        self.status_badge.configure(text="● Disconnected" if engine_ok else "● VPN engine missing",
                                    text_color=GREY if engine_ok else RED)
        self._footer(f"{text}  |  {self._mode_summary()}")
        if not engine_ok:
            messagebox.showwarning("VPN engine", f"{text}\n\nXray servers (My Xray Servers tab) still work.")
        if not self.servers:
            self.start_refresh()
        else:
            self.start_ping_test()

    # ======================= settings / profiles =======================
    def _load_settings(self) -> dict:
        s = {"front_on": False, "front_link": "", "gateway": True, "split_iran": True, "lan_share": False,
             "kill_switch": False, "auto_switch": True, "sort": SORT_MODES[0], "engine": "auto"}
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            s.update({k: v for k, v in saved.items() if k in s or k.endswith("_enc")})
        except Exception:
            pass
        s["front_link"] = unprotect_str(s.pop("front_link_enc", "")) or s.get("front_link", "")
        return s

    def _load_profiles(self) -> list[XrayProfile]:
        raw = unprotect_str(self.settings.pop("profiles_enc", ""))
        out = []
        try:
            for d in json.loads(raw or "[]"):
                try:
                    out.append(XrayProfile(d["link"], d.get("source", "")))
                except Exception:
                    pass
        except Exception:
            pass
        if self.settings.get("front_link") and not any(p.link == self.settings["front_link"] for p in out):
            try:
                out.insert(0, XrayProfile(self.settings["front_link"]))
            except Exception:
                pass
        self.subscriptions = json.loads(unprotect_str(self.settings.pop("subs_enc", "")) or "[]")
        return out

    def _save_settings(self):
        s = {k: v for k, v in self.settings.items() if not k.endswith("_enc")}
        s["front_link_enc"] = protect_str(s.pop("front_link", ""))   # Windows DPAPI, per user
        s["profiles_enc"] = protect_str(json.dumps([p.to_dict() for p in self.profiles]))
        s["subs_enc"] = protect_str(json.dumps(self.subscriptions))
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(s, f)
        except Exception:
            pass

    def _sync_settings(self):
        for key, var in self.opt_vars.items():
            self.settings[key] = bool(var.get())
        self.settings["sort"] = self.sort_option.get()
        self.settings["engine"] = self.engine_option.get().lower()
        self._save_settings()

    # ======================= UI =======================
    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ---- header
        header = ctk.CTkFrame(self, corner_radius=12, fg_color="#1a1c23")
        header.grid(row=0, column=0, padx=16, pady=(16, 6), sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(header, text="VPN Gate Guardian", font=ctk.CTkFont(size=18, weight="bold")).grid(
            row=0, column=0, rowspan=2, padx=16, pady=10, sticky="w")
        self.status_badge = ctk.CTkLabel(header, text="● Starting...", text_color=AMBER,
                                         font=ctk.CTkFont(size=14, weight="bold"), anchor="w")
        self.status_badge.grid(row=0, column=1, padx=10, pady=(10, 0), sticky="w")
        self.ip_label = ctk.CTkLabel(header, text="Exit IP: -", text_color="#64748b",
                                     font=ctk.CTkFont(size=12), anchor="w")
        self.ip_label.grid(row=1, column=1, padx=10, pady=(0, 10), sticky="w")
        self.engine_option = ctk.CTkOptionMenu(header, values=["Auto", "SoftEther", "OpenVPN"], width=105,
                                               command=lambda _: self._sync_settings())
        self.engine_option.set({"softether": "SoftEther", "openvpn": "OpenVPN"}.get(
            self.settings.get("engine", "auto"), "Auto"))
        self.engine_option.grid(row=0, column=2, rowspan=2, padx=(0, 8))
        if is_admin():
            ctk.CTkLabel(header, text="🛡 Admin", text_color=GREEN, font=ctk.CTkFont(size=12)).grid(
                row=0, column=3, rowspan=2, padx=(0, 8))
        else:
            ctk.CTkButton(header, text="🛡 Run as Admin", width=120, fg_color="#b45309", hover_color="#92400e",
                          command=self.restart_admin).grid(row=0, column=3, rowspan=2, padx=(0, 8))
        self.btn_change_ip = ctk.CTkButton(header, text="🔀 Change IP", width=110, state="disabled",
                                           command=self.change_ip, fg_color="#8b5cf6", hover_color="#7c3aed")
        self.btn_change_ip.grid(row=0, column=4, rowspan=2, padx=(0, 8))
        self.btn_disconnect = ctk.CTkButton(header, text="⏹ Disconnect", width=110, state="disabled",
                                            command=self.disconnect_vpn, fg_color=RED, hover_color="#dc2626")
        self.btn_disconnect.grid(row=0, column=5, rowspan=2, padx=(0, 16))

        # ---- options bar (shared by both tabs)
        opts = ctk.CTkFrame(self, corner_radius=10, fg_color="#15171d")
        opts.grid(row=1, column=0, padx=16, pady=4, sticky="ew")
        self.opt_vars = {}
        specs = [
            ("front_on", "Xray Front for VPN Gate"),
            ("gateway", "System proxy (Xray)"),
            ("split_iran", "Iran sites direct"),
            ("lan_share", "Share on LAN"),
            ("kill_switch", "Kill Switch"),
            ("auto_switch", "Auto-Switch"),
        ]
        for col, (key, label) in enumerate(specs):
            var = ctk.BooleanVar(value=bool(self.settings.get(key)))
            self.opt_vars[key] = var
            ctk.CTkCheckBox(opts, text=label, variable=var, command=self._on_option_change,
                            font=ctk.CTkFont(size=12), checkbox_width=18, checkbox_height=18).grid(
                row=0, column=col, padx=8, pady=8, sticky="w")

        # ---- tabs
        self.tabs = ctk.CTkTabview(self, corner_radius=12, fg_color="#111318", segmented_button_selected_color="#3b82f6")
        self.tabs.grid(row=3, column=0, padx=16, pady=(4, 4), sticky="nsew")
        self._build_vpngate_tab(self.tabs.add("VPN Gate Servers"))
        self._build_xray_tab(self.tabs.add("My Xray Servers"))

        # ---- footer
        self.footer_label = ctk.CTkLabel(self, text="", font=ctk.CTkFont(size=12),
                                         text_color="#64748b", anchor="w", justify="left", wraplength=1050)
        self.footer_label.grid(row=4, column=0, padx=16, pady=(0, 8), sticky="ew")

    def _build_vpngate_tab(self, tab):
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=0, column=0, pady=(0, 6), sticky="ew")
        bar.grid_columnconfigure(0, weight=1)
        self.search_entry = ctk.CTkEntry(bar, placeholder_text="🔍 Search country, code, or IP...", height=34)
        self.search_entry.grid(row=0, column=0, padx=(0, 8), sticky="ew")
        self.search_entry.bind("<KeyRelease>", lambda e: self.filter_servers())
        self.sort_option = ctk.CTkOptionMenu(bar, values=SORT_MODES, width=170, height=34,
                                             command=lambda _: (self._sync_settings(), self.filter_servers()))
        self.sort_option.set(self.settings.get("sort") if self.settings.get("sort") in SORT_MODES else SORT_MODES[0])
        self.sort_option.grid(row=0, column=1, padx=(0, 8))
        self.btn_ping = ctk.CTkButton(bar, text="⚡ Test Ping", width=105, height=34, command=self.start_ping_test,
                                      fg_color="#0ea5e9", hover_color="#0284c7")
        self.btn_ping.grid(row=0, column=2, padx=(0, 8))
        self.btn_refresh = ctk.CTkButton(bar, text="🔄 Refresh", width=100, height=34, command=self.start_refresh,
                                         fg_color="#3b82f6", hover_color="#2563eb")
        self.btn_refresh.grid(row=0, column=3, padx=(0, 8))
        ctk.CTkButton(bar, text="🚀 Connect Best", width=120, height=34, command=self.connect_best,
                      fg_color=GREEN, hover_color="#059669").grid(row=0, column=4)
        self.scroll_frame = ctk.CTkScrollableFrame(tab, corner_radius=10, fg_color="#0d0f13")
        self.scroll_frame.grid(row=1, column=0, sticky="nsew")
        self.scroll_frame.grid_columnconfigure(0, weight=1)

    def _build_xray_tab(self, tab):
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        bar = ctk.CTkFrame(tab, fg_color="transparent")
        bar.grid(row=0, column=0, pady=(0, 6), sticky="ew")
        bar.grid_columnconfigure(0, weight=1)
        self.link_entry = ctk.CTkEntry(bar, height=34,
                                       placeholder_text="Paste vless:// vmess:// trojan:// ss:// links, or a subscription URL (https://...)")
        self.link_entry.grid(row=0, column=0, padx=(0, 8), sticky="ew")
        ctk.CTkButton(bar, text="➕ Add", width=70, height=34, command=self.add_links).grid(row=0, column=1, padx=(0, 8))
        ctk.CTkButton(bar, text="📋 From Clipboard", width=130, height=34, fg_color="#334155", hover_color="#475569",
                      command=self.add_from_clipboard).grid(row=0, column=2, padx=(0, 8))
        ctk.CTkButton(bar, text="🔄 Update Subs", width=110, height=34, fg_color="#334155", hover_color="#475569",
                      command=self.update_subscriptions).grid(row=0, column=3, padx=(0, 8))
        self.btn_delay = ctk.CTkButton(bar, text="⚡ Test Delay", width=105, height=34, command=self.start_delay_test,
                                       fg_color="#0ea5e9", hover_color="#0284c7")
        self.btn_delay.grid(row=0, column=4, padx=(0, 8))
        ctk.CTkButton(bar, text="🚀 Connect Best", width=120, height=34, command=self.connect_best_xray,
                      fg_color=GREEN, hover_color="#059669").grid(row=0, column=5)
        self.xray_frame = ctk.CTkScrollableFrame(tab, corner_radius=10, fg_color="#0d0f13")
        self.xray_frame.grid(row=1, column=0, sticky="nsew")
        self.xray_frame.grid_columnconfigure(0, weight=1)

    def _mode_summary(self) -> str:
        eng = self.controller.engine_name(self.settings.get("engine", "auto"))
        xray = "Xray ready" if XrayProcess.binary() else "Xray missing"
        return f"Engine: {eng}  |  {xray}  |  Data: {data_dir()}"

    def _footer(self, text: str):
        self.footer_label.configure(text=text)

    def _on_option_change(self):
        self._sync_settings()
        if self.settings["kill_switch"] and not is_admin():
            if messagebox.askyesno("Kill Switch", "Kill switch needs Administrator rights.\nRestart as Administrator now?"):
                self.restart_admin()
        if self.settings["front_on"] and not self.settings.get("front_link"):
            if self.profiles:
                self.set_front(self._sorted_profiles()[0])
            else:
                messagebox.showinfo("Xray Front", "Add an Xray server in the 'My Xray Servers' tab first.")
                self.opt_vars["front_on"].set(False)
                self._sync_settings()
                self.tabs.set("My Xray Servers")
        if self.controller.busy:
            self._footer("Option changes apply on the next connection.")

    def restart_admin(self):
        if self.controller.busy:
            messagebox.showinfo("Admin", "Disconnect first.")
            return
        if relaunch_as_admin():
            self.on_closing()

    # ======================= Xray profiles =======================
    def _sorted_profiles(self) -> list[XrayProfile]:
        return sorted(self.profiles, key=lambda p: (p.failed, not p.reachable,
                                                    p.delay if p.delay is not None else 99999))

    def _add_link_list(self, links, source="") -> int:
        known = {p.link for p in self.profiles}
        added, errors = 0, []
        for l in links:
            if l in known:
                continue
            try:
                self.profiles.append(XrayProfile(l, source))
                known.add(l)
                added += 1
            except XrayLinkError as e:
                errors.append(str(e))
        if errors:
            self._footer(f"{len(errors)} link(s) skipped: {errors[0]}")
        return added

    def _ingest_text(self, text: str):
        text = text.strip()
        if not text:
            return
        if text.lower().startswith(("http://", "https://")) and "\n" not in text:
            url = text
            self._footer("Downloading subscription...")

            def run():
                try:
                    links = fetch_subscription(url)
                    self.events.put(("subs_loaded", {"url": url, "links": links}))
                except Exception as e:
                    self.events.put(("log", {"text": f"Subscription failed: {e}"}))
            threading.Thread(target=run, daemon=True).start()
            return
        links = extract_links(text)
        if not links:
            messagebox.showerror("Xray", "No valid vless/vmess/trojan/ss link found.")
            return
        n = self._add_link_list(links)
        self._save_settings()
        self._render_profiles()
        self._footer(f"Added {n} server(s). Press 'Test Delay' to find the fastest.")

    def add_links(self):
        self._ingest_text(self.link_entry.get())
        self.link_entry.delete(0, "end")

    def add_from_clipboard(self):
        try:
            self._ingest_text(self.clipboard_get())
        except Exception:
            messagebox.showinfo("Clipboard", "Clipboard is empty.")

    def _ev_subs_loaded(self, url, links):
        if url not in self.subscriptions:
            self.subscriptions.append(url)
        self.profiles = [p for p in self.profiles if p.source != url]
        n = self._add_link_list(links, url)
        self._save_settings()
        self._render_profiles()
        self._footer(f"Subscription: {n} server(s) loaded.")

    def update_subscriptions(self):
        if not self.subscriptions:
            messagebox.showinfo("Subscriptions", "No subscription URL added yet. Paste one into the box and press Add.")
            return
        for url in list(self.subscriptions):
            self._ingest_text(url)

    def delete_profile(self, p: XrayProfile):
        if self.connected_server is p:
            messagebox.showinfo("Xray", "Disconnect first.")
            return
        self.profiles = [x for x in self.profiles if x is not p]
        if self.settings.get("front_link") == p.link:
            self.settings["front_link"] = ""
            self.opt_vars["front_on"].set(False)
        self._sync_settings()
        self._render_profiles()

    def set_front(self, p: XrayProfile):
        self.settings["front_link"] = p.link
        self.opt_vars["front_on"].set(True)
        self._sync_settings()
        self._render_profiles()
        self._footer(f"VPN Gate connections will now go through Xray: {p.name}")

    def start_delay_test(self):
        if self.delay_testing or not self.profiles:
            return
        if not XrayProcess.binary():
            messagebox.showerror("Xray", "Xray is not ready yet.")
            return
        self.delay_testing = True
        self.btn_delay.configure(state="disabled", text="⏳ 0%")
        profs = [p for p in self.profiles if p is not self.connected_server]

        def run():
            try:
                real_delay_test(profs, progress=lambda d, t: self.events.put(("delay_progress", {"done": d, "total": t})))
            except Exception as e:
                self.events.put(("log", {"text": f"Delay test failed: {e}"}))
            self.events.put(("delay_done", {}))
        threading.Thread(target=run, daemon=True).start()

    def _ev_delay_progress(self, done, total):
        self.btn_delay.configure(text=f"⏳ {int(done * 100 / max(total, 1))}%")

    def _ev_delay_done(self):
        self.delay_testing = False
        self.btn_delay.configure(state="normal", text="⚡ Test Delay")
        for p in self.profiles:
            p.failed = False
        ok = sum(1 for p in self.profiles if p.delay is not None)
        self._render_profiles()
        self._footer(f"Delay test: {ok}/{len(self.profiles)} Xray servers work.")

    def _render_profiles(self):
        for w in self.xray_frame.winfo_children():
            w.destroy()
        if not self.profiles:
            ctk.CTkLabel(self.xray_frame, justify="center", text_color="#64748b", font=ctk.CTkFont(size=13),
                         text="No Xray servers yet.\nPaste a vless:// vmess:// trojan:// ss:// link or a subscription "
                              "URL above.\nThey can be used on their own, or as a 'front' to reach VPN Gate.").pack(pady=40)
            return
        front = self.settings.get("front_link")
        for rank, p in enumerate(self._sorted_profiles(), 1):
            is_conn = self.connected_server is p
            is_connecting = self.connecting_server is p and not is_conn
            card = ctk.CTkFrame(self.xray_frame, corner_radius=10, fg_color="#1a1c23", border_width=2,
                                border_color=GREEN if is_conn else (AMBER if is_connecting else "#1a1c23"))
            card.pack(fill="x", padx=4, pady=4)
            card.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(card, text=f"#{rank}", width=34, text_color="#64748b",
                         font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, rowspan=2, padx=(10, 6))
            proto = p.outbound.get("protocol", "?")
            net = p.outbound.get("streamSettings", {}).get("network", "tcp")
            sec = p.outbound.get("streamSettings", {}).get("security", "")
            title = f"{p.name[:48]}{'  ★ Front' if p.link == front else ''}"
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=13, weight="bold"), anchor="w").grid(
                row=0, column=1, sticky="w", pady=(6, 0))
            if p.failed:
                d_txt, color = "failed", RED
            elif p.delay is not None:
                d_txt = f"{p.delay} ms"
                color = GREEN if p.delay < 800 else AMBER
            elif p.tested:
                d_txt, color = "timeout", RED
            else:
                d_txt, color = "not tested", GREY
            sub = f"{proto}/{net}{'/' + sec if sec and sec != 'none' else ''}  •  {p.host}:{p.port}  |  Delay: {d_txt}"
            if p.source:
                sub += "  |  sub"
            ctk.CTkLabel(card, text=sub, font=ctk.CTkFont(size=11), text_color=color, anchor="w").grid(
                row=1, column=1, sticky="w", pady=(0, 6))
            box = ctk.CTkFrame(card, fg_color="transparent")
            box.grid(row=0, column=2, rowspan=2, padx=10, pady=6, sticky="e")
            ctk.CTkButton(box, text="★ Use as Front", width=100, height=28, font=ctk.CTkFont(size=11),
                          fg_color="#6366f1", hover_color="#4f46e5",
                          command=lambda x=p: self.set_front(x)).pack(side="left", padx=3)
            ctk.CTkButton(box, text="🗑", width=34, height=28, fg_color="#334155", hover_color="#475569",
                          command=lambda x=p: self.delete_profile(x)).pack(side="left", padx=3)
            if is_conn:
                txt, fg = "Disconnect", RED
            elif is_connecting:
                txt, fg = "Connecting…", AMBER
            else:
                txt, fg = "Connect", GREEN
            ctk.CTkButton(box, text=txt, width=95, height=28, font=ctk.CTkFont(size=11, weight="bold"), fg_color=fg,
                          command=lambda x=p: self.toggle_connect(x)).pack(side="left", padx=3)

    def connect_best_xray(self):
        cands = [p for p in self._sorted_profiles() if not p.failed and p.reachable]
        if not cands:
            messagebox.showinfo("Xray", "No working Xray server. Add servers and run Test Delay.")
            self.tabs.set("My Xray Servers")
            return
        self.connect_vpn(cands[0])

    # ======================= cache / fetch / ping =======================
    def _load_cache(self):
        for path in (CACHE_FILE, os.path.join(app_dir(), "cached_servers.json"), bootstrap.seed_servers_path()):
            if path and os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        self.servers = [VpnGateServer(row) for row in json.load(f)]
                    if self.servers:
                        self.filter_servers()
                        self._footer(f"Loaded {len(self.servers)} saved servers.")
                        return
                except Exception:
                    pass

    def _save_cache(self):
        try:
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump([s.to_dict() for s in self.servers], f)
        except Exception:
            pass

    def start_refresh(self):
        self.btn_refresh.configure(state="disabled", text="⏳ ...")
        profiles = self._sorted_profiles()
        put = lambda kind, **kw: self.events.put((kind, kw))

        def run():
            prog = lambda m: put("log", text=m)
            try:
                put("fetch_ok", servers=self.fetcher.get_servers(progress=prog), source=self.fetcher.last_source)
                return
            except Exception as e:
                err = str(e)
            # Last resort: fetch through the user's own Xray servers.
            for p in [x for x in profiles if x.reachable][:3]:
                if not XrayProcess.binary():
                    break
                proc = XrayProcess("fetch")
                try:
                    f = p.as_front()
                    ok, _ = proc.start(build_front_config(f.outbound, f.host, f.ip, None, port=FETCH_PROXY_PORT))
                    if ok:
                        servers = self.fetcher.get_servers(proxy=f"http://127.0.0.1:{FETCH_PROXY_PORT}", progress=prog)
                        put("fetch_ok", servers=servers, source=f"mirrors via Xray ({p.name})")
                        return
                except Exception as e:
                    err = str(e)
                finally:
                    proc.stop()
            put("fetch_err", text=err)

        threading.Thread(target=run, daemon=True).start()

    def start_ping_test(self):
        if self.pinging or not self.servers:
            return
        if self.controller.busy:
            self._footer("Disconnect first: pinging through the tunnel would measure the tunnel, not the servers.")
            return
        self.pinging = True
        self.btn_ping.configure(state="disabled", text="⏳ 0%")
        servers = list(self.servers)

        def run():
            measure_latency(servers, progress=lambda d, t: self.events.put(("ping_progress", {"done": d, "total": t})))
            self.events.put(("ping_done", {}))

        threading.Thread(target=run, daemon=True).start()

    # ======================= VPN Gate list =======================
    def filter_servers(self):
        q = self.search_entry.get().strip().lower()
        # Iranian VPN Gate servers exit inside Iran -> useless against the filter; shown only when searched.
        res = [s for s in self.servers
               if (not q and s.country_short.upper() != "IR")
               or (q and (q in s.country_long.lower() or q == s.country_short.lower() or q in s.ip))]
        self.filtered_servers = sort_servers(res, self.sort_option.get())
        self.display_limit = 25
        self._render_server_list()

    def _render_server_list(self):
        for w in self.scroll_frame.winfo_children():
            w.destroy()
        if not self.filtered_servers:
            ctk.CTkLabel(self.scroll_frame, text="No servers yet. Press Refresh.",
                         font=ctk.CTkFont(size=14), text_color="#64748b").pack(pady=40)
            return
        for idx, s in enumerate(self.filtered_servers[:self.display_limit]):
            self._render_card(s, idx + 1)
        remaining = len(self.filtered_servers) - self.display_limit
        if remaining > 0:
            ctk.CTkButton(self.scroll_frame, text=f"Show More ({remaining} remaining)", fg_color="#1e293b",
                          hover_color="#334155", command=self._load_more).pack(fill="x", padx=4, pady=8)

    def _load_more(self):
        self.display_limit += 25
        self._render_server_list()

    def _render_card(self, s: VpnGateServer, rank: int):
        is_conn = self.connected_server is s
        is_connecting = self.connecting_server is s and not is_conn
        border = GREEN if is_conn else (AMBER if is_connecting else "#1a1c23")
        card = ctk.CTkFrame(self.scroll_frame, corner_radius=10, fg_color="#1a1c23", border_width=2,
                            border_color=border)
        card.pack(fill="x", padx=4, pady=4)
        card.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(card, text=f"#{rank}", width=34, text_color="#64748b",
                     font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, rowspan=2, padx=(10, 0))
        ctk.CTkLabel(card, text=get_flag(s.country_short), font=ctk.CTkFont(size=24)).grid(
            row=0, column=1, rowspan=2, padx=(4, 10), pady=6)
        ctk.CTkLabel(card, text=f"{s.country_long} ({s.country_short})  •  {s.ip}:{s.port}",
                     font=ctk.CTkFont(size=13, weight="bold"), anchor="w").grid(row=0, column=2, sticky="w", pady=(6, 0))

        if s.failed:
            lat_txt, color = "failed to connect", RED
        elif s.latency is not None:
            lat_txt = f"{s.latency} ms"
            color = GREEN if s.latency < 150 else (AMBER if s.latency < 300 else GREY)
        elif s.tcp_port == 0:
            lat_txt, color = "unreachable", RED
        else:
            lat_txt, color = "not tested", GREY
        metrics = (f"Your ping: {lat_txt}  |  Speed: {s.speed_mbps} Mbps  |  "
                   f"Sessions: {s.num_sessions}  |  VPNGate ping: {s.ping} ms")
        ctk.CTkLabel(card, text=metrics, font=ctk.CTkFont(size=11), text_color=color, anchor="w").grid(
            row=1, column=2, sticky="w", pady=(0, 6))

        box = ctk.CTkFrame(card, fg_color="transparent")
        box.grid(row=0, column=3, rowspan=2, padx=12, pady=6, sticky="e")
        ctk.CTkButton(box, text="📱 QR", width=60, height=28, font=ctk.CTkFont(size=11), fg_color="#6366f1",
                      hover_color="#4f46e5", command=lambda srv=s: self.show_qr_dialog(srv)).pack(side="left", padx=3)
        ctk.CTkButton(box, text="💾 .ovpn", width=70, height=28, font=ctk.CTkFont(size=11), fg_color="#334155",
                      hover_color="#475569", command=lambda srv=s: self.export_ovpn(srv)).pack(side="left", padx=3)
        if is_conn:
            txt, fg, hv = "Disconnect", RED, "#dc2626"
        elif is_connecting:
            txt, fg, hv = "Connecting…", AMBER, "#d97706"
        else:
            txt, fg, hv = "Connect", GREEN, "#059669"
        ctk.CTkButton(box, text=txt, width=95, height=28, font=ctk.CTkFont(size=11, weight="bold"), fg_color=fg,
                      hover_color=hv, command=lambda srv=s: self.toggle_connect(srv)).pack(side="left", padx=3)

    # ======================= share / export =======================
    def show_qr_dialog(self, server: VpnGateServer):
        config = server.get_ovpn_config()
        if not config:
            messagebox.showerror("Error", "No configuration found for this server.")
            return
        self.mobile_share.start(server.ip, config)
        dlg = ctk.CTkToplevel(self)
        dlg.title(f"Mobile QR - {server.country_long}")
        dlg.geometry("380x440")
        dlg.resizable(False, False)
        dlg.grab_set()

        def close():
            self.mobile_share.stop()
            dlg.destroy()

        dlg.protocol("WM_DELETE_WINDOW", close)
        qr_tk = ImageTk.PhotoImage(self.mobile_share.generate_qr_image().resize((240, 240)))
        ctk.CTkLabel(dlg, text=f"📱 {server.country_long} [{server.ip}]",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(pady=(16, 4))
        ctk.CTkLabel(dlg, text="Scan on the same Wi-Fi to import into OpenVPN.\n"
                               "Link is token protected and stops when this window closes.",
                     font=ctk.CTkFont(size=11), text_color=GREY).pack(pady=(0, 10))
        lbl = ctk.CTkLabel(dlg, image=qr_tk, text="")
        lbl.image = qr_tk
        lbl.pack()
        ctk.CTkButton(dlg, text="Close", width=120, command=close).pack(pady=14)

    def export_ovpn(self, server: VpnGateServer):
        path = filedialog.asksaveasfilename(defaultextension=".ovpn",
                                            initialfile=f"VPN_{server.country_short}_{server.ip}.ovpn",
                                            filetypes=[("OpenVPN Config", "*.ovpn")])
        if path:
            if server.save_ovpn_file(path):
                messagebox.showinfo("Saved", f"Sanitized config saved to:\n{path}")
            else:
                messagebox.showerror("Error", "Failed to extract config data.")

    # ======================= connect =======================
    def _build_connect_options(self, xray_only: bool) -> ConnectOptions | None:
        if not self.ready:
            messagebox.showinfo("Please wait", "Components are still being prepared...")
            return None
        self._sync_settings()
        st = dict(self.settings)
        if not XrayProcess.binary():
            if xray_only or st["front_on"]:
                messagebox.showerror("Xray", "Xray component is missing.")
                return None
            st["gateway"] = False
        if st["kill_switch"] and not is_admin():
            if messagebox.askyesno("Kill Switch", "Kill switch needs Administrator rights.\n"
                                                  "Yes = restart as Admin,  No = connect without kill switch"):
                self.restart_admin()
                return None
            st["kill_switch"] = False
        return ConnectOptions(
            front_link=st["front_link"] if (st["front_on"] and not xray_only) else "",
            gateway=st["gateway"], split_iran=st["split_iran"], lan_share=st["lan_share"],
            kill_switch=st["kill_switch"], auto_switch=st["auto_switch"],
            engine=st.get("engine", "auto"),
        )

    def toggle_connect(self, server):
        if self.connected_server is server:
            self.disconnect_vpn()
        else:
            self.connect_vpn(server)

    def connect_best(self):
        cands = [s for s in self.filtered_servers if s.reachable and not s.failed]
        if not cands:
            messagebox.showinfo("Connect", "No reachable servers. Press Refresh, then Test Ping.")
            return
        self.connect_vpn(cands[0])

    def connect_vpn(self, server):
        xray_only = isinstance(server, XrayProfile)
        opts = self._build_connect_options(xray_only)
        if opts is None:
            return
        self.connecting_server = server
        self.btn_disconnect.configure(state="normal", text="⏹ Disconnect")
        self.btn_ping.configure(state="disabled")
        candidates = self._sorted_profiles() if xray_only else self.filtered_servers
        self.controller.connect(server, candidates, opts)
        self._rerender()

    def _rerender(self):
        self._render_server_list()
        self._render_profiles()

    def change_ip(self):
        self.controller.change_ip()
        self.btn_change_ip.configure(state="disabled")

    def disconnect_vpn(self):
        self.status_badge.configure(text="● Disconnecting...", text_color=AMBER)
        self.controller.disconnect()

    # ======================= events (main thread) =======================
    def _drain_events(self):
        try:
            while True:
                kind, kw = self.events.get_nowait()
                getattr(self, f"_ev_{kind}", lambda **_: None)(**kw)
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _ev_status(self, text, color):
        self.status_badge.configure(text=text, text_color=color)

    def _ev_log(self, text):
        self._footer(text)

    def _ev_error(self, text):
        self.status_badge.configure(text="● Error", text_color=RED)
        self._footer(text)
        messagebox.showerror("VPN Gate Guardian", text)

    def _ev_connecting(self, server):
        self.connecting_server = server
        self.connected_server = None
        self.ip_label.configure(text="Exit IP: -", text_color="#64748b")
        self._rerender()

    def _ev_server_failed(self, server, text=""):
        label = getattr(server, "name", None) or server.ip
        self._footer(f"{label} failed{': ' + text.strip()[:120] if text and text.strip() else ''} - trying next...")

    def _ev_connected(self, server, engine, front, gateway):
        self.connected_server = server
        self.connecting_server = None
        if isinstance(server, XrayProfile):
            chain = f"Xray → {server.name[:40]}"
        else:
            chain = f"{'Xray(' + front[:20] + ') → ' if front else ''}{engine} → {server.country_short} {server.ip}"
        self.status_badge.configure(text=f"● Connected: {chain}", text_color=GREEN)
        self.btn_change_ip.configure(state="normal")
        self.btn_disconnect.configure(state="normal")
        info = []
        if gateway:
            info.append(f"System proxy ON: HTTP 127.0.0.1:{GW_HTTP_PORT}  SOCKS 127.0.0.1:{GW_SOCKS_PORT}")
            if self.settings.get("lan_share"):
                info.append(f"LAN SOCKS5: <this PC IP>:{LAN_SOCKS_PORT}  user={self.controller.lan_user}  "
                            f"pass={self.controller.lan_pass}")
        if self.settings.get("kill_switch") and is_admin():
            info.append("Kill switch armed")
        self._footer("  |  ".join(info) or "Connected.")
        self.ip_label.configure(text="Exit IP: checking...", text_color="#64748b")
        self._rerender()

    def _ev_public_ip(self, ip, server):
        if server is not self.connected_server:
            return
        if not ip:
            self.ip_label.configure(text="Exit IP: unknown (check failed)", text_color=AMBER)
        elif isinstance(server, XrayProfile) or ip == server.ip:
            self.ip_label.configure(text=f"Exit IP: {ip}  ✓", text_color=GREEN)
        else:
            self.ip_label.configure(text=f"Exit IP: {ip}  (server {server.ip} uses a different exit address)",
                                    text_color=AMBER)

    def _ev_dropped(self, server):
        label = getattr(server, "name", None) or server.ip
        self._footer(f"Connection to {label} dropped."
                     + (" Switching to next server..." if self.settings.get("auto_switch") else ""))
        self.btn_change_ip.configure(state="disabled")

    def _ev_blocked(self, text):
        self.status_badge.configure(text="● BLOCKED (kill switch)", text_color=RED)
        self._footer(text)
        messagebox.showwarning("Kill Switch", text)

    def _ev_disconnected(self, blocked=False):
        self.connected_server = None
        self.connecting_server = None
        self.btn_change_ip.configure(state="disabled")
        self.btn_ping.configure(state="normal", text="⚡ Test Ping")
        self.ip_label.configure(text="Exit IP: -", text_color="#64748b")
        if blocked:
            self.btn_disconnect.configure(state="normal", text="🔓 Unblock")
        else:
            self.btn_disconnect.configure(state="disabled", text="⏹ Disconnect")
            if "Error" not in self.status_badge.cget("text"):
                self.status_badge.configure(text="● Disconnected", text_color=GREY)
        self._rerender()

    def _ev_fetch_ok(self, servers, source=""):
        self.servers = servers
        self._save_cache()
        self.filter_servers()
        self.btn_refresh.configure(state="normal", text="🔄 Refresh")
        self._footer(f"Updated: {len(servers)} servers from {source}. Measuring real ping from your PC...")
        self.start_ping_test()

    def _ev_fetch_err(self, text):
        self.btn_refresh.configure(state="normal", text="🔄 Refresh")
        n = len(self.servers)
        self._footer(f"Could not update the list ({text}). " +
                     (f"Using {n} saved servers." if n else "Add an Xray server to fetch the list through it."))
        if self.servers and not self.pinging:
            self.start_ping_test()

    def _ev_ping_progress(self, done, total):
        self.btn_ping.configure(text=f"⏳ {int(done * 100 / max(total, 1))}%")

    def _ev_ping_done(self):
        self.pinging = False
        self.btn_ping.configure(state="disabled" if self.controller.busy else "normal", text="⚡ Test Ping")
        ok = sum(1 for s in self.servers if s.latency is not None)
        self._save_cache()
        self.filter_servers()
        self._footer(f"Ping test done: {ok}/{len(self.servers)} servers reachable from your PC. "
                     f"Sorted by {self.sort_option.get()}.")

    # ======================= exit =======================
    def on_closing(self):
        self.withdraw()
        self.mobile_share.stop()
        self.controller.shutdown()
        self.destroy()


def _single_instance() -> bool:
    import ctypes
    import time
    k32 = ctypes.windll.kernel32
    k32.CreateMutexW.restype = ctypes.c_void_p
    # after "Run as Admin" the old instance needs a moment to exit
    for _ in range(40 if "--elevated" in sys.argv else 1):
        h = k32.CreateMutexW(None, False, "Global\\VPNGateGuardianMutex")
        if k32.GetLastError() != 183:  # ERROR_ALREADY_EXISTS
            globals()["_MUTEX"] = h
            return True
        k32.CloseHandle(ctypes.c_void_p(h))
        time.sleep(0.25)
    return False


if __name__ == "__main__":
    if not _single_instance():
        messagebox.showinfo("VPN Gate Guardian", "The app is already running.")
        sys.exit(0)
    app = VpnApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
