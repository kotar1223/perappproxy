"""PerAppProxy GUI v1.2 — copy, best servers dropdown, process picker."""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.wintypes
import json
import logging
import os
import queue
import signal
import socket
import sys
import threading
import time
import tkinter as tk
import winreg
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from typing import Optional

# ─── LOG ──────────────────────────────────────────────────────

LOG_DIR = Path.home() / ".perappproxy" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

log = logging.getLogger("perappproxy")
log.setLevel(logging.DEBUG)
_fh = logging.FileHandler(LOG_DIR / "proxy.log", encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
log.addHandler(_fh)


def log_gui(msg: str, level: str = "INFO"):
    log.log(getattr(logging, level, logging.INFO), msg)
    if hasattr(app, "_q"):
        app._q.put((msg, level))


# ─── CONFIG ───────────────────────────────────────────────────

CONFIG_DIR = Path.home() / ".perappproxy"
CONFIG_FILE = CONFIG_DIR / "config.toml"
PID_FILE = CONFIG_DIR / "proxy.pid"
PROXY_CACHE = CONFIG_DIR / "proxy_pool.json"


@dataclass
class Rule:
    process: str
    upstream: str


@dataclass
class Config:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    global_upstream: str = ""
    rules: list[Rule] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "proxy": {"listen_host": self.listen_host, "listen_port": self.listen_port, "global_upstream": self.global_upstream},
            "rules": [{"process": r.process, "upstream": r.upstream} for r in self.rules],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Config":
        p = d.get("proxy", {})
        rules = [Rule(process=r["process"], upstream=r["upstream"]) for r in d.get("rules", [])]
        return cls(listen_host=p.get("listen_host", "127.0.0.1"), listen_port=p.get("listen_port", 8080), global_upstream=p.get("global_upstream", ""), rules=rules)


def _read_toml(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    result: dict = {}
    sec: dict | list | None = None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("[[") and s.endswith("]]"):
            sec = {}
            result.setdefault(s[2:-2], []).append(sec)
        elif s.startswith("[") and s.endswith("]"):
            sec = {}
            result[s[1:-1]] = sec
        elif "=" in s and sec is not None:
            k, v = s.split("=", 1)
            k, v = k.strip(), v.strip().strip('"')
            if v.lower() == "true": v = True
            elif v.lower() == "false": v = False
            else:
                try: v = int(v)
                except ValueError:
                    try: v = float(v)
                    except ValueError: pass
            sec[k] = v
    return result


def _write_toml(path: Path, data: dict) -> None:
    lines = []
    for section, content in data.items():
        if isinstance(content, dict):
            lines.append(f"[{section}]")
            for k, v in content.items():
                lines.append(f'{k} = "{v}"' if isinstance(v, str) else f"{k} = {v}")
            lines.append("")
        elif isinstance(content, list):
            for item in content:
                lines.append(f"[[{section}]]")
                for k, v in item.items():
                    lines.append(f'{k} = "{v}"' if isinstance(v, str) else f"{k} = {v}")
                lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def load_config() -> Config:
    if CONFIG_FILE.exists():
        try: return Config.from_dict(_read_toml(CONFIG_FILE))
        except Exception: pass
    c = Config()
    save_config(c)
    return c


def save_config(config: Config) -> None:
    _write_toml(CONFIG_FILE, config.to_dict())


# ─── WIN API ──────────────────────────────────────────────────

TCP_TABLE_OWNER_PID_ALL = 5
AF_INET = 2


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", ctypes.wintypes.DWORD), ("dwLocalAddr", ctypes.wintypes.DWORD), ("dwLocalPort", ctypes.wintypes.DWORD), ("dwRemoteAddr", ctypes.wintypes.DWORD), ("dwRemotePort", ctypes.wintypes.DWORD), ("dwOwningPid", ctypes.wintypes.DWORD)]


def get_pid_for_port(port: int) -> int | None:
    size = ctypes.wintypes.DWORD(0)
    iphlpapi = ctypes.windll.iphlpapi
    iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    buf = (ctypes.c_byte * size.value)()
    if iphlpapi.GetExtendedTcpTable(ctypes.byref(buf[0]), ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0:
        return None
    count = ctypes.wintypes.DWORD()
    ctypes.memmove(ctypes.byref(count), buf, 4)
    table = (MIB_TCPROW_OWNER_PID * count.value)()
    ctypes.memmove(ctypes.byref(table), buf[4:], count.value * ctypes.sizeof(MIB_TCPROW_OWNER_PID))
    for row in table:
        if socket.ntohs(row.dwLocalPort) == port:
            return row.dwOwningPid
    return None


def get_proc_name(pid: int) -> str | None:
    try:
        import psutil
        return psutil.Process(pid).name()
    except Exception:
        return None


INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def set_system_proxy(host: str, port: int) -> None:
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_ALL_ACCESS)
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*;<local>")
    winreg.CloseKey(key)


def disable_system_proxy() -> None:
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_ALL_ACCESS)
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    winreg.CloseKey(key)


# ─── PROXY SERVER ─────────────────────────────────────────────

BUF = 65536


class ProxyServer:
    def __init__(self, host: str, port: int, config: Config):
        self.host, self.port, self.config = host, port, config
        self._server: asyncio.Server | None = None
        self._running = False

    async def start(self):
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self._running = True
        log_gui(f"Server started on {self.host}:{self.port}")

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        log_gui("Server stopped")

    @property
    def is_running(self):
        return self._running

    def _resolve(self, port: int) -> str | None:
        pid = get_pid_for_port(port)
        if pid is None:
            return self.config.global_upstream or None
        name = get_proc_name(pid)
        if name is None:
            return self.config.global_upstream or None
        for r in self.config.rules:
            if r.process.lower() == name.lower():
                log_gui(f"Route {name}:{port} -> {r.upstream}")
                return r.upstream
        return self.config.global_upstream or None

    @staticmethod
    def _parse(p: str) -> tuple[str, int]:
        for pr in ("socks5://", "socks4://", "http://", "https://"):
            if p.startswith(pr): p = p[len(pr):]
        if ":" in p:
            h, ps = p.rsplit(":", 1)
            return h, int(ps)
        return p, 8080

    async def _handle(self, reader, writer):
        port = writer.get_extra_info("sockname", (None, 0))[1]
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not line: return
            parts = line.decode("utf-8", errors="replace").strip().split()
            if len(parts) < 3: return
            if parts[0].upper() == "CONNECT":
                await self._connect(reader, writer, parts[1], port)
            else:
                await self._http(reader, writer, line, port)
        except Exception as e:
            log_gui(f"Error port {port}: {e}", "ERROR")
        finally:
            try: writer.close(); await writer.wait_closed()
            except Exception: pass

    async def _connect(self, cr, cw, target, port):
        up = self._resolve(port)
        if not up:
            cw.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); await cw.drain(); return
        host, prt = (target.rsplit(":", 1) + ["443"])[:2] if ":" in target else (target, 443)
        prt = int(prt)
        try:
            uh, uprt = self._parse(up)
            log_gui(f"CONNECT {host}:{prt} via {uh}:{uprt}")
            ur, uw = await asyncio.wait_for(asyncio.open_connection(uh, uprt), timeout=30)
            uw.write(f"CONNECT {host}:{prt} HTTP/1.1\r\nHost: {host}:{prt}\r\n\r\n".encode()); await uw.drain()
            resp = await asyncio.wait_for(ur.readline(), timeout=30)
            if not resp or b"200" not in resp:
                cw.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); await cw.drain(); uw.close(); return
            while True:
                l = await asyncio.wait_for(ur.readline(), timeout=30)
                if l in (b"\r\n", b""): break
            cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n"); await cw.drain()
            await self._tunnel(cr, cw, ur, uw)
        except Exception as e:
            log_gui(f"CONNECT error: {e}", "ERROR")
            try: cw.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); await cw.drain()
            except Exception: pass

    async def _http(self, cr, cw, first_line, port):
        up = self._resolve(port)
        if not up:
            cw.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); await cw.drain(); return
        try:
            uh, uprt = self._parse(up)
            ur, uw = await asyncio.wait_for(asyncio.open_connection(uh, uprt), timeout=30)
            uw.write(first_line)
            while True:
                l = await asyncio.wait_for(cr.readline(), timeout=30); uw.write(l)
                if l in (b"\r\n", b""): break
            await uw.drain()
            while True:
                d = await ur.read(BUF)
                if not d: break
                cw.write(d); await cw.drain()
            uw.close()
        except Exception as e:
            log_gui(f"HTTP error: {e}", "ERROR")

    async def _tunnel(self, cr, cw, ur, uw):
        async def cp(s, d):
            try:
                while True:
                    data = await s.read(BUF)
                    if not data: break
                    d.write(data); await d.drain()
            except Exception: pass
            finally:
                try: d.close()
                except Exception: pass
        await asyncio.gather(asyncio.create_task(cp(cr, uw)), asyncio.create_task(cp(ur, cw)), return_exceptions=True)


# ─── PROXY POOL ───────────────────────────────────────────────

import httpx

SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
]


@dataclass
class ProxyEntry:
    address: str
    protocol: str
    latency_ms: float = 0
    alive: bool = True

    @property
    def url(self) -> str:
        return f"{self.protocol}://{self.address}"

    def to_dict(self): return asdict(self)
    @classmethod
    def from_dict(cls, d): return cls(**d)


class ProxyPool:
    def __init__(self):
        self.proxies: list[ProxyEntry] = []
        self._load()

    def _load(self):
        if PROXY_CACHE.exists():
            try: self.proxies = [ProxyEntry.from_dict(p) for p in json.loads(PROXY_CACHE.read_text(encoding="utf-8"))]
            except Exception: self.proxies = []

    def _save(self):
        PROXY_CACHE.parent.mkdir(parents=True, exist_ok=True)
        PROXY_CACHE.write_text(json.dumps([p.to_dict() for p in self.proxies], indent=2), encoding="utf-8")

    def fetch(self) -> list[ProxyEntry]:
        new, existing = [], {p.address for p in self.proxies}
        log_gui("Fetching proxies...")
        with httpx.Client(timeout=10, follow_redirects=True) as c:
            for url in SOURCES:
                try:
                    r = c.get(url); r.raise_for_status()
                    proto = "socks5" if "socks5" in url else ("https" if "https" in url else "http")
                    for line in r.text.strip().splitlines():
                        line = line.strip()
                        if line and ":" in line and line not in existing:
                            new.append(ProxyEntry(address=line, protocol=proto)); existing.add(line)
                    log_gui(f"Source ok: {len(new)} total")
                except Exception as e:
                    log_gui(f"Source error: {e}", "WARNING")
        self.proxies.extend(new); self._save()
        log_gui(f"Fetched {len(new)}, total: {len(self.proxies)}")
        return new

    def check(self) -> list[ProxyEntry]:
        alive, total = [], len(self.proxies)
        log_gui(f"Checking {total} proxies...")
        with httpx.Client(timeout=5, follow_redirects=True) as c:
            for i, p in enumerate(self.proxies):
                try:
                    t = time.time()
                    r = c.get("http://httpbin.org/ip", proxy=p.url, timeout=5)
                    if r.status_code == 200:
                        p.alive = True; p.latency_ms = round((time.time() - t) * 1000, 1); alive.append(p)
                except Exception:
                    p.alive = False
                if (i + 1) % 50 == 0: log_gui(f"Checked {i+1}/{total}")
        self._save(); log_gui(f"Alive: {len(alive)}/{total}")
        return alive

    def add(self, addr: str, proto: str = "socks5") -> ProxyEntry:
        self.proxies = [p for p in self.proxies if p.address != addr]
        e = ProxyEntry(address=addr, protocol=proto, alive=True)
        self.proxies.append(e); self._save(); log_gui(f"Added: {e.url}")
        return e

    def remove(self, addr: str) -> bool:
        before = len(self.proxies)
        self.proxies = [p for p in self.proxies if p.address != addr]
        if len(self.proxies) < before: self._save(); log_gui(f"Removed: {addr}"); return True
        return False

    def clear(self):
        n = len(self.proxies); self.proxies.clear(); self._save(); log_gui(f"Cleared {n} proxies")

    def count(self):
        alive = sum(1 for p in self.proxies if p.alive)
        return {"total": len(self.proxies), "alive": alive, "dead": len(self.proxies) - alive}

    def best(self, n: int = 10) -> list[ProxyEntry]:
        alive = [p for p in self.proxies if p.alive and p.latency_ms > 0]
        alive.sort(key=lambda p: p.latency_ms)
        return alive[:n]


# ─── GUI ──────────────────────────────────────────────────────

class GUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PerAppProxy v1.2")
        self.root.geometry("820x680")
        self.config = load_config()
        self.pool = ProxyPool()
        self.server: Optional[ProxyServer] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._q: queue.Queue = queue.Queue()
        self._scanned_procs: list[str] = []
        self._build()
        self._refresh_status()
        self._poll()

    def _build(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=5, pady=(5, 0))
        self._tab_server(nb)
        self._tab_rules(nb)
        self._tab_pool(nb)
        self._tab_scanner(nb)
        self._tab_logs(nb)
        self.status_bar = ttk.Label(self.root, text="Ready", relief="sunken", anchor="w")
        self.status_bar.pack(fill="x", side="bottom", padx=5, pady=5)

    # ─── SERVER ───
    def _tab_server(self, nb):
        f = ttk.Frame(nb, padding=10); nb.add(f, text=" Server ")

        sf = ttk.LabelFrame(f, text="Status", padding=10); sf.pack(fill="x", pady=(0, 10))
        self.status_lbl = ttk.Label(sf, text="Stopped", font=("Segoe UI", 12, "bold"))
        self.status_lbl.pack(anchor="w")
        info = ttk.Frame(sf); info.pack(fill="x", pady=(5, 0))
        ttk.Label(info, text="Listen:").grid(row=0, column=0, sticky="w")
        self.listen_lbl = ttk.Label(info, text=f"{self.config.listen_host}:{self.config.listen_port}")
        self.listen_lbl.grid(row=0, column=1, sticky="w", padx=(5, 20))
        ttk.Label(info, text="Global:").grid(row=0, column=2, sticky="w")
        self.global_lbl = ttk.Label(info, text=self.config.global_upstream or "(none)")
        self.global_lbl.grid(row=0, column=3, sticky="w", padx=(5, 0))
        ttk.Label(info, text="Rules:").grid(row=0, column=4, sticky="w", padx=(20, 0))
        self.rules_cnt = ttk.Label(info, text=str(len(self.config.rules)))
        self.rules_cnt.grid(row=0, column=5, sticky="w", padx=(5, 0))

        ctrl = ttk.Frame(f); ctrl.pack(fill="x", pady=(0, 10))
        self.start_btn = ttk.Button(ctrl, text="Start", command=self._start); self.start_btn.pack(side="left", padx=(0, 5))
        self.stop_btn = ttk.Button(ctrl, text="Stop", command=self._stop, state="disabled"); self.stop_btn.pack(side="left", padx=(0, 20))
        ttk.Button(ctrl, text="Proxy ON", command=self._proxy_on).pack(side="left", padx=(0, 5))
        ttk.Button(ctrl, text="Proxy OFF", command=self._proxy_off).pack(side="left")

        gf = ttk.LabelFrame(f, text="Default Proxy", padding=5); gf.pack(fill="x")
        self.global_ent = ttk.Entry(gf); self.global_ent.insert(0, self.config.global_upstream)
        self.global_ent.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(gf, text="Set", command=self._set_global).pack(side="right")

    def _start(self):
        if self.server and self.server.is_running: return
        self.server = ProxyServer(self.config.listen_host, self.config.listen_port, self.config)
        self.loop = asyncio.new_event_loop()
        def run(): asyncio.set_event_loop(self.loop); self.loop.run_until_complete(self.server.start()); self.loop.run_forever()
        threading.Thread(target=run, daemon=True).start()
        self.start_btn.config(state="disabled"); self.stop_btn.config(state="normal")
        self.status_lbl.config(text="Running", foreground="green"); self._status("Server running")

    def _stop(self):
        if self.server and self.server.is_running and self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.start_btn.config(state="normal"); self.stop_btn.config(state="disabled")
        self.status_lbl.config(text="Stopped", foreground="red"); self._status("Server stopped")

    def _proxy_on(self):
        set_system_proxy(self.config.listen_host, self.config.listen_port)
        log_gui(f"System proxy ON -> 127.0.0.1:{self.config.listen_port}")
        messagebox.showinfo("OK", f"System proxy ON")

    def _proxy_off(self):
        disable_system_proxy(); log_gui("System proxy OFF"); messagebox.showinfo("OK", "System proxy OFF")

    def _set_global(self):
        v = self.global_ent.get().strip(); self.config.global_upstream = v; save_config(self.config)
        self.global_lbl.config(text=v or "(none)"); log_gui(f"Global: {v}"); messagebox.showinfo("OK", f"Global: {v}")

    # ─── RULES ───
    def _tab_rules(self, nb):
        f = ttk.Frame(nb, padding=10); nb.add(f, text=" Rules ")

        af = ttk.LabelFrame(f, text="Add Rule", padding=5); af.pack(fill="x", pady=(0, 10))

        # Process picker
        ttk.Label(af, text="Process:").grid(row=0, column=0, sticky="w")
        self.proc_combo = ttk.Combobox(af, width=25, values=self._get_process_list())
        self.proc_combo.grid(row=0, column=1, padx=5)
        ttk.Button(af, text="Refresh", width=7, command=self._refresh_proc_list).grid(row=0, column=2, padx=(0, 10))

        # Server picker
        ttk.Label(af, text="Server:").grid(row=0, column=3, sticky="w")
        self.srv_combo = ttk.Combobox(af, width=30, values=self._get_best_list())
        self.srv_combo.grid(row=0, column=4, padx=5)
        ttk.Button(af, text="Refresh", width=7, command=self._refresh_srv_list).grid(row=0, column=5, padx=(0, 10))

        # Copy buttons
        bf1 = ttk.Frame(af); bf1.grid(row=1, column=0, columnspan=6, sticky="w", pady=(5, 0))
        ttk.Button(bf1, text="Copy Process", command=self._copy_proc).pack(side="left", padx=(0, 5))
        ttk.Button(bf1, text="Copy Server", command=self._copy_srv).pack(side="left", padx=(0, 5))

        # Add button
        ttk.Button(af, text="Add Rule", command=self._add_rule).grid(row=0, column=6, padx=10)

        # Rules list
        lf = ttk.LabelFrame(f, text="Active Rules", padding=5); lf.pack(fill="both", expand=True)
        self.rules_tree = ttk.Treeview(lf, columns=("num", "proc", "up"), show="headings", height=10)
        self.rules_tree.heading("num", text="#"); self.rules_tree.heading("proc", text="Process"); self.rules_tree.heading("up", text="Server")
        self.rules_tree.column("num", width=40); self.rules_tree.column("proc", width=200); self.rules_tree.column("up", width=480)
        self.rules_tree.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.rules_tree.yview); sb.pack(side="right", fill="y")
        self.rules_tree.configure(yscrollcommand=sb.set)

        # Buttons
        bfr = ttk.Frame(f); bfr.pack(fill="x", pady=(5, 0))
        ttk.Button(bfr, text="Copy Selected", command=self._copy_rule).pack(side="left")
        ttk.Button(bfr, text="Remove Selected", command=self._rm_rule).pack(side="left", padx=(10, 0))
        ttk.Button(bfr, text="Clear All", command=self._clear_rules).pack(side="left", padx=(10, 0))
        ttk.Button(bfr, text="Refresh", command=self._refresh_rules).pack(side="right")
        self._refresh_rules()

    def _get_process_list(self):
        return sorted(set(self._scanned_procs)) or ["(scan first)"]

    def _refresh_proc_list(self):
        import psutil
        self._scanned_procs.clear()
        for c in psutil.net_connections(kind="tcp"):
            if c.pid:
                try: self._scanned_procs.append(psutil.Process(c.pid).name())
                except Exception: pass
        self._scanned_procs = sorted(set(self._scanned_procs))
        self.proc_combo.config(values=self._scanned_procs or ["(none found)"])
        log_gui(f"Found {len(self._scanned_procs)} processes")

    def _get_best_list(self):
        best = self.pool.best(20)
        return [p.url for p in best] or ["(fetch & check pool first)"]

    def _refresh_srv_list(self):
        self.srv_combo.config(values=self._get_best_list())

    def _copy_proc(self):
        v = self.proc_combo.get()
        if v and v not in ("(scan first)", "(none found)"):
            self.root.clipboard_clear(); self.root.clipboard_append(v)
            log_gui(f"Copied process: {v}")

    def _copy_srv(self):
        v = self.srv_combo.get()
        if v and v not in ("(fetch & check pool first)",):
            self.root.clipboard_clear(); self.root.clipboard_append(v)
            log_gui(f"Copied server: {v}")

    def _copy_rule(self):
        sel = self.rules_tree.selection()
        if not sel: return
        vals = self.rules_tree.item(sel[0])["values"]
        text = f"{vals[1]} -> {vals[2]}"
        self.root.clipboard_clear(); self.root.clipboard_append(text)
        log_gui(f"Copied: {text}")

    def _refresh_rules(self):
        self.config = load_config()
        for i in self.rules_tree.get_children(): self.rules_tree.delete(i)
        for idx, r in enumerate(self.config.rules, 1):
            self.rules_tree.insert("", "end", values=(idx, r.process, r.upstream))
        self.rules_cnt.config(text=str(len(self.config.rules)))

    def _add_rule(self):
        p = self.proc_combo.get().strip()
        u = self.srv_combo.get().strip()
        if not p or not u or p in ("(scan first)", "(none found)") or u in ("(fetch & check pool first)",):
            messagebox.showwarning("Error", "Pick process and server from dropdowns"); return
        self.config.rules = [r for r in self.config.rules if r.process.lower() != p.lower()]
        self.config.rules.append(Rule(process=p, upstream=u))
        save_config(self.config); log_gui(f"Rule: {p} -> {u}")
        self._refresh_rules()

    def _rm_rule(self):
        for item in self.rules_tree.selection():
            p = self.rules_tree.item(item)["values"][1]
            self.config.rules = [r for r in self.config.rules if r.process.lower() != str(p).lower()]
            log_gui(f"Removed: {p}")
        save_config(self.config); self._refresh_rules()

    def _clear_rules(self):
        if not self.config.rules: return
        if messagebox.askyesno("Confirm", f"Clear all {len(self.config.rules)} rules?"):
            self.config.rules.clear(); save_config(self.config); log_gui("All rules cleared"); self._refresh_rules()

    # ─── POOL ───
    def _tab_pool(self, nb):
        f = ttk.Frame(nb, padding=10); nb.add(f, text=" Proxy Pool ")

        ctrl = ttk.Frame(f); ctrl.pack(fill="x", pady=(0, 10))
        ttk.Button(ctrl, text="Fetch", command=self._pool_fetch).pack(side="left", padx=(0, 5))
        ttk.Button(ctrl, text="Check Alive", command=self._pool_check).pack(side="left", padx=(0, 5))
        ttk.Button(ctrl, text="Refresh", command=self._refresh_pool).pack(side="left", padx=(0, 5))
        ttk.Button(ctrl, text="Clear Pool", command=self._pool_clear).pack(side="left", padx=(0, 20))
        ttk.Label(ctrl, text="Add:").pack(side="left")
        self.pool_ent = ttk.Entry(ctrl, width=25); self.pool_ent.pack(side="left", padx=5)
        ttk.Button(ctrl, text="+", command=self._pool_add).pack(side="left", padx=(0, 5))
        ttk.Button(ctrl, text="Remove", command=self._pool_rm).pack(side="left")
        ttk.Button(ctrl, text="Copy Selected", command=self._pool_copy).pack(side="left", padx=(10, 0))

        lf = ttk.LabelFrame(f, text="Pool", padding=5); lf.pack(fill="both", expand=True)
        self.pool_tree = ttk.Treeview(lf, columns=("addr", "type", "lat", "status"), show="headings", height=12)
        self.pool_tree.heading("addr", text="Address"); self.pool_tree.heading("type", text="Type")
        self.pool_tree.heading("lat", text="Latency"); self.pool_tree.heading("status", text="Status")
        self.pool_tree.column("addr", width=300); self.pool_tree.column("type", width=80)
        self.pool_tree.column("lat", width=80); self.pool_tree.column("status", width=80)
        self.pool_tree.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.pool_tree.yview); sb.pack(side="right", fill="y")
        self.pool_tree.configure(yscrollcommand=sb.set)

        self.pool_stats = ttk.Label(f, text=""); self.pool_stats.pack(fill="x", pady=(5, 0))
        self._refresh_pool()

    def _refresh_pool(self):
        self.pool = ProxyPool()
        for i in self.pool_tree.get_children(): self.pool_tree.delete(i)
        for p in self.pool.proxies:
            s = "OK" if p.alive else "DEAD"
            l = f"{p.latency_ms:.0f}ms" if p.latency_ms > 0 else "-"
            self.pool_tree.insert("", "end", values=(p.address, p.protocol, l, s))
        st = self.pool.count()
        self.pool_stats.config(text=f"Total: {st['total']} | Alive: {st['alive']} | Dead: {st['dead']}")

    def _pool_fetch(self):
        def do():
            n = self.pool.fetch()
            self.root.after(0, self._refresh_pool)
            self.root.after(0, lambda: messagebox.showinfo("OK", f"Added {n} proxies"))
        threading.Thread(target=do, daemon=True).start()

    def _pool_check(self):
        def do(): self.pool.check(); self.root.after(0, self._refresh_pool)
        threading.Thread(target=do, daemon=True).start()

    def _pool_add(self):
        a = self.pool_ent.get().strip()
        if not a: return
        proto = "http" if "http" in a else "socks5"
        self.pool.add(a, proto); self.pool_ent.delete(0, "end"); self._refresh_pool()

    def _pool_rm(self):
        for item in self.pool_tree.selection():
            self.pool.remove(self.pool_tree.item(item)["values"][0])
        self._refresh_pool()

    def _pool_clear(self):
        if self.pool.count()["total"] == 0: return
        if messagebox.askyesno("Confirm", f"Clear all {self.pool.count()['total']} proxies?"):
            self.pool.clear(); self._refresh_pool()

    def _pool_copy(self):
        sel = self.pool_tree.selection()
        if not sel: return
        addr = self.pool_tree.item(sel[0])["values"][0]
        self.root.clipboard_clear(); self.root.clipboard_append(f"socks5://{addr}")
        log_gui(f"Copied: socks5://{addr}")

    # ─── SCANNER ───
    def _tab_scanner(self, nb):
        f = ttk.Frame(nb, padding=10); nb.add(f, text=" Scanner ")
        bf = ttk.Frame(f); bf.pack(fill="x", pady=(0, 10))
        ttk.Button(bf, text="Scan", command=self._scan).pack(side="left")
        ttk.Button(bf, text="Clear", command=self._scan_clear).pack(side="left", padx=(10, 0))
        lf = ttk.Frame(f); lf.pack(fill="both", expand=True)
        self.scan_tree = ttk.Treeview(lf, columns=("proc", "cnt", "remote"), show="headings", height=15)
        self.scan_tree.heading("proc", text="Process"); self.scan_tree.heading("cnt", text="#"); self.scan_tree.heading("remote", text="Remote")
        self.scan_tree.column("proc", width=220); self.scan_tree.column("cnt", width=60); self.scan_tree.column("remote", width=440)
        self.scan_tree.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.scan_tree.yview); sb.pack(side="right", fill="y")
        self.scan_tree.configure(yscrollcommand=sb.set)

    def _scan(self):
        import psutil
        for i in self.scan_tree.get_children(): self.scan_tree.delete(i)
        self._scanned_procs.clear()
        by_proc: dict[str, list] = {}
        for c in psutil.net_connections(kind="tcp"):
            if c.status != "ESTABLISHED" or c.laddr.port == 0: continue
            name = ""
            if c.pid:
                try: name = psutil.Process(c.pid).name()
                except Exception: name = f"<pid={c.pid}>"
            if name: self._scanned_procs.append(name)
            by_proc.setdefault(name, []).append(c)
        self._scanned_procs = sorted(set(self._scanned_procs))
        for proc, cl in sorted(by_proc.items()):
            remotes = [f"{c.raddr.ip}:{c.raddr.port}" for c in cl[:3] if c.raddr]
            self.scan_tree.insert("", "end", values=(proc, len(cl), ", ".join(remotes)))
        self._refresh_proc_list()
        log_gui(f"Scan: {len(by_proc)} processes")

    def _scan_clear(self):
        for i in self.scan_tree.get_children(): self.scan_tree.delete(i)

    # ─── LOGS ───
    def _tab_logs(self, nb):
        f = ttk.Frame(nb, padding=10); nb.add(f, text=" Logs ")
        cf = ttk.Frame(f); cf.pack(fill="x", pady=(0, 5))
        ttk.Button(cf, text="Clear", command=self._log_clear).pack(side="left")
        ttk.Button(cf, text="Open File", command=self._log_open).pack(side="left", padx=(10, 0))
        ttk.Button(cf, text="Copy All", command=self._log_copy).pack(side="left", padx=(10, 0))
        ttk.Label(cf, text=str(LOG_DIR / "proxy.log")).pack(side="right")
        self.log_text = scrolledtext.ScrolledText(f, height=20, font=("Consolas", 9), state="disabled",
                                                  bg="#1e1e1e", fg="#d4d4d4", insertbackground="white")
        self.log_text.pack(fill="both", expand=True)
        self.log_text.tag_config("INFO", foreground="#d4d4d4")
        self.log_text.tag_config("WARNING", foreground="#e5c07b")
        self.log_text.tag_config("ERROR", foreground="#e06c75")
        self.log_text.tag_config("DEBUG", foreground="#61afef")

    def _log_clear(self):
        self.log_text.config(state="normal"); self.log_text.delete("1.0", "end"); self.log_text.config(state="disabled")

    def _log_open(self):
        os.startfile(str(LOG_DIR / "proxy.log"))

    def _log_copy(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.log_text.get("1.0", "end"))
        log_gui("Logs copied to clipboard")

    # ─── STATUS ───
    def _status(self, msg):
        self.status_bar.config(text=msg)

    def _refresh_status(self):
        self.listen_lbl.config(text=f"{self.config.listen_host}:{self.config.listen_port}")
        self.global_lbl.config(text=self.config.global_upstream or "(none)")
        self.rules_cnt.config(text=str(len(self.config.rules)))
        st = self.pool.count()
        self._status(f"Pool: {st['alive']} alive/{st['total']} | Rules: {len(self.config.rules)}")

    def _poll(self):
        while not self._q.empty():
            msg, level = self._q.get_nowait()
            ts = datetime.now().strftime("%H:%M:%S")
            self.log_text.config(state="normal")
            self.log_text.insert("end", f"[{ts}] [{level}] {msg}\n", level)
            self.log_text.see("end")
            self.log_text.config(state="disabled")
        self.root.after(100, self._poll)

    def run(self):
        self.root.mainloop()


app: GUI


def main():
    global app
    app = GUI()
    app.run()


if __name__ == "__main__":
    main()
