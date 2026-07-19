"""PerAppProxy GUI — fully standalone version for PyInstaller."""

from __future__ import annotations

import asyncio
import ctypes
import ctypes.wintypes
import json
import os
import random
import signal
import socket
import sys
import threading
import time
import tkinter as tk
import winreg
from dataclasses import dataclass, field, asdict
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Optional

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
    current_section: dict | list | None = None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("[[") and s.endswith("]]"):
            key = s[2:-2]
            current_section = {}
            result.setdefault(key, []).append(current_section)
        elif s.startswith("[") and s.endswith("]"):
            key = s[1:-1]
            current_section = {}
            result[key] = current_section
        elif "=" in s and current_section is not None:
            k, v = s.split("=", 1)
            k, v = k.strip(), v.strip().strip('"')
            if v.lower() == "true": v = True
            elif v.lower() == "false": v = False
            else:
                try: v = int(v)
                except ValueError:
                    try: v = float(v)
                    except ValueError: pass
            current_section[k] = v
    return result


def _write_toml(path: Path, data: dict) -> None:
    lines: list[str] = []
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
        try:
            return Config.from_dict(_read_toml(CONFIG_FILE))
        except Exception:
            pass
    c = Config()
    save_config(c)
    return c


def save_config(config: Config) -> None:
    _write_toml(CONFIG_FILE, config.to_dict())


# ─── WIN API ──────────────────────────────────────────────────

TCP_TABLE_OWNER_PID_ALL = 5
AF_INET = 2
iphlpapi = ctypes.windll.iphlpapi


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", ctypes.wintypes.DWORD), ("dwLocalAddr", ctypes.wintypes.DWORD), ("dwLocalPort", ctypes.wintypes.DWORD), ("dwRemoteAddr", ctypes.wintypes.DWORD), ("dwRemotePort", ctypes.wintypes.DWORD), ("dwOwningPid", ctypes.wintypes.DWORD)]


def get_pid_for_port(local_port: int) -> int | None:
    size = ctypes.wintypes.DWORD(0)
    phlpapi = ctypes.windll.iphlpapi
    phlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    buf = (ctypes.c_byte * size.value)()
    if phlpapi.GetExtendedTcpTable(ctypes.byref(buf[0]), ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != 0:
        return None
    count = ctypes.wintypes.DWORD()
    ctypes.memmove(ctypes.byref(count), buf, 4)
    table = (MIB_TCPROW_OWNER_PID * count.value)()
    ctypes.memmove(ctypes.byref(table), buf[4:], count.value * ctypes.sizeof(MIB_TCPROW_OWNER_PID))
    for row in table:
        if socket.ntohs(row.dwLocalPort) == local_port:
            return row.dwOwningPid
    return None


def get_process_name(pid: int) -> str | None:
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

BUFFER_SIZE = 65536

class ProxyServer:
    def __init__(self, host: str, port: int, config: Config) -> None:
        self.host = host
        self.port = port
        self.config = config
        self._server: asyncio.Server | None = None
        self._running = False

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self._running = True

    async def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    @property
    def is_running(self) -> bool:
        return self._running

    def _resolve(self, local_port: int) -> str | None:
        pid = get_pid_for_port(local_port)
        if pid is None:
            return self.config.global_upstream or None
        name = get_process_name(pid)
        if name is None:
            return self.config.global_upstream or None
        for r in self.config.rules:
            if r.process.lower() == name.lower():
                return r.upstream
        return self.config.global_upstream or None

    @staticmethod
    def _parse_proxy(proxy: str) -> tuple[str, int]:
        for p in ("socks5://", "socks4://", "http://", "https://"):
            if proxy.startswith(p):
                proxy = proxy[len(p):]
                break
        if ":" in proxy:
            h, ps = proxy.rsplit(":", 1)
            return h, int(ps)
        return proxy, 8080

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        local_port = writer.get_extra_info("sockname", (None, 0))[1]
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=30)
            if not line:
                return
            parts = line.decode("utf-8", errors="replace").strip().split()
            if len(parts) < 3:
                return
            method = parts[0].upper()
            if method == "CONNECT":
                await self._handle_connect(reader, writer, parts[1], local_port)
            else:
                await self._handle_http(reader, writer, line, local_port)
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(self, reader, writer, target, local_port):
        upstream = self._resolve(local_port)
        if not upstream:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            return
        host, port = (target.rsplit(":", 1) + ["443"])[:2] if ":" in target else (target, 443)
        port = int(port)
        try:
            uh, up = self._parse_proxy(upstream)
            ur, uw = await asyncio.wait_for(asyncio.open_connection(uh, up), timeout=30)
            uw.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
            await uw.drain()
            resp = await asyncio.wait_for(ur.readline(), timeout=30)
            if not resp or b"200" not in resp:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
                uw.close()
                return
            while True:
                l = await asyncio.wait_for(ur.readline(), timeout=30)
                if l == b"\r\n" or l == b"":
                    break
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await self._tunnel(reader, writer, ur, uw)
        except Exception:
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            except Exception:
                pass

    async def _handle_http(self, reader, writer, first_line, local_port):
        upstream = self._resolve(local_port)
        if not upstream:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            return
        try:
            uh, up = self._parse_proxy(upstream)
            ur, uw = await asyncio.wait_for(asyncio.open_connection(uh, up), timeout=30)
            uw.write(first_line)
            while True:
                l = await asyncio.wait_for(reader.readline(), timeout=30)
                uw.write(l)
                if l == b"\r\n" or l == b"":
                    break
            await uw.drain()
            while True:
                d = await ur.read(BUFFER_SIZE)
                if not d:
                    break
                writer.write(d)
                await writer.drain()
            uw.close()
        except Exception:
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
            except Exception:
                pass

    async def _tunnel(self, cr, cw, ur, uw):
        async def copy(s, d):
            try:
                while True:
                    data = await s.read(BUFFER_SIZE)
                    if not data: break
                    d.write(data)
                    await d.drain()
            except Exception: pass
            finally:
                try: d.close()
                except Exception: pass
        await asyncio.gather(asyncio.create_task(copy(cr, uw)), asyncio.create_task(copy(ur, cw)), return_exceptions=True)


# ─── PROXY POOL ───────────────────────────────────────────────

import httpx

FREE_PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
]


@dataclass
class ProxyEntry:
    address: str
    protocol: str
    country: str = ""
    latency_ms: float = 0
    last_checked: float = 0
    alive: bool = True

    @property
    def url(self) -> str:
        return f"{self.protocol}://{self.address}"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ProxyEntry":
        return cls(**d)


class ProxyPool:
    def __init__(self) -> None:
        self.proxies: list[ProxyEntry] = []
        self._load()

    def _load(self):
        if PROXY_CACHE.exists():
            try:
                self.proxies = [ProxyEntry.from_dict(p) for p in json.loads(PROXY_CACHE.read_text(encoding="utf-8"))]
            except Exception:
                self.proxies = []

    def _save(self):
        PROXY_CACHE.parent.mkdir(parents=True, exist_ok=True)
        PROXY_CACHE.write_text(json.dumps([p.to_dict() for p in self.proxies], indent=2), encoding="utf-8")

    def fetch(self) -> list[ProxyEntry]:
        new = []
        existing = {p.address for p in self.proxies}
        with httpx.Client(timeout=10, follow_redirects=True) as c:
            for url in FREE_PROXY_SOURCES:
                try:
                    r = c.get(url)
                    r.raise_for_status()
                    proto = "socks5" if "socks5" in url else ("https" if "https" in url else "http")
                    for line in r.text.strip().splitlines():
                        line = line.strip()
                        if line and ":" in line and line not in existing:
                            new.append(ProxyEntry(address=line, protocol=proto))
                            existing.add(line)
                except Exception:
                    continue
        self.proxies.extend(new)
        self._save()
        return new

    def check(self) -> list[ProxyEntry]:
        alive = []
        with httpx.Client(timeout=5, follow_redirects=True) as c:
            for p in self.proxies:
                try:
                    start = time.time()
                    r = c.get("http://httpbin.org/ip", proxy=p.url, timeout=5)
                    if r.status_code == 200:
                        p.alive = True
                        p.latency_ms = round((time.time() - start) * 1000, 1)
                        p.last_checked = time.time()
                        alive.append(p)
                except Exception:
                    p.alive = False
        self._save()
        return alive

    def add(self, address: str, protocol: str = "socks5") -> ProxyEntry:
        self.proxies = [p for p in self.proxies if p.address != address]
        entry = ProxyEntry(address=address, protocol=protocol, alive=True, last_checked=time.time())
        self.proxies.append(entry)
        self._save()
        return entry

    def remove(self, address: str) -> bool:
        before = len(self.proxies)
        self.proxies = [p for p in self.proxies if p.address != address]
        if len(self.proxies) < before:
            self._save()
            return True
        return False

    def count(self) -> dict:
        alive = sum(1 for p in self.proxies if p.alive)
        return {"total": len(self.proxies), "alive": alive, "dead": len(self.proxies) - alive}


# ─── GUI ──────────────────────────────────────────────────────

class PerAppProxyGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PerAppProxy v1.0.0")
        self.root.geometry("750x580")
        self.config = load_config()
        self.pool = ProxyPool()
        self.server: Optional[ProxyServer] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._build()
        self._refresh_status()

    def _build(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=5, pady=5)
        self._build_server_tab(nb)
        self._build_rules_tab(nb)
        self._build_pool_tab(nb)
        self._build_scanner_tab(nb)

    # ─── SERVER ───
    def _build_server_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=" Server ")

        sf = ttk.LabelFrame(f, text="Status", padding=10)
        sf.pack(fill="x", pady=(0, 10))
        self.status_label = ttk.Label(sf, text="Stopped", font=("Segoe UI", 12, "bold"))
        self.status_label.pack(anchor="w")

        info = ttk.Frame(sf)
        info.pack(fill="x", pady=(5, 0))
        ttk.Label(info, text="Listen:").grid(row=0, column=0, sticky="w")
        self.listen_lbl = ttk.Label(info, text=f"{self.config.listen_host}:{self.config.listen_port}")
        self.listen_lbl.grid(row=0, column=1, sticky="w", padx=(5, 20))
        ttk.Label(info, text="Global:").grid(row=0, column=2, sticky="w")
        self.global_lbl = ttk.Label(info, text=self.config.global_upstream or "(none)")
        self.global_lbl.grid(row=0, column=3, sticky="w", padx=(5, 0))

        ctrl = ttk.Frame(f)
        ctrl.pack(fill="x", pady=(0, 10))
        self.start_btn = ttk.Button(ctrl, text="Start Server", command=self._start)
        self.start_btn.pack(side="left", padx=(0, 5))
        self.stop_btn = ttk.Button(ctrl, text="Stop Server", command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 20))
        ttk.Button(ctrl, text="Proxy ON", command=self._proxy_on).pack(side="left", padx=(0, 5))
        ttk.Button(ctrl, text="Proxy OFF", command=self._proxy_off).pack(side="left")

        gf = ttk.LabelFrame(f, text="Default Proxy", padding=5)
        gf.pack(fill="x")
        self.global_entry = ttk.Entry(gf)
        self.global_entry.insert(0, self.config.global_upstream)
        self.global_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(gf, text="Set", command=self._set_global).pack(side="right")

    def _start(self):
        if self.server and self.server.is_running:
            return
        self.server = ProxyServer(self.config.listen_host, self.config.listen_port, self.config)
        self.loop = asyncio.new_event_loop()
        def run():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self.server.start())
            self.loop.run_forever()
        threading.Thread(target=run, daemon=True).start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_label.config(text="Running", foreground="green")

    def _stop(self):
        if self.server and self.server.is_running and self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Stopped", foreground="red")

    def _proxy_on(self):
        set_system_proxy(self.config.listen_host, self.config.listen_port)
        messagebox.showinfo("OK", f"System proxy ON -> 127.0.0.1:{self.config.listen_port}")

    def _proxy_off(self):
        disable_system_proxy()
        messagebox.showinfo("OK", "System proxy OFF")

    def _set_global(self):
        v = self.global_entry.get().strip()
        self.config.global_upstream = v
        save_config(self.config)
        self.global_lbl.config(text=v or "(none)")
        messagebox.showinfo("OK", f"Global: {v or '(none)'}")

    # ─── RULES ───
    def _build_rules_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=" Rules ")

        af = ttk.LabelFrame(f, text="Add Rule", padding=5)
        af.pack(fill="x", pady=(0, 10))
        ttk.Label(af, text="Process:").grid(row=0, column=0)
        self.proc_entry = ttk.Entry(af, width=25)
        self.proc_entry.grid(row=0, column=1, padx=5)
        ttk.Label(af, text="Proxy:").grid(row=0, column=2)
        self.up_entry = ttk.Entry(af, width=35)
        self.up_entry.grid(row=0, column=3, padx=5)
        ttk.Button(af, text="Add", command=self._add_rule).grid(row=0, column=4, padx=5)

        lf = ttk.LabelFrame(f, text="Rules", padding=5)
        lf.pack(fill="both", expand=True)
        self.rules_tree = ttk.Treeview(lf, columns=("proc", "up"), show="headings", height=10)
        self.rules_tree.heading("proc", text="Process")
        self.rules_tree.heading("up", text="Upstream")
        self.rules_tree.column("proc", width=200)
        self.rules_tree.column("up", width=450)
        self.rules_tree.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.rules_tree.yview)
        sb.pack(side="right", fill="y")
        self.rules_tree.configure(yscrollcommand=sb.set)

        bf = ttk.Frame(f)
        bf.pack(fill="x", pady=(5, 0))
        ttk.Button(bf, text="Remove Selected", command=self._rm_rule).pack(side="left")
        ttk.Button(bf, text="Refresh", command=self._refresh_rules).pack(side="right")
        self._refresh_rules()

    def _refresh_rules(self):
        self.config = load_config()
        for i in self.rules_tree.get_children():
            self.rules_tree.delete(i)
        for r in self.config.rules:
            self.rules_tree.insert("", "end", values=(r.process, r.upstream))

    def _add_rule(self):
        p, u = self.proc_entry.get().strip(), self.up_entry.get().strip()
        if not p or not u:
            messagebox.showwarning("Error", "Fill both fields")
            return
        self.config.rules = [r for r in self.config.rules if r.process.lower() != p.lower()]
        self.config.rules.append(Rule(process=p, upstream=u))
        save_config(self.config)
        self.proc_entry.delete(0, "end")
        self.up_entry.delete(0, "end")
        self._refresh_rules()

    def _rm_rule(self):
        for item in self.rules_tree.selection():
            p = self.rules_tree.item(item)["values"][0]
            self.config.rules = [r for r in self.config.rules if r.process.lower() != p.lower()]
        save_config(self.config)
        self._refresh_rules()

    # ─── POOL ───
    def _build_pool_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=" Proxy Pool ")

        ctrl = ttk.Frame(f)
        ctrl.pack(fill="x", pady=(0, 10))
        ttk.Button(ctrl, text="Fetch", command=self._pool_fetch).pack(side="left", padx=(0, 5))
        ttk.Button(ctrl, text="Check Alive", command=self._pool_check).pack(side="left", padx=(0, 5))
        ttk.Button(ctrl, text="Refresh", command=self._refresh_pool).pack(side="left", padx=(0, 20))
        ttk.Label(ctrl, text="Add:").pack(side="left")
        self.pool_entry = ttk.Entry(ctrl, width=25)
        self.pool_entry.pack(side="left", padx=5)
        ttk.Button(ctrl, text="+", command=self._pool_add).pack(side="left")

        lf = ttk.LabelFrame(f, text="Pool", padding=5)
        lf.pack(fill="both", expand=True)
        self.pool_tree = ttk.Treeview(lf, columns=("addr", "type", "lat", "status"), show="headings", height=12)
        self.pool_tree.heading("addr", text="Address")
        self.pool_tree.heading("type", text="Type")
        self.pool_tree.heading("lat", text="Latency")
        self.pool_tree.heading("status", text="Status")
        self.pool_tree.column("addr", width=280)
        self.pool_tree.column("type", width=80)
        self.pool_tree.column("lat", width=80)
        self.pool_tree.column("status", width=80)
        self.pool_tree.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.pool_tree.yview)
        sb.pack(side="right", fill="y")
        self.pool_tree.configure(yscrollcommand=sb.set)
        self._refresh_pool()

    def _refresh_pool(self):
        self.pool = ProxyPool()
        for i in self.pool_tree.get_children():
            self.pool_tree.delete(i)
        for p in self.pool.proxies:
            status = "OK" if p.alive else "DEAD"
            lat = f"{p.latency_ms:.0f}ms" if p.latency_ms > 0 else "-"
            self.pool_tree.insert("", "end", values=(p.address, p.protocol, lat, status))

    def _pool_fetch(self):
        def do():
            new = self.pool.fetch()
            self.root.after(0, self._refresh_pool)
            self.root.after(0, lambda: messagebox.showinfo("OK", f"Added {len(new)} proxies"))
        threading.Thread(target=do, daemon=True).start()

    def _pool_check(self):
        def do():
            self.pool.check()
            self.root.after(0, self._refresh_pool)
        threading.Thread(target=do, daemon=True).start()

    def _pool_add(self):
        addr = self.pool_entry.get().strip()
        if not addr:
            return
        proto = "http" if "http" in addr else "socks5"
        self.pool.add(addr, proto)
        self.pool_entry.delete(0, "end")
        self._refresh_pool()

    # ─── SCANNER ───
    def _build_scanner_tab(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text=" Scanner ")
        ttk.Button(f, text="Scan Connections", command=self._scan).pack(pady=(0, 10))
        lf = ttk.Frame(f)
        lf.pack(fill="both", expand=True)
        self.scan_tree = ttk.Treeview(lf, columns=("proc", "count", "remote"), show="headings", height=15)
        self.scan_tree.heading("proc", text="Process")
        self.scan_tree.heading("count", text="#")
        self.scan_tree.heading("remote", text="Remote")
        self.scan_tree.column("proc", width=200)
        self.scan_tree.column("count", width=60)
        self.scan_tree.column("remote", width=400)
        self.scan_tree.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(lf, orient="vertical", command=self.scan_tree.yview)
        sb.pack(side="right", fill="y")
        self.scan_tree.configure(yscrollcommand=sb.set)

    def _scan(self):
        import psutil
        for i in self.scan_tree.get_children():
            self.scan_tree.delete(i)
        by_proc: dict[str, list] = {}
        for c in psutil.net_connections(kind="tcp"):
            if c.status != "ESTABLISHED" or c.laddr.port == 0:
                continue
            name = ""
            if c.pid:
                try:
                    name = psutil.Process(c.pid).name()
                except Exception:
                    name = f"<pid={c.pid}>"
            by_proc.setdefault(name, []).append(c)
        for proc, cl in sorted(by_proc.items()):
            remotes = [f"{c.raddr.ip}:{c.raddr.port}" for c in cl[:3] if c.raddr]
            self.scan_tree.insert("", "end", values=(proc, len(cl), ", ".join(remotes)))

    def _refresh_status(self):
        self.listen_lbl.config(text=f"{self.config.listen_host}:{self.config.listen_port}")
        self.global_lbl.config(text=self.config.global_upstream or "(none)")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    PerAppProxyGUI().run()
