"""PerAppProxy GUI — graphical interface for per-application proxy routing."""

from __future__ import annotations

import asyncio
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from pathlib import Path
from typing import Optional

from .config import Config, Rule, load_config, save_config, CONFIG_FILE
from .proxy_server import ProxyServer
from .route_resolver import RouteResolver
from .proxy_pool import ProxyPool


class PerAppProxyGUI:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("PerAppProxy v0.3.0")
        self.root.geometry("700x550")
        self.root.resizable(True, True)

        self.config = load_config()
        self.pool = ProxyPool()
        self.server: Optional[ProxyServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None

        self._build_ui()
        self._refresh_status()

    def _build_ui(self) -> None:
        # ─── Notebook (tabs) ────────────────────────────
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=5, pady=5)

        # Tab 1: Server
        self._build_server_tab(notebook)
        # Tab 2: Rules
        self._build_rules_tab(notebook)
        # Tab 3: Proxy Pool
        self._build_pool_tab(notebook)
        # Tab 4: Scanner
        self._build_scanner_tab(notebook)

    # ─── SERVER TAB ────────────────────────────────────
    def _build_server_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=10)
        notebook.add(frame, text=" Server ")

        # Status
        status_frame = ttk.LabelFrame(frame, text="Status", padding=10)
        status_frame.pack(fill="x", pady=(0, 10))

        self.status_label = ttk.Label(status_frame, text="Stopped", font=("Segoe UI", 12, "bold"))
        self.status_label.pack(anchor="w")

        info_frame = ttk.Frame(status_frame)
        info_frame.pack(fill="x", pady=(5, 0))

        ttk.Label(info_frame, text="Listen:").grid(row=0, column=0, sticky="w")
        self.listen_label = ttk.Label(info_frame, text=f"{self.config.listen_host}:{self.config.listen_port}")
        self.listen_label.grid(row=0, column=1, sticky="w", padx=(5, 20))

        ttk.Label(info_frame, text="Global:").grid(row=0, column=2, sticky="w")
        self.global_label = ttk.Label(info_frame, text=self.config.global_upstream or "(none)")
        self.global_label.grid(row=0, column=3, sticky="w", padx=(5, 0))

        # Controls
        ctrl_frame = ttk.Frame(frame)
        ctrl_frame.pack(fill="x", pady=(0, 10))

        self.start_btn = ttk.Button(ctrl_frame, text="Start Server", command=self._start_server)
        self.start_btn.pack(side="left", padx=(0, 5))

        self.stop_btn = ttk.Button(ctrl_frame, text="Stop Server", command=self._stop_server, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 20))

        ttk.Button(ctrl_frame, text="System Proxy ON", command=self._proxy_on).pack(side="left", padx=(0, 5))
        ttk.Button(ctrl_frame, text="System Proxy OFF", command=self._proxy_off).pack(side="left")

        # Global upstream
        global_frame = ttk.LabelFrame(frame, text="Default Proxy (Global)", padding=5)
        global_frame.pack(fill="x", pady=(0, 10))

        self.global_entry = ttk.Entry(global_frame)
        self.global_entry.insert(0, self.config.global_upstream)
        self.global_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(global_frame, text="Set", command=self._set_global).pack(side="right")

    def _start_server(self) -> None:
        if self.server and self.server.is_running:
            return
        resolver = RouteResolver(self.config)
        self.server = ProxyServer(self.config.listen_host, self.config.listen_port, resolver)
        self.loop = asyncio.new_event_loop()

        def run():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self.server.start())
            self.loop.run_forever()

        self.server_thread = threading.Thread(target=run, daemon=True)
        self.server_thread.start()

        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_label.config(text="Running", foreground="green")

    def _stop_server(self) -> None:
        if self.server and self.server.is_running and self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Stopped", foreground="red")

    def _proxy_on(self) -> None:
        from .system_proxy import set_system_proxy
        set_system_proxy(self.config.listen_host, self.config.listen_port)
        messagebox.showinfo("Done", f"System proxy ON -> 127.0.0.1:{self.config.listen_port}")

    def _proxy_off(self) -> None:
        from .system_proxy import disable_system_proxy
        disable_system_proxy()
        messagebox.showinfo("Done", "System proxy OFF")

    def _set_global(self) -> None:
        val = self.global_entry.get().strip()
        self.config.global_upstream = val
        save_config(self.config)
        self.global_label.config(text=val or "(none)")
        messagebox.showinfo("Done", f"Global proxy set to: {val or '(none)'}")

    # ─── RULES TAB ─────────────────────────────────────
    def _build_rules_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=10)
        notebook.add(frame, text=" Rules ")

        # Add rule
        add_frame = ttk.LabelFrame(frame, text="Add Rule", padding=5)
        add_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(add_frame, text="Process:").grid(row=0, column=0, sticky="w")
        self.process_entry = ttk.Entry(add_frame, width=25)
        self.process_entry.grid(row=0, column=1, padx=5)

        ttk.Label(add_frame, text="Proxy:").grid(row=0, column=2, sticky="w")
        self.upstream_entry = ttk.Entry(add_frame, width=35)
        self.upstream_entry.grid(row=0, column=3, padx=5)

        ttk.Button(add_frame, text="Add", command=self._add_rule).grid(row=0, column=4, padx=5)

        # Rules list
        list_frame = ttk.LabelFrame(frame, text="Active Rules", padding=5)
        list_frame.pack(fill="both", expand=True)

        self.rules_tree = ttk.Treeview(list_frame, columns=("process", "upstream"), show="headings", height=10)
        self.rules_tree.heading("process", text="Process")
        self.rules_tree.heading("upstream", text="Upstream Proxy")
        self.rules_tree.column("process", width=200)
        self.rules_tree.column("upstream", width=400)
        self.rules_tree.pack(fill="both", expand=True, side="left")

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.rules_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.rules_tree.configure(yscrollcommand=scrollbar.set)

        # Remove button
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(5, 0))
        ttk.Button(btn_frame, text="Remove Selected", command=self._remove_rule).pack(side="left")
        ttk.Button(btn_frame, text="Refresh", command=self._refresh_rules).pack(side="right")

        self._refresh_rules()

    def _refresh_rules(self) -> None:
        self.config = load_config()
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)
        for rule in self.config.rules:
            self.rules_tree.insert("", "end", values=(rule.process, rule.upstream))

    def _add_rule(self) -> None:
        process = self.process_entry.get().strip()
        upstream = self.upstream_entry.get().strip()
        if not process or not upstream:
            messagebox.showwarning("Error", "Fill in both fields")
            return
        self.config.rules = [r for r in self.config.rules if r.process.lower() != process.lower()]
        self.config.rules.append(Rule(process=process, upstream=upstream))
        save_config(self.config)
        self.process_entry.delete(0, "end")
        self.upstream_entry.delete(0, "end")
        self._refresh_rules()

    def _remove_rule(self) -> None:
        selected = self.rules_tree.selection()
        if not selected:
            return
        for item in selected:
            process = self.rules_tree.item(item)["values"][0]
            self.config.rules = [r for r in self.config.rules if r.process.lower() != process.lower()]
        save_config(self.config)
        self._refresh_rules()

    # ─── POOL TAB ──────────────────────────────────────
    def _build_pool_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=10)
        notebook.add(frame, text=" Proxy Pool ")

        # Controls
        ctrl_frame = ttk.Frame(frame)
        ctrl_frame.pack(fill="x", pady=(0, 10))

        ttk.Button(ctrl_frame, text="Fetch Free Proxies", command=self._pool_fetch).pack(side="left", padx=(0, 5))
        ttk.Button(ctrl_frame, text="Check Alive", command=self._pool_check).pack(side="left", padx=(0, 5))
        ttk.Button(ctrl_frame, text="Refresh List", command=self._refresh_pool).pack(side="left", padx=(0, 20))

        # Add custom
        ttk.Label(ctrl_frame, text="Add:").pack(side="left")
        self.pool_addr_entry = ttk.Entry(ctrl_frame, width=25)
        self.pool_addr_entry.pack(side="left", padx=5)
        ttk.Button(ctrl_frame, text="+", command=self._pool_add).pack(side="left")

        # Pool list
        list_frame = ttk.LabelFrame(frame, text="Proxy Pool", padding=5)
        list_frame.pack(fill="both", expand=True)

        self.pool_tree = ttk.Treeview(list_frame, columns=("addr", "type", "latency", "status"), show="headings", height=12)
        self.pool_tree.heading("addr", text="Address")
        self.pool_tree.heading("type", text="Type")
        self.pool_tree.heading("latency", text="Latency")
        self.pool_tree.heading("status", text="Status")
        self.pool_tree.column("addr", width=250)
        self.pool_tree.column("type", width=80)
        self.pool_tree.column("latency", width=80)
        self.pool_tree.column("status", width=80)
        self.pool_tree.pack(fill="both", expand=True, side="left")

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.pool_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.pool_tree.configure(yscrollcommand=scrollbar.set)

        self._refresh_pool()

    def _refresh_pool(self) -> None:
        self.pool = ProxyPool()
        for item in self.pool_tree.get_children():
            self.pool_tree.delete(item)
        for p in self.pool.list_all():
            status = "OK" if p.alive else "DEAD"
            lat = f"{p.latency_ms:.0f}ms" if p.latency_ms > 0 else "-"
            self.pool_tree.insert("", "end", values=(p.address, p.protocol, lat, status))

    def _pool_fetch(self) -> None:
        def do():
            self.pool.fetch_free_proxies()
            self.pool.proxies.extend(self.pool.fetch_free_proxies())
            self.pool._save_cache()
            self.root.after(0, self._refresh_pool)
            self.root.after(0, lambda: messagebox.showinfo("Done", f"Fetched {len(self.pool.proxies)} proxies"))
        threading.Thread(target=do, daemon=True).start()

    def _pool_check(self) -> None:
        def do():
            self.pool.validate_proxies()
            self.pool._save_cache()
            self.root.after(0, self._refresh_pool)
        threading.Thread(target=do, daemon=True).start()

    def _pool_add(self) -> None:
        addr = self.pool_addr_entry.get().strip()
        if not addr:
            return
        proto = "socks5"
        if "http" in addr:
            proto = "http"
        self.pool.add_proxy(addr, proto)
        self.pool_addr_entry.delete(0, "end")
        self._refresh_pool()

    # ─── SCANNER TAB ───────────────────────────────────
    def _build_scanner_tab(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=10)
        notebook.add(frame, text=" Scanner ")

        ttk.Button(frame, text="Scan Connections", command=self._scan).pack(pady=(0, 10))

        list_frame = ttk.Frame(frame)
        list_frame.pack(fill="both", expand=True)

        self.scan_tree = ttk.Treeview(list_frame, columns=("process", "connections", "remote"), show="headings", height=15)
        self.scan_tree.heading("process", text="Process")
        self.scan_tree.heading("connections", text="Connections")
        self.scan_tree.heading("remote", text="Remote")
        self.scan_tree.column("process", width=200)
        self.scan_tree.column("connections", width=100)
        self.scan_tree.column("remote", width=350)
        self.scan_tree.pack(fill="both", expand=True, side="left")

        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.scan_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.scan_tree.configure(yscrollcommand=scrollbar.set)

    def _scan(self) -> None:
        from .scanner import scan_connections
        conns = scan_connections()
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)

        by_proc: dict[str, list[dict]] = {}
        for c in conns:
            by_proc.setdefault(c["process"], []).append(c)

        for proc, cl in sorted(by_proc.items()):
            remotes = [c["remote"] for c in cl[:3]]
            self.scan_tree.insert("", "end", values=(proc, len(cl), ", ".join(remotes)))

    # ─── STATUS ────────────────────────────────────────
    def _refresh_status(self) -> None:
        self.listen_label.config(text=f"{self.config.listen_host}:{self.config.listen_port}")
        self.global_label.config(text=self.config.global_upstream or "(none)")

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    app = PerAppProxyGUI()
    app.run()


if __name__ == "__main__":
    main()
