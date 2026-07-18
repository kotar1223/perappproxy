"""Scan active network connections and show process info."""

from __future__ import annotations

import psutil

from .win_api import get_pid_for_connection_fast


def scan_connections() -> list[dict]:
    """Return list of active TCP connections with process info."""
    results = []
    for conn in psutil.net_connections(kind="tcp"):
        if conn.status != "ESTABLISHED":
            continue
        if conn.laddr.port == 0:
            continue

        pid = conn.pid
        name = ""
        if pid:
            try:
                name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = f"<pid={pid}>"

        results.append({
            "local": f"{conn.laddr.ip}:{conn.laddr.port}",
            "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-",
            "pid": pid or 0,
            "process": name,
        })

    return results
