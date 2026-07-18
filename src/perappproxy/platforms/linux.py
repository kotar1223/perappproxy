"""Linux backend — process identification via /proc/net/tcp, system proxy via env vars."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import psutil


def _port_to_hex(port: int) -> str:
    return f"{port:08X}"


def _read_proc_net_tcp() -> list[dict]:
    """Parse /proc/net/tcp for local port -> inode mapping."""
    entries = []
    try:
        text = Path("/proc/net/tcp").read_text()
    except (FileNotFoundError, PermissionError):
        return entries

    for line in text.strip().splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 10:
            continue
        local = parts[1]
        if ":" not in local:
            continue
        hex_port = local.split(":")[1]
        try:
            port = int(hex_port, 16)
        except ValueError:
            continue
        inode = parts[9]
        entries.append({"port": port, "inode": inode})
    return entries


def _inode_to_pid(entries: list[dict]) -> dict[int, int]:
    """Map inode -> PID by scanning /proc/*/fd."""
    inode_pid: dict[str, int] = {}
    for pid_dir in Path("/proc").iterdir():
        if not pid_dir.name.isdigit():
            continue
        pid = int(pid_dir.name)
        fd_dir = pid_dir / "fd"
        if not fd_dir.exists():
            continue
        try:
            for fd in fd_dir.iterdir():
                try:
                    link = os.readlink(fd)
                    if "socket:" in link:
                        inode = link.split("[")[1].rstrip("]")
                        inode_pid[inode] = pid
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            continue

    result: dict[int, int] = {}
    for entry in entries:
        if entry["inode"] in inode_pid:
            result[entry["port"]] = inode_pid[entry["inode"]]
    return result


class LinuxBackend:
    def __init__(self) -> None:
        self._pid_cache: dict[int, str] = {}

    def get_pid_for_port(self, local_port: int) -> int | None:
        entries = _read_proc_net_tcp()
        port_map = _inode_to_pid(entries)
        return port_map.get(local_port)

    def get_process_name(self, pid: int) -> str | None:
        if pid in self._pid_cache:
            return self._pid_cache[pid]
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            self._pid_cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def get_system_proxy(self) -> tuple[str, int]:
        http_proxy = os.environ.get("http_proxy", os.environ.get("HTTP_PROXY", ""))
        if http_proxy:
            return http_proxy, 1
        return "", 0

    def set_system_proxy(self, host: str, port: int) -> None:
        proxy_url = f"http://{host}:{port}"
        os.environ["http_proxy"] = proxy_url
        os.environ["https_proxy"] = proxy_url
        os.environ["HTTP_PROXY"] = proxy_url
        os.environ["HTTPS_PROXY"] = proxy_url

        # Also write to shell profile for persistence
        shell_profiles = [
            Path.home() / ".bashrc",
            Path.home() / ".zshrc",
            Path.home() / ".profile",
        ]
        marker = "# PerAppProxy"
        export_lines = [
            f"{marker}",
            f'export http_proxy="{proxy_url}"',
            f'export https_proxy="{proxy_url}"',
            f'export HTTP_PROXY="{proxy_url}"',
            f'export HTTPS_PROXY="{proxy_url}"',
            f'{marker}',
        ]

        for profile in shell_profiles:
            if not profile.exists():
                continue
            text = profile.read_text()
            # Remove old entries
            lines = []
            skip = False
            for line in text.splitlines():
                if marker in line:
                    skip = not skip
                    continue
                if not skip:
                    lines.append(line)
            # Add new
            lines.extend(export_lines)
            profile.write_text("\n".join(lines) + "\n")

    def disable_system_proxy(self) -> None:
        for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
            os.environ.pop(var, None)

        shell_profiles = [
            Path.home() / ".bashrc",
            Path.home() / ".zshrc",
            Path.home() / ".profile",
        ]
        marker = "# PerAppProxy"
        for profile in shell_profiles:
            if not profile.exists():
                continue
            text = profile.read_text()
            lines = []
            skip = False
            for line in text.splitlines():
                if marker in line:
                    skip = not skip
                    continue
                if not skip:
                    lines.append(line)
            profile.write_text("\n".join(lines) + "\n")

    def scan_connections(self) -> list[dict]:
        results = []
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != "ESTABLISHED" or conn.laddr.port == 0:
                continue
            name = ""
            if conn.pid:
                name = self.get_process_name(conn.pid) or f"<pid={conn.pid}>"
            results.append({
                "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-",
                "pid": conn.pid or 0,
                "process": name,
            })
        return results
