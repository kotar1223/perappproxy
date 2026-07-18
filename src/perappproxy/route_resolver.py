"""Resolve which upstream proxy to use based on the source process."""

from __future__ import annotations

import psutil

from .config import Config, Rule
from .win_api import get_pid_for_connection_fast


class RouteResolver:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._pid_cache: dict[int, str] = {}

    def update_config(self, config: Config) -> None:
        self._config = config

    def _get_process_name(self, pid: int) -> str | None:
        if pid in self._pid_cache:
            return self._pid_cache[pid]
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            self._pid_cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def resolve(self, local_port: int) -> str | None:
        """Return upstream proxy URL for a connection on local_port, or None to block."""
        pid = get_pid_for_connection_fast(local_port)
        if pid is None:
            return self._config.global_upstream or None

        name = self._get_process_name(pid)
        if name is None:
            return self._config.global_upstream or None

        name_lower = name.lower()
        for rule in self._config.rules:
            if rule.process.lower() == name_lower:
                return rule.upstream

        return self._config.global_upstream or None

    def get_process_for_port(self, local_port: int) -> str:
        """Human-readable process name for a port."""
        pid = get_pid_for_connection_fast(local_port)
        if pid is None:
            return f"unknown (pid=?:{local_port})"
        name = self._get_process_name(pid)
        return f"{name or 'unknown'} (pid={pid}:{local_port})"
