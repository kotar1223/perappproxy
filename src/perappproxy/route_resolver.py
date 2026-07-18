"""Resolve which upstream proxy to use based on the source process."""

from __future__ import annotations

from .config import Config
from .platforms import get_backend


class RouteResolver:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._backend = get_backend()

    def update_config(self, config: Config) -> None:
        self._config = config

    def resolve(self, local_port: int) -> str | None:
        """Return upstream proxy URL for a connection on local_port, or None to block."""
        pid = self._backend.get_pid_for_port(local_port)
        if pid is None:
            return self._config.global_upstream or None

        name = self._backend.get_process_name(pid)
        if name is None:
            return self._config.global_upstream or None

        name_lower = name.lower()
        for rule in self._config.rules:
            if rule.process.lower() == name_lower:
                return rule.upstream

        return self._config.global_upstream or None

    def get_process_for_port(self, local_port: int) -> str:
        """Human-readable process name for a port."""
        pid = self._backend.get_pid_for_port(local_port)
        if pid is None:
            return f"unknown (pid=?:{local_port})"
        name = self._backend.get_process_name(pid)
        return f"{name or 'unknown'} (pid={pid}:{local_port})"
