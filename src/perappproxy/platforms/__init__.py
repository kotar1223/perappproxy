"""Cross-platform abstraction for process identification and system proxy."""

from __future__ import annotations

import sys
from typing import Protocol


class PlatformBackend(Protocol):
    def get_pid_for_port(self, local_port: int) -> int | None: ...
    def get_process_name(self, pid: int) -> str | None: ...
    def get_system_proxy(self) -> tuple[str, int]: ...
    def set_system_proxy(self, host: str, port: int) -> None: ...
    def disable_system_proxy(self) -> None: ...
    def scan_connections(self) -> list[dict]: ...


def get_backend() -> PlatformBackend:
    if sys.platform == "win32":
        from .win32 import Win32Backend
        return Win32Backend()
    elif sys.platform == "linux":
        from .linux import LinuxBackend
        return LinuxBackend()
    else:
        raise OSError(f"Unsupported platform: {sys.platform}")
