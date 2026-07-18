"""Cross-platform active connections scanner."""

from __future__ import annotations

from .platforms import get_backend


def scan_connections() -> list[dict]:
    return get_backend().scan_connections()
