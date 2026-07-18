"""Cross-platform system proxy toggle."""

from __future__ import annotations

from .platforms import get_backend


def get_system_proxy() -> tuple[str, int]:
    return get_backend().get_system_proxy()


def set_system_proxy(host: str, port: int) -> None:
    get_backend().set_system_proxy(host, port)


def disable_system_proxy() -> None:
    get_backend().disable_system_proxy()
