"""Enable/disable Windows system proxy via registry."""

from __future__ import annotations

import winreg

INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


def _open_key() -> winreg.HKEYType:
    return winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_ALL_ACCESS)


def get_system_proxy() -> tuple[str, int]:
    """Return (proxy_server, enabled)."""
    try:
        key = _open_key()
        enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
        try:
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        except FileNotFoundError:
            server = ""
        winreg.CloseKey(key)
        return server, enabled
    except FileNotFoundError:
        return "", 0


def set_system_proxy(proxy: str, port: int) -> None:
    """Set system proxy to host:port."""
    key = _open_key()
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
    # Bypass local addresses
    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*;<local>")
    winreg.CloseKey(key)


def disable_system_proxy() -> None:
    """Disable system proxy."""
    key = _open_key()
    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    winreg.CloseKey(key)
