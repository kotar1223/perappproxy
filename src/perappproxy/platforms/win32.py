"""Windows backend — process identification via WinAPI, system proxy via registry."""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import os
import signal
import socket
import winreg

import psutil

TCP_TABLE_OWNER_PID_ALL = 5
AF_INET = 2

iphlpapi = ctypes.windll.iphlpapi


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.wintypes.DWORD),
        ("dwLocalAddr", ctypes.wintypes.DWORD),
        ("dwLocalPort", ctypes.wintypes.DWORD),
        ("dwRemoteAddr", ctypes.wintypes.DWORD),
        ("dwRemotePort", ctypes.wintypes.DWORD),
        ("dwOwningPid", ctypes.wintypes.DWORD),
    ]


INTERNET_SETTINGS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"


class Win32Backend:
    def __init__(self) -> None:
        self._pid_cache: dict[int, str] = {}

    def get_pid_for_port(self, local_port: int) -> int | None:
        size = ctypes.wintypes.DWORD(0)
        phlpapi = ctypes.windll.iphlpapi

        phlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        buf = (ctypes.c_byte * size.value)()
        ret = phlpapi.GetExtendedTcpTable(ctypes.byref(buf[0]), ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        if ret != 0:
            return None

        count = ctypes.wintypes.DWORD()
        ctypes.memmove(ctypes.byref(count), buf, 4)

        table = (MIB_TCPROW_OWNER_PID * count.value)()
        ctypes.memmove(ctypes.byref(table), buf[4:], count.value * ctypes.sizeof(MIB_TCPROW_OWNER_PID))

        for row in table:
            if socket.ntohs(row.dwLocalPort) == local_port:
                return row.dwOwningPid
        return None

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
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_ALL_ACCESS)
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            try:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
            except FileNotFoundError:
                server = ""
            winreg.CloseKey(key)
            return server, enabled
        except FileNotFoundError:
            return "", 0

    def set_system_proxy(self, host: str, port: int) -> None:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"127.0.0.1:{port}")
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*;<local>")
        winreg.CloseKey(key)

    def disable_system_proxy(self) -> None:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INTERNET_SETTINGS_KEY, 0, winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)

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
