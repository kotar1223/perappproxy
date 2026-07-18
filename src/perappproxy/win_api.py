"""Windows API for mapping network connections to PIDs."""

from __future__ import annotations

import ctypes
import ctypes.wintypes
import socket
import struct
from collections import defaultdict

# https://learn.microsoft.com/en-us/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_pid
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


def _ntohs(port: int) -> int:
    """Convert network byte order port to host byte order."""
    return socket.ntohs(port)


def get_pid_for_connection(local_port: int) -> int | None:
    """Find the PID that owns a connection on the given local port."""
    size = ctypes.wintypes.DWORD(0)
    phlpapi = ctypes.windll.iphlpapi

    # First call to get required size
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
        row_port = _ntohs(row.dwLocalPort)
        if row_port == local_port:
            return row.dwOwningPid

    return None


def get_pid_for_connection_fast(local_port: int) -> int | None:
    """Get PID for a local port — cached call via GetExtendedTcpTable."""
    size = ctypes.wintypes.DWORD(0)

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
        if _ntohs(row.dwLocalPort) == local_port:
            return row.dwOwningPid

    return None
