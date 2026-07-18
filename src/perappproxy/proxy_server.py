"""Async HTTP/CONNECT proxy server with per-app routing."""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .route_resolver import RouteResolver

logger = logging.getLogger("perappproxy")

BUFFER_SIZE = 65536
HTTP_TIMEOUT = 30


class ProxyServer:
    def __init__(self, host: str, port: int, resolver: "RouteResolver") -> None:
        self.host = host
        self.port = port
        self.resolver = resolver
        self._server: asyncio.Server | None = None
        self._running = False

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        self._running = True
        logger.info("Proxy server listening on %s:%d", self.host, self.port)

    async def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        logger.info("Proxy server stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peername = writer.get_extra_info("peername")
        local_port = writer.get_extra_info("sockname", (None, 0))[1]
        logger.debug("Connection from %s (local port %d)", peername, local_port)

        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=HTTP_TIMEOUT)
            if not request_line:
                return

            first_line = request_line.decode("utf-8", errors="replace").strip()
            parts = first_line.split()
            if len(parts) < 3:
                return

            method = parts[0].upper()

            if method == "CONNECT":
                await self._handle_connect(reader, writer, parts[1], local_port)
            else:
                # For plain HTTP, we need to read the full request
                await self._handle_http(reader, writer, request_line, method, local_port)
        except asyncio.TimeoutError:
            logger.debug("Connection timed out")
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except Exception:
            logger.exception("Error handling connection")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _get_upstream_for_port(self, local_port: int) -> str | None:
        return self.resolver.resolve(local_port)

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
        local_port: int,
    ) -> None:
        """Handle CONNECT method (HTTPS tunneling)."""
        upstream = self._get_upstream_for_port(local_port)
        if not upstream:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            return

        # Parse target host:port
        if ":" in target:
            host, port = target.rsplit(":", 1)
            port = int(port)
        else:
            host = target
            port = 443

        try:
            upstream_host, upstream_port = self._parse_proxy(upstream)
            logger.info(
                "CONNECT %s:%d via %s:%d (from port %d)",
                host, port, upstream_host, upstream_port, local_port,
            )

            # Connect to upstream proxy
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(upstream_host, upstream_port),
                timeout=HTTP_TIMEOUT,
            )

            # Send CONNECT to upstream proxy
            connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            up_writer.write(connect_req.encode())
            await up_writer.drain()

            # Read upstream response
            resp = await asyncio.wait_for(up_reader.readline(), timeout=HTTP_TIMEOUT)
            if not resp or b"200" not in resp:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
                up_writer.close()
                return

            # Drain remaining headers
            while True:
                line = await asyncio.wait_for(up_reader.readline(), timeout=HTTP_TIMEOUT)
                if line == b"\r\n" or line == b"":
                    break

            # Send 200 to client
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            # Bidirectional copy
            await self._tunnel(reader, writer, up_reader, up_writer)

        except asyncio.TimeoutError:
            logger.warning("Connection to upstream timed out")
            writer.write(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n")
            await writer.drain()
        except Exception as e:
            logger.exception("CONNECT error: %s", e)
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        first_line: bytes,
        method: str,
        local_port: int,
    ) -> None:
        """Handle plain HTTP requests (GET, POST, etc.)."""
        upstream = self._get_upstream_for_port(local_port)
        if not upstream:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            return

        # Parse URL from first line
        parts = first_line.decode("utf-8", errors="replace").strip().split()
        if len(parts) < 2:
            return

        url = parts[1]

        try:
            upstream_host, upstream_port = self._parse_proxy(upstream)
            logger.info(
                "HTTP %s %s via %s:%d (from port %d)",
                method, url, upstream_host, upstream_port, local_port,
            )

            # Connect to upstream proxy
            up_reader, up_writer = await asyncio.wait_for(
                asyncio.open_connection(upstream_host, upstream_port),
                timeout=HTTP_TIMEOUT,
            )

            # Forward the full request line
            up_writer.write(first_line)

            # Read and forward headers
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=HTTP_TIMEOUT)
                up_writer.write(line)
                if line == b"\r\n" or line == b"":
                    break

            await up_writer.drain()

            # Forward body if present
            # (simplified — assumes no streaming body for HTTP proxy)
            # Read response and forward to client
            await self._copy_stream(up_reader, writer)

            up_writer.close()

        except Exception as e:
            logger.exception("HTTP error: %s", e)
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()

    async def _tunnel(
        self,
        client_r: asyncio.StreamReader,
        client_w: asyncio.StreamWriter,
        upstream_r: asyncio.StreamReader,
        upstream_w: asyncio.StreamWriter,
    ) -> None:
        """Bidirectional data copy between client and upstream."""
        async def copy(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    data = await src.read(BUFFER_SIZE)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except Exception:
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        t1 = asyncio.create_task(copy(client_r, upstream_w))
        t2 = asyncio.create_task(copy(upstream_r, client_w))
        await asyncio.gather(t1, t2, return_exceptions=True)

    async def _copy_stream(
        self, src: asyncio.StreamReader, dst: asyncio.StreamWriter
    ) -> None:
        """Copy data from src to dst until EOF."""
        try:
            while True:
                data = await src.read(BUFFER_SIZE)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except Exception:
            pass

    @staticmethod
    def _parse_proxy(proxy: str) -> tuple[str, int]:
        """Parse proxy URL into (host, port)."""
        # Strip protocol prefix
        for prefix in ("socks5://", "socks4://", "http://", "https://"):
            if proxy.startswith(prefix):
                proxy = proxy[len(prefix):]
                break

        if ":" in proxy:
            host, port_str = proxy.rsplit(":", 1)
            port = int(port_str)
        else:
            host = proxy
            port = 8080

        return host, port
