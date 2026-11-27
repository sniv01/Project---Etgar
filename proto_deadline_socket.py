#!/usr/bin/env python3
"""
proto_deadline_socket.py — Standalone Prototype v3 for Athena Review (V36.0.3 Step B Final)
100% Python 3 Standard Library (`socket`, `ssl`, `selectors`, `io`, `http.client`, `urllib.parse`).
Completely independent of `etgar_scout.py` (`main` untouched).

Contracts enforced:
  1. Cumulative Network I/O Deadline checked BOTH BEFORE and AFTER every network I/O operation
     (`connect_tcp_with_deadline`, `do_handshake`, `recv_into`, `send`, `conn.request`,
     `conn.getresponse`, every `resp.read1` iteration including EOF, and before returning body),
     so an operation finishing after deadline expiry is NEVER reported as success.
  2. Explicit Exclusion: does NOT bound synchronous OS DNS resolution (`socket.getaddrinfo`),
     which is checked immediately upon return before TCP connect.
  3. Zero SSLContext side-effect mutation: validates caller context (`CERT_REQUIRED` & `check_hostname`).
  4. Strict socket/SSLSocket FD cleanup on EVERY handshake failure path and full HTTPResponse lifecycle.
"""

from __future__ import annotations

import errno
import http.client
import io
import os
import selectors
import socket
import ssl
import time
import urllib.parse
from typing import Callable, Dict, List, Optional, Tuple


class DeadlineExceededError(TimeoutError):
    """Raised when the Cumulative Network I/O Deadline is exceeded."""


class _DeadlineRawIO(io.RawIOBase):
    """RawIOBase adapter over DeadlineSocket with ref-count release on close()."""

    def __init__(self, dsock: "DeadlineSocket"):
        super().__init__()
        self._dsock = dsock
        self._released = False

    def readable(self) -> bool:
        return True

    def readinto(self, b: bytearray) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed file.")
        return self._dsock.recv_into(b)

    def close(self) -> None:
        if not self._released:
            self._released = True
            self._dsock._decref_io()
        super().close()


class DeadlineSocket:
    """
    Non-blocking socket/SSLSocket wrapper enforcing a single Cumulative Network I/O Deadline.
    Exclusion: does NOT bound synchronous OS DNS resolution (`socket.getaddrinfo`).
    """

    def __init__(
        self,
        sock: socket.socket,
        deadline: float,
        clock_fn: Callable[[], float] = time.monotonic,
    ):
        self._sock = sock
        self._sock.setblocking(False)
        self._deadline = float(deadline)
        self._clock = clock_fn
        self._io_refs = 0
        self._closed = False
        self._real_closed = False

    def remaining(self) -> float:
        return self._deadline - self._clock()

    def _check_deadline(self) -> float:
        rem = self.remaining()
        if rem <= 0.0:
            self.force_close()
            raise DeadlineExceededError("CUMULATIVE_NETWORK_IO_DEADLINE_EXCEEDED")
        return rem

    def _wait_event(self, event_mask: int) -> None:
        rem = self._check_deadline()
        sel = selectors.DefaultSelector()
        try:
            sel.register(self._sock, event_mask)
            events = sel.select(timeout=rem)
        finally:
            sel.close()
        if not events or self.remaining() <= 0.0:
            self.force_close()
            raise DeadlineExceededError("CUMULATIVE_NETWORK_IO_DEADLINE_EXCEEDED")

    def do_handshake(self) -> None:
        """Non-blocking TLS handshake strictly bounded by the cumulative deadline (checked before & after)."""
        while True:
            self._check_deadline()
            try:
                self._sock.do_handshake()
                # Post-I/O deadline check: handshake finishing after expiry must NOT report success
                self._check_deadline()
                return
            except ssl.SSLWantReadError:
                self._wait_event(selectors.EVENT_READ)
            except ssl.SSLWantWriteError:
                self._wait_event(selectors.EVENT_WRITE)
            except BlockingIOError:
                self._wait_event(selectors.EVENT_READ)

    def recv_into(self, buffer, nbytes: Optional[int] = None, flags: int = 0) -> int:
        if nbytes is None:
            nbytes = len(buffer)
        while True:
            self._check_deadline()
            try:
                # Attempt non-blocking read FIRST so ssl_sock.pending() > 0 drains immediately
                if isinstance(self._sock, ssl.SSLSocket):
                    n = self._sock.recv_into(buffer, nbytes)
                else:
                    n = self._sock.recv_into(buffer, nbytes, flags)
                # Post-I/O deadline check: read/EOF finishing after expiry must NOT report success
                self._check_deadline()
                return n
            except ssl.SSLWantReadError:
                self._wait_event(selectors.EVENT_READ)
            except ssl.SSLWantWriteError:
                self._wait_event(selectors.EVENT_WRITE)
            except BlockingIOError:
                self._wait_event(selectors.EVENT_READ)

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        buf = bytearray(bufsize)
        n = self.recv_into(buf, bufsize, flags)
        return bytes(buf[:n])

    def send(self, data, flags: int = 0) -> int:
        while True:
            self._check_deadline()
            try:
                if isinstance(self._sock, ssl.SSLSocket):
                    sent = self._sock.send(data)
                else:
                    sent = self._sock.send(data, flags)
                # Post-I/O deadline check: send finishing after expiry must NOT report success
                self._check_deadline()
                return sent
            except ssl.SSLWantWriteError:
                self._wait_event(selectors.EVENT_WRITE)
            except ssl.SSLWantReadError:
                self._wait_event(selectors.EVENT_READ)
            except BlockingIOError:
                self._wait_event(selectors.EVENT_WRITE)

    def sendall(self, data, flags: int = 0) -> None:
        mv = memoryview(data)
        if mv.ndim > 1 or mv.format != "B":
            mv = mv.cast("B")
        total = len(mv)
        offset = 0
        while offset < total:
            sent = self.send(mv[offset:], flags)
            if sent == 0:
                raise ConnectionResetError("Socket connection broken during sendall.")
            offset += sent
        self._check_deadline()

    def pending(self) -> int:
        if isinstance(self._sock, ssl.SSLSocket):
            return self._sock.pending()
        return 0

    def makefile(self, mode: str = "rb", buffering: Optional[int] = None, *args, **kwargs):
        if mode not in ("r", "rb"):
            raise ValueError(f"DeadlineSocket.makefile only supports read-binary mode, got {mode!r}")
        self._io_refs += 1
        raw = _DeadlineRawIO(self)
        if buffering == 0:
            return raw
        buf_size = io.DEFAULT_BUFFER_SIZE if (buffering is None or buffering < 0) else buffering
        return io.BufferedReader(raw, buffer_size=buf_size)

    def settimeout(self, value: Optional[float]) -> None:
        # Cumulative deadline governs all I/O; ignore inactivity timeout overrides from http.client
        pass

    def gettimeout(self) -> float:
        return max(0.0, self.remaining())

    def fileno(self) -> int:
        return self._sock.fileno()

    def _decref_io(self) -> None:
        if self._io_refs > 0:
            self._io_refs -= 1
        if self._closed and self._io_refs <= 0:
            self._real_close()

    def _real_close(self) -> None:
        if not self._real_closed:
            self._real_closed = True
            try:
                self._sock.close()
            except OSError:
                pass

    def close(self) -> None:
        self._closed = True
        if self._io_refs <= 0:
            self._real_close()

    def force_close(self) -> None:
        self._closed = True
        self._real_close()


def connect_tcp_with_deadline(
    ip: str,
    port: int,
    deadline: float,
    clock_fn: Callable[[], float] = time.monotonic,
) -> socket.socket:
    """Non-blocking TCP connect bounded by the Cumulative Network I/O Deadline (checked before & after)."""
    rem = deadline - clock_fn()
    if rem <= 0.0:
        raise DeadlineExceededError("CUMULATIVE_NETWORK_IO_DEADLINE_EXCEEDED")

    af = socket.AF_INET6 if ":" in ip else socket.AF_INET
    raw_sock = socket.socket(af, socket.SOCK_STREAM)
    raw_sock.setblocking(False)
    try:
        err = raw_sock.connect_ex((ip, port))
        if err not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035):
            raise OSError(err, os.strerror(err) if hasattr(os, "strerror") else str(err))
        if err != 0:
            rem = deadline - clock_fn()
            if rem <= 0.0:
                raise DeadlineExceededError("CUMULATIVE_NETWORK_IO_DEADLINE_EXCEEDED")
            sel = selectors.DefaultSelector()
            try:
                sel.register(raw_sock, selectors.EVENT_WRITE)
                events = sel.select(timeout=rem)
            finally:
                sel.close()
            if not events or (deadline - clock_fn()) <= 0.0:
                raise DeadlineExceededError("CUMULATIVE_NETWORK_IO_DEADLINE_EXCEEDED")
            so_err = raw_sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if so_err != 0:
                raise OSError(so_err, f"TCP connect failed with SO_ERROR={so_err}")
        # Post-connect deadline check (covers immediate connect_ex==0 finishing after expiry)
        if (deadline - clock_fn()) <= 0.0:
            raise DeadlineExceededError("CUMULATIVE_NETWORK_IO_DEADLINE_EXCEEDED")
        return raw_sock
    except Exception:
        raw_sock.close()
        raise


class DeadlinePinnedHTTPSConnection(http.client.HTTPSConnection):
    """
    Prototype IP-pinned HTTPSConnection enforcing a single Cumulative Network I/O Deadline.
    NEVER mutates a caller-provided SSLContext; validates required TLS security settings instead.
    Guarantees complete socket/SSLSocket cleanup on EVERY failure path during connect/handshake.
    """

    def __init__(
        self,
        hostname: str,
        pinned_ip: str,
        port: int,
        deadline: float,
        context: Optional[ssl.SSLContext] = None,
        clock_fn: Callable[[], float] = time.monotonic,
    ):
        if context is None:
            ctx = ssl.create_default_context()
        else:
            if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                raise ValueError(
                    "DeadlinePinnedHTTPSConnection requires an SSLContext with "
                    "verify_mode=ssl.CERT_REQUIRED and check_hostname=True (caller context is never mutated)."
                )
            ctx = context

        rem = max(0.001, deadline - clock_fn())
        super().__init__(hostname, port=port, timeout=rem, context=ctx)
        self._pinned_ip = pinned_ip
        self._orig_hostname = hostname
        self._deadline = float(deadline)
        self._clock = clock_fn

    def set_tunnel(self, *args, **kwargs) -> None:
        raise RuntimeError("HTTP proxy tunneling is permanently disabled in DeadlinePinnedHTTPSConnection.")

    def connect(self) -> None:
        raw_sock: Optional[socket.socket] = None
        ssl_sock: Optional[ssl.SSLSocket] = None
        dsock: Optional[DeadlineSocket] = None
        try:
            raw_sock = connect_tcp_with_deadline(self._pinned_ip, self.port, self._deadline, self._clock)
            ssl_sock = self._context.wrap_socket(
                raw_sock,
                server_hostname=self._orig_hostname,
                do_handshake_on_connect=False,
            )
            dsock = DeadlineSocket(ssl_sock, self._deadline, clock_fn=self._clock)
            dsock.do_handshake()
            self.sock = dsock
        except Exception:
            if dsock is not None:
                dsock.force_close()
            elif ssl_sock is not None:
                try:
                    ssl_sock.close()
                except OSError:
                    pass
            elif raw_sock is not None:
                try:
                    raw_sock.close()
                except OSError:
                    pass
            raise


def fetch_https_with_deadline(
    url: str,
    pinned_ip_resolver: Callable[[str, int], str],
    timeout_sec: float,
    context: Optional[ssl.SSLContext] = None,
    max_redirects: int = 3,
    max_bytes: int = 2_097_152,
    clock_fn: Callable[[], float] = time.monotonic,
) -> Tuple[str, int, bytes]:
    """
    Standalone prototype fetch routine demonstrating real multi-hop redirect handling,
    response-body reading via `read1(16384)`, strict FD cleanup, and post-I/O deadline checks
    (including after end-of-body EOF) under a single Cumulative Network I/O Deadline.
    """
    if timeout_sec <= 0:
        raise DeadlineExceededError("CUMULATIVE_NETWORK_IO_DEADLINE_EXCEEDED")
    deadline = clock_fn() + float(timeout_sec)
    current_url = url
    visited = set()

    def _assert_within_deadline() -> None:
        if deadline - clock_fn() <= 0.0:
            raise DeadlineExceededError("CUMULATIVE_NETWORK_IO_DEADLINE_EXCEEDED")

    for hop in range(max_redirects + 1):
        if current_url in visited:
            raise RuntimeError(f"Redirect loop detected: {current_url}")
        visited.add(current_url)

        _assert_within_deadline()

        parsed = urllib.parse.urlsplit(current_url)
        host = parsed.hostname or ""
        port = parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        # DNS resolution is explicitly outside the non-blocking socket deadline,
        # but checked immediately upon return before opening a TCP connection.
        pinned_ip = pinned_ip_resolver(host, port)
        _assert_within_deadline()

        headers = {
            "Host": host if port == 443 else f"{host}:{port}",
            "Connection": "close",
            "Accept-Encoding": "identity",
        }

        conn = DeadlinePinnedHTTPSConnection(
            hostname=host,
            pinned_ip=pinned_ip,
            port=port,
            deadline=deadline,
            context=context,
            clock_fn=clock_fn,
        )
        resp: Optional[http.client.HTTPResponse] = None
        try:
            conn.request("GET", path, headers=headers)
            _assert_within_deadline()
            resp = conn.getresponse()
            _assert_within_deadline()
            status = resp.status
            resp_headers: Dict[str, str] = {k.lower(): v for k, v in resp.getheaders()}
            chunks: List[bytes] = []
            total = 0
            while True:
                _assert_within_deadline()
                chunk = resp.read1(16384)
                # Post-I/O check on EVERY chunk AND on EOF (chunk == b"")!
                _assert_within_deadline()
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise RuntimeError(f"Response exceeded max_bytes ({max_bytes})")
                chunks.append(chunk)
            body = b"".join(chunks)
            # Final post-body-completion deadline check before reporting success
            _assert_within_deadline()
        finally:
            if resp is not None:
                try:
                    resp.close()
                except OSError:
                    pass
            conn.close()

        if status in (301, 302, 303, 307, 308):
            if hop >= max_redirects:
                raise RuntimeError(f"Exceeded max_redirects ({max_redirects})")
            loc = resp_headers.get("location")
            if not loc:
                raise RuntimeError(f"Redirect {status} without Location header")
            current_url = urllib.parse.urljoin(current_url, loc.strip())
            continue

        return current_url, status, body

    raise RuntimeError(f"Exceeded max_redirects ({max_redirects})")
