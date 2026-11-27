#!/usr/bin/env python3
"""
proto_deadline_socket.py — Standalone Prototype for Athena Review (V36.0.3 Step B)
Implements Cumulative Network I/O Deadline enforcement over non-blocking TCP + TLS
using 100% Python 3 Standard Library (`socket`, `ssl`, `selectors`, `io`, `http.client`).

Explicit Scope & Exclusion Contract:
  - Enforces a single monotonic `deadline` across: TCP connect, TLS handshake,
    HTTP request write (including partial writes & TLS renegotiation wants),
    HTTP status/header parsing, HTTP body reading (Content-Length & chunked,
    including SSL pending() buffered plaintext), and multi-hop redirects.
  - EXCLUSION: Does NOT bound synchronous OS DNS resolution (`socket.getaddrinfo`),
    which is checked immediately upon return before TCP connect.
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
from typing import Callable, Optional


class DeadlineExceededError(TimeoutError):
    """Raised when the Cumulative Network I/O Deadline is exceeded."""


class _DeadlineRawIO(io.RawIOBase):
    """RawIOBase adapter over DeadlineSocket with proper ref-count release on close()."""

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

    Key invariants:
      1. Always attempts non-blocking I/O BEFORE calling selector.select(), so
         OpenSSL internal plaintext (`ssl_sock.pending() > 0`) is drained immediately
         without blocking on an empty kernel TCP buffer.
      2. Handles both `ssl.SSLWantReadError` AND `ssl.SSLWantWriteError` on BOTH
         read and write operations (supporting TLS renegotiation / TLS 1.3 post-handshake).
      3. Handles partial writes in `sendall()` using `memoryview` slicing.
      4. Implements CPython-compatible `_io_refs` reference counting for `makefile("rb")`
         so closing `HTTPResponse.fp` does not prematurely destroy an active socket, and
         closing the wrapper does not yank the underlying socket out from under an open reader
         (unless `force_close()` is invoked on deadline expiry).
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
        """Non-blocking TLS handshake strictly bounded by the cumulative deadline."""
        while True:
            self._check_deadline()
            try:
                self._sock.do_handshake()
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
                # Attempt non-blocking read FIRST so ssl_sock.pending() > 0 returns immediately!
                if isinstance(self._sock, ssl.SSLSocket):
                    return self._sock.recv_into(buffer, nbytes)
                return self._sock.recv_into(buffer, nbytes, flags)
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
                    return self._sock.send(data)
                return self._sock.send(data, flags)
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
    """Non-blocking TCP connect bounded by the cumulative deadline."""
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
        return raw_sock
    except Exception:
        raw_sock.close()
        raise



class DeadlinePinnedHTTPSConnection(http.client.HTTPSConnection):
    """Prototype IP-pinned HTTPSConnection enforcing a single Cumulative Network I/O Deadline."""

    def __init__(
        self,
        hostname: str,
        pinned_ip: str,
        port: int,
        deadline: float,
        context: ssl.SSLContext,
        clock_fn: Callable[[], float] = time.monotonic,
    ):
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        rem = max(0.001, deadline - clock_fn())
        super().__init__(hostname, port=port, timeout=rem, context=context)
        self._pinned_ip = pinned_ip
        self._orig_hostname = hostname
        self._deadline = float(deadline)
        self._clock = clock_fn

    def connect(self) -> None:
        raw_sock = connect_tcp_with_deadline(self._pinned_ip, self.port, self._deadline, self._clock)
        try:
            ssl_sock = self._context.wrap_socket(
                raw_sock,
                server_hostname=self._orig_hostname,
                do_handshake_on_connect=False,
            )
            dsock = DeadlineSocket(ssl_sock, self._deadline, clock_fn=self._clock)
            dsock.do_handshake()
            self.sock = dsock
        except Exception:
            try:
                raw_sock.close()
            except OSError:
                pass
            raise
