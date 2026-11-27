#!/usr/bin/env python3
"""
test_proto_deadline_socket.py — Standalone Adversarial Tests for DeadlineSocket Prototype (Athena Step B)
Tests:
  1. SSLWantReadError & SSLWantWriteError on BOTH read AND write (via real socketpair + selectors)
  2. Partial writes in sendall() + deadline enforcement during slow partial writes
  3. Real OpenSSL TLS `pending()` buffered plaintext drained without hanging on selector
  4. `makefile("rb")` / BufferedReader reference-counting lifecycle (no premature close, no FD leak)
  5. Live OpenSSL TLS Slow-Drip Body (Content-Length AND Chunked)
  6. Live OpenSSL TLS Slow-Drip Headers
  7. Live OpenSSL TLS Slow-Drip Handshake (stalled ServerHello)
  8. Live OpenSSL TLS Cumulative Multi-Hop Redirects (both expiry & success)
"""

import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

import proto_deadline_socket as pds


class _ScriptedWantSocket:
    """Wraps a real OS socketpair endpoint so selectors works, while injecting SSLWantRead/WantWrite & partial writes."""

    def __init__(self, real_sock: socket.socket, read_faults=None, write_faults=None, max_write_chunk: int = 4):
        self._real = real_sock
        self._real.setblocking(False)
        self._read_faults = list(read_faults or [])
        self._write_faults = list(write_faults or [])
        self._max_write_chunk = max_write_chunk
        self.closed = False

    def setblocking(self, flag: bool):
        self._real.setblocking(flag)

    def fileno(self) -> int:
        return self._real.fileno()

    def recv_into(self, buf, nbytes=None, flags=0):
        if self._read_faults:
            exc = self._read_faults.pop(0)
            if exc is not None:
                raise exc
        return self._real.recv_into(buf, nbytes if nbytes is not None else len(buf), flags)

    def send(self, data, flags=0):
        if self._write_faults:
            exc = self._write_faults.pop(0)
            if exc is not None:
                raise exc
        mv = memoryview(data)
        chunk = mv[: self._max_write_chunk]
        return self._real.send(chunk, flags)

    def close(self):
        self.closed = True
        self._real.close()


class TestDeadlineSocketUnitAndTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl_bin = shutil.which("openssl")
        cls.td = tempfile.TemporaryDirectory()
        cls.tdp = Path(cls.td.name)
        cls.key_path = cls.tdp / "srv.key"
        cls.crt_path = cls.tdp / "srv.crt"
        if cls.openssl_bin:
            proc = subprocess.run(
                [
                    cls.openssl_bin, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(cls.key_path), "-out", str(cls.crt_path),
                    "-days", "1", "-subj", "/CN=api.openalex.org",
                    "-addext", "subjectAltName=DNS:api.openalex.org",
                ],
                capture_output=True, text=True,
            )
            assert proc.returncode == 0, proc.stderr

    @classmethod
    def tearDownClass(cls):
        cls.td.cleanup()

    def _start_tls_server(self, handler_fn, accept_count: int = 1):
        srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv_ctx.load_cert_chain(certfile=str(self.crt_path), keyfile=str(self.key_path))
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(4)

        def _worker():
            try:
                for _ in range(accept_count):
                    try:
                        srv.settimeout(5.0)
                        raw_c, _ = srv.accept()
                    except socket.timeout:
                        break
                    try:
                        handler_fn(raw_c, srv_ctx)
                    except Exception:
                        pass
                    finally:
                        try:
                            raw_c.close()
                        except OSError:
                            pass
            finally:
                srv.close()

        th = threading.Thread(target=_worker, daemon=True)
        th.start()
        return port, th

    def test_01_want_read_and_want_write_on_both_read_and_write_plus_partial_writes(self):
        s_cli, s_srv = socket.socketpair()
        try:
            # Send 17 bytes for recv() + 1 extra byte so s_cli remains readable when send() hits SSLWantReadError
            # (simulating an inbound TLS renegotiation/KeyUpdate record arriving during write).
            s_srv.sendall(b"HELLO_WORLD_12345X")
            scripted = _ScriptedWantSocket(
                s_cli,
                read_faults=[ssl.SSLWantReadError(), ssl.SSLWantWriteError()],
                write_faults=[ssl.SSLWantWriteError(), ssl.SSLWantReadError()],
                max_write_chunk=3,
            )
            ds = pds.DeadlineSocket(scripted, deadline=time.monotonic() + 2.0)
            try:
                got = ds.recv(17)
                self.assertEqual(got, b"HELLO_WORLD_12345")

                payload = b"PARTIAL_WRITE_TEST_PAYLOAD"
                ds.sendall(payload)
                s_srv.settimeout(2.0)
                recvd = b""
                while len(recvd) < len(payload):
                    recvd += s_srv.recv(64)
                self.assertEqual(recvd, payload)
            finally:
                ds.close()
        finally:
            s_srv.close()

        # Negative check: SSLWantReadError during sendall when peer stays silent MUST time out at deadline!
        s_cli2, s_srv2 = socket.socketpair()
        try:
            scripted2 = _ScriptedWantSocket(s_cli2, write_faults=[ssl.SSLWantReadError()])
            t0 = time.monotonic()
            ds2 = pds.DeadlineSocket(scripted2, deadline=t0 + 0.30)
            try:
                with self.assertRaises(pds.DeadlineExceededError):
                    ds2.sendall(b"STALLED_WRITE")
                self.assertLess(time.monotonic() - t0, 0.80)
                self.assertTrue(scripted2.closed)
            finally:
                ds2.close()
        finally:
            s_srv2.close()

    def test_02_makefile_refcount_no_premature_close_and_no_fd_leak(self):
        s_cli, s_srv = socket.socketpair()
        try:
            s_srv.sendall(b"LINE1\nLINE2\n")
            scripted = _ScriptedWantSocket(s_cli)
            ds = pds.DeadlineSocket(scripted, deadline=time.monotonic() + 2.0)

            fp = ds.makefile("rb")
            self.assertEqual(fp.readline(), b"LINE1\n")

            # Closing ds while fp is still open MUST NOT close the underlying socket!
            ds.close()
            self.assertFalse(scripted.closed, "Underlying socket was closed prematurely while makefile() reader still open!")
            self.assertEqual(fp.readline(), b"LINE2\n")

            # Closing fp now decrements _io_refs to 0 and MUST close the underlying socket (no leak!)
            fp.close()
            self.assertTrue(scripted.closed, "Underlying socket leaked after both ds.close() and fp.close()!")
        finally:
            s_srv.close()

        # Reverse order: closing fp first MUST NOT close ds until ds.close() is called
        s_cli2, s_srv2 = socket.socketpair()
        try:
            s_srv2.sendall(b"PING")
            scripted2 = _ScriptedWantSocket(s_cli2)
            ds2 = pds.DeadlineSocket(scripted2, deadline=time.monotonic() + 2.0)
            fp2 = ds2.makefile("rb")
            fp2.close()
            self.assertFalse(scripted2.closed, "fp.close() prematurely closed underlying socket while ds2 still active!")
            self.assertEqual(ds2.recv(4), b"PING")
            ds2.close()
            self.assertTrue(scripted2.closed)
        finally:
            s_srv2.close()

    def test_03_live_tls_ssl_pending_plaintext_drained_without_selector_hang(self):
        if not self.openssl_bin:
            self.skipTest("openssl unavailable")

        big_blob = b"A" * 12000

        def _handler(raw_c, srv_ctx):
            with srv_ctx.wrap_socket(raw_c, server_side=True) as tls_c:
                tls_c.sendall(big_blob)
                # Keep connection open silently for 2 seconds -> kernel TCP recv buffer is EMPTY!
                time.sleep(2.0)

        port, th = self._start_tls_server(_handler)
        try:
            deadline = time.monotonic() + 0.8
            raw = pds.connect_tcp_with_deadline("127.0.0.1", port, deadline)
            ctx = ssl.create_default_context(cafile=str(self.crt_path))
            ssl_s = ctx.wrap_socket(raw, server_hostname="api.openalex.org", do_handshake_on_connect=False)
            ds = pds.DeadlineSocket(ssl_s, deadline)
            try:
                ds.do_handshake()
                # Read only 64 bytes -> OpenSSL decrypts full TLS record leaving >11,000 bytes in ssl.pending()!
                first = ds.recv(64)
                self.assertEqual(first, b"A" * 64)
                self.assertGreater(ds.pending(), 0, "Expected OpenSSL pending() > 0 after small partial read")
                # Now drain remaining bytes: MUST return immediately (< 0.2s) without hanging on selector!
                t0 = time.monotonic()
                collected = bytearray(first)
                while len(collected) < len(big_blob):
                    collected.extend(ds.recv(1024))
                elapsed = time.monotonic() - t0
                self.assertEqual(bytes(collected), big_blob)
                self.assertLess(elapsed, 0.35, f"Draining SSL pending() stalled for {elapsed:.2f}s!")
            finally:
                ds.force_close()
        finally:
            th.join(timeout=3.0)

    def test_04_live_tls_slow_drip_body_content_length_and_chunked(self):
        if not self.openssl_bin:
            self.skipTest("openssl unavailable")

        for mode in ("content_length", "chunked"):
            with self.subTest(mode=mode):
                def _handler(raw_c, srv_ctx, m=mode):
                    with srv_ctx.wrap_socket(raw_c, server_side=True) as tls_c:
                        tls_c.recv(2048)
                        if m == "content_length":
                            tls_c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 320\r\nConnection: close\r\n\r\n")
                            for _ in range(20):
                                time.sleep(0.12)
                                tls_c.sendall(b"0123456789abcdef")
                        else:
                            tls_c.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
                            for _ in range(20):
                                time.sleep(0.12)
                                tls_c.sendall(b"10\r\n0123456789abcdef\r\n")
                            tls_c.sendall(b"0\r\n\r\n")

                port, th = self._start_tls_server(_handler)
                ctx = ssl.create_default_context(cafile=str(self.crt_path))
                t0 = time.monotonic()
                deadline = t0 + 0.55
                conn = pds.DeadlinePinnedHTTPSConnection("api.openalex.org", "127.0.0.1", port, deadline, ctx)
                try:
                    with self.assertRaises(pds.DeadlineExceededError):
                        conn.request("GET", "/drip", headers={"Host": "api.openalex.org", "Connection": "close"})
                        resp = conn.getresponse()
                        while resp.read1(16384):
                            pass
                    elapsed = time.monotonic() - t0
                    self.assertLess(elapsed, 1.15, f"Slow-drip ({mode}) took {elapsed:.2f}s (exceeded 0.55s deadline!)")
                finally:
                    conn.close()
                    th.join(timeout=3.0)

    def test_05_live_tls_slow_drip_headers_enforced(self):
        if not self.openssl_bin:
            self.skipTest("openssl unavailable")

        def _handler(raw_c, srv_ctx):
            with srv_ctx.wrap_socket(raw_c, server_side=True) as tls_c:
                tls_c.recv(2048)
                tls_c.sendall(b"HTTP/1.1 200 OK\r\n")
                for i in range(25):
                    time.sleep(0.10)
                    tls_c.sendall(f"X-Slow-{i}: value\r\n".encode("ascii"))
                tls_c.sendall(b"Content-Length: 2\r\n\r\nOK")

        port, th = self._start_tls_server(_handler)
        ctx = ssl.create_default_context(cafile=str(self.crt_path))
        t0 = time.monotonic()
        conn = pds.DeadlinePinnedHTTPSConnection("api.openalex.org", "127.0.0.1", port, t0 + 0.50, ctx)
        try:
            with self.assertRaises(pds.DeadlineExceededError):
                conn.request("GET", "/slow-hdr", headers={"Host": "api.openalex.org", "Connection": "close"})
                conn.getresponse()
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 1.10)
        finally:
            conn.close()
            th.join(timeout=3.0)

    def test_06_live_tls_stalled_handshake_enforced(self):
        if not self.openssl_bin:
            self.skipTest("openssl unavailable")

        def _silent_handler(raw_c, _srv_ctx):
            # Accept TCP and stay completely silent during TLS ClientHello!
            time.sleep(2.5)

        port, th = self._start_tls_server(_silent_handler)
        ctx = ssl.create_default_context(cafile=str(self.crt_path))
        t0 = time.monotonic()
        conn = pds.DeadlinePinnedHTTPSConnection("api.openalex.org", "127.0.0.1", port, t0 + 0.45, ctx)
        try:
            with self.assertRaises(pds.DeadlineExceededError):
                conn.connect()
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 0.95)
        finally:
            conn.close()
            th.join(timeout=3.0)

    def test_07_live_tls_cumulative_multi_hop_redirect_deadline(self):
        if not self.openssl_bin:
            self.skipTest("openssl unavailable")

        def _redirect_handler(raw_c, srv_ctx):
            with srv_ctx.wrap_socket(raw_c, server_side=True) as tls_c:
                req = tls_c.recv(2048)
                time.sleep(0.35)
                if b"GET /hop1" in req:
                    tls_c.sendall(b"HTTP/1.1 302 Found\r\nLocation: /hop2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                else:
                    tls_c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nDONE")

        # Case A: 2 hops × 0.35s = 0.70s > 0.55s cumulative deadline -> MUST fail!
        port1, th1 = self._start_tls_server(_redirect_handler, accept_count=2)
        ctx = ssl.create_default_context(cafile=str(self.crt_path))
        t0 = time.monotonic()
        deadline_tight = t0 + 0.55
        with self.assertRaises(pds.DeadlineExceededError):
            path = "/hop1"
            for _ in range(3):
                c = pds.DeadlinePinnedHTTPSConnection("api.openalex.org", "127.0.0.1", port1, deadline_tight, ctx)
                try:
                    c.request("GET", path, headers={"Host": "api.openalex.org", "Connection": "close"})
                    r = c.getresponse()
                    _ = r.read1(1024)
                    if r.status == 302:
                        path = r.getheader("Location")
                        continue
                    break
                finally:
                    c.close()
        self.assertLess(time.monotonic() - t0, 1.15)
        th1.join(timeout=3.0)

        # Case B: Same 2 hops with 1.8s cumulative deadline -> MUST succeed!
        port2, th2 = self._start_tls_server(_redirect_handler, accept_count=2)
        deadline_ok = time.monotonic() + 1.8
        path = "/hop1"
        body = b""
        for _ in range(3):
            c = pds.DeadlinePinnedHTTPSConnection("api.openalex.org", "127.0.0.1", port2, deadline_ok, ctx)
            try:
                c.request("GET", path, headers={"Host": "api.openalex.org", "Connection": "close"})
                r = c.getresponse()
                body = r.read1(1024)
                if r.status == 302:
                    path = r.getheader("Location")
                    continue
                break
            finally:
                c.close()
        self.assertEqual(body, b"DONE")
        th2.join(timeout=3.0)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__))
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if res.wasSuccessful() else 1)
