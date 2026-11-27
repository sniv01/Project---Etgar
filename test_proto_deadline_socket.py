#!/usr/bin/env python3
"""
test_proto_deadline_socket.py — Hardened Standalone Tests for DeadlineSocket Prototype v3
Includes deterministic post-I/O deadline checks (Athena's final reinforcement for Step B):
  - Test 10: Post-I/O deadline expiry after successful `do_handshake()`, `recv_into()`, and `send()`
  - Test 11: Post-I/O deadline expiry at end of response body reading (EOF) in `fetch_https_with_deadline()`
"""

import os
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


def _open_fd_count() -> int:
    if os.path.isdir("/proc/self/fd"):
        return len(os.listdir("/proc/self/fd"))
    return -1


class _ScriptedWantSocket:
    def __init__(
        self,
        real_sock: socket.socket,
        read_faults=None,
        write_faults=None,
        max_write_chunk: int = 4,
        on_read=None,
        on_write=None,
        on_handshake=None,
    ):
        self._real = real_sock
        self._real.setblocking(False)
        self._read_faults = list(read_faults or [])
        self._write_faults = list(write_faults or [])
        self._max_write_chunk = max_write_chunk
        self._on_read = on_read
        self._on_write = on_write
        self._on_handshake = on_handshake
        self.closed = False

    def setblocking(self, flag: bool):
        self._real.setblocking(flag)

    def fileno(self) -> int:
        return self._real.fileno()

    def do_handshake(self):
        if self._on_handshake:
            self._on_handshake()

    def recv_into(self, buf, nbytes=None, flags=0):
        if self._read_faults:
            exc = self._read_faults.pop(0)
            if exc is not None:
                raise exc
        n = self._real.recv_into(buf, nbytes if nbytes is not None else len(buf), flags)
        if self._on_read:
            self._on_read(n)
        return n

    def send(self, data, flags=0):
        if self._write_faults:
            exc = self._write_faults.pop(0)
            if exc is not None:
                raise exc
        mv = memoryview(data)
        sent = self._real.send(mv[: self._max_write_chunk], flags)
        if self._on_write:
            self._on_write(sent)
        return sent

    def close(self):
        self.closed = True
        self._real.close()


class TestDeadlineSocketHardened(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.openssl_bin = shutil.which("openssl")
        cls.td = tempfile.TemporaryDirectory()
        cls.tdp = Path(cls.td.name)
        cls.key_path = cls.tdp / "srv.key"
        cls.crt_path = cls.tdp / "srv.crt"
        cls.bad_key = cls.tdp / "bad.key"
        cls.bad_crt = cls.tdp / "bad.crt"
        if cls.openssl_bin:
            for k, c, san in [
                (cls.key_path, cls.crt_path, "DNS:api.openalex.org"),
                (cls.bad_key, cls.bad_crt, "DNS:wrong.example.org"),
            ]:
                proc = subprocess.run(
                    [
                        cls.openssl_bin, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(k), "-out", str(c),
                        "-days", "1", "-subj", "/CN=test.local",
                        "-addext", f"subjectAltName={san}",
                    ],
                    capture_output=True, text=True,
                )
                assert proc.returncode == 0, proc.stderr

    @classmethod
    def tearDownClass(cls):
        cls.td.cleanup()

    def _start_tls_server(self, handler_fn, accept_count: int = 1, key_path=None, crt_path=None):
        srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        srv_ctx.load_cert_chain(certfile=str(crt_path or self.crt_path), keyfile=str(key_path or self.key_path))
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
            s_srv.sendall(b"HELLO_WORLD_12345X")
            scripted = _ScriptedWantSocket(
                s_cli,
                read_faults=[ssl.SSLWantReadError(), ssl.SSLWantWriteError()],
                write_faults=[ssl.SSLWantWriteError(), ssl.SSLWantReadError()],
                max_write_chunk=3,
            )
            ds = pds.DeadlineSocket(scripted, deadline=time.monotonic() + 2.0)
            try:
                self.assertEqual(ds.recv(17), b"HELLO_WORLD_12345")
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
            ds.close()
            self.assertFalse(scripted.closed)
            self.assertEqual(fp.readline(), b"LINE2\n")
            fp.close()
            self.assertTrue(scripted.closed)
        finally:
            s_srv.close()

        s_cli2, s_srv2 = socket.socketpair()
        try:
            s_srv2.sendall(b"PING")
            scripted2 = _ScriptedWantSocket(s_cli2)
            ds2 = pds.DeadlineSocket(scripted2, deadline=time.monotonic() + 2.0)
            fp2 = ds2.makefile("rb")
            fp2.close()
            self.assertFalse(scripted2.closed)
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
                first = ds.recv(64)
                self.assertEqual(first, b"A" * 64)
                self.assertGreater(ds.pending(), 0)
                t0 = time.monotonic()
                collected = bytearray(first)
                while len(collected) < len(big_blob):
                    collected.extend(ds.recv(1024))
                self.assertEqual(bytes(collected), big_blob)
                self.assertLess(time.monotonic() - t0, 0.35)
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
                with self.assertRaises(pds.DeadlineExceededError):
                    pds.fetch_https_with_deadline(
                        f"https://api.openalex.org:{port}/drip",
                        pinned_ip_resolver=lambda h, p: "127.0.0.1",
                        timeout_sec=0.55,
                        context=ctx,
                    )
                self.assertLess(time.monotonic() - t0, 1.15)
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
        with self.assertRaises(pds.DeadlineExceededError):
            pds.fetch_https_with_deadline(
                f"https://api.openalex.org:{port}/slow-hdr",
                pinned_ip_resolver=lambda h, p: "127.0.0.1",
                timeout_sec=0.50,
                context=ctx,
            )
        self.assertLess(time.monotonic() - t0, 1.10)
        th.join(timeout=3.0)

    def test_06_live_tls_multi_hop_redirect_through_real_fetch_function(self):
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

        port1, th1 = self._start_tls_server(_redirect_handler, accept_count=2)
        ctx = ssl.create_default_context(cafile=str(self.crt_path))
        t0 = time.monotonic()
        with self.assertRaises(pds.DeadlineExceededError):
            pds.fetch_https_with_deadline(
                f"https://api.openalex.org:{port1}/hop1",
                pinned_ip_resolver=lambda h, p: "127.0.0.1",
                timeout_sec=0.55,
                context=ctx,
                max_redirects=3,
            )
        self.assertLess(time.monotonic() - t0, 1.15)
        th1.join(timeout=3.0)

        port2, th2 = self._start_tls_server(_redirect_handler, accept_count=2)
        final_u, status, body = pds.fetch_https_with_deadline(
            f"https://api.openalex.org:{port2}/hop1",
            pinned_ip_resolver=lambda h, p: "127.0.0.1",
            timeout_sec=2.0,
            context=ctx,
            max_redirects=3,
        )
        self.assertEqual(status, 200)
        self.assertTrue(final_u.endswith("/hop2"))
        self.assertEqual(body, b"DONE")
        th2.join(timeout=3.0)

    def test_07_handshake_failures_cert_protocol_and_stalled_leave_zero_fd_leaks(self):
        if not self.openssl_bin:
            self.skipTest("openssl unavailable")

        def _bad_cert_handler(raw_c, srv_ctx):
            try:
                with srv_ctx.wrap_socket(raw_c, server_side=True):
                    pass
            except ssl.SSLError:
                pass

        def _protocol_err_handler(raw_c, _srv_ctx):
            raw_c.recv(1024)
            raw_c.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\nNot TLS!")

        def _silent_handler(raw_c, _srv_ctx):
            time.sleep(1.5)

        fd_before = _open_fd_count()

        p1, th1 = self._start_tls_server(_bad_cert_handler, key_path=self.bad_key, crt_path=self.bad_crt)
        ctx_bad = ssl.create_default_context(cafile=str(self.bad_crt))
        c1 = pds.DeadlinePinnedHTTPSConnection("api.openalex.org", "127.0.0.1", p1, time.monotonic() + 2.0, ctx_bad)
        with self.assertRaises(ssl.SSLCertVerificationError):
            c1.connect()
        c1.close()
        th1.join(timeout=3.0)

        p2, th2 = self._start_tls_server(_protocol_err_handler)
        ctx_ok = ssl.create_default_context(cafile=str(self.crt_path))
        c2 = pds.DeadlinePinnedHTTPSConnection("api.openalex.org", "127.0.0.1", p2, time.monotonic() + 2.0, ctx_ok)
        with self.assertRaises(ssl.SSLError):
            c2.connect()
        c2.close()
        th2.join(timeout=3.0)

        p3, th3 = self._start_tls_server(_silent_handler)
        c3 = pds.DeadlinePinnedHTTPSConnection("api.openalex.org", "127.0.0.1", p3, time.monotonic() + 0.35, ctx_ok)
        with self.assertRaises(pds.DeadlineExceededError):
            c3.connect()
        c3.close()
        th3.join(timeout=3.0)

        fd_after = _open_fd_count()
        if fd_before >= 0:
            self.assertEqual(fd_after, fd_before, f"FD leak detected: before={fd_before}, after={fd_after}")

    def test_08_full_http_response_lifecycle_and_zero_fd_leak(self):
        if not self.openssl_bin:
            self.skipTest("openssl unavailable")

        def _ok_handler(raw_c, srv_ctx):
            with srv_ctx.wrap_socket(raw_c, server_side=True) as tls_c:
                tls_c.recv(2048)
                tls_c.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"X-Etgar-Test: verified\r\n"
                    b"Content-Length: 19\r\n"
                    b"Connection: close\r\n\r\n"
                    b'{"lifecycle":"ok!"}'
                )

        fd_before = _open_fd_count()
        port, th = self._start_tls_server(_ok_handler)
        ctx = ssl.create_default_context(cafile=str(self.crt_path))
        conn = pds.DeadlinePinnedHTTPSConnection("api.openalex.org", "127.0.0.1", port, time.monotonic() + 2.0, ctx)
        resp = None
        ds_ref = None
        try:
            conn.request("GET", "/ok", headers={"Host": "api.openalex.org", "Connection": "close"})
            ds_ref = conn.sock
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.getheader("X-Etgar-Test"), "verified")
            chunks = []
            while True:
                c = resp.read1(8)
                if not c:
                    break
                chunks.append(c)
            self.assertEqual(b"".join(chunks), b'{"lifecycle":"ok!"}')
        finally:
            if resp is not None:
                resp.close()
            conn.close()
        th.join(timeout=3.0)

        self.assertIsNotNone(ds_ref)
        self.assertTrue(ds_ref._real_closed)
        self.assertEqual(ds_ref._io_refs, 0)
        fd_after = _open_fd_count()
        if fd_before >= 0:
            self.assertEqual(fd_after, fd_before)

    def test_09_caller_ssl_context_is_never_mutated(self):
        insecure_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        insecure_ctx.check_hostname = False
        insecure_ctx.verify_mode = ssl.CERT_NONE

        with self.assertRaises(ValueError):
            pds.DeadlinePinnedHTTPSConnection("api.openalex.org", "127.0.0.1", 443, time.monotonic() + 2.0, insecure_ctx)

        self.assertFalse(insecure_ctx.check_hostname)
        self.assertEqual(insecure_ctx.verify_mode, ssl.CERT_NONE)

    def test_10_post_io_deadline_checked_after_successful_handshake_recv_and_send(self):
        """Athena reinforcement: an I/O call that completes AFTER deadline expiry MUST NOT report success."""
        # A. do_handshake succeeds, but clock crossed deadline during handshake
        s1, s1_peer = socket.socketpair()
        try:
            clk = {"t": 100.0}
            scripted = _ScriptedWantSocket(s1, on_handshake=lambda: clk.__setitem__("t", 105.0))
            ds = pds.DeadlineSocket(scripted, deadline=102.0, clock_fn=lambda: clk["t"])
            with self.assertRaises(pds.DeadlineExceededError):
                ds.do_handshake()
            self.assertTrue(scripted.closed)
        finally:
            s1_peer.close()

        # B. recv_into succeeds with valid data, but clock crossed deadline during recv_into
        s2, s2_peer = socket.socketpair()
        try:
            s2_peer.sendall(b"LATE_DATA")
            clk2 = {"t": 100.0}
            scripted2 = _ScriptedWantSocket(s2, on_read=lambda n: clk2.__setitem__("t", 105.0))
            ds2 = pds.DeadlineSocket(scripted2, deadline=102.0, clock_fn=lambda: clk2["t"])
            with self.assertRaises(pds.DeadlineExceededError):
                ds2.recv(9)
            self.assertTrue(scripted2.closed)
        finally:
            s2_peer.close()

        # C. send succeeds, but clock crossed deadline during send
        s3, s3_peer = socket.socketpair()
        try:
            clk3 = {"t": 100.0}
            scripted3 = _ScriptedWantSocket(s3, on_write=lambda n: clk3.__setitem__("t", 105.0))
            ds3 = pds.DeadlineSocket(scripted3, deadline=102.0, clock_fn=lambda: clk3["t"])
            with self.assertRaises(pds.DeadlineExceededError):
                ds3.send(b"OK")
            self.assertTrue(scripted3.closed)
        finally:
            s3_peer.close()

    def test_11_post_body_completion_eof_after_deadline_raises_never_returns_success(self):
        """Athena reinforcement: completing response body read (EOF) past deadline MUST raise DeadlineExceededError."""
        if not self.openssl_bin:
            self.skipTest("openssl unavailable")

        def _fast_body_handler(raw_c, srv_ctx):
            with srv_ctx.wrap_socket(raw_c, server_side=True) as tls_c:
                tls_c.recv(2048)
                # Send complete headers + full body in a single write (so HTTPResponse buffers it in one read),
                # then close connection cleanly.
                tls_c.sendall(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 10\r\n"
                    b"Connection: close\r\n\r\n"
                    b"0123456789"
                )

        # Deterministic clock: stays well within deadline until the very last EOF check after body read,
        # simulating the case where the final chunk/EOF arrives right after the deadline expired!
        fd_before = _open_fd_count()
        port, th = self._start_tls_server(_fast_body_handler)
        ctx = ssl.create_default_context(cafile=str(self.crt_path))

        # Advance synthetic clock right when resp.read1 returns b"" (EOF)
        base_clock = {"t": 1000.0}
        orig_read1 = pds.http.client.HTTPResponse.read1

        def _expiring_on_eof_read1(self_resp, n=-1):
            data = orig_read1(self_resp, n)
            if data == b"":
                # Body reached EOF — advance clock PAST deadline (1002.0) right as EOF completes!
                base_clock["t"] = 1005.0
            return data
        pds.http.client.HTTPResponse.read1 = _expiring_on_eof_read1
        try:
            with self.assertRaises(pds.DeadlineExceededError):
                pds.fetch_https_with_deadline(
                    f"https://api.openalex.org:{port}/eof-late",
                    pinned_ip_resolver=lambda h, p: "127.0.0.1",
                    timeout_sec=2.0,
                    context=ctx,
                    clock_fn=lambda: base_clock["t"],
                )
        finally:
            pds.http.client.HTTPResponse.read1 = orig_read1
            th.join(timeout=3.0)

        fd_after = _open_fd_count()
        if fd_before >= 0:
            self.assertEqual(fd_after, fd_before, f"FD leak on post-EOF deadline expiry: before={fd_before}, after={fd_after}")


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__))
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if res.wasSuccessful() else 1)
