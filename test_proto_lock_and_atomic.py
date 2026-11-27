#!/usr/bin/env python3
"""
test_proto_lock_and_atomic.py — Synchronized Subprocess & Adversarial Tests v2 (V36.0.3 Step C Final)

Adds Athena's required tests for Step C:
  - test_L06: Windows `_try_kernel_lock()` error discrimination (contention vs real OS errors)
  - test_L07: `_write_metadata_locked()` partial-write loop (3 bytes/call) + 0-byte short-write guard
  - test_W05: Exercises Windows `os.rename` fallback INSIDE `atomic_write_bytes()` itself for
              BOTH `winerror=1` and `winerror=50` (success, race FileExistsError, and NO fallback
              on `winerror=5` / generic OSError)
  - test_W06: Real Windows NTFS test exercising `atomic_write_bytes()` fallback with `winerror=1` & `50`
"""

import errno
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

import proto_lock_and_atomic as pla


def _make_win_oserror(winerror: int, err_no: int = 0, msg: str = "winerr") -> OSError:
    exc = OSError(err_no, msg)
    exc.winerror = winerror
    return exc


def _run_synchronized_subprocesses(worker_script: str, n_procs: int, extra_args_list):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    barrier_port = srv.getsockname()[1]
    srv.listen(n_procs + 2)
    srv.settimeout(10.0)

    ready_conns = []
    barrier_err = []

    def _barrier_coordinator():
        try:
            while len(ready_conns) < n_procs:
                conn, _ = srv.accept()
                ready_conns.append(conn)
            for c in ready_conns:
                c.sendall(b"G")
        except Exception as exc:
            barrier_err.append(exc)
        finally:
            for c in ready_conns:
                try:
                    c.close()
                except OSError:
                    pass
            srv.close()

    coord = threading.Thread(target=_barrier_coordinator, daemon=True)
    coord.start()

    cwd = str(Path(__file__).resolve().parent)
    procs = []
    for i in range(n_procs):
        cmd = [sys.executable, "-c", worker_script, str(barrier_port), str(i)] + list(extra_args_list[i])
        procs.append(subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))

    outputs = []
    for p in procs:
        out, err = p.communicate(timeout=15)
        outputs.append((p.returncode, out.strip(), err.strip()))
    coord.join(timeout=5)
    if barrier_err:
        raise RuntimeError(f"Barrier coordinator failed: {barrier_err[0]}")
    return outputs


LOCK_RACE_WORKER = (
    "import json, socket, sys, time\n"
    "from pathlib import Path\n"
    "import proto_lock_and_atomic as pla\n"
    "port = int(sys.argv[1]); idx = int(sys.argv[2])\n"
    "lock_path = Path(sys.argv[3]); hold_sec = float(sys.argv[4])\n"
    "s = socket.create_connection(('127.0.0.1', port), timeout=10)\n"
    "assert s.recv(1) == b'G'\n"
    "s.close()\n"
    "lk = pla.CrashSafeLock(lock_path, f'SUBPROC-{idx}')\n"
    "try:\n"
    "    rec = lk.acquire()\n"
    "    time.sleep(hold_sec)\n"
    "    ino = lock_path.stat().st_ino\n"
    "    lk.release()\n"
    "    print(json.dumps({'status': 'ACQUIRED', 'idx': idx, 'recovered': rec is not None, 'ino': ino}))\n"
    "except pla.LockConflictError as exc:\n"
    "    print(json.dumps({'status': 'BLOCKED', 'idx': idx, 'msg': str(exc)}))\n"
)

ATOMIC_RACE_WORKER = (
    "import json, socket, sys\n"
    "from pathlib import Path\n"
    "import proto_lock_and_atomic as pla\n"
    "port = int(sys.argv[1]); idx = int(sys.argv[2])\n"
    "target_path = Path(sys.argv[3])\n"
    "payload = f'WINNER_PAYLOAD_FROM_PROC_{idx}_' + ('X' * 4096)\n"
    "s = socket.create_connection(('127.0.0.1', port), timeout=10)\n"
    "assert s.recv(1) == b'G'\n"
    "s.close()\n"
    "try:\n"
    "    pla.atomic_write_bytes(target_path, payload.encode('utf-8'), overwrite=False)\n"
    "    print(json.dumps({'status': 'WROTE', 'idx': idx, 'len': len(payload)}))\n"
    "except FileExistsError:\n"
    "    print(json.dumps({'status': 'EXISTS', 'idx': idx}))\n"
)


class TestCrashSafeLockSubprocessAndFork(unittest.TestCase):
    def test_L01_synchronized_subprocesses_stale_lock_exactly_one_wins_and_inode_persists(self):
        with tempfile.TemporaryDirectory() as td:
            lp = Path(td) / "etgar_scout.lock"
            stale_body = b" " + json.dumps({"state": "ACTIVE", "pid": 999999, "run_id": "CRASHED-99"}).encode("utf-8")
            lp.write_bytes(stale_body)
            orig_ino = lp.stat().st_ino

            outputs = _run_synchronized_subprocesses(
                LOCK_RACE_WORKER,
                n_procs=2,
                extra_args_list=[[str(lp), "0.35"], [str(lp), "0.35"]],
            )
            parsed = [json.loads(out) for rc, out, err in outputs if rc == 0]
            self.assertEqual(len(parsed), 2, f"Subprocess failed: {outputs}")

            acquired = [r for r in parsed if r["status"] == "ACQUIRED"]
            blocked = [r for r in parsed if r["status"] == "BLOCKED"]
            self.assertEqual(len(acquired), 1)
            self.assertEqual(len(blocked), 1)
            self.assertTrue(acquired[0]["recovered"])
            self.assertTrue(lp.exists())
            self.assertEqual(lp.stat().st_ino, orig_ino)
            self.assertEqual(acquired[0]["ino"], orig_ino)

    def test_L02_synchronized_subprocesses_clean_lock_no_zero_byte_race(self):
        with tempfile.TemporaryDirectory() as td:
            lp = Path(td) / "clean.lock"
            outputs = _run_synchronized_subprocesses(
                LOCK_RACE_WORKER,
                n_procs=3,
                extra_args_list=[[str(lp), "0.35"], [str(lp), "0.35"], [str(lp), "0.35"]],
            )
            parsed = [json.loads(out) for rc, out, err in outputs if rc == 0]
            self.assertEqual(len(parsed), 3, f"Subprocess failed: {outputs}")
            acquired = [r for r in parsed if r["status"] == "ACQUIRED"]
            blocked = [r for r in parsed if r["status"] == "BLOCKED"]
            self.assertEqual(len(acquired), 1)
            self.assertEqual(len(blocked), 2)
            self.assertFalse(acquired[0]["recovered"])
            self.assertTrue(lp.exists())

    def test_L03_real_sigkill_holder_recovered_with_same_inode(self):
        with tempfile.TemporaryDirectory() as td:
            lp = Path(td) / "sigkill.lock"
            holder_code = (
                "import sys, time\n"
                "from pathlib import Path\n"
                "import proto_lock_and_atomic as pla\n"
                "lk = pla.CrashSafeLock(Path(sys.argv[1]), 'VICTIM-RUN')\n"
                "lk.acquire()\n"
                "print('LOCKED', flush=True)\n"
                "time.sleep(30)\n"
            )
            cwd = str(Path(__file__).resolve().parent)
            proc = subprocess.Popen(
                [sys.executable, "-c", holder_code, str(lp)],
                cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                self.assertEqual(proc.stdout.readline().strip(), "LOCKED")
                orig_ino = lp.stat().st_ino

                with self.assertRaises(pla.LockConflictError):
                    pla.CrashSafeLock(lp, "PROBE-WHILE-ALIVE").acquire()

                proc.kill()
                proc.wait(timeout=5)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)

            rec_lock = pla.CrashSafeLock(lp, "RECOVER-RUN")
            ev = rec_lock.acquire()
            try:
                self.assertIsNotNone(ev)
                self.assertEqual(ev["event"], "STALE_LOCK_RECOVERED")
                self.assertEqual(ev["previous_lock"]["run_id"], "VICTIM-RUN")
                self.assertEqual(lp.stat().st_ino, orig_ino)
            finally:
                rec_lock.release()
            self.assertTrue(lp.exists())
            self.assertEqual(lp.stat().st_ino, orig_ino)

    def test_L04_corrupt_metadata_never_suppresses_lock_conflict(self):
        with tempfile.TemporaryDirectory() as td:
            lp = Path(td) / "corrupt_meta.lock"
            holder_code = (
                "import os, sys, time\n"
                "from pathlib import Path\n"
                "import proto_lock_and_atomic as pla\n"
                "lp = Path(sys.argv[1])\n"
                "lk = pla.CrashSafeLock(lp, 'CORRUPT-META-HOLDER')\n"
                "lk.acquire()\n"
                "os.lseek(lk._fd, 1, os.SEEK_SET)\n"
                "os.write(lk._fd, b'{PARTIAL_CORRUPT_JSON')\n"
                "os.ftruncate(lk._fd, 22)\n"
                "print('CORRUPTED_AND_LOCKED', flush=True)\n"
                "time.sleep(10)\n"
            )
            cwd = str(Path(__file__).resolve().parent)
            proc = subprocess.Popen(
                [sys.executable, "-c", holder_code, str(lp)],
                cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                self.assertEqual(proc.stdout.readline().strip(), "CORRUPTED_AND_LOCKED")
                with self.assertRaises(pla.LockConflictError):
                    pla.CrashSafeLock(lp, "CONTENDER").acquire()
            finally:
                proc.kill()
                proc.wait(timeout=5)

    @unittest.skipIf(os.name == "nt" or not hasattr(os, "fork"), "POSIX os.fork() test")
    def test_L05_posix_fork_child_isolation_and_single_hook_registration(self):
        with tempfile.TemporaryDirectory() as td:
            lp = Path(td) / "fork.lock"

            for i in range(5):
                lk_tmp = pla.CrashSafeLock(lp, f"CYCLE-{i}")
                lk_tmp.acquire()
                lk_tmp.release()
            self.assertEqual(pla._FORK_HOOK_REG_COUNT, 1)

            parent_lock = pla.CrashSafeLock(lp, "PARENT-A")
            parent_lock.acquire()
            r_pipe, w_pipe = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(r_pipe)
                try:
                    ok_cleared = (not parent_lock._acquired) and (parent_lock._fd is None)
                    parent_lock.release()
                    os.write(w_pipe, b"OK" if ok_cleared else b"FAIL")
                finally:
                    os.close(w_pipe)
                    os._exit(0)
            else:
                os.close(w_pipe)
                child_msg = os.read(r_pipe, 16)
                os.close(r_pipe)
                os.waitpid(pid, 0)
                self.assertEqual(child_msg, b"OK")

                probe_script = (
                    "import sys\nfrom pathlib import Path\nimport proto_lock_and_atomic as pla\n"
                    "try:\n    pla.CrashSafeLock(Path(sys.argv[1]), 'THIRD').acquire()\n    print('ACQUIRED')\n"
                    "except pla.LockConflictError:\n    print('BLOCKED')\n"
                )
                cwd = str(Path(__file__).resolve().parent)
                res = subprocess.run([sys.executable, "-c", probe_script, str(lp)], cwd=cwd, capture_output=True, text=True)
                self.assertEqual(res.stdout.strip(), "BLOCKED")
                parent_lock.release()

            lp_b = Path(td) / "fork_hostage.lock"
            hostage_script = (
                "import os, sys, time\nfrom pathlib import Path\nimport proto_lock_and_atomic as pla\n"
                "lp = Path(sys.argv[1])\n"
                "lk = pla.CrashSafeLock(lp, 'FORK-PARENT')\n"
                "lk.acquire()\n"
                "cpid = os.fork()\n"
                "if cpid == 0:\n"
                "    time.sleep(1.5)\n"
                "    os._exit(0)\n"
                "print(str(cpid), flush=True)\n"
                "os._exit(0)\n"
            )
            cwd = str(Path(__file__).resolve().parent)
            p_host = subprocess.run([sys.executable, "-c", hostage_script, str(lp_b)], cwd=cwd, capture_output=True, text=True)
            self.assertEqual(p_host.returncode, 0, p_host.stderr)
            grandchild_pid = int(p_host.stdout.strip())
            t0 = time.monotonic()
            lk_after = pla.CrashSafeLock(lp_b, "AFTER-PARENT-EXIT")
            ev = lk_after.acquire()
            try:
                self.assertIsNotNone(ev)
                self.assertEqual(ev["event"], "STALE_LOCK_RECOVERED")
                self.assertLess(time.monotonic() - t0, 0.4)
            finally:
                lk_after.release()
                try:
                    os.kill(grandchild_pid, 9)
                except OSError:
                    pass

    def test_L06_windows_lock_error_discrimination_contention_vs_system_errors(self):
        """Athena Fix #1: Windows _try_kernel_lock returns False ONLY for lock contention, and propagates real OS errors."""
        with tempfile.TemporaryDirectory() as td:
            lp = Path(td) / "win_err.lock"
            lp.write_bytes(b" {}")
            lk = pla.CrashSafeLock(lp, "WIN-ERR-TEST")

            fake_msvcrt = types.SimpleNamespace(LK_NBLCK=2, LK_UNLCK=0, locking=None)

            contention_cases = [
                PermissionError(errno.EACCES, "Permission denied"),
                OSError(getattr(errno, "EDEADLOCK", 36), "Resource deadlock avoided"),
                _make_win_oserror(33, errno.EACCES, "ERROR_LOCK_VIOLATION"),
                _make_win_oserror(32, errno.EACCES, "ERROR_SHARING_VIOLATION"),
            ]
            for exc in contention_cases:
                with self.subTest(contention=repr(exc)):
                    fake_msvcrt.locking = mock.Mock(side_effect=exc)
                    with mock.patch.object(pla, "msvcrt", fake_msvcrt), mock.patch.object(pla, "_is_windows", return_value=True):
                        with self.assertRaises(pla.LockConflictError):
                            lk.acquire()

            system_error_cases = [
                OSError(errno.EBADF, "Bad file descriptor"),
                OSError(errno.EIO, "Input/output error"),
                OSError(errno.ENOSPC, "No space left on device"),
                OSError(errno.EINVAL, "Invalid argument"),
                _make_win_oserror(5, errno.EACCES, "ERROR_ACCESS_DENIED (ACL, not lock contention)"),
            ]
            for exc in system_error_cases:
                with self.subTest(system_error=repr(exc)):
                    fake_msvcrt.locking = mock.Mock(side_effect=exc)
                    with mock.patch.object(pla, "msvcrt", fake_msvcrt), mock.patch.object(pla, "_is_windows", return_value=True):
                        with self.assertRaises(OSError) as ctx:
                            lk.acquire()
                        self.assertNotIsInstance(ctx.exception, pla.LockConflictError)

    def test_L07_write_metadata_locked_uses_write_all_loop_for_partial_writes(self):
        """Athena Fix #2: _write_metadata_locked handles partial os.write calls cleanly and rejects 0-byte writes."""
        with tempfile.TemporaryDirectory() as td:
            lp = Path(td) / "partial_meta.lock"
            fd = os.open(str(lp), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                real_write = os.write
                write_calls = [0]

                def partial_write(fdesc, buf):
                    if fdesc == fd:
                        write_calls[0] += 1
                        return real_write(fdesc, bytes(buf)[:3])
                    return real_write(fdesc, buf)

                record = {"state": "ACTIVE", "pid": 12345, "run_id": "PARTIAL-WRITE-CHECK"}
                with mock.patch("os.write", side_effect=partial_write):
                    pla._write_metadata_locked(fd, record)

                self.assertGreater(write_calls[0], 10, "Expected multiple partial os.write calls")
                parsed, non_empty = pla._read_metadata_best_effort(fd)
                self.assertTrue(non_empty)
                self.assertEqual(parsed, record)

                with mock.patch("os.write", return_value=0):
                    with self.assertRaises(OSError):
                        pla._write_metadata_locked(fd, record)
            finally:
                os.close(fd)


class TestAtomicWriteAndOrphanCleanup(unittest.TestCase):
    def test_W01_four_synchronized_subprocesses_race_overwrite_false(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "daily_briefing.json"
            outputs = _run_synchronized_subprocesses(
                ATOMIC_RACE_WORKER,
                n_procs=4,
                extra_args_list=[[str(target)] for _ in range(4)],
            )
            parsed = [json.loads(out) for rc, out, err in outputs if rc == 0]
            self.assertEqual(len(parsed), 4, f"Subprocess failed: {outputs}")

            winners = [r for r in parsed if r["status"] == "WROTE"]
            losers = [r for r in parsed if r["status"] == "EXISTS"]
            self.assertEqual(len(winners), 1)
            self.assertEqual(len(losers), 3)

            win_idx = winners[0]["idx"]
            expected = f"WINNER_PAYLOAD_FROM_PROC_{win_idx}_" + ("X" * 4096)
            self.assertEqual(target.read_text(encoding="utf-8"), expected)

            leftover = [p.name for p in Path(td).iterdir() if ".tmp." in p.name]
            self.assertEqual(leftover, [])

    def test_W02_fail_closed_on_unsupported_hardlinks_and_no_fallback_on_permission_error(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "out.json"

            if os.name != "nt":
                with mock.patch("os.link", side_effect=OSError(errno.EOPNOTSUPP, "hard links unsupported")):
                    with self.assertRaises(pla.AtomicPublishUnsupportedError):
                        pla.atomic_write_bytes(target, b"DATA", overwrite=False)
                self.assertFalse(target.exists())
                self.assertEqual(list(Path(td).iterdir()), [])

            perm_err = PermissionError(errno.EACCES, "Access denied")
            with mock.patch("os.link", side_effect=perm_err), mock.patch("os.rename") as mock_rename:
                with self.assertRaises(PermissionError):
                    pla.atomic_write_bytes(target, b"DATA", overwrite=False)
                mock_rename.assert_not_called()
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(td).iterdir()), [])

    def test_W03_publish_success_separated_from_temp_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "published.json"
            warnings = []
            with mock.patch("os.unlink", side_effect=PermissionError("transient AV lock on tmp")):
                res_path = pla.atomic_write_bytes(
                    target, b"DURABLE_CONTENT", overwrite=False, on_cleanup_warning=warnings.append
                )
            self.assertEqual(res_path, target)
            self.assertEqual(target.read_bytes(), b"DURABLE_CONTENT")
            self.assertEqual(len(warnings), 1)
            self.assertIn("NON_FATAL_TEMP_CLEANUP_WARNING", warnings[0])

    def test_W04_cleanup_orphan_temps_requires_active_lock(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            lp = tdp / "etgar_scout.lock"
            orphan = tdp / ".brief.json.tmp.99999.0123456789abcdef"
            real_file = tdp / "brief.json"
            orphan.write_bytes(b"leftover")
            real_file.write_bytes(b"real")

            lk = pla.CrashSafeLock(lp, "CLEANUP-RUN")
            with self.assertRaises(pla.LockRequiredError):
                pla.cleanup_orphan_temps(tdp, lk)
            self.assertTrue(orphan.exists())

            with lk:
                cleaned = pla.cleanup_orphan_temps(tdp, lk)
            self.assertEqual(cleaned, [orphan.name])
            self.assertFalse(orphan.exists())
            self.assertTrue(real_file.exists())
            self.assertTrue(lp.exists())

    def test_W05_windows_fallback_inside_atomic_write_bytes_for_winerror_1_and_50(self):
        """Athena Fix #3: exercises Windows fallback INSIDE atomic_write_bytes() itself for winerror 1 & 50."""
        real_rename = os.rename

        def win_semantics_rename(src: str, dst: str) -> None:
            if os.path.exists(dst):
                raise FileExistsError(errno.EEXIST, "File exists (Windows os.rename)", dst)
            real_rename(src, dst)

        for winerr_code in (1, 50):
            with self.subTest(winerror=winerr_code):
                with tempfile.TemporaryDirectory() as td:
                    tdp = Path(td)
                    target = tdp / f"win_fb_{winerr_code}.json"

                    link_err = _make_win_oserror(winerr_code, errno.EINVAL, f"hardlink unsupported winerror={winerr_code}")
                    with (
                        mock.patch.object(pla, "_is_windows", return_value=True),
                        mock.patch("os.link", side_effect=link_err) as m_link,
                        mock.patch("os.rename", side_effect=win_semantics_rename) as m_rename,
                    ):
                        res = pla.atomic_write_bytes(target, f"WIN_DATA_{winerr_code}".encode("utf-8"), overwrite=False)
                    self.assertEqual(res, target)
                    self.assertEqual(target.read_bytes(), f"WIN_DATA_{winerr_code}".encode("utf-8"))
                    m_link.assert_called_once()
                    m_rename.assert_called_once()
                    self.assertEqual([p.name for p in tdp.iterdir() if ".tmp." in p.name], [])

                    orig_exists = Path.exists
                    injected = {"done": False}

                    def race_exists(self_path: Path) -> bool:
                        if self_path == target and not injected["done"]:
                            injected["done"] = True
                            return False
                        return orig_exists(self_path)

                    with (
                        mock.patch.object(pla, "_is_windows", return_value=True),
                        mock.patch.object(Path, "exists", race_exists),
                        mock.patch("os.link", side_effect=link_err),
                        mock.patch("os.rename", side_effect=win_semantics_rename) as m_rename2,
                    ):
                        with self.assertRaises(FileExistsError):
                            pla.atomic_write_bytes(target, b"MUST_NOT_OVERWRITE", overwrite=False)
                    m_rename2.assert_called_once()
                    self.assertEqual(target.read_bytes(), f"WIN_DATA_{winerr_code}".encode("utf-8"))
                    self.assertEqual([p.name for p in tdp.iterdir() if ".tmp." in p.name], [])

        for blocked_winerr in (5, 2, 183):
            with self.subTest(blocked_winerror=blocked_winerr):
                with tempfile.TemporaryDirectory() as td:
                    tdp = Path(td)
                    target = tdp / f"no_fb_{blocked_winerr}.json"
                    err_obj = _make_win_oserror(blocked_winerr, errno.EACCES, f"winerror={blocked_winerr}")
                    with (
                        mock.patch.object(pla, "_is_windows", return_value=True),
                        mock.patch("os.link", side_effect=err_obj),
                        mock.patch("os.rename") as m_rename_blocked,
                    ):
                        with self.assertRaises(OSError) as ctx:
                            pla.atomic_write_bytes(target, b"DATA", overwrite=False)
                    self.assertEqual(getattr(ctx.exception, "winerror", None), blocked_winerr)
                    m_rename_blocked.assert_not_called()
                    self.assertFalse(target.exists())
                    self.assertEqual(list(tdp.iterdir()), [])

    @unittest.skipUnless(os.name == "nt", "Real Windows OS os.rename fallback verification")
    def test_W06_real_windows_atomic_write_bytes_fallback_winerror_1_and_50(self):
        """Runs on real Windows: exercises atomic_write_bytes() -> real os.rename() with winerror 1 & 50."""
        for winerr_code in (1, 50):
            with self.subTest(real_win_winerror=winerr_code):
                with tempfile.TemporaryDirectory() as td:
                    tdp = Path(td)
                    target = tdp / f"real_win_{winerr_code}.json"
                    link_err = _make_win_oserror(winerr_code, errno.EINVAL, f"simulated winerror={winerr_code}")

                    with mock.patch("os.link", side_effect=link_err):
                        pla.atomic_write_bytes(target, b"ORIGINAL_WIN", overwrite=False)
                    self.assertEqual(target.read_bytes(), b"ORIGINAL_WIN")

                    orig_exists = Path.exists
                    injected = {"done": False}

                    def race_exists(self_path: Path) -> bool:
                        if self_path == target and not injected["done"]:
                            injected["done"] = True
                            return False
                        return orig_exists(self_path)

                    with mock.patch.object(Path, "exists", race_exists), mock.patch("os.link", side_effect=link_err):
                        with self.assertRaises(FileExistsError):
                            pla.atomic_write_bytes(target, b"OVERWRITE_ATTEMPT", overwrite=False)
                    self.assertEqual(target.read_bytes(), b"ORIGINAL_WIN")
                    self.assertEqual([p.name for p in tdp.iterdir() if ".tmp." in p.name], [])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__))
    res = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if res.wasSuccessful() else 1)
