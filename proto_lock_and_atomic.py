#!/usr/bin/env python3
"""
proto_lock_and_atomic.py — Standalone Prototype v2 for Athena Review (V36.0.3 Step C Final)
100% Python 3 Standard Library. Completely independent of `etgar_scout.py` (`main` untouched).

Hardening added per Athena's review of Step C:
  1. Windows `_try_kernel_lock()` distinguishes genuine lock contention errors
     (`winerror in (32, 33)` or `errno in (EACCES, EDEADLOCK, EDEADLK, EAGAIN)` when `winerror is None`)
     from real OS/system errors (`EBADF`, `EIO`, `ENOSPC`, `EINVAL`, `winerror=5` ACL denied, etc.),
     propagating real OS errors upward instead of returning `False`.
  2. `_write_metadata_locked()` uses a complete `_write_all(fd, data)` loop handling partial writes
     (raising `OSError` on 0-byte short writes), shared with `atomic_write_bytes()`.
  3. `atomic_write_bytes(..., overwrite=False)` Windows fallback (`os.rename`) is restricted strictly
     to `os.name == "nt"` and `winerror in (1, 50)` (`ERROR_INVALID_FUNCTION`, `ERROR_NOT_SUPPORTED`).
"""

from __future__ import annotations

import datetime
import errno
import json
import os
import re
import secrets
import weakref
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

if os.name == "nt":
    import msvcrt
else:
    msvcrt = None  # type: ignore[assignment]
    import fcntl

def _is_windows() -> bool:
    return os.name == "nt"


SCRIPT_VERSION = "36.0.3-proto"
ORPHAN_TEMP_PATTERN = re.compile(r"^\..+\.tmp\.\d+\.[0-9a-f]{16}$")
WINDOWS_HARDLINK_UNSUPPORTED_WINERRORS = (1, 50)  # ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED
WINDOWS_LOCK_CONTENTION_WINERRORS = (32, 33)  # ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
WINDOWS_LOCK_CONTENTION_ERRNOS = tuple(
    e
    for e in (
        getattr(errno, "EACCES", 13),
        getattr(errno, "EDEADLOCK", 36),
        getattr(errno, "EDEADLK", 35),
        getattr(errno, "EAGAIN", 11),
    )
    if e is not None
)
POSIX_HARDLINK_UNSUPPORTED_ERRNOS = (
    errno.EOPNOTSUPP,
    errno.EXDEV,
    errno.EMLINK,
    getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
)


class LockConflictError(Exception):
    """Raised when another active process holds the kernel lock."""


class LockRequiredError(Exception):
    """Raised when an operation requiring an active CrashSafeLock is called without one."""


class AtomicPublishUnsupportedError(OSError):
    """Raised (fail-closed) when atomic non-overwriting publish cannot be guaranteed."""


# ==============================================================================
# CENTRALIZED SINGLE FORK HOOK REGISTRY (POSIX ONLY)
# ==============================================================================

_ACTIVE_LOCKS: "weakref.WeakSet[CrashSafeLock]" = weakref.WeakSet()
_FORK_HOOK_REGISTERED: bool = False
_FORK_HOOK_REG_COUNT: int = 0


def _on_fork_child() -> None:
    """
    Runs in child process immediately after os.fork() on POSIX.
    Inspects each live CrashSafeLock dynamically (no captured static FD numbers),
    clears object state FIRST to prevent double/reused-FD closure, and closes the
    inherited FD via os.close() ONLY (never LOCK_UN, never writing to the lock file).
    """
    for lock in list(_ACTIVE_LOCKS):
        fd = lock._fd
        lock._fd = None
        lock._acquired = False
        lock._owner_pid = None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _ensure_fork_hook_registered() -> None:
    global _FORK_HOOK_REGISTERED, _FORK_HOOK_REG_COUNT
    if not _is_windows() and not _FORK_HOOK_REGISTERED and hasattr(os, "register_at_fork"):
        os.register_at_fork(after_in_child=_on_fork_child)
        _FORK_HOOK_REGISTERED = True
        _FORK_HOOK_REG_COUNT += 1


# ==============================================================================
# LOW-LEVEL WRITE-ALL & WINDOWS CONTENTION HELPERS
# ==============================================================================

def _write_all(fd: int, data: bytes) -> None:
    """Writes all bytes to `fd`, looping over partial writes and raising on 0-byte short writes."""
    mv = memoryview(data)
    written = 0
    total = len(mv)
    while written < total:
        n = os.write(fd, mv[written:])
        if n <= 0:
            raise OSError("Short write (0 bytes) while writing file descriptor.")
        written += n


def _is_windows_lock_contention(exc: OSError) -> bool:
    """
    Distinguishes Windows `msvcrt.locking(..., LK_NBLCK, 1)` lock contention from real OS errors.
      - When `winerror` is present: ONLY `32` (SHARING_VIOLATION) and `33` (LOCK_VIOLATION)
        indicate lock contention; e.g., `winerror=5` (ACCESS_DENIED) propagates as a real error.
      - When `winerror` is None (standard MSVC CRT `_locking` via `PyErr_SetFromErrno`):
        ONLY `EACCES` (13), `EDEADLOCK` (36), `EDEADLK`, or `EAGAIN` indicate contention;
        `EBADF`, `EINVAL`, `EIO`, `ENOSPC`, etc. propagate upward.
    """
    winerr = getattr(exc, "winerror", None)
    if winerr is not None:
        return winerr in WINDOWS_LOCK_CONTENTION_WINERRORS
    return exc.errno in WINDOWS_LOCK_CONTENTION_ERRNOS


# ==============================================================================
# 1. KERNEL-LOCKED CrashSafeLock (NEVER UNLINKED)
# ==============================================================================

def _read_metadata_best_effort(fd: int) -> Tuple[Optional[Dict[str, Any]], bool]:
    """
    Reads JSON metadata starting at byte offset 1 (skipping sentinel byte 0).
    Returns (parsed_dict_or_None, was_non_empty).
    NEVER raises on partial/corrupt/unreadable content (best-effort diagnostics).
    """
    try:
        st_size = os.fstat(fd).st_size
        if st_size <= 1:
            return None, False
        os.lseek(fd, 1, os.SEEK_SET)
        chunks: List[bytes] = []
        total = 0
        while total < 65536:
            b = os.read(fd, 4096)
            if not b:
                break
            chunks.append(b)
            total += len(b)
        raw = b"".join(chunks).strip()
        if not raw:
            return None, False
        parsed = json.loads(raw.decode("utf-8", errors="strict"))
        if isinstance(parsed, dict):
            return parsed, True
        return {"corrupt": True, "type": type(parsed).__name__}, True
    except Exception:
        return {"corrupt": True}, True


def _write_metadata_locked(fd: int, record: Dict[str, Any]) -> None:
    """
    Writes sentinel byte 0 (b' ') + UTF-8 JSON metadata starting at offset 1 using a
    full write-all loop (`_write_all`), truncates trailing bytes, and fsyncs while held.
    """
    body = json.dumps(record, ensure_ascii=False).encode("utf-8")
    if _is_windows():
        # Ensure sentinel byte 0 exists if file is empty (this handle holds byte-0 lock)
        if os.fstat(fd).st_size == 0:
            os.lseek(fd, 0, os.SEEK_SET)
            _write_all(fd, b" " + body)
            os.ftruncate(fd, 1 + len(body))
        else:
            os.lseek(fd, 1, os.SEEK_SET)
            _write_all(fd, body)
            os.ftruncate(fd, 1 + len(body))
    else:
        payload = b" " + body
        os.lseek(fd, 0, os.SEEK_SET)
        _write_all(fd, payload)
        os.ftruncate(fd, len(payload))
    os.fsync(fd)


class CrashSafeLock:
    """
    Kernel-enforced persistent lock file (NEVER unlinked).
      - POSIX: fcntl.flock(fd, LOCK_EX | LOCK_NB) + centralized single os.register_at_fork hook.
      - Windows: msvcrt.locking(fd, LK_NBLCK, 1) on byte 0; metadata at offset 1 is best-effort only.
    """

    def __init__(self, lock_path: Path, run_id: str):
        self.lock_path = Path(lock_path)
        self.run_id = run_id
        self._fd: Optional[int] = None
        self._acquired: bool = False
        self._owner_pid: Optional[int] = None
        self.recovered_event: Optional[Dict[str, Any]] = None
        _ensure_fork_hook_registered()
        _ACTIVE_LOCKS.add(self)

    def is_acquired_by_current_process(self) -> bool:
        return self._acquired and self._fd is not None and self._owner_pid == os.getpid()

    def _try_kernel_lock(self, fd: int) -> bool:
        if _is_windows():
            # Windows byte-range locks work on byte 0 even on a 0-byte file;
            # never perform an unprotected pre-lock write or swallow non-contention OS errors!
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                return True
            except OSError as exc:
                if _is_windows_lock_contention(exc):
                    return False
                raise
        else:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except (BlockingIOError, OSError) as exc:
                if isinstance(exc, BlockingIOError) or exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EACCES):
                    return False
                raise

    def _kernel_unlock(self, fd: int) -> None:
        if _is_windows():
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)

    def acquire(self) -> Optional[Dict[str, Any]]:
        if self.is_acquired_by_current_process():
            raise LockConflictError("CrashSafeLock already acquired by this instance.")

        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        fd = os.open(str(self.lock_path), flags, 0o600)
        try:
            os.set_inheritable(fd, False)
            if not self._try_kernel_lock(fd):
                holder, _non_empty = _read_metadata_best_effort(fd)
                holder_desc = (
                    f"pid={holder.get('pid')}, run_id={holder.get('run_id')}"
                    if isinstance(holder, dict) and not holder.get("corrupt")
                    else "metadata unavailable/in-flight"
                )
                raise LockConflictError(f"Active Etgar Scout kernel lock held ({holder_desc}).")

            prior, was_non_empty = _read_metadata_best_effort(fd)
            self.recovered_event = None
            if was_non_empty:
                if prior is None or prior.get("corrupt") or prior.get("state") == "ACTIVE":
                    self.recovered_event = {
                        "event": "STALE_LOCK_RECOVERED",
                        "recovered_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "previous_lock": prior or {"corrupt": True},
                    }

            _write_metadata_locked(
                fd,
                {
                    "state": "ACTIVE",
                    "pid": os.getpid(),
                    "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "run_id": self.run_id,
                    "script_version": SCRIPT_VERSION,
                },
            )
            self._fd = fd
            self._acquired = True
            self._owner_pid = os.getpid()
            return self.recovered_event
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def release(self) -> None:
        """
        Releases kernel lock and closes FD WITHOUT unlinking the lock file.
        No-op if not acquired or if called from a forked child process.
        """
        if not self._acquired or self._fd is None:
            return
        if self._owner_pid != os.getpid():
            self._fd = None
            self._acquired = False
            self._owner_pid = None
            return

        fd = self._fd
        self._fd = None
        self._acquired = False
        self._owner_pid = None
        try:
            try:
                _write_metadata_locked(
                    fd,
                    {
                        "state": "RELEASED",
                        "pid": os.getpid(),
                        "released_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "run_id": self.run_id,
                        "script_version": SCRIPT_VERSION,
                    },
                )
            except OSError:
                pass
            try:
                self._kernel_unlock(fd)
            except OSError:
                pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass

    def __enter__(self) -> "CrashSafeLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


# ==============================================================================
# 2. FAIL-CLOSED ATOMIC WRITER (SEPARATING PUBLISH SUCCESS FROM TEMP CLEANUP)
# ==============================================================================

def _fsync_dir_best_effort(directory: Path) -> None:
    if _is_windows():
        return
    try:
        dir_fd = os.open(str(directory), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass


def atomic_write_bytes(
    target: Path,
    data: bytes,
    overwrite: bool = False,
    on_cleanup_warning: Optional[Callable[[str], None]] = None,
) -> Path:
    """
    Atomically writes `data` to `target`.
      - Temp file created exclusively with `O_CREAT | O_EXCL` and random 16-hex token,
        written via `_write_all` and `os.fsync()`d before publish.
      - `overwrite=True`: `os.replace(tmp_path, target)`.
      - `overwrite=False`: FAIL-CLOSED atomic non-overwriting publish via `os.link(tmp_path, target)`.
        * On Windows ONLY, falls back to `os.rename(tmp_path, target)` ONLY if `os.link` fails
          with `winerror in (1, 50)` (unsupported hard links). Never falls back on `PermissionError`,
          `FileExistsError`, or generic `OSError`.
        * On POSIX, unsupported hard-link errors raise `AtomicPublishUnsupportedError` (fail-closed).
      - Publish success is strictly separated from temp-cleanup failure: once `published == True`,
        a failed `os.unlink(tmp_path)` reports a non-fatal warning via `on_cleanup_warning` and
        does NOT fail the write operation.
    """
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)

    # Fast-fail pre-check (convenience only — NEVER relied upon for race safety!)
    if not overwrite and target.exists():
        raise FileExistsError(f"Refusing to overwrite existing file: {target}")

    tmp_path: Optional[Path] = None
    fd: Optional[int] = None
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    for _ in range(8):
        cand = target.parent / f".{target.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
        try:
            fd = os.open(str(cand), flags, 0o600)
            tmp_path = cand
            break
        except FileExistsError:
            continue
    if fd is None or tmp_path is None:
        raise OSError("Failed to allocate unique temporary file name.")

    published = False
    tmp_consumed = False
    try:
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
            fd = None

        if overwrite:
            os.replace(str(tmp_path), str(target))
            published = True
            tmp_consumed = True
        else:
            try:
                os.link(str(tmp_path), str(target))
                published = True
            except FileExistsError:
                raise
            except OSError as exc:
                winerr = getattr(exc, "winerror", None)
                if _is_windows() and winerr in WINDOWS_HARDLINK_UNSUPPORTED_WINERRORS:
                    # Windows-only fallback for filesystems lacking hard links (e.g., FAT32/exFAT):
                    # On Windows, os.rename() fails atomically with FileExistsError if target exists.
                    os.rename(str(tmp_path), str(target))
                    published = True
                    tmp_consumed = True
                elif not _is_windows() and exc.errno in POSIX_HARDLINK_UNSUPPORTED_ERRNOS:
                    raise AtomicPublishUnsupportedError(
                        exc.errno,
                        f"Atomic non-overwriting publish unsupported on filesystem for {target} (fail-closed): {exc}",
                    ) from exc
                else:
                    raise

        _fsync_dir_best_effort(target.parent)
    finally:
        if tmp_path is not None and not tmp_consumed:
            try:
                os.unlink(str(tmp_path))
            except FileNotFoundError:
                pass
            except OSError as cleanup_exc:
                if published:
                    msg = f"NON_FATAL_TEMP_CLEANUP_WARNING: published {target.name}, failed to unlink {tmp_path.name}: {cleanup_exc}"
                    if on_cleanup_warning is not None:
                        on_cleanup_warning(msg)
                else:
                    pass

    return target


def cleanup_orphan_temps(output_dir: Path, lock: CrashSafeLock) -> List[str]:
    """
    Cleans orphan `.tmp.<pid>.<16hex>` files inside `output_dir`.
    Precondition: MUST be called ONLY while `lock` is actively held by this process,
    under the documented invariant that all writers to `output_dir` coordinate via `lock`.
    """
    if not isinstance(lock, CrashSafeLock) or not lock.is_acquired_by_current_process():
        raise LockRequiredError("cleanup_orphan_temps requires an active CrashSafeLock held by the current process.")

    cleaned: List[str] = []
    out_dir = Path(output_dir)
    if not out_dir.exists():
        return cleaned
    for entry in sorted(out_dir.iterdir()):
        if entry.is_file() and ORPHAN_TEMP_PATTERN.match(entry.name):
            try:
                os.unlink(str(entry))
                cleaned.append(entry.name)
            except OSError:
                pass
    return cleaned
