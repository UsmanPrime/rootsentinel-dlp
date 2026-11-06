"""Filesystem rules: path validation, no-follow reads, durable exclusive writes, instance lock.

POSIX uses descriptor-relative access (``dir_fd``) and ``O_NOFOLLOW`` for the staging
directory. Windows has no ``dir_fd``; it uses ``lstat``, the reparse-point attribute, link
counts and a post-open identity comparison, the same approach as the backend's private
file reader. Both leave a small window against a hostile writer who can replace the
operator-owned parent directories; that case is outside the threat model.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import NamedTuple

IS_WINDOWS = os.name == "nt"
REPARSE_POINT = 0x400
MAX_FILE_SIZE = 10 * 1024 * 1024
REPO_ROOT = Path(__file__).resolve().parents[2]

_O_BINARY = getattr(os, "O_BINARY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
USE_DIR_FD = (not IS_WINDOWS and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
              and os.unlink in os.supports_dir_fd and os.rename in os.supports_dir_fd
              and os.listdir in os.supports_fd)


class PathRuleError(ValueError):
    pass


class Unstable(Exception):
    """The file changed (or was swapped) while it was being read."""


class Observation(NamedTuple):
    dev: int
    ino: int
    size: int
    mtime_ns: int


def is_link_or_reparse(st) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & REPARSE_POINT)


def observation_of(st) -> Observation:
    return Observation(st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def classify(st) -> str | None:
    """Return a rejection reason for a staging entry, or None if it may be admitted."""
    if is_link_or_reparse(st):
        return "LINK_OR_REPARSE_POINT"
    if stat.S_ISDIR(st.st_mode):
        return "DIRECTORY_NOT_SCANNED"
    if not stat.S_ISREG(st.st_mode):
        return "SPECIAL_FILE"
    if st.st_nlink != 1:
        return "HARDLINK"
    if st.st_ino == 0:
        return "IDENTITY_UNAVAILABLE"
    if st.st_size == 0:
        return "EMPTY_FILE"
    if st.st_size > MAX_FILE_SIZE:
        return "TOO_LARGE"
    return None


def check_location(path: Path, what: str, repo_root: Path = REPO_ROOT) -> Path:
    """Absolute, outside the repository and OneDrive, and no link or reparse component."""
    if not path.is_absolute():
        raise PathRuleError(f"{what} must be an absolute path")
    for part in (path, *path.parents):
        try:
            st = os.lstat(part)
        except FileNotFoundError:
            continue
        except OSError:
            raise PathRuleError(f"{what} cannot be inspected") from None
        if is_link_or_reparse(st):
            raise PathRuleError(f"{what} contains a symbolic link, junction or reparse point")
    resolved = path.resolve()
    repo = repo_root.resolve()
    if resolved == repo or repo in resolved.parents or resolved in repo.parents:
        raise PathRuleError(f"{what} must be outside the source repository")
    if any(p.lower().startswith("onedrive") for p in (*path.parts, *resolved.parts)):
        raise PathRuleError(f"{what} must not be inside OneDrive")
    for variable in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        value = os.environ.get(variable)
        if value:
            root = Path(value).resolve()
            if resolved == root or root in resolved.parents:
                raise PathRuleError(f"{what} must not be inside a synchronized OneDrive folder")
    return resolved


def ensure_dir(path: Path, what: str, *, private: bool) -> Path:
    resolved = check_location(path, what)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved = check_location(path, what)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise PathRuleError(f"{what} is not a directory")
    if private and not IS_WINDOWS and st.st_mode & 0o077:
        raise PathRuleError(f"{what} must not be accessible to group or others (mode 0700)")
    return resolved


def require_same_device(paths: dict[str, Path]) -> None:
    devices = {name: os.stat(path).st_dev for name, path in paths.items()}
    if len(set(devices.values())) != 1:
        raise PathRuleError("staging, outbound, quarantine and state must be on one volume (atomic rename)")


def require_distinct(paths: dict[str, Path]) -> None:
    items = [(n, p.resolve()) for n, p in paths.items()]
    for i, (a_name, a) in enumerate(items):
        for b_name, b in items[i + 1:]:
            if a == b or a in b.parents or b in a.parents:
                raise PathRuleError(f"{a_name} and {b_name} must be distinct, non-nested directories")


class DirHandle:
    """A directory used descriptor-relative on POSIX and path-relative on Windows."""

    def __init__(self, path: Path):
        self.path = path
        self.fd = os.open(path, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW) if USE_DIR_FD else None

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def names(self) -> list[str]:
        return sorted(os.listdir(self.fd if self.fd is not None else self.path))

    def lstat(self, name: str):
        if self.fd is not None:
            return os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        return os.lstat(self.path / name)

    def exists(self, name: str) -> bool:
        try:
            self.lstat(name)
            return True
        except FileNotFoundError:
            return False

    def open_read(self, name: str) -> int:
        flags = os.O_RDONLY | _O_BINARY | _O_NOFOLLOW | _O_NONBLOCK
        if self.fd is not None:
            return os.open(name, flags, dir_fd=self.fd)
        return os.open(self.path / name, flags)

    def unlink(self, name: str) -> None:
        if self.fd is not None:
            os.unlink(name, dir_fd=self.fd)
        else:
            os.unlink(self.path / name)


def rename_between(src: DirHandle, src_name: str, dst: DirHandle, dst_name: str) -> None:
    """Move without overwriting (names are unique per entry)."""
    if dst.exists(dst_name):
        raise FileExistsError(dst_name)
    if src.fd is not None and dst.fd is not None:
        os.rename(src_name, dst_name, src_dir_fd=src.fd, dst_dir_fd=dst.fd)
    else:
        os.rename(src.path / src_name, dst.path / dst_name)


def read_verified(directory: DirHandle, name: str, expected: Observation) -> bytes:
    """Read the file once, proving it is the same regular file before, during and after."""
    before = directory.lstat(name)
    if classify(before) is not None or observation_of(before) != expected:
        raise Unstable(name)
    fd = directory.open_read(name)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or observation_of(opened) != expected):
            raise Unstable(name)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(expected.size + 1)
        if len(data) != expected.size:
            raise Unstable(name)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    if observation_of(after) != expected or observation_of(directory.lstat(name)) != expected:
        raise Unstable(name)
    return data


def write_exclusive(path: Path, data: bytes, on_chunk=None) -> None:
    """Create a new file, write it, and fsync it. A failure removes the partial file."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            for offset in range(0, len(data), 65536):
                handle.write(data[offset:offset + 65536])
                if on_chunk is not None:
                    handle.flush()
                    on_chunk(offset + min(65536, len(data) - offset))
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        # A hard crash (os._exit, power loss) never reaches here; startup cleans such leftovers.
        path.unlink(missing_ok=True)
        raise


def fsync_dir(path: Path) -> None:
    if IS_WINDOWS:
        return  # Windows exposes no directory fsync; durability of renames is not claimed.
    fd = os.open(path, os.O_RDONLY | _O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sha256_file(path: Path) -> str | None:
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_SIZE:
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return None


class AlreadyRunning(RuntimeError):
    pass


class InstanceLock:
    """Advisory single-instance lock in the state directory."""

    def __init__(self, path: Path):
        self.path, self.fd = path, None

    def __enter__(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | _O_BINARY, 0o600)
        try:
            if os.fstat(self.fd).st_size == 0:
                os.write(self.fd, b"0")
            os.lseek(self.fd, 0, os.SEEK_SET)
            if IS_WINDOWS:
                import msvcrt
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.fd)
            self.fd = None
            raise AlreadyRunning("another agent instance is using this state directory") from None
        return self

    def __exit__(self, *exc):
        if self.fd is not None:
            try:
                if IS_WINDOWS:
                    import msvcrt
                    os.lseek(self.fd, 0, os.SEEK_SET)
                    msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            finally:
                os.close(self.fd)
                self.fd = None


USERNAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,63}$")


class Credentials:
    __slots__ = ("username", "password")

    def __init__(self, username: str, password: str):
        self.username, self.password = username, password

    def __repr__(self) -> str:
        return f"Credentials(username={self.username!r}, password=<redacted>)"


def read_credentials(path: Path) -> tuple[Credentials, bool]:
    """Load a private JSON credentials file. Returns (credentials, acl_verified).

    POSIX enforces mode 0600. Windows cannot verify the DACL here, so ``acl_verified`` is
    False there and the caller must say so; only the path rules are enforced.
    """
    check_location(path, "credentials file")
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > 4096:
        raise PathRuleError("credentials file must be a small regular file with one link")
    if not IS_WINDOWS and st.st_mode & 0o077:
        raise PathRuleError("credentials file must not be accessible to group or others (mode 0600)")
    try:
        value = json.loads(path.read_bytes())
        if set(value) != {"username", "password"} or not all(isinstance(v, str) for v in value.values()):
            raise ValueError
        if not USERNAME.fullmatch(value["username"]) or not 1 <= len(value["password"]) <= 128:
            raise ValueError
    except (ValueError, TypeError):
        raise PathRuleError("credentials file must be JSON with only username and password") from None
    return Credentials(value["username"], value["password"]), not IS_WINDOWS


def write_credentials(path: Path, username: str, password: str) -> None:
    check_location(path.parent, "credentials directory")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    check_location(path, "credentials file")
    payload = json.dumps({"username": username, "password": password}).encode("ascii")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY | _O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
