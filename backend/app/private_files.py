"""Bounded private-file operations under operator-owned external directories.

POSIX uses O_NOFOLLOW; on Windows we reject reparse points and compare handle
identity. Private parent directories/ACLs are trusted; hostile host owners are not.
"""
import os
from pathlib import Path
import stat

from .config import validate_external_path
from .errors import DomainError
from .settings import SOURCE_ROOT


def private_directory(path: Path):
    validate_external_path(path, SOURCE_ROOT)
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise DomainError("UNSAFE_STORAGE", 503)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise DomainError("UNSAFE_STORAGE_PERMISSIONS", 503)
    if os.name == "nt":
        from .windows_acl import require_private_acl
        require_private_acl(path)


def regular(info):
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not getattr(info, "st_file_attributes", 0) & 0x400


def read_private(path: Path, maximum: int) -> bytes:
    for parent in path.parents:
        if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
            raise DomainError("UNSAFE_STORAGE", 503)
    before = path.lstat()
    if not regular(before):
        raise DomainError("UNSAFE_SNAPSHOT", 503)
    if os.name == "nt":
        from .windows_acl import require_private_acl
        require_private_acl(path)
    elif before.st_mode & 0o077:
        raise DomainError("UNSAFE_STORAGE_PERMISSIONS", 503)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not regular(opened) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise DomainError("UNSAFE_SNAPSHOT", 503)
        if opened.st_size > maximum:
            raise DomainError("SNAPSHOT_TOO_LARGE", 503)
        data = handle.read(maximum + 1)
        if len(data) > maximum:
            raise DomainError("SNAPSHOT_TOO_LARGE", 503)
        return data


def write_exclusive(path: Path, data: bytes):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def sync_directory(path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
