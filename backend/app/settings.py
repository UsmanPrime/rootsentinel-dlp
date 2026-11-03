"""Explicit local-only Phase 02 configuration; no filesystem writes on import."""
from dataclasses import dataclass
import os
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy.engine import make_url

from .config import StoragePaths, validate_external_path

SOURCE_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    paths: StoragePaths
    database_url: str
    mode: str = "public_demo"
    origin: str = "http://127.0.0.1:5173"
    secure_cookies: bool = True
    session_seconds: int = 3600

    def __post_init__(self):
        if self.mode not in {"local", "public_demo"}:
            raise ValueError("Unsupported mode")
        parsed = urlsplit(self.origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username:
            raise ValueError("Origin must be a bare HTTP(S) origin")
        if not self.secure_cookies and (self.mode != "local" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}):
            raise ValueError("Insecure cookies are permitted only on local loopback")
        if not 60 <= self.session_seconds <= 86400:
            raise ValueError("Invalid session lifetime")
        validate_external_path(self.paths.runtime, SOURCE_ROOT)
        validate_external_path(self.paths.artifacts, SOURCE_ROOT)
        url = make_url(self.database_url)
        if url.drivername == "sqlite":
            if not url.database or url.database == ":memory:":
                raise ValueError("Use an external on-disk SQLite database")
            target = validate_external_path(Path(url.database), SOURCE_ROOT)
            if target.parent != self.paths.database.parent.resolve():
                raise ValueError("SQLite database must be in the configured runtime database directory")
        elif url.drivername != "postgresql+psycopg":
            raise ValueError("Unsupported database driver")

    @classmethod
    def from_environment(cls):
        paths = StoragePaths.from_environment(SOURCE_ROOT)
        return cls(
            paths, os.environ.get("ROOTSENTINEL_DATABASE_URL", f"sqlite:///{paths.database.as_posix()}"),
            os.environ.get("ROOTSENTINEL_MODE", "public_demo"),
            os.environ.get("ROOTSENTINEL_ORIGIN", "http://127.0.0.1:5173"),
            os.environ.get("ROOTSENTINEL_SECURE_COOKIES", "true") != "false",
        )

    def prepare_storage(self):
        # The private runtime's parent is operator-controlled. This is not a
        # hostile local staging adapter; that descriptor-relative adapter is later.
        for path in (self.paths.runtime, self.paths.database.parent, self.paths.snapshots):
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                raise ValueError("Runtime storage cannot be a link")
            validate_external_path(path, SOURCE_ROOT)
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.name != "nt" and path.stat().st_mode & 0o077:
                raise ValueError("Runtime directories must be private (0700)")
