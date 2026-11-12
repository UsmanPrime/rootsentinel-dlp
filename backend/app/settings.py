"""Explicit local-only Phase 02 configuration; no filesystem writes on import."""
from dataclasses import dataclass
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from sqlalchemy.engine import make_url

from .config import StoragePaths, validate_external_path

SOURCE_ROOT = Path(__file__).resolve().parents[2]
HOST_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::[0-9]{1,5})?")
# A plain header field name: letters, digits and single inner hyphens, at most 64 characters.
HEADER_NAME_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
# A Git commit id: 7 to 40 lowercase hex digits. Anything else is reported as "unknown", never echoed.
COMMIT_PATTERN = re.compile(r"[0-9a-f]{7,40}")


def build_commit(environ=None) -> str:
    """The deployed commit: ROOTSENTINEL_COMMIT (a build argument set by CI or the image build), else the
    host's RENDER_GIT_COMMIT, else "unknown". Only a well-formed commit id is ever returned."""
    environ = os.environ if environ is None else environ
    for name in ("ROOTSENTINEL_COMMIT", "RENDER_GIT_COMMIT"):
        value = (environ.get(name) or "").strip().lower()
        if COMMIT_PATTERN.fullmatch(value):
            return value
    return "unknown"


# (field, lowest, highest) for every operator-tunable visitor cap. The audit ceiling stays below the 20000 event
# audit capacity, so real users always keep room.
VISITOR_BOUNDS = (
    ("visitor_entries_per_ip_hour", 1, 60),
    ("visitor_max_concurrent", 1, 50),
    ("visitor_sessions_per_day", 1, 200),
    ("visitor_scans_per_session", 1, 10),
    ("visitor_upload_bytes", 1024, 262144),
    ("visitor_audit_ceiling", 1000, 18000),
)


def _integer(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer") from None


@dataclass(frozen=True)
class Settings:
    paths: StoragePaths
    database_url: str
    mode: str = "public_demo"
    origin: str = "http://127.0.0.1:5173"
    secure_cookies: bool = True
    session_seconds: int = 3600
    audit_key_file: Path | None = None
    checkpoint_root: Path | None = None
    retention_seconds: int = 900
    # Hosted-deployment knobs (Phase 06A). Defaults reproduce the earlier local behavior exactly.
    extra_hosts: tuple[str, ...] = ()
    trusted_proxy_hops: int = 0
    frontend_dir: Path | None = None
    max_upload_bytes: int = 10485760
    transfer_rate_per_minute: int = 30
    # Optional single-address header set by the edge in front of the host (for example True-Client-IP).
    # Empty keeps the earlier behavior (socket peer, or the hop count above).
    client_ip_header: str = ""
    # The deployed commit id reported by /health; never a secret (see build_commit).
    commit: str = "unknown"
    # The Ed25519 key file that signs audit tree heads. A separate secret from the HMAC keyring above.
    transparency_key_file: Path | None = None
    # Visitor mode (Chunk V). Off unless explicitly enabled. Every cap has a hard upper bound checked below.
    visitor_mode_enabled: bool = False
    visitor_entries_per_ip_hour: int = 6
    visitor_max_concurrent: int = 10
    visitor_sessions_per_day: int = 30
    visitor_scans_per_session: int = 3
    visitor_upload_bytes: int = 65536
    visitor_audit_ceiling: int = 14000

    @property
    def visitor_upload_limit(self) -> int:
        """The upload cap a visitor session enforces: never above the general cap."""
        return min(self.visitor_upload_bytes, self.max_upload_bytes)

    @property
    def hosted(self) -> bool:
        """An https origin means a TLS-terminating host fronts the app; loopback development uses http."""
        return urlsplit(self.origin).scheme == "https"

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
        if not 1 <= self.retention_seconds <= 900:
            raise ValueError("Retention must be 1 through 900 seconds")
        if not 0 <= self.trusted_proxy_hops <= 5:
            raise ValueError("Trusted proxy hops must be 0 through 5")
        if self.client_ip_header:
            name = self.client_ip_header.strip().lower()
            if len(name) > 64 or HEADER_NAME_PATTERN.fullmatch(name) is None:
                raise ValueError("The client IP header must be a plain header name (letters, digits and hyphens)")
            if self.trusted_proxy_hops:
                raise ValueError("Set either the client IP header or trusted proxy hops, not both")
            object.__setattr__(self, "client_ip_header", name)
        if self.commit != "unknown" and COMMIT_PATTERN.fullmatch(self.commit) is None:
            object.__setattr__(self, "commit", "unknown")
        if not 1024 <= self.max_upload_bytes <= 10485760:
            raise ValueError("Upload cap must be 1024 through 10485760 bytes")
        if not 1 <= self.transfer_rate_per_minute <= 120:
            raise ValueError("Transfer rate must be 1 through 120 per minute")
        for name, low, high in VISITOR_BOUNDS:
            if not low <= getattr(self, name) <= high:
                raise ValueError(f"{name} must be {low} through {high}")
        if any(HOST_PATTERN.fullmatch(host) is None for host in self.extra_hosts):
            raise ValueError("Extra hosts must be exact lowercase host names (optional port); wildcards are not allowed")
        if self.frontend_dir is not None and not self.frontend_dir.is_absolute():
            raise ValueError("The frontend directory must be absolute")
        for path in (self.audit_key_file, self.checkpoint_root, self.transparency_key_file):
            if path is not None:
                resolved = validate_external_path(path, SOURCE_ROOT)
                if self.paths.runtime.resolve() in resolved.parents or resolved == self.paths.runtime.resolve():
                    raise ValueError("Audit keys/checkpoints must be independent of runtime storage")
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
            session_seconds=_integer("ROOTSENTINEL_SESSION_SECONDS", 3600),
            audit_key_file=Path(os.environ["ROOTSENTINEL_AUDIT_KEY_FILE"]) if os.environ.get("ROOTSENTINEL_AUDIT_KEY_FILE") else None,
            checkpoint_root=Path(os.environ["ROOTSENTINEL_CHECKPOINT_ROOT"]) if os.environ.get("ROOTSENTINEL_CHECKPOINT_ROOT") else None,
            retention_seconds=_integer("ROOTSENTINEL_RETENTION_SECONDS", 900),
            extra_hosts=tuple(h.strip() for h in os.environ.get("ROOTSENTINEL_EXTRA_HOSTS", "").split(",") if h.strip()),
            trusted_proxy_hops=_integer("ROOTSENTINEL_TRUSTED_PROXY_HOPS", 0),
            frontend_dir=Path(os.environ["ROOTSENTINEL_FRONTEND_DIR"]) if os.environ.get("ROOTSENTINEL_FRONTEND_DIR") else None,
            max_upload_bytes=_integer("ROOTSENTINEL_MAX_UPLOAD_BYTES", 10485760),
            transfer_rate_per_minute=_integer("ROOTSENTINEL_TRANSFER_RATE_PER_MINUTE", 30),
            client_ip_header=os.environ.get("ROOTSENTINEL_CLIENT_IP_HEADER", "").strip(),
            commit=build_commit(),
            visitor_mode_enabled=os.environ.get("ROOTSENTINEL_VISITOR_MODE_ENABLED", "false").strip().lower() == "true",
            visitor_entries_per_ip_hour=_integer("ROOTSENTINEL_VISITOR_ENTRIES_PER_IP_HOUR", 6),
            visitor_max_concurrent=_integer("ROOTSENTINEL_VISITOR_MAX_CONCURRENT", 10),
            visitor_sessions_per_day=_integer("ROOTSENTINEL_VISITOR_SESSIONS_PER_DAY", 30),
            visitor_scans_per_session=_integer("ROOTSENTINEL_VISITOR_SCANS_PER_SESSION", 3),
            visitor_upload_bytes=_integer("ROOTSENTINEL_VISITOR_UPLOAD_BYTES", 65536),
            visitor_audit_ceiling=_integer("ROOTSENTINEL_VISITOR_AUDIT_CEILING", 14000),
            transparency_key_file=Path(os.environ["ROOTSENTINEL_TRANSPARENCY_KEY_FILE"]) if os.environ.get("ROOTSENTINEL_TRANSPARENCY_KEY_FILE") else None,
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
