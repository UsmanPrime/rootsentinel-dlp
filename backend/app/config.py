"""Path selection only: importing this module never creates directories."""

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Mapping


def _contains(parent: Path, child: Path) -> bool:
    return child == parent or parent in child.parents


def validate_external_path(path: Path, source_root: Path, sync_roots: tuple[Path, ...] = ()) -> Path:
    if not path.is_absolute():
        raise ValueError("Runtime paths must be absolute")
    resolved, source = path.resolve(), source_root.resolve()
    if _contains(source, resolved) or _contains(resolved, source):
        raise ValueError("Runtime storage must be separate from the source tree")
    if any(part.lower().startswith("onedrive") for part in resolved.parts):
        raise ValueError("OneDrive is not a runtime security boundary")
    for sync in sync_roots:
        sync = sync.resolve()
        if _contains(sync, resolved) or _contains(resolved, sync):
            raise ValueError("Runtime storage overlaps synchronized storage")
    return resolved


@dataclass(frozen=True)
class StoragePaths:
    runtime: Path
    artifacts: Path

    @property
    def database(self) -> Path:
        return self.runtime / "database" / "rootsentinel.sqlite3"

    @property
    def snapshots(self) -> Path:
        return self.runtime / "snapshots"

    @classmethod
    def from_environment(cls, source_root: Path, environ: Mapping[str, str] | None = None) -> "StoragePaths":
        env = os.environ if environ is None else environ
        base = env.get("LOCALAPPDATA") if os.name == "nt" else env.get("XDG_DATA_HOME")
        base_path = Path(base) if base else Path.home() / ".local" / "share"
        if os.name == "nt" and not base and "ROOTSENTINEL_RUNTIME_ROOT" not in env:
            raise ValueError("LOCALAPPDATA or an explicit external runtime path is required")
        sync = tuple(Path(env[key]) for key in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial") if env.get(key))
        runtime = validate_external_path(Path(env.get("ROOTSENTINEL_RUNTIME_ROOT", str(base_path / "RootSentinel" / "runtime"))), source_root, sync)
        artifacts = validate_external_path(Path(env.get("ROOTSENTINEL_ARTIFACT_ROOT", str(base_path / "RootSentinel" / "artifacts"))), source_root, sync)
        if _contains(runtime, artifacts) or _contains(artifacts, runtime):
            raise ValueError("Runtime and artifacts must not overlap")
        return cls(runtime, artifacts)


# Visitor mode constants (Chunk V). The caps an operator may tune are Settings fields with hard bounds;
# these are fixed by design.
VISITOR_ABSOLUTE_SECONDS = 1800     # a visitor session ends 30 minutes after entry and is never extended
VISITOR_IDLE_SECONDS = 600          # and after 10 minutes without a request (see VISITOR_SEEN_THROTTLE_SECONDS)
VISITOR_SEEN_THROTTLE_SECONDS = 60  # last_seen_at is written at most once per 60 s per session
VISITOR_CLEANUP_BATCH = 50          # expired visitor sessions handled per lazy cleanup
