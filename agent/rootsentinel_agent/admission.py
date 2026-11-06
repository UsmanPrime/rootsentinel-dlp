"""Admission: which staging entries may be read, and when a file counts as finished.

Nonrecursive: only direct children of the staging directory are considered; a directory
dropped there is reported and never scanned, and nothing outside regular files can reach
the outbound directory. Stability polling admits an ordinary file after ``stable_polls``
consecutive identical observations and a quiet period. Stability cannot tell a paused
writer from a finished one; a producer that writes then renames to ``*.ready`` gives a
reliable signal and is admitted at once (the read itself re-verifies identity).
"""
from __future__ import annotations

from dataclasses import dataclass, field
import time

from .fsutil import DirHandle, Observation, classify, observation_of

READY_SUFFIX = ".ready"


@dataclass
class Scan:
    observations: dict[str, Observation] = field(default_factory=dict)
    rejections: dict[str, tuple[str, object]] = field(default_factory=dict)  # name -> (reason, stat)


def scan_directory(staging: DirHandle) -> Scan:
    result = Scan()
    for name in staging.names():
        try:
            st = staging.lstat(name)
        except FileNotFoundError:
            continue
        reason = classify(st)
        if reason is None:
            result.observations[name] = observation_of(st)
        else:
            result.rejections[name] = (reason, st)
    return result


def rejection_key(reason: str, st) -> str:
    """Identify a rejected thing so it is reported once, not on every poll."""
    if reason in {"EMPTY_FILE", "TOO_LARGE"}:
        return f"{reason}:{st.st_dev}:{st.st_ino}:{st.st_size}:{st.st_mtime_ns}"
    return f"{reason}:{st.st_dev}:{st.st_ino}"


class StabilityTracker:
    def __init__(self, stable_polls: int = 2, settle_seconds: float = 2.0, require_ready: bool = False):
        self.stable_polls, self.settle_ns = stable_polls, int(settle_seconds * 1e9)
        self.require_ready = require_ready
        self.seen: dict[str, tuple[Observation, int]] = {}

    def step(self, current: dict[str, Observation], now_ns: int | None = None):
        """Return (ready, waiting) name lists for this poll."""
        now_ns = time.time_ns() if now_ns is None else now_ns
        ready, waiting = [], []
        for name, observation in sorted(current.items()):
            is_ready_name = name.lower().endswith(READY_SUFFIX)
            if self.require_ready and not is_ready_name:
                continue
            previous = self.seen.get(name)
            count = previous[1] + 1 if previous and previous[0] == observation else 1
            self.seen[name] = (observation, count)
            needed = 1 if is_ready_name else self.stable_polls
            quiet = is_ready_name or now_ns - observation.mtime_ns >= self.settle_ns
            (ready if count >= needed and quiet else waiting).append(name)
        for name in list(self.seen):
            if name not in current:
                del self.seen[name]
        return ready, waiting

    def forget(self, name: str) -> None:
        self.seen.pop(name, None)
