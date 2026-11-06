"""Append-only JSON-lines journal with per-line CRC. fsync before the action a record announces.

Records never contain payload bytes, passwords, cookies or CSRF tokens; an allowlist of
field names enforces that. The state directory is operator-owned and trusted: the CRC
detects a torn final write, not tampering.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import zlib

from .fsutil import Observation, fsync_dir

LOG = logging.getLogger("rootsentinel_agent")
TERMINAL = frozenset({"DELIVERED", "QUARANTINED", "HELD", "REJECTED", "ABANDONED"})
EVENTS = frozenset({"PREPARED", "SUBMITTED", "RELEASING", "STAGED", "PLACED", "DELIVERED",
                    "QUARANTINED", "RETRY", "HELD", "REJECTED", "ABANDONED"})
FIELDS = frozenset({"key", "label", "out", "orig", "src", "sha256", "size", "attempt", "transfer",
                    "tstate", "expires", "incident", "reason", "not_before", "tmp", "rk", "report"})
_META = frozenset({"v", "seq", "t", "entry", "ev", "crc"})
_O_BINARY = getattr(os, "O_BINARY", 0)


class JournalCorrupt(Exception):
    pass


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _crc(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "crc"}
    return format(zlib.crc32(_canonical(body).encode("ascii")) & 0xFFFFFFFF, "08x")


class Journal:
    def __init__(self, path: Path):
        self.path = path
        self.entries: dict[str, dict] = {}
        self.seq = 0
        self.rejected: set[str] = set()
        self.fd: int | None = None

    def open(self) -> None:
        existed = self.path.exists()
        if existed:
            self._load()
        self.fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _O_BINARY, 0o600)
        if not existed:
            fsync_dir(self.path.parent)

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def _load(self) -> None:
        raw = self.path.read_bytes()
        lines = raw.split(b"\n")
        torn = lines.pop() != b""           # bytes after the last newline are an unfinished write
        valid_length = 0
        for index, line in enumerate(lines):
            try:
                record = json.loads(line)
                if record.get("crc") != _crc(record) or record.get("v") != 1:
                    raise ValueError
            except (ValueError, AttributeError):
                if index == len(lines) - 1:  # a damaged final line is a torn write
                    torn = True
                    break
                raise JournalCorrupt(f"journal record {index + 1} is invalid; refusing to continue") from None
            self._apply(record)
            valid_length += len(line) + 1
        if torn:
            LOG.warning("journal: discarded an unfinished final record (previous state stands)")
            with open(self.path, "r+b") as handle:
                handle.truncate(valid_length)

    def _apply(self, record: dict) -> None:
        entry = self.entries.setdefault(record["entry"], {"id": record["entry"]})
        entry.update({k: v for k, v in record.items() if k not in _META})
        entry["state"], entry["updated"] = record["ev"], record["t"]
        self.seq = max(self.seq, record["seq"])
        if record.get("rk"):
            self.rejected.add(record["rk"])

    def append(self, entry: str, event: str, **fields) -> dict:
        if event not in EVENTS or set(fields) - FIELDS:
            raise ValueError("unsupported journal event or field")
        record = {"v": 1, "seq": self.seq + 1, "t": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                  "entry": entry, "ev": event, **fields}
        record["crc"] = _crc(record)
        line = (_canonical(record) + "\n").encode("ascii")
        view = memoryview(line)
        while view:
            view = view[os.write(self.fd, view):]
        os.fsync(self.fd)
        self._apply(record)
        return self.entries[entry]

    def active(self) -> list[dict]:
        return sorted((e for e in self.entries.values() if e["state"] not in TERMINAL), key=lambda e: e["updated"])

    def known_source(self, observation: Observation) -> bool:
        # A rejected thing may become admissible (for example a hardlink count drops back to 1).
        wanted = list(observation)
        return any(e.get("src") == wanted for e in self.entries.values() if e["state"] != "REJECTED")

    def reserved_names(self) -> set[str]:
        return {e["out"].lower() for e in self.entries.values() if e.get("out") and e["state"] not in {"QUARANTINED", "HELD", "REJECTED", "ABANDONED"}}
