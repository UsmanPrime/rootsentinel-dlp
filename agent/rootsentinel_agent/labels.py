"""Filename label sanitizer. Labels are display metadata only; they never become paths on the server.

The gateway accepts ``^[A-Za-z0-9][A-Za-z0-9 ._()-]*$`` with 1 to 120 characters. The same
label also names the delivered file, so Windows-hostile names are neutralised as well.
"""
import re

MAX_LABEL = 120
READY_SUFFIX = ".ready"
SERVER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()-]*$")
_DISALLOWED = re.compile(r"[^A-Za-z0-9 ._()-]")
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def strip_ready(name: str) -> str:
    return name[: -len(READY_SUFFIX)] if name.lower().endswith(READY_SUFFIX) else name


def _split_ext(name: str):
    stem, dot, ext = name.rpartition(".")
    if dot and stem and 0 < len(ext) <= 16 and ext.isalnum():
        return stem, "." + ext
    return name, ""


def sanitize_label(name: str) -> str:
    """Return a label the gateway accepts. Deterministic, idempotent and total."""
    cleaned = _DISALLOWED.sub("_", name).rstrip(". ")
    if not cleaned:
        return "file"
    if not (cleaned[0].isascii() and cleaned[0].isalnum()):
        cleaned = "f" + cleaned  # keep the rest (and any extension) recognisable
    stem, ext = _split_ext(cleaned)
    if stem.split(".", 1)[0].upper() in _RESERVED:
        stem = "f-" + stem
    if len(stem) + len(ext) > MAX_LABEL:
        stem = stem[: MAX_LABEL - len(ext)].rstrip(". ")
    label = (stem + ext).rstrip(". ")
    return label or "file"


def outbound_name(label: str, entry_id: str, taken) -> str:
    """Pick a delivery name; ``taken`` answers case-insensitively whether a name is in use."""
    if not taken(label.lower()):
        return label
    stem, ext = _split_ext(label)
    suffix = "-" + entry_id.replace("-", "")[:8]
    candidate = stem[: MAX_LABEL - len(ext) - len(suffix)].rstrip(". ") + suffix + ext
    counter = 1
    while taken(candidate.lower()):
        counter += 1
        extra = f"{suffix}.{counter}"
        candidate = stem[: MAX_LABEL - len(ext) - len(extra)].rstrip(". ") + extra + ext
    return candidate
