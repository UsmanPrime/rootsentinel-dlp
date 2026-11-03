"""Bounded temporary intake; freeze once, unlink, and pass immutable bytes on.

    No producer-specified path, content execution, filename-based trust or release.
"""
from dataclasses import dataclass, field
from pathlib import Path
import tempfile
from uuid import uuid4

from .crypto import MAX_FILE_SIZE
from .errors import DomainError


@dataclass(frozen=True)
class FrozenInput:
    id: str
    data: bytes = field(repr=False)


async def receive_snapshot(stream, directory: Path, limit=MAX_FILE_SIZE) -> FrozenInput:
    if not 0 < limit <= MAX_FILE_SIZE:
        raise ValueError("Invalid intake limit")
    size = 0
    # Exclusive random temporary handle. Removed on all exits, including cancellation.
    with tempfile.TemporaryFile(mode="w+b", dir=directory, prefix="rs-") as snapshot:
        async for part in stream:
            if type(part) is not bytes:
                raise DomainError("INVALID_STREAM", 400)
            size += len(part)
            if size > limit:
                raise DomainError("INPUT_TOO_LARGE", 413)
            snapshot.write(part)
        snapshot.seek(0)
        data = snapshot.read(limit + 1)
        if len(data) != size:
            raise DomainError("SNAPSHOT_FAILURE", 503)
        return FrozenInput(str(uuid4()), data)
