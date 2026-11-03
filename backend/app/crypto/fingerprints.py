"""Bounded streaming fingerprint computation; never executes or decodes input."""

from hashlib import sha256
from io import BytesIO
from typing import BinaryIO

from .merkle import tree_root
from .models import CHUNK_SIZE, MAX_FILE_SIZE, PROFILE_ID, SPEC_VERSION, Chunk, Fingerprint, Manifest


def fingerprint_stream(stream: BinaryIO) -> Fingerprint:
    """Read from the current position to EOF, tolerating short blocking reads.

    The caller owns and closes the stream. This is not a filesystem snapshot or
    an upload parser. A later gateway must provide its own frozen input.
    """
    whole = sha256()
    size = 0
    pending = bytearray()
    chunks: list[Chunk] = []
    while True:
        requested = CHUNK_SIZE - len(pending)
        data = stream.read(requested)
        if type(data) is not bytes:
            raise ValueError("A blocking binary stream is required")
        if len(data) > requested:
            raise ValueError("Stream returned more bytes than requested")
        if not data:
            break
        size += len(data)
        if size > MAX_FILE_SIZE:
            raise ValueError("File exceeds 10 MiB limit")
        whole.update(data)
        pending.extend(data)
        if len(pending) == CHUNK_SIZE:
            chunks.append(Chunk(len(chunks), len(pending), sha256(pending).hexdigest()))
            pending.clear()
    if pending:
        chunks.append(Chunk(len(chunks), len(pending), sha256(pending).hexdigest()))
    manifest = Manifest(
        SPEC_VERSION, PROFILE_ID, size, CHUNK_SIZE, len(chunks),
        whole.hexdigest(), tree_root(chunks).hex(),
    )
    return Fingerprint(manifest, tuple(chunks))


def fingerprint_bytes(data: bytes) -> Fingerprint:
    if type(data) is not bytes:
        raise ValueError("Input must be bytes")
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("File exceeds 10 MiB limit")
    return fingerprint_stream(BytesIO(data))


def verify_file(data: bytes, trusted_manifest: Manifest) -> bool:
    """Compare the complete file, not merely one included descriptor."""
    try:
        return fingerprint_bytes(data).manifest == trusted_manifest
    except (ValueError, TypeError):
        return False
