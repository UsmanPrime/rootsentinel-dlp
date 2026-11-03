"""Strict immutable wire types for rs-fixed-sha256-v1.

Only canonical lowercase hex is accepted. A manifest supplied by an attacker is
not a trusted baseline: callers must obtain it through an authenticated registry.
"""

from dataclasses import asdict, dataclass
import re
import struct
from typing import Any

PROFILE_ID = "rs-fixed-sha256-v1"
SPEC_VERSION = 1
CHUNK_SIZE = 1024
MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_CHUNKS = MAX_FILE_SIZE // CHUNK_SIZE
MAX_PROOF_SIBLINGS = (MAX_CHUNKS - 1).bit_length()


def integer(value: int, minimum: int, maximum: int, field: str) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"Invalid {field}")


def digest_bytes(value: str) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("Digest must be 64 lowercase hexadecimal characters")
    return bytes.fromhex(value)


def strict_fields(value: Any, expected: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("Unexpected or missing fields")
    return value


@dataclass(frozen=True, slots=True)
class Chunk:
    index: int
    length: int
    sha256: str

    def __post_init__(self) -> None:
        integer(self.index, 0, MAX_CHUNKS - 1, "chunk index")
        integer(self.length, 1, CHUNK_SIZE, "chunk length")
        digest_bytes(self.sha256)

    @property
    def offset(self) -> int:
        return self.index * CHUNK_SIZE

    def descriptor(self) -> bytes:
        return struct.pack(">QI", self.index, self.length) + digest_bytes(self.sha256)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Any) -> "Chunk":
        return cls(**strict_fields(value, {"index", "length", "sha256"}))


@dataclass(frozen=True, slots=True)
class Manifest:
    spec_version: int
    profile_id: str
    file_size: int
    chunk_size: int
    chunk_count: int
    file_sha256: str
    merkle_root: str

    def __post_init__(self) -> None:
        integer(self.spec_version, SPEC_VERSION, SPEC_VERSION, "spec version")
        if self.profile_id != PROFILE_ID:
            raise ValueError("Unsupported profile")
        integer(self.file_size, 0, MAX_FILE_SIZE, "file size")
        integer(self.chunk_size, CHUNK_SIZE, CHUNK_SIZE, "chunk size")
        integer(self.chunk_count, 0, MAX_CHUNKS, "chunk count")
        if self.chunk_count != (self.file_size + CHUNK_SIZE - 1) // CHUNK_SIZE:
            raise ValueError("Inconsistent file size and chunk count")
        digest_bytes(self.file_sha256)
        digest_bytes(self.merkle_root)
        if self.file_size == 0:
            empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            if self.file_sha256 != empty or self.merkle_root != empty:
                raise ValueError("Invalid empty-file manifest")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Any) -> "Manifest":
        return cls(**strict_fields(value, set(cls.__dataclass_fields__)))


@dataclass(frozen=True, slots=True)
class Fingerprint:
    manifest: Manifest
    chunks: tuple[Chunk, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, Manifest) or type(self.chunks) is not tuple:
            raise ValueError("Invalid fingerprint types")
        if len(self.chunks) != self.manifest.chunk_count:
            raise ValueError("Chunk count mismatch")
        for i, chunk in enumerate(self.chunks):
            expected = min(CHUNK_SIZE, self.manifest.file_size - i * CHUNK_SIZE)
            if not isinstance(chunk, Chunk) or chunk.index != i or chunk.length != expected:
                raise ValueError("Invalid chunk ordering or length")


@dataclass(frozen=True, slots=True)
class Proof:
    spec_version: int
    profile_id: str
    tree_size: int
    chunk: Chunk
    siblings: tuple[str, ...]

    def __post_init__(self) -> None:
        integer(self.spec_version, SPEC_VERSION, SPEC_VERSION, "spec version")
        if self.profile_id != PROFILE_ID:
            raise ValueError("Unsupported profile")
        integer(self.tree_size, 1, MAX_CHUNKS, "tree size")
        if not isinstance(self.chunk, Chunk) or self.chunk.index >= self.tree_size:
            raise ValueError("Leaf index outside tree")
        if type(self.siblings) is not tuple or len(self.siblings) > MAX_PROOF_SIBLINGS:
            raise ValueError("Invalid proof path")
        for sibling in self.siblings:
            digest_bytes(sibling)

    def to_dict(self) -> dict:
        return {
            "spec_version": self.spec_version, "profile_id": self.profile_id,
            "tree_size": self.tree_size, "chunk": self.chunk.to_dict(),
            "siblings": list(self.siblings),
        }

    @classmethod
    def from_dict(cls, value: Any) -> "Proof":
        value = strict_fields(value, set(cls.__dataclass_fields__))
        siblings = value["siblings"]
        if not isinstance(siblings, list) or len(siblings) > MAX_PROOF_SIBLINGS:
            raise ValueError("Invalid proof path")
        return cls(
            value["spec_version"], value["profile_id"], value["tree_size"],
            Chunk.from_dict(value["chunk"]), tuple(siblings),
        )
