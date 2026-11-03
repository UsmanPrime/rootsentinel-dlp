"""RFC 9162 tree shape over RootSentinel's 44-byte chunk descriptors."""

from hashlib import sha256
from hmac import compare_digest
from typing import Any, Sequence

from .models import Chunk, Fingerprint, Manifest, Proof, PROFILE_ID, SPEC_VERSION, digest_bytes


def leaf_hash(chunk: Chunk) -> bytes:
    return sha256(b"\x00" + chunk.descriptor()).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("Nodes must be SHA-256 digests")
    return sha256(b"\x01" + left + right).digest()


def _split(size: int) -> int:
    return 1 << ((size - 1).bit_length() - 1)


def tree_root(chunks: Sequence[Chunk]) -> bytes:
    def root(start: int, end: int) -> bytes:
        size = end - start
        if size == 0:
            return sha256(b"").digest()
        if size == 1:
            return leaf_hash(chunks[start])
        middle = start + _split(size)
        return node_hash(root(start, middle), root(middle, end))

    return root(0, len(chunks))


def create_proof(fingerprint: Fingerprint, index: int) -> Proof:
    chunks = fingerprint.chunks
    if type(index) is not int or not 0 <= index < len(chunks):
        raise ValueError("Leaf index outside tree")
    if tree_root(chunks).hex() != fingerprint.manifest.merkle_root:
        raise ValueError("Chunks do not match the manifest root")

    def path(start: int, end: int) -> list[str]:
        if end - start == 1:
            return []
        middle = start + _split(end - start)
        if index < middle:
            return path(start, middle) + [tree_root(chunks[middle:end]).hex()]
        return path(middle, end) + [tree_root(chunks[start:middle]).hex()]

    return Proof(SPEC_VERSION, PROFILE_ID, len(chunks), chunks[index], tuple(path(0, len(chunks))))


def verify_proof(
    proof: Proof | dict[str, Any], trusted_manifest: Manifest | dict[str, Any],
    chunk_bytes: bytes | None = None,
) -> bool:
    """Fail closed on malformed proofs; baseline trust is the caller's responsibility.

    Without chunk_bytes this verifies descriptor inclusion only. There is no root
    in Proof: callers must explicitly provide the separately trusted manifest.
    """
    try:
        if not isinstance(proof, Proof):
            proof = Proof.from_dict(proof)
        if not isinstance(trusted_manifest, Manifest):
            trusted_manifest = Manifest.from_dict(trusted_manifest)
        if proof.tree_size != trusted_manifest.chunk_count:
            return False
        chunk = proof.chunk
        expected_length = min(1024, trusted_manifest.file_size - chunk.offset)
        if chunk.length != expected_length:
            return False
        if chunk_bytes is not None:
            if type(chunk_bytes) is not bytes or len(chunk_bytes) != chunk.length:
                return False
            if not compare_digest(sha256(chunk_bytes).hexdigest(), chunk.sha256):
                return False

        # RFC 9162 section 2.1.3.2, using the descriptor's leaf hash as r.
        fn, sn = chunk.index, proof.tree_size - 1
        result = leaf_hash(chunk)
        for encoded in proof.siblings:
            if sn == 0:
                return False
            sibling = digest_bytes(encoded)
            if fn & 1 or fn == sn:
                result = node_hash(sibling, result)
                if not fn & 1:
                    while fn and not fn & 1:
                        fn >>= 1
                        sn >>= 1
            else:
                result = node_hash(result, sibling)
            fn >>= 1
            sn >>= 1
        return sn == 0 and compare_digest(result, digest_bytes(trusted_manifest.merkle_root))
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False
