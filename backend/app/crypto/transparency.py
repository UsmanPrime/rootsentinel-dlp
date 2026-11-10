"""RFC 9162 Merkle tree over audit events, and Ed25519 signed tree heads.

This module is separate from ``merkle.py`` (the asset fingerprint tree, profile rs-fixed-sha256-v1), which it
neither imports nor changes. Everything here follows RFC 9162 section 2.1:

* leaf hash  = SHA-256(0x00 || leaf data)
* node hash  = SHA-256(0x01 || left || right)
* a tree of n > 1 leaves splits at k, the largest power of two smaller than n
* inclusion proofs: generation 2.1.3.1, verification 2.1.3.2
* consistency proofs: generation 2.1.4.1, verification 2.1.4.2

The module holds no database or file access. Hashes are raw 32-byte values; the callers encode them as hex.
"""
from hashlib import sha256
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = sha256(b"").digest()
STH_DOMAIN = b"RootSentinelSTH\x00\x01"
STH_FIELDS = ("key_id", "log_id", "root_hash", "timestamp", "tree_size")


def leaf_hash(data: bytes) -> bytes:
    return sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(NODE_PREFIX + left + right).digest()


def split_point(n: int) -> int:
    """The largest power of two smaller than n (n > 1)."""
    if n < 2:
        raise ValueError("A split needs at least two leaves")
    return 1 << ((n - 1).bit_length() - 1)


def event_leaf(canonical: str, mac: str) -> bytes:
    """Leaf data of one audit event: u32be(len(canonical)) || canonical (ASCII) || the 32 raw bytes of its HMAC."""
    encoded = canonical.encode("ascii")
    raw_mac = bytes.fromhex(mac)
    if len(raw_mac) != 32:
        raise ValueError("An event MAC is 32 bytes")
    return len(encoded).to_bytes(4, "big") + encoded + raw_mac


class MerkleLog:
    """An append-only list of leaf hashes with the hash of every complete aligned subtree kept per level.

    ``levels[k][i]`` is the hash of leaves [i * 2^k, (i + 1) * 2^k). Appending touches one entry per level
    (O(log n)); the root and both kinds of proof for any earlier size are read from these entries. ``truncate``
    removes leaves from the end, which the caller uses when a database transaction rolls back.
    """

    def __init__(self):
        self.levels = [[]]

    @property
    def size(self) -> int:
        return len(self.levels[0])

    def append(self, hashed: bytes) -> int:
        if type(hashed) is not bytes or len(hashed) != 32:
            raise ValueError("A leaf hash is 32 bytes")
        self.levels[0].append(hashed)
        level = 0
        while len(self.levels[level]) % 2 == 0:
            if level + 1 == len(self.levels):
                self.levels.append([])
            pair = self.levels[level]
            self.levels[level + 1].append(node_hash(pair[-2], pair[-1]))
            level += 1
        return self.size - 1

    def truncate(self, size: int):
        if not 0 <= size <= self.size:
            raise ValueError("Cannot truncate to that size")
        for level in range(len(self.levels)):
            del self.levels[level][size >> level:]
        while len(self.levels) > 1 and not self.levels[-1]:
            self.levels.pop()

    def leaf(self, index: int) -> bytes:
        if not 0 <= index < self.size:
            raise ValueError("No such leaf")
        return self.levels[0][index]

    def _range(self, start: int, end: int) -> bytes:
        """MTH(D[start:end]) for 0 <= start < end <= size, where start is a multiple of the subtree width."""
        width = end - start
        if width & (width - 1) == 0:
            return self.levels[width.bit_length() - 1][start // width]
        k = split_point(width)
        return node_hash(self._range(start, start + k), self._range(start + k, end))

    def _checked(self, size):
        size = self.size if size is None else size
        if type(size) is not int or not 0 <= size <= self.size:
            raise ValueError("Tree size outside the log")
        return size

    def root(self, size: int | None = None) -> bytes:
        size = self._checked(size)
        return EMPTY_ROOT if size == 0 else self._range(0, size)

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        """PATH(m, D_n), RFC 9162 section 2.1.3.1."""
        size = self._checked(size)
        if type(index) is not int or not 0 <= index < size:
            raise ValueError("Leaf index outside the tree")

        def path(m, start, end):
            if end - start == 1:
                return []
            k = split_point(end - start)
            if m < k:
                return path(m, start, start + k) + [self._range(start + k, end)]
            return path(m - k, start + k, end) + [self._range(start, start + k)]
        return path(index, 0, size)

    def consistency_proof(self, first: int, second: int | None = None) -> list[bytes]:
        """PROOF(m, D_n), RFC 9162 section 2.1.4.1, for 0 < first <= second. Empty when first equals second."""
        second = self._checked(second)
        if type(first) is not int or not 0 < first <= second:
            raise ValueError("Tree sizes outside the log")

        def subproof(m, start, end, complete):
            if m == end - start:
                return [] if complete else [self._range(start, end)]
            k = split_point(end - start)
            if m <= k:
                return subproof(m, start, start + k, complete) + [self._range(start + k, end)]
            return subproof(m - k, start + k, end, False) + [self._range(start, start + k)]
        return subproof(first, 0, second, True)


def verify_inclusion(hashed: bytes, index: int, size: int, path: list[bytes], root: bytes) -> bool:
    """RFC 9162 section 2.1.3.2."""
    if type(index) is not int or type(size) is not int or not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, hashed
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, path: list[bytes]) -> bool:
    """RFC 9162 section 2.1.4.2 for 0 < first < second.

    Two cases outside that section are defined here: equal sizes are consistent only with an empty path and
    equal roots, and a first size of zero is never accepted (an empty tree proves nothing about a later one).
    """
    if type(first) is not int or type(second) is not int or not 0 < first <= second:
        return False
    if first == second:
        return not path and first_root == second_root
    if not path:
        return False
    path = list(path)
    if first & (first - 1) == 0:
        path.insert(0, first_root)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


# ---------------------------------------------------------------------------------------------- signed tree heads
def key_id_for(public_key: bytes) -> str:
    """The key id is the lowercase hex SHA-256 of the 32 raw public key bytes."""
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ValueError("An Ed25519 public key is 32 bytes")
    return sha256(public_key).hexdigest()


def sth_bytes(head: dict) -> bytes:
    """The exact bytes that are signed: a domain prefix, then the five fields as canonical JSON.

    Canonical JSON here is: keys in the order key_id, log_id, root_hash, timestamp, tree_size (alphabetical),
    no whitespace, ASCII only, tree_size as a decimal integer and every other value a string.
    """
    if set(head) != set(STH_FIELDS) or type(head["tree_size"]) is not int or head["tree_size"] < 0:
        raise ValueError("A tree head has exactly five fields")
    if any(type(head[name]) is not str for name in STH_FIELDS if name != "tree_size"):
        raise ValueError("Tree head values are strings")
    return STH_DOMAIN + json.dumps({name: head[name] for name in STH_FIELDS}, sort_keys=True,
                                   separators=(",", ":"), ensure_ascii=True).encode("ascii")


def public_key_of(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def sign_head(seed: bytes, head: dict) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(sth_bytes(head))


def verify_head(public_key: bytes, head: dict, signature: bytes) -> bool:
    """True only when the signature is valid for these exact fields and the key id names this public key."""
    try:
        if head["key_id"] != key_id_for(public_key):
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, sth_bytes(head))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False
