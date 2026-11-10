"""RFC 9162 Merkle tree and signed tree heads (backend/app/crypto/transparency.py), without a database.

The reference below is written directly from the definitions in RFC 9162 section 2.1 and shares no code with
the module: it recomputes every hash from the leaf list each time. The published vectors are the ones used by
the Certificate Transparency reference implementation (RFC 6962 trees are the same trees).
"""
from hashlib import sha256
import secrets

import pytest

from app.crypto import transparency as t
from app.crypto.transparency import MerkleLog, verify_consistency, verify_inclusion


# ---------------------------------------------------------------------------------------------- naive reference
def ref_mth(leaves):
    if not leaves:
        return sha256(b"").digest()
    if len(leaves) == 1:
        return sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return sha256(b"\x01" + ref_mth(leaves[:k]) + ref_mth(leaves[k:])).digest()


def ref_path(m, leaves):
    if len(leaves) == 1:
        return []
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    if m < k:
        return ref_path(m, leaves[:k]) + [ref_mth(leaves[k:])]
    return ref_path(m - k, leaves[k:]) + [ref_mth(leaves[:k])]


def ref_subproof(m, leaves, complete):
    if m == len(leaves):
        return [] if complete else [ref_mth(leaves)]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    if m <= k:
        return ref_subproof(m, leaves[:k], complete) + [ref_mth(leaves[k:])]
    return ref_subproof(m - k, leaves[k:], False) + [ref_mth(leaves[:k])]


LEAVES = [f"synthetic leaf {i}".encode() for i in range(128)]


@pytest.fixture(scope="module")
def log():
    built = MerkleLog()
    for data in LEAVES:
        built.append(t.leaf_hash(data))
    return built


@pytest.fixture(scope="module")
def reference_roots():
    return [ref_mth(LEAVES[:n]) for n in range(129)]


# ---------------------------------------------------------------------------------------------- exhaustive 1..128
def test_every_root_from_1_to_128_matches_the_reference(log, reference_roots):
    assert log.root(0) == sha256(b"").digest() == t.EMPTY_ROOT
    for n in range(1, 129):
        assert log.root(n) == reference_roots[n]
    assert log.root() == reference_roots[128]


def test_every_inclusion_proof_from_1_to_128_matches_the_reference_and_verifies(log, reference_roots):
    checked = 0
    for n in range(1, 129):
        for m in range(n):
            path = log.inclusion_proof(m, n)
            assert path == ref_path(m, LEAVES[:n])
            assert verify_inclusion(t.leaf_hash(LEAVES[m]), m, n, path, reference_roots[n])
            checked += 1
    assert checked == 128 * 129 // 2


def test_every_consistency_proof_from_1_to_128_matches_the_reference_and_verifies(log, reference_roots):
    checked = 0
    for n in range(1, 129):
        for m in range(1, n + 1):
            path = log.consistency_proof(m, n)
            assert path == ref_subproof(m, LEAVES[:n], True)
            assert verify_consistency(m, n, reference_roots[m], reference_roots[n], path)
            checked += 1
    assert checked == 128 * 129 // 2


def test_incremental_append_equals_the_reference_at_every_step():
    grown = MerkleLog()
    for n, data in enumerate(LEAVES[:70], start=1):
        assert grown.append(t.leaf_hash(data)) == n - 1
        assert grown.size == n and grown.root() == ref_mth(LEAVES[:n])


def test_truncate_restores_an_earlier_tree_exactly(log):
    copy = MerkleLog()
    for data in LEAVES[:100]:
        copy.append(t.leaf_hash(data))
    for size in (99, 64, 63, 33, 1, 0):
        copy.truncate(size)
        assert copy.size == size and copy.root() == log.root(size)
    for data in LEAVES[:37]:
        copy.append(t.leaf_hash(data))
    assert copy.root() == log.root(37) and copy.inclusion_proof(20) == log.inclusion_proof(20, 37)
    with pytest.raises(ValueError):
        copy.truncate(38)


# ---------------------------------------------------------------------------------------------- published vectors
CT_INPUTS = ["", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"]
CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]
# (leaf number from 1, tree size, path) and (first size, second size, path), as in the reference implementation.
CT_INCLUSION = [
    (1, 1, []),
    (1, 8, ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"]),
    (6, 8, ["bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]),
    (3, 3, ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"]),
    (2, 5, ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"]),
]
CT_CONSISTENCY = [
    (1, 1, []),
    (1, 8, ["96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"]),
    (6, 8, ["0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"]),
    (2, 5, ["5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b"]),
]


@pytest.fixture(scope="module")
def ct_log():
    built = MerkleLog()
    for value in CT_INPUTS:
        built.append(t.leaf_hash(bytes.fromhex(value)))
    return built


def test_published_certificate_transparency_roots(ct_log):
    assert t.EMPTY_ROOT.hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert [ct_log.root(n).hex() for n in range(1, 9)] == CT_ROOTS


@pytest.mark.parametrize("leaf,size,expected", CT_INCLUSION)
def test_published_certificate_transparency_inclusion_proofs(ct_log, leaf, size, expected):
    path = ct_log.inclusion_proof(leaf - 1, size)
    assert [p.hex() for p in path] == expected
    assert verify_inclusion(ct_log.leaf(leaf - 1), leaf - 1, size, path, bytes.fromhex(CT_ROOTS[size - 1]))


@pytest.mark.parametrize("first,second,expected", CT_CONSISTENCY)
def test_published_certificate_transparency_consistency_proofs(ct_log, first, second, expected):
    path = ct_log.consistency_proof(first, second)
    assert [p.hex() for p in path] == expected
    assert verify_consistency(first, second, bytes.fromhex(CT_ROOTS[first - 1]), bytes.fromhex(CT_ROOTS[second - 1]), path)


# ---------------------------------------------------------------------------------------------- rejection
def flipped(value):
    return bytes([value[0] ^ 1]) + value[1:]


def test_a_tampered_leaf_root_path_index_or_size_fails_inclusion(log):
    n, m = 100, 41
    path, root, leaf = log.inclusion_proof(m, n), log.root(n), log.leaf(m)
    assert verify_inclusion(leaf, m, n, path, root)
    assert not verify_inclusion(flipped(leaf), m, n, path, root)
    assert not verify_inclusion(leaf, m, n, path, flipped(root))
    assert not verify_inclusion(leaf, m + 1, n, path, root)
    # A size is rejected when it changes the shape of the path. (Sizes that give this leaf the same path shape
    # are told apart by the root, which a signed tree head binds to exactly one size.)
    assert not verify_inclusion(leaf, m, 64, path, root)
    assert not verify_inclusion(leaf, m, 42, path, root)
    assert not verify_inclusion(leaf, m, n, path[:-1], root)
    assert not verify_inclusion(leaf, m, n, path + [path[-1]], root)
    assert not verify_inclusion(leaf, m, n, [flipped(path[0])] + path[1:], root)
    assert not verify_inclusion(leaf, n, n, path, root)                       # index outside the tree
    assert not verify_inclusion(leaf, -1, n, path, root)
    assert not verify_inclusion(log.leaf(m + 1), m, n, path, root)            # another leaf's hash


def test_a_forked_or_stale_tree_fails_consistency(log):
    first, second = 37, 100
    path = log.consistency_proof(first, second)
    assert verify_consistency(first, second, log.root(first), log.root(second), path)
    assert not verify_consistency(first, second, flipped(log.root(first)), log.root(second), path)
    assert not verify_consistency(first, second, log.root(first), flipped(log.root(second)), path)
    assert not verify_consistency(first, second, log.root(first), log.root(second), path[:-1])
    assert not verify_consistency(first + 1, second, log.root(first), log.root(second), path)
    assert not verify_consistency(second, first, log.root(second), log.root(first), path)     # a smaller "newer" tree
    assert not verify_consistency(first, second, log.root(first), log.root(second), [])
    assert not verify_consistency(0, second, t.EMPTY_ROOT, log.root(second), [])
    # A fork: the same first 37 leaves, then different later leaves. Its root is not consistent with the proof.
    fork = MerkleLog()
    for data in LEAVES[:first]:
        fork.append(t.leaf_hash(data))
    for i in range(first, second):
        fork.append(t.leaf_hash(b"forked " + LEAVES[i]))
    assert fork.root(first) == log.root(first)
    assert not verify_consistency(first, second, log.root(first), fork.root(second), path)
    assert verify_consistency(first, second, fork.root(first), fork.root(second), fork.consistency_proof(first, second))
    # A history rewrite: one early leaf differs, so no proof links the honest earlier root to the new tree.
    rewritten = MerkleLog()
    for i, data in enumerate(LEAVES[:second]):
        rewritten.append(t.leaf_hash(b"rewritten" if i == 5 else data))
    assert not verify_consistency(first, second, log.root(first), rewritten.root(second), rewritten.consistency_proof(first, second))


def test_equal_sizes_are_consistent_only_with_equal_roots_and_no_path(log):
    assert log.consistency_proof(64, 64) == []
    assert verify_consistency(64, 64, log.root(64), log.root(64), [])
    assert not verify_consistency(64, 64, log.root(64), flipped(log.root(64)), [])
    assert not verify_consistency(64, 64, log.root(64), log.root(64), [log.root(64)])


@pytest.mark.parametrize("call", [
    lambda log: log.inclusion_proof(5, 5), lambda log: log.inclusion_proof(-1, 5), lambda log: log.inclusion_proof(0, 129),
    lambda log: log.inclusion_proof(0, 0), lambda log: log.consistency_proof(0, 5), lambda log: log.consistency_proof(6, 5),
    lambda log: log.consistency_proof(1, 129), lambda log: log.root(129), lambda log: log.root(-1), lambda log: log.leaf(128),
    lambda log: log.inclusion_proof(True, 5), lambda log: log.append(b"short"), lambda log: t.split_point(1),
])
def test_out_of_range_requests_are_refused(log, call):
    with pytest.raises(ValueError):
        call(log)


# ---------------------------------------------------------------------------------------------- leaf encoding
def test_the_event_leaf_encoding_is_length_prefixed_and_binds_the_mac():
    canonical, mac = '{"kind":"X","sequence":1}', "ab" * 32
    data = t.event_leaf(canonical, mac)
    assert data == (25).to_bytes(4, "big") + canonical.encode("ascii") + bytes.fromhex(mac)
    assert t.leaf_hash(data) == sha256(b"\x00" + data).digest()
    assert t.event_leaf(canonical, "cd" * 32) != data and t.event_leaf(canonical + " ", mac) != data
    for bad in ("ab" * 31, "zz" * 32, ""):
        with pytest.raises(ValueError):
            t.event_leaf(canonical, bad)
    with pytest.raises(UnicodeEncodeError):
        t.event_leaf("café", mac)


# ---------------------------------------------------------------------------------------------- signed tree heads
HEAD = {"log_id": "6f1c0f0e-5a53-4f0b-9c38-0d6d1c2e9a11", "tree_size": 64, "root_hash": "11" * 32,
        "timestamp": "2026-11-10T12:00:00.000000Z", "key_id": ""}


def signed():
    seed = secrets.token_bytes(32)
    public = t.public_key_of(seed)
    head = {**HEAD, "key_id": t.key_id_for(public)}
    return seed, public, head, t.sign_head(seed, head)


def test_the_signed_bytes_are_exactly_the_documented_encoding():
    head = {**HEAD, "key_id": "22" * 32}
    expected = (b'RootSentinelSTH\x00\x01{"key_id":"' + b"22" * 32 + b'","log_id":"6f1c0f0e-5a53-4f0b-9c38-0d6d1c2e9a11",'
                b'"root_hash":"' + b"11" * 32 + b'","timestamp":"2026-11-10T12:00:00.000000Z","tree_size":64}')
    assert t.sth_bytes(head) == expected
    for bad in ({**head, "extra": "x"}, {k: v for k, v in head.items() if k != "log_id"}, {**head, "tree_size": "64"},
                {**head, "tree_size": -1}, {**head, "root_hash": 7}, {**head, "tree_size": True}):
        with pytest.raises(ValueError):
            t.sth_bytes(bad)


def test_rfc_8032_ed25519_test_vector_one():
    # RFC 8032 section 7.1, TEST 1: the library derives the published public key from the published secret key.
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    assert t.public_key_of(seed).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert t.key_id_for(t.public_key_of(seed)) == sha256(t.public_key_of(seed)).hexdigest()


def test_a_signed_head_verifies_and_every_change_is_rejected():
    seed, public, head, signature = signed()
    assert len(signature) == 64 and t.verify_head(public, head, signature)
    assert t.sign_head(seed, head) == signature                               # Ed25519 signatures are deterministic
    for name, value in (("tree_size", 65), ("root_hash", "12" * 32), ("timestamp", "2026-11-10T12:00:00.000001Z"),
                        ("log_id", "6f1c0f0e-5a53-4f0b-9c38-0d6d1c2e9a12")):
        assert not t.verify_head(public, {**head, name: value}, signature)
    assert not t.verify_head(public, head, flipped(signature))
    assert not t.verify_head(public, head, signature[:-1])
    assert not t.verify_head(public, {k: v for k, v in head.items() if k != "timestamp"}, signature)


def test_a_head_signed_by_another_key_is_rejected():
    seed, public, head, signature = signed()
    other_seed = secrets.token_bytes(32)
    other_public = t.public_key_of(other_seed)
    assert not t.verify_head(other_public, head, signature)                   # the key id does not name this key
    forged = {**head, "key_id": t.key_id_for(other_public)}
    assert not t.verify_head(other_public, forged, signature)                 # right id, wrong signature
    assert not t.verify_head(public, forged, t.sign_head(other_seed, forged)) # signed by the other key, checked with ours
    assert t.verify_head(other_public, forged, t.sign_head(other_seed, forged))
    assert not t.verify_head(b"short", head, signature)
    with pytest.raises(ValueError):
        t.key_id_for(b"short")
