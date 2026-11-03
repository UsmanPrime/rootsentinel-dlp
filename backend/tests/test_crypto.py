"""Unit tests runnable with pytest or the dependency-free unittest fallback."""

from dataclasses import replace
from hashlib import sha256
from io import BytesIO
import json
import random
import unittest

from app.crypto import (
    CHUNK_SIZE, MAX_FILE_SIZE, Chunk, Fingerprint, Manifest, Proof,
    create_proof, fingerprint_bytes, fingerprint_stream, verify_file, verify_proof,
)
from app.crypto.merkle import leaf_hash, tree_root


class CryptoTests(unittest.TestCase):
    def test_known_sha256_vectors(self):
        for data, expected in [
            (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ]:
            with self.subTest(data=data):
                self.assertEqual(fingerprint_bytes(data).manifest.file_sha256, expected)

    def test_chunk_boundaries(self):
        for size in [0, 1, 1023, 1024, 1025, 2048, 3073]:
            with self.subTest(size=size):
                data = bytes(i % 251 for i in range(size))
                result = fingerprint_bytes(data)
                expected = [data[i:i+1024] for i in range(0, size, 1024)]
                self.assertEqual([c.length for c in result.chunks], [len(x) for x in expected])
                self.assertEqual([c.sha256 for c in result.chunks], [sha256(x).hexdigest() for x in expected])
                self.assertEqual([c.offset for c in result.chunks], list(range(0, size, 1024)))
                self.assertEqual(result.manifest.file_size, size)

    def test_short_reads_do_not_change_boundaries(self):
        class ShortReader(BytesIO):
            def read(self, size=-1):
                return super().read(min(size, 7))
        data = bytes(range(256)) * 21
        stream = ShortReader(data)
        self.assertEqual(fingerprint_stream(stream), fingerprint_bytes(data))
        self.assertFalse(stream.closed)

    def test_stream_current_position(self):
        stream = BytesIO(b"skip:payload")
        stream.seek(5)
        self.assertEqual(fingerprint_stream(stream), fingerprint_bytes(b"payload"))

    def test_invalid_streams_and_types(self):
        class BadReader:
            def __init__(self, value): self.value = value
            def read(self, size): return self.value
        for data in [None, "text", bytearray(b"x"), b"x" * 1025]:
            with self.subTest(data_type=type(data)):
                with self.assertRaises(ValueError): fingerprint_stream(BadReader(data))
        with self.assertRaises(ValueError): fingerprint_bytes("abc")

    def test_maximum_and_oversize(self):
        accepted = fingerprint_bytes(b"x" * MAX_FILE_SIZE)
        self.assertEqual(accepted.manifest.chunk_count, 10240)
        self.assertTrue(verify_proof(create_proof(accepted, 10239), accepted.manifest))
        with self.assertRaises(ValueError): fingerprint_bytes(b"x" * (MAX_FILE_SIZE + 1))
        with self.assertRaises(ValueError): fingerprint_stream(BytesIO(b"x" * (MAX_FILE_SIZE + 1)))

    def test_raw_encoding_and_newlines(self):
        values = [b"a\nb\n", b"a\r\nb\r\n", "a\nb\n".encode("utf-16")]
        self.assertEqual(len({fingerprint_bytes(x).manifest.file_sha256 for x in values}), 3)

    def test_deterministic_serialization(self):
        first = fingerprint_bytes(b"source\n" * 400)
        second = fingerprint_bytes(b"source\n" * 400)
        self.assertEqual(first, second)
        self.assertEqual(Manifest.from_dict(json.loads(json.dumps(first.manifest.to_dict()))), first.manifest)
        proof = create_proof(first, 1)
        self.assertEqual(Proof.from_dict(json.loads(json.dumps(proof.to_dict()))), proof)

    def test_descriptor_has_independent_fixed_encoding(self):
        chunk = Chunk(1, 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(chunk.descriptor().hex(), "000000000000000100000003ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(len(chunk.descriptor()), 44)

    def test_tree_shape_independent_expectations(self):
        # Explicit parenthesization, without the production tree/proof helpers.
        data = b"A" * 1024 + b"B" * 1024 + b"C"
        result = fingerprint_bytes(data)
        leaves = [sha256(b"\x00" + i.to_bytes(8, "big") + len(block).to_bytes(4, "big") + sha256(block).digest()).digest()
                  for i, block in enumerate([b"A"*1024, b"B"*1024, b"C"])]
        expected = sha256(b"\x01" + sha256(b"\x01" + leaves[0] + leaves[1]).digest() + leaves[2]).hexdigest()
        self.assertEqual(result.manifest.merkle_root, expected)
        self.assertEqual(expected, "b77f5d4eb26d8387914ce5dd21753f67c1594343db08d9ffab1ace114aae98de")
        self.assertEqual(fingerprint_bytes(b"abc").manifest.merkle_root,
                         "a34106b7957e189e60f1bd7506a867159d5ea04a8bbcdeb379425343f842f6bf")
        self.assertEqual(create_proof(result, 0).siblings, (leaves[1].hex(), leaves[2].hex()))
        self.assertEqual(create_proof(result, 2).siblings, (sha256(b"\x01" + leaves[0] + leaves[1]).hexdigest(),))

    def test_domain_separation(self):
        chunk = fingerprint_bytes(b"abc").chunks[0]
        self.assertNotEqual(leaf_hash(chunk), sha256(chunk.descriptor()).digest())
        self.assertNotEqual(leaf_hash(chunk), sha256(b"\x01" + chunk.descriptor()).digest())

    def test_all_leaves_and_variable_tree_shapes(self):
        rng = random.Random(3002)  # Synthetic test data, never secret generation.
        for count in [1, 2, 3, 5, 8, 17, *range(4, 33)]:
            data = rng.randbytes((count - 1) * 1024 + 31)
            result = fingerprint_bytes(data)
            for i in range(count):
                with self.subTest(count=count, index=i):
                    proof = create_proof(result, i)
                    self.assertTrue(verify_proof(proof, result.manifest, data[i*1024:(i+1)*1024]))
                    self.assertTrue(verify_proof(proof.to_dict(), result.manifest.to_dict()))

    def test_empty_tree(self):
        result = fingerprint_bytes(b"")
        self.assertEqual(result.chunks, ())
        self.assertEqual(result.manifest.merkle_root, result.manifest.file_sha256)
        with self.assertRaises(ValueError): create_proof(result, 0)

    def test_mutation_and_reordering(self):
        first = fingerprint_bytes(b"A"*1024 + b"B"*1024)
        reordered = fingerprint_bytes(b"B"*1024 + b"A"*1024)
        modified = fingerprint_bytes(b"Z" + b"A"*1023 + b"B"*1024)
        self.assertNotEqual(first.manifest.merkle_root, reordered.manifest.merkle_root)
        self.assertNotEqual(first.manifest.file_sha256, modified.manifest.file_sha256)
        self.assertEqual(first.chunks[1], modified.chunks[1])
        self.assertNotEqual(first.chunks[0], modified.chunks[0])

    def test_tampered_proofs_fail(self):
        result = fingerprint_bytes(b"A"*1024 + b"B"*1024 + b"C")
        original = create_proof(result, 0).to_dict()
        mutations = []
        def changed(field, value):
            item = json.loads(json.dumps(original)); item[field] = value; mutations.append(item)
        changed("tree_size", 4)
        changed("tree_size", 0)
        changed("tree_size", True)
        changed("profile_id", "unknown")
        changed("spec_version", 2)
        changed("siblings", original["siblings"][:-1])
        changed("siblings", original["siblings"] + ["00"*32])
        changed("siblings", ["00"*32, original["siblings"][1]])
        changed("siblings", ["xyz"])
        changed("siblings", ["AA"*32])
        changed("siblings", ["00"*32]*100)
        changed("siblings", "not-an-array")
        changed("chunk", {**original["chunk"], "index": 1})
        changed("chunk", {**original["chunk"], "index": 3})
        changed("chunk", {**original["chunk"], "index": -1})
        changed("chunk", {**original["chunk"], "length": 0})
        changed("chunk", {**original["chunk"], "length": 1023})
        changed("chunk", {**original["chunk"], "sha256": "00"*32})
        changed("root", "00"*32)  # Proof cannot bring its own root.
        for item in [*mutations, {}, None, [], 3]:
            with self.subTest(proof=item):
                self.assertFalse(verify_proof(item, result.manifest))
        self.assertFalse(verify_proof(original, result.manifest, b"Z"*1024))
        self.assertFalse(verify_proof(original, result.manifest, b"A"))
        self.assertFalse(verify_proof(original, replace(result.manifest, merkle_root="00"*32)))

    def test_invalid_manifests(self):
        manifest = fingerprint_bytes(b"abc").manifest.to_dict()
        for field, value in [("file_size", -1), ("file_size", MAX_FILE_SIZE+1), ("file_size", 1025),
                             ("chunk_count", 2), ("chunk_size", 512), ("spec_version", True),
                             ("file_sha256", "00"), ("profile_id", "unsupported")]:
            with self.subTest(field=field):
                with self.assertRaises(ValueError): Manifest.from_dict({**manifest, field: value})
        with self.assertRaises(ValueError): Manifest.from_dict({**manifest, "extra": 1})
        with self.assertRaises(ValueError): replace(fingerprint_bytes(b"").manifest, merkle_root="00"*32)

    def test_invalid_fingerprint_and_proof_creation(self):
        result = fingerprint_bytes(b"A"*1024 + b"B")
        with self.assertRaises(ValueError): Fingerprint(result.manifest, tuple(reversed(result.chunks)))
        with self.assertRaises(ValueError): create_proof(result, True)
        with self.assertRaises(ValueError): create_proof(result, -1)
        corrupt = replace(result, manifest=replace(result.manifest, merkle_root="00"*32))
        with self.assertRaises(ValueError): create_proof(corrupt, 0)

    def test_full_file_verification_is_separate(self):
        result = fingerprint_bytes(b"abc")
        self.assertTrue(verify_file(b"abc", result.manifest))
        self.assertFalse(verify_file(b"abd", result.manifest))
        # A proof alone does not establish the whole-file digest field.
        changed = replace(result.manifest, file_sha256="00"*32)
        self.assertTrue(verify_proof(create_proof(result, 0), changed))
        self.assertFalse(verify_file(b"abc", changed))


if __name__ == "__main__":
    unittest.main()
