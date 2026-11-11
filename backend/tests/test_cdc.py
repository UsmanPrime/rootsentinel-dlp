"""rs-cdc-gear-v1: the gear table, exact chunk boundaries of fixed inputs, and the chunking properties.

The vectors live in fixtures/cdc-vectors.json, a file of their own: no existing vector file is touched.
"""
from hashlib import sha256
import json
from pathlib import Path
import random
import sys

import pytest

from app.crypto import cdc
from app.crypto.cdc import CdcChunk, cdc_chunks, cut_points

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import cdc_vectors  # noqa: E402

VECTORS = json.loads((ROOT / "fixtures" / "cdc-vectors.json").read_text(encoding="utf-8"))


def stream(seed, size):
    return cdc_vectors.counter_stream(seed, size)


def lengths(data):
    return [c.length for c in cdc_chunks(data)]


# ---------------------------------------------------------------------------------------------- vectors
def test_the_vector_file_is_what_the_generator_writes():
    expected = json.dumps(cdc_vectors.make_vectors(), indent=2, sort_keys=True) + "\n"
    assert (ROOT / "fixtures" / "cdc-vectors.json").read_text(encoding="utf-8") == expected
    assert cdc_vectors.main.__module__ == "cdc_vectors"


def test_the_gear_table_is_derived_from_sha256_in_counter_mode():
    # Recomputed here from the documented rule alone, without calling the module's derivation.
    values = []
    for counter in range(64):
        digest = sha256(b"RootSentinel rs-cdc-gear-v1 gear table" + counter.to_bytes(4, "big")).digest()
        values += [int.from_bytes(digest[k:k + 8], "big") for k in (0, 8, 16, 24)]
    assert tuple(values) == cdc.GEAR and len(set(values)) == 256 and all(0 <= v < 2 ** 64 for v in values)
    table = b"".join(v.to_bytes(8, "big") for v in values)
    assert sha256(table).hexdigest() == VECTORS["gear"]["table_sha256"] == cdc.gear_table_sha256()
    assert VECTORS["gear"]["table_sha256"] == "6a80b73d855e1aaaba9dc9b54d5e9bd4047e1d2b1ea9803fb0e4b33ee28c1d13"
    assert VECTORS["gear"]["first"][0] == "0x7bf93287f471c4d9" and VECTORS["gear"]["last"][-1] == "0x6a0ae301002d122c"


def test_the_published_parameters():
    assert (cdc.MIN_SIZE, cdc.NORMAL_SIZE, cdc.MAX_SIZE, cdc.NORMALIZATION_LEVEL) == (512, 2048, 8192, 2)
    assert VECTORS["parameters"] == {"min_size": 512, "normal_size": 2048, "max_size": 8192, "normalization_level": 2,
                                     "mask_s": "0x0000d93003530000", "mask_l": "0x0000d90003500000"}
    # Level 2 around an 11-bit (2 KiB) average: 13 bits before the normal size, 9 after, and the easier mask
    # is a subset of the harder one, so a cut point of the first phase is still one in the second.
    assert bin(cdc.MASK_S).count("1") == 13 and bin(cdc.MASK_L).count("1") == 9
    assert cdc.MASK_L & ~cdc.MASK_S == 0 and cdc.MASK_S < 2 ** 48


@pytest.mark.parametrize("name", sorted(VECTORS["cases"]))
def test_exact_chunk_boundaries_of_fixed_inputs(name):
    case = VECTORS["cases"][name]
    data = cdc_vectors.inputs()[name][1]
    assert len(data) == case["size"] and sha256(data).hexdigest() == case["sha256"]
    chunks = cdc_chunks(data)
    assert [c.offset + c.length for c in chunks] == case["cut_points"] == cut_points(data)
    assert [c.sha256 for c in chunks] == case["chunk_sha256"]
    assert cdc_vectors.reference_cuts(data) == case["cut_points"]


def test_pinned_boundaries():
    # A few literals, so that an accidental rewrite of the vector file by a changed chunker is still caught.
    cases = VECTORS["cases"]
    assert cases["empty"]["cut_points"] == [] and cases["one_byte"]["cut_points"] == [1]
    assert cases["min_size"]["cut_points"] == [512] and cases["min_size_plus_one"]["cut_points"] == [513]
    assert cases["zeros_20000"]["cut_points"] == [8192, 16384, 20000]
    assert cases["source_sample"]["cut_points"] == [1474, 3751, 5984, 6954]
    assert cases["stream_64k"]["cut_points"][:4] == [3326, 4852, 8316, 10468] and len(cases["stream_64k"]["cut_points"]) == 27


# ---------------------------------------------------------------------------------------------- properties
SIZES = [0, 1, 511, 512, 513, 2047, 2048, 2049, 8191, 8192, 8193, 40000, 150001]


@pytest.mark.parametrize("size", SIZES)
def test_chunks_are_deterministic_bounded_and_concatenate_to_the_input(size):
    data = stream(f"property {size}", size)
    chunks = cdc_chunks(data)
    assert chunks == cdc_chunks(bytes(bytearray(data)))                      # deterministic, independent of the object
    assert b"".join(data[c.offset:c.offset + c.length] for c in chunks) == data
    assert [c.offset for c in chunks] == [sum(x.length for x in chunks[:i]) for i in range(len(chunks))]
    assert all(c.sha256 == sha256(data[c.offset:c.offset + c.length]).hexdigest() for c in chunks)
    assert all(cdc.MIN_SIZE <= c.length <= cdc.MAX_SIZE for c in chunks[:-1])
    assert all(1 <= c.length <= cdc.MAX_SIZE for c in chunks[-1:])
    assert [c.offset + c.length for c in chunks] == cdc_vectors.reference_cuts(data)


def test_random_inputs_agree_with_the_reference_implementation():
    generator = random.Random(20261111)
    for _ in range(40):
        size = generator.randrange(0, 30000)
        # Low-entropy alphabets as well as full bytes: few distinct byte values make long chunks.
        alphabet = generator.choice([256, 256, 16, 4, 2])
        data = bytes(generator.randrange(alphabet) for _ in range(size))
        assert cut_points(data) == cdc_vectors.reference_cuts(data)


def test_average_chunk_size_is_near_the_nominal_two_kibibytes():
    sizes = lengths(stream("average", 1 << 20))[:-1]
    assert 1900 <= sum(sizes) / len(sizes) <= 2700 and min(sizes) >= 512 and max(sizes) <= 8192


@pytest.mark.parametrize("prefix", [b"!", b"# inserted line\n", stream("prefix", 300), stream("prefix", 5000)])
def test_boundaries_resynchronise_after_an_inserted_prefix(prefix):
    data = stream("resync", 200000)
    original = {c.sha256: c for c in cdc_chunks(data)}
    shifted = cdc_chunks(prefix + data)
    shared = [c for c in shifted if c.sha256 in original]
    # Once a boundary of the original is hit again, every later chunk is the original chunk, moved by the prefix.
    first = shifted.index(shared[0])
    assert shifted[first:] == tuple(shared) and first <= 6
    assert all(c.offset - len(prefix) == original[c.sha256].offset for c in shared)
    assert sum(c.length for c in shared) >= len(data) - 16384


@pytest.mark.parametrize("removed", [1, 17, 300, 5000])
def test_boundaries_resynchronise_after_a_deleted_prefix(removed):
    data = stream("resync", 200000)
    original = {c.sha256: c for c in cdc_chunks(data)}
    cut = cdc_chunks(data[removed:])
    shared = [c for c in cut if c.sha256 in original]
    first = cut.index(shared[0])
    assert cut[first:] == tuple(shared) and first <= 6
    assert all(c.offset + removed == original[c.sha256].offset for c in shared)
    assert sum(c.length for c in shared) >= len(data) - removed - 16384


def test_an_insertion_in_the_middle_changes_only_nearby_chunks():
    data = stream("middle", 200000)
    original = {c.sha256 for c in cdc_chunks(data)}
    edited = cdc_chunks(data[:100000] + b"# inserted line\n" + data[100000:])
    assert sum(c.length for c in edited if c.sha256 in original) >= len(data) - 16384


def test_fixed_blocks_do_not_resynchronise_which_is_why_this_profile_exists():
    from app.crypto import fingerprint_bytes
    data = stream("resync", 200000)
    original = {c.sha256 for c in fingerprint_bytes(data).chunks}
    assert not [c for c in fingerprint_bytes(b"!" + data).chunks if c.sha256 in original]


def test_content_without_a_cut_point_falls_back_to_maximum_size_chunks():
    # The documented limitation: repetitive content has no cut point, so its chunks are position-defined
    # and a shifted copy shares none of them.
    for data in (bytes(30000), b"SYNTHETIC-PROTECTED-" * 128, b"abcdefgh" * 4000):
        sizes = lengths(data)
        assert sizes[:-1] == [8192] * (len(sizes) - 1)
        if len(set(data)) > 1:      # a run of one byte value is the same chunk at any position
            assert not {c.sha256 for c in cdc_chunks(data)} & {c.sha256 for c in cdc_chunks(b"!" + data)}


# ---------------------------------------------------------------------------------------------- input and type checks
def test_inputs_are_validated():
    with pytest.raises(ValueError, match="bytes"):
        cdc_chunks(bytearray(b"abc"))
    with pytest.raises(ValueError, match="10 MiB"):
        cdc_chunks(bytes(10 * 1024 * 1024 + 1))
    assert cdc_chunks(b"") == ()
    assert cut_points(bytearray(b"abc")) == [3] and cut_points(memoryview(b"")) == []


@pytest.mark.parametrize("fields", [(-1, 1, "0" * 64), (0, 0, "0" * 64), (0, 8193, "0" * 64), (0, 1, "0" * 63),
                                    (0, 1, "A" * 64), (10 * 1024 * 1024, 1, "0" * 64), (True, 1, "0" * 64)])
def test_chunk_descriptors_are_strict(fields):
    with pytest.raises(ValueError):
        CdcChunk(*fields)


def test_chunk_descriptor_round_trip():
    chunk = CdcChunk(512, 8192, "ab" * 32)
    assert chunk.to_dict() == {"offset": 512, "length": 8192, "sha256": "ab" * 32}
