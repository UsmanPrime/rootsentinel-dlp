"""Test vectors of the detection profile rs-cdc-gear-v1: the gear table and exact chunk boundaries.

Every input is rebuilt from a rule stated in the vector file, so the file holds no payload. A second
implementation (``reference_cuts`` below, a direct transcription of the published algorithm without
any optimisation) must agree with the application's chunker before anything is written or accepted.

  python -B scripts/cdc_vectors.py           # check fixtures/cdc-vectors.json (default, read-only)
  python -B scripts/cdc_vectors.py --write   # rewrite it deliberately
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.crypto import cdc  # noqa: E402
from app.synthetic import source_sample  # noqa: E402

VECTORS = ROOT / "fixtures" / "cdc-vectors.json"


def counter_stream(seed: str, size: int) -> bytes:
    """SHA-256(seed || u32be(counter)) for counter 0, 1, ... concatenated and cut to ``size`` bytes."""
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += sha256(seed.encode("ascii") + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:size])


def inputs() -> dict[str, tuple[str, bytes]]:
    stream = counter_stream("rs-cdc-gear-v1 test vector", 65536)
    return {
        "empty": ("no bytes", b""),
        "one_byte": ("the single byte 0x00", b"\x00"),
        "min_size": ("counter stream, seed 'rs-cdc-gear-v1 test vector', first 512 bytes", stream[:512]),
        "min_size_plus_one": ("counter stream, seed 'rs-cdc-gear-v1 test vector', first 513 bytes", stream[:513]),
        "stream_64k": ("counter stream, seed 'rs-cdc-gear-v1 test vector', 65,536 bytes", stream),
        "stream_64k_prefixed": ("the byte 0x21 followed by stream_64k", b"!" + stream),
        "stream_64k_without_first_100": ("stream_64k without its first 100 bytes", stream[100:]),
        "zeros_20000": ("20,000 bytes 0x00 (no cut point: maximum-size chunks)", bytes(20000)),
        "source_sample": ("app.synthetic.source_sample(), the second hosted seed asset", source_sample()),
    }


def reference_cuts(data: bytes) -> list[int]:
    """Algorithm 2 of the 2020 paper, per chunk, with this profile's constants. Slow and plain on purpose."""
    cuts, start = [], 0
    while start < len(data):
        n = min(len(data) - start, cdc.MAX_SIZE)
        length = n
        if n > cdc.MIN_SIZE:
            normal = min(cdc.NORMAL_SIZE, n)
            fp = 0
            for i in range(cdc.MIN_SIZE, n):
                fp = ((fp << 1) + cdc.GEAR[data[start + i]]) % (1 << 64)
                if fp & (cdc.MASK_S if i < normal else cdc.MASK_L) == 0:
                    length = i
                    break
        start += length
        cuts.append(start)
    return cuts


def make_vectors() -> dict:
    cases = {}
    for name, (rule, data) in inputs().items():
        chunks = cdc.cdc_chunks(data)
        ends = [c.offset + c.length for c in chunks]
        if ends != reference_cuts(data) or ends != cdc.cut_points(data):
            raise SystemExit(f"chunker and reference implementation disagree on {name}")
        cases[name] = {"input": rule, "size": len(data), "sha256": sha256(data).hexdigest(),
                       "cut_points": ends, "chunk_sha256": [c.sha256 for c in chunks]}
    return {
        "profile_id": cdc.CDC_PROFILE_ID, "profile_version": cdc.CDC_PROFILE_VERSION,
        "parameters": {"min_size": cdc.MIN_SIZE, "normal_size": cdc.NORMAL_SIZE, "max_size": cdc.MAX_SIZE,
                       "normalization_level": cdc.NORMALIZATION_LEVEL,
                       "mask_s": f"0x{cdc.MASK_S:016x}", "mask_l": f"0x{cdc.MASK_L:016x}"},
        "gear": {"domain": cdc.GEAR_DOMAIN.decode("ascii"),
                 "derivation": "SHA-256(domain || u32be(counter)), counter 0..63; each digest is four big-endian 64-bit values",
                 "table_sha256": cdc.gear_table_sha256(),
                 "first": [f"0x{v:016x}" for v in cdc.GEAR[:4]], "last": [f"0x{v:016x}" for v in cdc.GEAR[-4:]]},
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = json.dumps(make_vectors(), indent=2, sort_keys=True) + "\n"
    if args.write:
        VECTORS.write_text(expected, encoding="utf-8", newline="\n")
        print("CDC test vectors written; no payload files created.")
    elif not VECTORS.exists() or VECTORS.read_text(encoding="utf-8") != expected:
        print("CDC test vector mismatch.", file=sys.stderr)
        return 1
    else:
        print(f"Verified {len(inputs())} CDC test vectors and the gear table.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
