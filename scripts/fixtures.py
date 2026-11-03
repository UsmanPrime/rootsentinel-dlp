"""Reproducible synthetic inputs. No payload files are written by this tool.

Use --write-manifest to update the tracked, non-sensitive manifest deliberately.
Default/check mode compares the fixture definitions against that manifest.
"""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.crypto import fingerprint_bytes  # noqa: E402


def synthetic_inputs() -> dict[str, bytes]:
    blocks = []
    for i in range(8):
        line = f"# synthetic RootSentinel fixture block {i}; no proprietary source\n".encode("ascii")
        blocks.append((line * (1024 // len(line) + 1))[:1024])
    protected = b"".join(blocks)
    return {
        "empty": b"",
        "small": b"# synthetic example\nvalue = 3002\n",
        "protected": protected,
        "renamed": protected,
        "single_byte_change": b"!" + protected[1:],
        "aligned_partial": blocks[2] + blocks[3],
        "aligned_embedding": b"x" * 1024 + protected + b"y" * 1024,
        "shifted": b"!" + protected,
        "crlf": protected.replace(b"\n", b"\r\n"),
        "utf16": protected.decode("ascii").encode("utf-16le"),
        "benign": b"# unrelated synthetic public note\n" * 80,
    }


def make_manifest() -> dict:
    return {
        "generator_version": 1,
        "construction": "deterministic ASCII fixture blocks; no random seed required",
        "fixtures": {name: fingerprint_bytes(data).manifest.to_dict()
                     for name, data in synthetic_inputs().items()},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-manifest", action="store_true")
    args = parser.parse_args()
    path = ROOT / "fixtures" / "manifest.json"
    expected = json.dumps(make_manifest(), indent=2, sort_keys=True) + "\n"
    if args.write_manifest:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(expected, encoding="utf-8", newline="\n")
        print("Synthetic fixture manifest written; no payload files created.")
    elif not path.exists() or path.read_text(encoding="utf-8") != expected:
        print("Fixture manifest mismatch.", file=sys.stderr)
        return 1
    else:
        print(f"Verified {len(synthetic_inputs())} synthetic fixture manifests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
