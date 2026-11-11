"""Deterministic SYNTHETIC source-code corpus for the Phase 05 staging demo and tests.

Nothing here is real intellectual property: every file is generated from a fixed algorithm
and says so in its header. No payload files are stored in Git, only a manifest.

  python -B scripts/source_corpus.py                  # check the manifest (default, read-only)
  python -B scripts/source_corpus.py --write-manifest # update fixtures/source-corpus-manifest.json
  python -B scripts/source_corpus.py --out DIR        # write the files outside the repository
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from app.crypto import fingerprint_bytes  # noqa: E402

MANIFEST = ROOT / "fixtures" / "source-corpus-manifest.json"
PROTECTED = ("billing/invoice_engine.py", "billing/tax_rules.py", "pricing/margin_model.py",
             "auth/token_vault.py", "ml/ranking_core.py")
BENIGN = ("docs/readme_notes.txt", "utils/string_helpers.py", "tests/test_helpers.py")


def _text(path: str, kind: str, target: int) -> bytes:
    name = path.replace("/", "_").replace(".", "_")
    parts = [f"# SYNTHETIC RootSentinel demo source ({kind}): {path}\n"
             "# Generated deterministically. Not real intellectual property.\n"]
    index = 0
    while sum(map(len, parts)) < target:
        d = hashlib.sha256(f"rootsentinel-synthetic-corpus-v1:{path}:{index}".encode()).hexdigest()
        parts.append(f"\ndef {name}_step_{index}(value):\n    # synthetic rule {d[:12]}\n"
                     f"    return (value * 0x{d[12:20]} + 0x{d[20:28]}) % 0x{d[28:36]}\n")
        index += 1
    return "".join(parts).encode("ascii")


def corpus() -> dict[str, bytes]:
    files = {}
    for path in PROTECTED:
        files["protected/" + path] = _text(path, "protected", 5120 + int(hashlib.sha256(path.encode()).hexdigest()[:4], 16) % 4096)
    for path in BENIGN:
        files["benign/" + path] = _text(path, "benign", 2000 + int(hashlib.sha256(path.encode()).hexdigest()[:3], 16) % 1000)
    return files


def variants(data: bytes) -> dict[str, bytes]:
    """Copies of a protected file as an insider might make them. Several are KNOWN MISSES of
    fixed 1 KiB block matching; they are documented and asserted, not hidden. The content-defined
    profile (policy rule set rs-policy-v2) finds the shifted and the inserted copy; the re-encoded
    and compressed copies stay misses of both profiles."""
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("copy.py", data)
    tail = len(data) % 1024
    header = data.index(b"\n\n") + 1 if b"\n\n" in data else 0
    return {
        "inserted": data[:header] + b"# inserted line\n" + data[header:],  # KNOWN MISS of fixed blocks: a line added in the first block
        "exact_renamed": data,
        "aligned_partial": data[1024:3072],            # two whole aligned blocks: follows the policy (BLOCK)
        "single_aligned_block": data[1024:2048],       # exactly the default threshold (BLOCK)
        "sub_threshold_tail": data[len(data) - tail:] if tail else data[-512:],  # below threshold: allowed
        "shifted": b"!" + data,                        # KNOWN MISS: shifts every block boundary
        "crlf": data.replace(b"\n", b"\r\n"),          # KNOWN MISS: changes every block
        "utf16": data.decode("ascii").encode("utf-16-le"),  # KNOWN MISS: re-encoded
        "zipped": archive.getvalue(),                  # KNOWN MISS: compressed
    }


def make_manifest() -> dict:
    return {"generator_version": 1,
            "construction": "deterministic ASCII source-shaped text; SYNTHETIC, not real intellectual property",
            "files": {name: {**{k: v for k, v in fingerprint_bytes(data).manifest.to_dict().items()
                                if k in {"file_size", "file_sha256", "chunk_count", "merkle_root"}}}
                      for name, data in sorted(corpus().items())}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write-manifest", action="store_true")
    parser.add_argument("--out", type=Path, help="write the corpus files here (must be outside the repository)")
    args = parser.parse_args()
    if args.out is not None:
        target = args.out.resolve()
        if target == ROOT or ROOT in target.parents or target in ROOT.parents:
            print("refusing to write payload files inside the repository", file=sys.stderr)
            return 2
        for name, data in corpus().items():
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        print(f"wrote {len(corpus())} synthetic files ({len(PROTECTED)} protected, {len(BENIGN)} benign)")
        return 0
    expected = json.dumps(make_manifest(), indent=2, sort_keys=True) + "\n"
    if args.write_manifest:
        MANIFEST.parent.mkdir(parents=True, exist_ok=True)
        MANIFEST.write_text(expected, encoding="utf-8", newline="\n")
        print("Source corpus manifest written; no payload files created.")
    elif not MANIFEST.exists() or MANIFEST.read_text(encoding="utf-8") != expected:
        print("Source corpus manifest mismatch.", file=sys.stderr)
        return 1
    else:
        print(f"Verified {len(corpus())} synthetic corpus manifests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
