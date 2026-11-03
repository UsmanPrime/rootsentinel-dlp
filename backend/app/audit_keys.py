"""Offline key setup/rotation. Prints identifiers only, never secret material."""
import argparse
import base64
import os
from pathlib import Path
import secrets
from uuid import uuid4

from .audit import KeyRing, canonical
from .private_files import private_directory, write_exclusive, sync_directory


def provision(path: Path, rotate=False):
    private_directory(path.parent)
    old = KeyRing.load(path) if rotate else None
    key_id = "k-" + uuid4().hex
    keys = dict(old.keys) if old else {}
    if len(keys) >= 32:
        raise ValueError("Key retention capacity reached; archive and plan a new stream")
    keys[key_id] = secrets.token_bytes(32)
    encoded = canonical({"version": 1, "active_id": key_id,
        "keys": {k: base64.b64encode(v).decode("ascii") for k, v in keys.items()}}).encode("ascii")
    if rotate:
        temporary = path.parent / ("key-rotation-" + uuid4().hex + ".tmp")
        try:
            write_exclusive(temporary, encoded)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
    else:
        write_exclusive(path, encoded)
    sync_directory(path.parent)
    return key_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["init", "rotate"])
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    identifier = provision(args.path, rotate=args.action == "rotate")
    print("Audit key configured:", identifier, "Restart the single API worker to load it.")


if __name__ == "__main__":
    main()
