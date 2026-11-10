"""Offline key setup/rotation. Prints identifiers only, never secret material."""
import argparse
import base64
import os
from pathlib import Path
import secrets
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .audit import KeyRing, canonical
from .crypto.transparency import key_id_for, public_key_of
from .private_files import private_directory, write_exclusive, sync_directory
from .transparency import MAX_KEYS, SigningKeys


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


def provision_signing(path: Path, rotate=False):
    """Create (or rotate) the Ed25519 key file that signs audit tree heads. Returns the new key id only.

    The file is separate from the HMAC keyring. Rotation keeps the earlier keys so that older tree heads still
    verify; only the new key signs."""
    private_directory(path.parent)
    old = SigningKeys.load(path) if rotate else None
    seeds = dict(old.seeds) if old else {}
    if len(seeds) >= MAX_KEYS:
        raise ValueError("Key retention capacity reached; archive and plan a new stream")
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    key_id = key_id_for(public_key_of(seed))
    seeds[key_id] = seed
    encoded = canonical({"version": 1, "algorithm": "Ed25519", "active_id": key_id,
        "keys": {k: base64.b64encode(v).decode("ascii") for k, v in seeds.items()}}).encode("ascii")
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["init", "rotate", "init-transparency", "rotate-transparency", "public-transparency"])
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    if args.action == "public-transparency":
        # Public keys only, for a witness to pin. The private seeds are never printed by any action.
        keys = SigningKeys.load(args.path)
        print("# RootSentinel tree-head public keys (Ed25519, hex). Active key id:", keys.active_id)
        for key_id, public in sorted(keys.public.items()):
            print(public.hex())
        return
    if args.action.endswith("-transparency"):
        identifier = provision_signing(args.path, rotate=args.action.startswith("rotate"))
        print("Transparency signing key configured.")
        print("key_id:", identifier)
        print("file:  ", args.path)
        print("Restart the single API worker to load it.")
        return
    identifier = provision(args.path, rotate=args.action == "rotate")
    print("Audit key configured:", identifier, "Restart the single API worker to load it.")


if __name__ == "__main__":
    main()
