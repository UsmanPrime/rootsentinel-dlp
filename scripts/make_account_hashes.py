"""Create the private accounts file (Argon2id password HASHES only) used by ``python -m app.bootstrap``.

Run this on your own machine, never on the host, and never commit its output:

    python -B scripts/make_account_hashes.py --out D:\\private\\rootsentinel-accounts.json \\
        --account presenter-admin:ADMIN --account presenter-analyst:ANALYST --account class-user-1:EMPLOYEE

For each account it asks for a password twice with a hidden prompt (12 to 128 characters). Passwords
are never accepted on the command line or from the environment, never printed and never written:
only the Argon2id hash is. ``--password-file`` (one line) exists for automated tests, where a
generated throwaway password is used for every account. The output file is created exclusively, mode
0600, and must be outside the repository. Upload its contents as a secret file on the host.
"""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from pydantic import TypeAdapter  # noqa: E402

from app.auth import HASHER  # noqa: E402
from app.schemas import Username  # noqa: E402

ROLES = {"ADMIN", "ANALYST", "EMPLOYEE"}
RESERVED = "system-bootstrap"


def parse_account(text: str) -> tuple[str, str]:
    name, separator, role = text.partition(":")
    if not separator or role not in ROLES:
        raise SystemExit("Each --account must look like name:ROLE where ROLE is ADMIN, ANALYST or EMPLOYEE.")
    name = TypeAdapter(Username).validate_python(name)
    if name == RESERVED:
        raise SystemExit("That account name is reserved.")
    return name, role


def ask_password(name: str) -> str:
    first = getpass.getpass(f"Password for {name} (12-128 characters): ")
    if not 12 <= len(first) <= 128:
        raise SystemExit("A password must be 12 to 128 characters.")
    if getpass.getpass("Confirm: ") != first:
        raise SystemExit("The confirmation did not match.")
    return first


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--account", action="append", required=True, metavar="NAME:ROLE")
    parser.add_argument("--password-file", type=Path, help="testing only: one-line file used for every account")
    args = parser.parse_args(argv)
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents:
        raise SystemExit("Refusing to write the accounts file inside the repository.")
    accounts = [parse_account(a) for a in args.account]
    if len({n for n, _ in accounts}) != len(accounts):
        raise SystemExit("Account names must be unique.")
    shared = None
    if args.password_file:
        shared = args.password_file.read_text(encoding="utf-8").strip()
        if not 12 <= len(shared) <= 128:
            raise SystemExit("The password file must hold one line of 12 to 128 characters.")
    entries = [{"username": n, "role": r, "password_hash": HASHER.hash(shared if shared is not None else ask_password(n)), "enabled": True}
               for n, r in accounts]
    out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({"version": 1, "accounts": entries}, handle, indent=2)
        handle.write("\n")
    print(f"Wrote {len(entries)} account hashes. Keep the file private; passwords were not stored.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
