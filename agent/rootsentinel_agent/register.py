"""ADMIN tool: register a folder of synthetic files as protected assets through the REST API.

There is no bulk import endpoint, so this posts one file per request, serially (the gateway
has two shared processing slots and no queue). Every registration bumps the registry
revision, which turns in-flight ALLOWED transfers STALE: run this before the agent.
The ADMIN password is only ever read from a hidden prompt (or passed in-process by tests).
"""
from __future__ import annotations

import argparse
import getpass
import logging
import os
from pathlib import Path
import stat
import sys
import time

from .client import ApiError, GatewayClient, ProtocolViolation, Unavailable
from .fsutil import MAX_FILE_SIZE, check_location
from .labels import sanitize_label

LOG = logging.getLogger("rootsentinel_agent")


def collect_files(folder: Path, prefix: str = "") -> list[tuple[str, Path]]:
    """Regular, non-link files below ``folder`` with unique sanitized labels."""
    found, used = [], set()
    for current, directories, names in os.walk(folder, followlinks=False):
        directories[:] = sorted(d for d in directories if not (Path(current) / d).is_symlink())
        for name in sorted(names):
            path = Path(current) / name
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not 0 < st.st_size <= MAX_FILE_SIZE:
                continue
            relative = "_".join(path.relative_to(folder).parts)
            label = sanitize_label(prefix + relative)
            base, counter = label, 1
            while label.lower() in used:
                counter += 1
                label = sanitize_label(f"{base}-{counter}")
            used.add(label.lower())
            found.append((label, path))
    return found


def register_folder(client: GatewayClient, folder: Path, *, prefix: str = "", sleep=time.sleep) -> dict:
    summary = {"registered": 0, "existing": 0, "failed": 0, "items": []}
    for label, path in collect_files(folder, prefix):
        data = path.read_bytes()
        outcome = "failed"
        for _ in range(30):
            try:
                client.register_asset(label, data)
                outcome = "registered"
            except ApiError as error:
                if error.code == "DUPLICATE_ASSET_LABEL":
                    outcome = "existing"
                elif error.code in {"SCAN_CAPACITY", "LOGIN_CAPACITY"}:
                    sleep(1.0)
                    continue
                else:
                    outcome = "failed:" + error.code
            except (Unavailable, ProtocolViolation):
                outcome = "failed:UNAVAILABLE"
            break
        key = "failed" if outcome.startswith("failed") else outcome
        summary[key] += 1
        summary["items"].append({"label": label, "size": len(data), "outcome": outcome})
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--origin", default="http://127.0.0.1:5173")
    parser.add_argument("--username", required=True)
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--label-prefix", default="")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    try:
        check_location(args.folder, "folder")
        client = GatewayClient(args.base_url, args.origin)
        user = client.login(args.username, getpass.getpass("ADMIN password: "))
        if user.get("role") != "ADMIN":
            print("The account must have role ADMIN to register protected assets.", file=sys.stderr)
            return 2
        summary = register_folder(client, args.folder, prefix=args.label_prefix)
        client.logout()
    except (ValueError, ApiError, Unavailable, ProtocolViolation) as error:
        print(f"registration stopped: {type(error).__name__}", file=sys.stderr)
        return 2
    for item in summary["items"]:
        print(f"{item['outcome']:<28} {item['label']} ({item['size']} bytes)")
    print(f"registered={summary['registered']} existing={summary['existing']} failed={summary['failed']}")
    return 0 if not summary["failed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
