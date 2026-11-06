"""Command line: init, init-credentials, check, run, status, requeue.

Credentials come only from a private JSON file or a hidden prompt. There is intentionally
no password option and no environment variable for secrets.
"""
from __future__ import annotations

import argparse
import getpass
import logging
import os
from pathlib import Path
import sys

from .client import ApiError, GatewayClient, ProtocolViolation, Unavailable
from .fsutil import (IS_WINDOWS, AlreadyRunning, Credentials, InstanceLock, PathRuleError, ensure_dir,
                     read_credentials, require_distinct, require_same_device, write_credentials)
from .journal import Journal, JournalCorrupt, TERMINAL
from .pipeline import Agent, AgentConfig, Fatal

LOG = logging.getLogger("rootsentinel_agent")
DIRS = ("staging", "outbound", "quarantine", "state")


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", type=Path, default=os.environ.get("ROOTSENTINEL_AGENT_ROOT"),
                        help="parent of staging/, outbound/, quarantine/, state/")
    for name in DIRS:
        parser.add_argument(f"--{name}", type=Path, help=f"override the {name} directory")


def add_gateway(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-url", default=os.environ.get("ROOTSENTINEL_AGENT_BASE_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--origin", default=os.environ.get("ROOTSENTINEL_AGENT_ORIGIN", "http://127.0.0.1:5173"))
    parser.add_argument("--credentials-file", type=Path, help="private JSON file with username and password")
    parser.add_argument("--username", help="with --prompt: the agent account name")
    parser.add_argument("--prompt", action="store_true", help="ask for the password with a hidden prompt")


def directories(args) -> dict[str, Path]:
    found = {}
    for name in DIRS:
        explicit = getattr(args, name)
        if explicit is not None:
            found[name] = explicit
        elif args.root is not None:
            found[name] = Path(args.root) / name
        else:
            raise PathRuleError("give --root or an explicit path for every directory")
    return found


def prepare_directories(paths: dict[str, Path]) -> None:
    require_distinct(paths)
    ensure_dir(paths["staging"], "staging", private=False)
    ensure_dir(paths["outbound"], "outbound", private=False)
    ensure_dir(paths["quarantine"], "quarantine", private=True)
    ensure_dir(paths["state"], "state", private=True)
    ensure_dir(paths["state"] / "tmp", "state/tmp", private=True)
    require_same_device({**paths, "tmp": paths["state"] / "tmp"})
    if not IS_WINDOWS and os.lstat(paths["outbound"]).st_mode & 0o022:
        raise PathRuleError("outbound must not be writable by group or others")


def credentials_from(args) -> Credentials:
    if args.credentials_file and args.prompt:
        raise PathRuleError("choose either --credentials-file or --prompt")
    if args.credentials_file:
        creds, verified = read_credentials(args.credentials_file)
        if not verified:
            LOG.warning("credentials file permissions are NOT verified on Windows (path rules only); "
                        "keep it in a directory only your account can read")
        return creds
    if args.prompt:
        if not args.username:
            raise PathRuleError("--prompt requires --username")
        return Credentials(args.username, getpass.getpass("Agent account password: "))
    raise PathRuleError("give --credentials-file or --prompt")


def build_agent(args) -> tuple[Agent, Journal]:
    paths = directories(args)
    prepare_directories(paths)
    config = AgentConfig(paths["staging"], paths["outbound"], paths["quarantine"], paths["state"],
                         credentials_from(args), poll_interval=args.poll_interval, settle_seconds=args.settle,
                         require_ready=args.require_ready, max_attempts=args.max_attempts,
                         rate_per_minute=args.rate_per_minute)
    journal = Journal(paths["state"] / "journal.jsonl")
    return Agent(config, GatewayClient(args.base_url, args.origin), journal), journal


def cmd_init(args) -> int:
    paths = directories(args)
    prepare_directories(paths)
    for name, path in paths.items():
        print(f"{name:<11} {path}")
    print("Directories are ready. On Windows, restricting who may write to outbound is an operator step.")
    return 0


def cmd_init_credentials(args) -> int:
    first = getpass.getpass("Agent account password: ")
    if first != getpass.getpass("Confirm password: "):
        print("passwords differ", file=sys.stderr)
        return 2
    write_credentials(args.file, args.username, first)
    print(f"credentials file created: {args.file}")
    if IS_WINDOWS:
        print("NOTE: Windows permissions are not verified by the agent; keep this directory private to your account.")
    return 0


def cmd_check(args) -> int:
    paths = directories(args)
    prepare_directories(paths)
    creds = credentials_from(args)
    client = GatewayClient(args.base_url, args.origin)
    health = client.health()
    print(f"gateway mode={health.get('mode')} release_configured={health.get('release_configured')}")
    if health.get("mode") != "local" or not health.get("release_configured"):
        print("the gateway is not ready to release (needs local mode, an audit key file and a checkpoint root)", file=sys.stderr)
        return 2
    user = client.login(creds.username, creds.password)
    print(f"login ok, role={user.get('role')}")
    client.logout()
    if user.get("role") != "EMPLOYEE":
        print("the agent account must have role EMPLOYEE", file=sys.stderr)
        return 2
    print("check passed")
    return 0


def cmd_run(args) -> int:
    agent, journal = build_agent(args)
    try:
        with InstanceLock(agent.cfg.state / "lock"):
            journal.open()
            try:
                return agent.run(once=args.once, max_wait=args.max_wait)
            finally:
                journal.close()
    finally:
        agent.close()


def cmd_status(args) -> int:
    paths = directories(args)
    journal = Journal(paths["state"] / "journal.jsonl")
    if journal.path.exists():
        journal._load()
    counts: dict[str, int] = {}
    for entry in journal.entries.values():
        counts[entry["state"]] = counts.get(entry["state"], 0) + 1
    print("entries by state:", ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "(none)")
    for entry in sorted(journal.entries.values(), key=lambda e: e["updated"]):
        if entry["state"] in {"HELD", "REJECTED"} or entry["state"] not in TERMINAL:
            print(f"  {entry['id'][:8]} {entry['state']:<10} {entry.get('label', '')} {entry.get('reason') or ''}")
    return 0


def cmd_requeue(args) -> int:
    paths = directories(args)
    with InstanceLock(paths["state"] / "lock"):
        journal = Journal(paths["state"] / "journal.jsonl")
        journal.open()
        try:
            count = 0
            for entry in list(journal.entries.values()):
                if entry["state"] == "HELD" and (args.all_held or entry["id"].startswith(args.entry or "\0")):
                    journal.append(entry["id"], "RETRY", reason="OPERATOR_REQUEUE", not_before=0.0, attempt=0)
                    count += 1
            print(f"requeued {count} held entries")
        finally:
            journal.close()
    return 0


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="rootsentinel_agent", description=__doc__, allow_abbrev=False)
    sub = top.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", allow_abbrev=False); add_common(p); p.set_defaults(func=cmd_init)
    p = sub.add_parser("init-credentials", allow_abbrev=False)
    p.add_argument("--file", type=Path, required=True); p.add_argument("--username", required=True)
    p.set_defaults(func=cmd_init_credentials)
    p = sub.add_parser("check", allow_abbrev=False); add_common(p); add_gateway(p); p.set_defaults(func=cmd_check)
    p = sub.add_parser("run", allow_abbrev=False); add_common(p); add_gateway(p)
    p.add_argument("--once", action="store_true", help="exit when every file in staging is settled")
    p.add_argument("--require-ready", action="store_true", help="only admit files renamed to *.ready")
    p.add_argument("--poll-interval", type=float, default=1.0)
    p.add_argument("--settle", type=float, default=2.0, help="seconds a file must be unmodified")
    p.add_argument("--max-attempts", type=int, default=5)
    p.add_argument("--rate-per-minute", type=int, default=20, help="self-imposed cap on submit+release calls")
    p.add_argument("--max-wait", type=float, default=300.0, help="--once: give up after this many seconds")
    p.set_defaults(func=cmd_run)
    p = sub.add_parser("status", allow_abbrev=False); add_common(p); p.set_defaults(func=cmd_status)
    p = sub.add_parser("requeue", allow_abbrev=False); add_common(p)
    p.add_argument("--entry", help="entry id prefix"); p.add_argument("--all-held", action="store_true")
    p.set_defaults(func=cmd_requeue)
    return top


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    try:
        return args.func(args)
    except (PathRuleError, Fatal, AlreadyRunning, JournalCorrupt) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except (ApiError, Unavailable, ProtocolViolation) as error:
        print(f"error: gateway request failed ({type(error).__name__})", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
