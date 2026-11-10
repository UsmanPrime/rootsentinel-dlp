"""An independent witness for the RootSentinel audit transparency log.

The witness keeps one small state file outside the gateway: the last signed tree head it accepted. On each
run it pins the gateway's Ed25519 public key from a LOCAL file (never from the gateway), fetches the latest
signed tree head, verifies the signature, asks for a consistency proof from the saved head to the new one,
verifies that too, and only then saves the new head. A rollback, a rewritten history, a fork, a different log
or a head signed by another key ends with a non-zero exit code and the saved head is left untouched.

It can also verify an exported evidence bundle offline (no network at all).

    python scripts/witness.py check  --base-url https://HOST --public-key keys.txt --state witness-state.json --username NAME
    python scripts/witness.py bundle --public-key keys.txt export.json

The public key file holds one 64-character hex Ed25519 public key per line (lines starting with # are
comments). Get it once from the operator: ``python -m app.audit_keys public-transparency <key file>``.
Keep earlier keys in the file after a rotation so that older heads still verify.

This script imports nothing from the application: only the standard library and ``cryptography``. The
password is read from a hidden prompt or a private one-line file and is never printed.
Exit codes: 0 verified, 1 verification failed, 2 could not run (usage, network, sign-in).
"""
import argparse
import getpass
from hashlib import sha256
import http.client
import json
import os
from pathlib import Path
import sys
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

STH_DOMAIN = b"RootSentinelSTH\x00\x01"
STH_FIELDS = ("key_id", "log_id", "root_hash", "timestamp", "tree_size")
MAX_TREE = 20000


class Rejected(Exception):
    """A verification failure: what was served does not prove what it claims."""


class Unavailable(Exception):
    """The check could not be carried out (network, sign-in, unreadable input)."""


# ---------------------------------------------------------------------------------------------- RFC 9162, section 2.1
def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right).digest()


def event_leaf_hash(canonical: str, mac: str) -> bytes:
    encoded = canonical.encode("ascii")
    raw_mac = bytes.fromhex(mac)
    if len(raw_mac) != 32:
        raise ValueError("An event MAC is 32 bytes")
    return sha256(b"\x00" + len(encoded).to_bytes(4, "big") + encoded + raw_mac).digest()


def verify_inclusion(leaf: bytes, index: int, size: int, path: list, root: bytes) -> bool:
    """Section 2.1.3.2."""
    if type(index) is not int or type(size) is not int or not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, path: list) -> bool:
    """Section 2.1.4.2 for 0 < first < second; equal sizes need equal roots and an empty path."""
    if type(first) is not int or type(second) is not int or not 0 < first <= second:
        return False
    if first == second:
        return not path and first_root == second_root
    if not path:
        return False
    path = list(path)
    if first & (first - 1) == 0:
        path.insert(0, first_root)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node_hash(c, fr), node_hash(c, sr)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


# ---------------------------------------------------------------------------------------------- signed tree heads
def load_pinned_keys(path: Path) -> dict:
    """key id -> raw public key, from a local file of hex public keys."""
    try:
        lines = [line.strip() for line in path.read_text(encoding="ascii").splitlines()]
    except (OSError, ValueError):
        raise Unavailable("the public key file could not be read") from None
    keys = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        try:
            raw = bytes.fromhex(line)
        except ValueError:
            raw = b""
        if len(raw) != 32:
            raise Unavailable("the public key file must hold 64-character hex Ed25519 public keys, one per line")
        keys[sha256(raw).hexdigest()] = raw
    if not keys:
        raise Unavailable("the public key file holds no key")
    return keys


def checked_head(value, keys: dict) -> dict:
    """The six fields of a served head after structural checks and signature verification with a pinned key."""
    if not isinstance(value, dict) or set(value) != {*STH_FIELDS, "signature"}:
        raise Rejected("the tree head does not have the expected fields")
    if type(value["tree_size"]) is not int or not 1 <= value["tree_size"] <= MAX_TREE:
        raise Rejected("the tree size is out of range")
    if any(type(value[name]) is not str for name in (*STH_FIELDS[:4], "signature")):
        raise Rejected("the tree head fields have the wrong type")
    public = keys.get(value["key_id"])
    if public is None:
        raise Rejected("the tree head is signed by a key that is not pinned in the public key file")
    signed = STH_DOMAIN + json.dumps({name: value[name] for name in STH_FIELDS}, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode("ascii")
    try:
        root, signature = bytes.fromhex(value["root_hash"]), bytes.fromhex(value["signature"])
        if len(root) != 32:
            raise ValueError()
        Ed25519PublicKey.from_public_bytes(public).verify(signature, signed)
    except (InvalidSignature, ValueError):
        raise Rejected("the tree head signature does not verify with the pinned key") from None
    return value


def hex_path(path) -> list:
    if not isinstance(path, list) or len(path) > 64 or any(type(p) is not str for p in path):
        raise Rejected("the proof path is malformed")
    try:
        steps = [bytes.fromhex(p) for p in path]
    except ValueError:
        raise Rejected("the proof path is malformed") from None
    if any(len(step) != 32 for step in steps):
        raise Rejected("the proof path is malformed")
    return steps


def load_state(path: Path, keys: dict):
    """The saved head, or None on the first run. A saved head that no longer verifies is a failure, not a reset."""
    if not path.exists():
        return None
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, ValueError):
        raise Rejected("the saved state file is unreadable; it is not replaced automatically") from None
    try:
        return checked_head(value, keys)
    except Rejected as error:
        raise Rejected(f"the saved state no longer verifies ({error}); it is not replaced automatically") from None


def save_state(path: Path, head: dict):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(head, sort_keys=True, indent=2) + "\n", encoding="ascii")
    if os.name != "nt":
        temporary.chmod(0o600)
    os.replace(temporary, path)


def advance(saved, current: dict, fetch_consistency) -> str:
    """Decide whether ``current`` may replace ``saved``. Returns a description; raises Rejected otherwise."""
    if saved is None:
        return f"first head accepted: size {current['tree_size']} (nothing earlier to compare with)"
    if saved["log_id"] != current["log_id"]:
        raise Rejected("the gateway now serves a different log than the saved head (new database or audit stream)")
    if current["tree_size"] < saved["tree_size"]:
        raise Rejected(f"rollback: the log shrank from size {saved['tree_size']} to {current['tree_size']}")
    if current["tree_size"] == saved["tree_size"]:
        if current["root_hash"] != saved["root_hash"]:
            raise Rejected(f"fork: two different roots at size {current['tree_size']}")
        return f"unchanged: size {current['tree_size']}"
    proof = fetch_consistency(saved["tree_size"], current["tree_size"])
    if not isinstance(proof, dict) or proof.get("first") != saved["tree_size"] or proof.get("second") != current["tree_size"]:
        raise Rejected("the consistency proof is for other tree sizes")
    if not verify_consistency(saved["tree_size"], current["tree_size"], bytes.fromhex(saved["root_hash"]),
                              bytes.fromhex(current["root_hash"]), hex_path(proof.get("path"))):
        raise Rejected(f"history was rewritten: size {current['tree_size']} is not an extension of the saved size {saved['tree_size']}")
    return f"consistent: the log grew from size {saved['tree_size']} to {current['tree_size']}"


# ---------------------------------------------------------------------------------------------- evidence bundle
def verify_bundle(document, keys: dict) -> str:
    bundle = document.get("transparency") if isinstance(document, dict) and "transparency" in document else document
    if not isinstance(bundle, dict) or bundle.get("format") != "rootsentinel-evidence-v1":
        raise Rejected("this is not a signed evidence bundle (no transparency section in the export)")
    head = checked_head(bundle.get("sth"), keys)        # the pinned key decides, not the key printed in the bundle
    if bundle.get("key_id") != head["key_id"]:
        raise Rejected("the bundle names another key than its tree head")
    events = bundle.get("events")
    if not isinstance(events, list) or not events or len(events) > 500:
        raise Rejected("the bundle holds no events")
    root = bytes.fromhex(head["root_hash"])
    for entry in events:
        try:
            canonical, mac, sequence = entry["canonical"], entry["mac"], entry["sequence"]
            stated = json.loads(canonical)
            leaf = event_leaf_hash(canonical, mac)
        except (KeyError, TypeError, ValueError):
            raise Rejected("an event in the bundle is malformed") from None
        if type(sequence) is not int or stated.get("sequence") != sequence or stated.get("stream_id") != head["log_id"]:
            raise Rejected(f"event {sequence!r} does not match its own content")
        if not verify_inclusion(leaf, sequence - 1, head["tree_size"], hex_path(entry.get("path")), root):
            raise Rejected(f"event {sequence} is not in the signed tree")
    return f"bundle verified: {len(events)} event(s) are in the tree of size {head['tree_size']} signed by key {head['key_id'][:16]}"


# ---------------------------------------------------------------------------------------------- transport
class Gateway:
    def __init__(self, base_url: str, origin: str | None):
        self.base = urlsplit(base_url)
        self.origin = origin or f"{self.base.scheme}://{self.base.netloc}"
        if self.base.scheme not in {"http", "https"} or not self.base.hostname:
            raise Unavailable("--base-url must be an http(s) URL")
        if self.base.scheme == "http" and self.base.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise Unavailable("plain http is only allowed to a loopback address; use https for a remote host")
        self.cookie = self.csrf = None

    def call(self, method, path, json_body=None):
        connection_class = http.client.HTTPSConnection if self.base.scheme == "https" else http.client.HTTPConnection
        connection = connection_class(self.base.hostname, self.base.port, timeout=60)
        headers = {"Host": urlsplit(self.origin).netloc, "Accept": "application/json"}
        body = None
        if method != "GET":
            headers["Origin"] = self.origin
            if self.csrf:
                headers["X-CSRF-Token"] = self.csrf
        if self.cookie:
            headers["Cookie"] = "rs_session=" + self.cookie
        if json_body is not None:
            body, headers["Content-Type"] = json.dumps(json_body).encode(), "application/json"
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(1048576)
            cookies = [v for k, v in response.getheaders() if k.lower() == "set-cookie"]
        except OSError:
            raise Unavailable("the gateway could not be reached") from None
        finally:
            connection.close()
        try:
            return response.status, json.loads(data) if data else None, cookies
        except ValueError:
            return response.status, None, cookies

    def sign_in(self, username, password):
        status, body, cookies = self.call("POST", "/api/v1/auth/login", {"username": username, "password": password})
        cookie = next((c for c in cookies if c.startswith("rs_session=")), "")
        if status != 200 or not cookie or not isinstance(body, dict):
            raise Unavailable(f"sign-in was refused (HTTP {status})")
        self.cookie, self.csrf = cookie.split(";", 1)[0].split("=", 1)[1], body.get("csrf_token")

    def sign_out(self):
        if self.cookie:
            try:
                self.call("POST", "/api/v1/auth/logout")
            except Unavailable:
                pass
            self.cookie = self.csrf = None

    def get(self, path):
        status, body, _ = self.call("GET", path)
        if status != 200:
            raise Unavailable(f"GET {path.split('?')[0]} answered HTTP {status}")
        return body


def check(gateway, keys: dict, state_path: Path) -> str:
    """One witness round against a signed-in gateway. Saves the new head only after everything verified."""
    saved = load_state(state_path, keys)
    current = checked_head(gateway.get("/api/v1/transparency/sth"), keys)
    outcome = advance(saved, current, lambda first, second: gateway.get(f"/api/v1/transparency/proof/consistency?first={first}&second={second}"))
    save_state(state_path, current)
    return outcome


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    online = commands.add_parser("check", help="fetch the latest signed tree head and prove it extends the saved one")
    online.add_argument("--base-url", required=True)
    online.add_argument("--origin", help="the gateway's configured origin when it differs from --base-url")
    online.add_argument("--public-key", type=Path, required=True, help="local file of pinned hex public keys")
    online.add_argument("--state", type=Path, required=True, help="where the last accepted head is kept")
    online.add_argument("--username", required=True, help="an ANALYST or ADMIN account")
    online.add_argument("--password-file", type=Path, help="one-line file; otherwise a hidden prompt is used")
    offline = commands.add_parser("bundle", help="verify an exported evidence bundle offline")
    offline.add_argument("--public-key", type=Path, required=True)
    offline.add_argument("bundle", type=Path)
    args = parser.parse_args(argv)
    try:
        keys = load_pinned_keys(args.public_key)
        if args.command == "bundle":
            try:
                document = json.loads(args.bundle.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raise Unavailable("the bundle file could not be read as JSON") from None
            print("PASS", verify_bundle(document, keys))
            return 0
        gateway = Gateway(args.base_url, args.origin)
        try:
            password = args.password_file.read_text(encoding="utf-8").strip() if args.password_file else getpass.getpass("Password: ")
        except OSError:
            raise Unavailable("the password file could not be read") from None
        gateway.sign_in(args.username, password)
        try:
            print("PASS", check(gateway, keys, args.state))
        finally:
            gateway.sign_out()
        return 0
    except Rejected as error:
        print("FAIL", error, file=sys.stderr)
        return 1
    except Unavailable as error:
        print("ERROR", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
