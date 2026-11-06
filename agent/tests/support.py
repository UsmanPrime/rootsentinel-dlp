"""Test helpers: temp layouts, fast agent config, and a stateful fake gateway with fault injection."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import http.server
import json
import os
from pathlib import Path
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

from rootsentinel_agent.client import GatewayClient  # noqa: E402
from rootsentinel_agent.fsutil import Credentials  # noqa: E402
from rootsentinel_agent.journal import Journal  # noqa: E402
from rootsentinel_agent.pipeline import Agent, AgentConfig, Failpoints  # noqa: E402

PASSWORD = "synthetic-test-password-not-a-secret"
SENTINEL_COOKIE = "S" * 43
SENTINEL_CSRF = "c" * 64


def make_dirs(base: Path) -> dict:
    dirs = {name: base / name for name in ("staging", "outbound", "quarantine", "state")}
    for path in dirs.values():
        path.mkdir(parents=True)
    (dirs["state"] / "tmp").mkdir()
    if os.name != "nt":
        for name in ("quarantine", "state"):
            dirs[name].chmod(0o700)
        (dirs["state"] / "tmp").chmod(0o700)
    return dirs


def fast_config(dirs: dict, username="emp-test", **override) -> AgentConfig:
    values = dict(poll_interval=0.02, settle_seconds=0.05, wait_scale=0.01, unavailable_wait=0.05,
                  min_relogin=0.0, retry_base=0.01, retry_cap=0.05, rate_per_minute=100000)
    values.update(override)
    return AgentConfig(dirs["staging"], dirs["outbound"], dirs["quarantine"], dirs["state"],
                       Credentials(username, PASSWORD), **values)


def make_agent(dirs: dict, client: GatewayClient, failpoints: Failpoints | None = None, username="emp-test", **override) -> Agent:
    journal = Journal(dirs["state"] / "journal.jsonl")
    journal.open()
    return Agent(fast_config(dirs, username, **override), client, journal, failpoints or Failpoints(), sleep=time.sleep)


def finish(agent: Agent) -> None:
    agent.journal.close()
    agent.close()


def put(dirs: dict, name: str, data: bytes, age: float = 1.0) -> Path:
    """Create a staging file that already looks settled."""
    path = dirs["staging"] / name
    path.write_bytes(data)
    old = time.time() - age
    os.utime(path, (old, old))
    return path


def listing(path: Path) -> list[str]:
    return sorted(os.listdir(path))


class MiniGateway:
    """A small stateful stand-in for the real gateway, for error-path tests only."""

    def __init__(self, decision=lambda data: "ALLOWED", role="EMPLOYEE", origin="http://127.0.0.1:5173"):
        self.decision, self.role, self.origin = decision, role, origin
        self.faults: dict[str, list] = {"login": [], "submit": [], "release": [], "get": []}
        self.transfers: dict[str, dict] = {}
        self.by_key: dict[str, str] = {}
        self.log: list[tuple] = []
        self.tamper_release = None
        self.lie_digest = False
        self.token = SENTINEL_COOKIE
        self.lock = threading.Lock()
        handler = self._handler()
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def client(self, **kw) -> GatewayClient:
        return GatewayClient(self.base_url, self.origin, **kw)

    def count(self, kind: str) -> int:
        return sum(1 for entry in self.log if entry[0] == kind)

    def _view(self, transfer: dict) -> dict:
        view = {k: transfer[k] for k in ("id", "actor_id", "filename", "state", "reason", "file_sha256", "file_size", "created_at", "expires_at", "incident_id")}
        view["release_eligible"] = transfer["state"] == "ALLOWED"
        blocked = transfer["state"] == "BLOCKED"
        view["scan"] = {"decision": {"outcome": "BLOCK" if blocked else "ALLOW", "reason": "EXACT_PROTECTED_FILE" if blocked else "NO_QUALIFYING_MATCH", "qualifying_versions": []},
                        "detection": {"matches": [{"exact": True, "matched_bytes": transfer["file_size"], "coverage": {"numerator": transfer["file_size"], "denominator": transfer["file_size"]}}] if blocked else []}}
        return view

    def _handler(self):
        gateway = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _respond(self, result):
                if result == "drop":
                    self.close_connection = True
                    self.connection.close()
                    return
                status, headers, body = result
                items = list(headers.items() if isinstance(headers, dict) else headers)
                lie = next((value for name, value in items if name == "X-Lie-Length"), None)
                self.send_response(status)
                for name, value in items:
                    if name != "X-Lie-Length":
                        self.send_header(name, value)
                self.send_header("Content-Length", str(lie if lie is not None else len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def do_GET(self):
                self._respond(gateway.handle(self, b""))

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                self._respond(gateway.handle(self, self.rfile.read(length)))

        return Handler

    # -- protocol -----------------------------------------------------------------------
    @staticmethod
    def error(status: int, code: str):
        return status, {"Content-Type": "application/json"}, json.dumps({"error": {"code": code, "outcome": "INDETERMINATE", "release_authorized": False}}).encode()

    def _fault(self, kind: str):
        with self.lock:
            fault = self.faults[kind].pop(0) if self.faults[kind] else None
        if fault is None:
            return None
        if fault[0] == "sleep":
            time.sleep(fault[1])
            return None
        if fault[0] == "drop":
            return "drop"
        if fault[0] == "consume":
            return fault
        if fault[0] == "status":
            return self.error(fault[1], fault[2])
        return None

    def handle(self, request, body: bytes):
        parts = urlsplit(request.path)
        path, query = parts.path, parse_qs(parts.query)
        method = request.command
        if path == "/health":
            return 200, {"Content-Type": "application/json"}, b'{"status":"ok","mode":"local","release_configured":true}'
        if method == "POST" and request.headers.get("Origin") != self.origin and path != "/health":
            self.log.append(("origin-rejected", path))
            return self.error(403, "ORIGIN_REJECTED")
        if path == "/api/v1/auth/login":
            self.log.append(("login", path))
            fault = self._fault("login")
            if fault:
                return fault
            payload = json.loads(body)
            if payload.get("password") != PASSWORD:
                return self.error(401, "INVALID_CREDENTIALS")
            cookie = f"rs_session={self.token}; HttpOnly; Max-Age=3600; Path=/api/v1; SameSite=strict; Secure"
            return 200, [("Content-Type", "application/json"), ("Set-Cookie", cookie)], json.dumps(
                {"user": {"id": "u1", "username": payload["username"], "role": self.role}, "csrf_token": SENTINEL_CSRF}).encode()
        cookie = request.headers.get("Cookie", "")
        if f"rs_session={self.token}" not in cookie:
            return self.error(401, "AUTHENTICATION_REQUIRED")
        if method == "POST" and request.headers.get("X-CSRF-Token") != SENTINEL_CSRF:
            return self.error(403, "CSRF_REJECTED")
        if path == "/api/v1/auth/logout":
            self.log.append(("logout", path))
            return 204, {}, b""
        if path == "/api/v1/transfers" and method == "POST":
            fault = self._fault("submit")
            key = request.headers.get("Idempotency-Key", "")
            self.log.append(("submit", key))
            if fault:
                return fault
            if request.headers.get("Content-Type") != "application/octet-stream":
                return self.error(415, "OCTET_STREAM_REQUIRED")
            digest = hashlib.sha256(body).hexdigest()
            existing = self.by_key.get(key)
            if existing:
                return 201, {"Content-Type": "application/json"}, json.dumps(self._view(self.transfers[existing])).encode()
            state = self.decision(body)
            now = datetime.now(timezone.utc)
            transfer = {"id": str(uuid4()), "actor_id": "u1", "filename": query.get("filename", [""])[0], "state": state,
                        "reason": "SYNTHETIC", "file_sha256": "0" * 64 if self.lie_digest else digest, "file_size": len(body), "data": body,
                        "created_at": now.isoformat(), "expires_at": (now + timedelta(seconds=900)).isoformat().replace("+00:00", "Z"),
                        "incident_id": str(uuid4()) if state == "BLOCKED" else None}
            self.transfers[transfer["id"]] = transfer
            self.by_key[key] = transfer["id"]
            return 201, {"Content-Type": "application/json"}, json.dumps(self._view(transfer)).encode()
        if path.startswith("/api/v1/transfers/") and method == "GET":
            self.log.append(("get", path))
            fault = self._fault("get")
            if fault:
                return fault
            transfer = self.transfers.get(path.rsplit("/", 1)[1])
            if not transfer:
                return self.error(404, "NOT_FOUND")
            return 200, {"Content-Type": "application/json"}, json.dumps(self._view(transfer)).encode()
        if path.endswith("/release") and method == "POST":
            self.log.append(("release", path))
            fault = self._fault("release")
            transfer = self.transfers.get(path.split("/")[-2])
            if fault == ("consume",) and transfer:
                transfer["state"] = "DELIVERY_UNKNOWN"      # the single use is spent but the bytes never arrive
                return "drop"
            if fault:
                return fault
            if not transfer:
                return self.error(404, "NOT_FOUND")
            if transfer["state"] != "ALLOWED":
                return self.error(409, "TRANSFER_NOT_ALLOWED")
            transfer["state"] = "STREAM_FINISHED"
            data = self.tamper_release(transfer["data"]) if self.tamper_release else transfer["data"]
            headers = {"Content-Type": "application/octet-stream"}
            if self.tamper_release and self.tamper_release.__name__ == "short_read":
                headers["X-Lie-Length"] = len(transfer["data"]) + 50
            return 200, headers, data
        return self.error(404, "NOT_FOUND")
