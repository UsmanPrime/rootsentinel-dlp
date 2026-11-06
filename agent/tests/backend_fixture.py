"""A real RootSentinel gateway (uvicorn over a real loopback socket) in a thread.

Disposable by construction: temporary runtime, generated audit key and generated random
credentials, all under pytest's temporary directory. Backend settings are the defaults a
real deployment uses: local mode and Secure session cookies (the agent must cope).

The gateway enforces login throttling (15/min per IP) and 30/120 transfer calls per
minute. A whole test suite from one loopback address would trip them, so by default those
two counters (not any security decision) are bypassed in this test process. Throttle
behaviour itself is covered separately against the fake gateway. No file under
backend/app is modified.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import threading
import time

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "backend"))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
import uvicorn  # noqa: E402
from sqlalchemy import update  # noqa: E402

from app import auth as auth_module, gateway_api  # noqa: E402
from app.api import create_app  # noqa: E402
from app.auth import HASHER  # noqa: E402
from app.config import StoragePaths  # noqa: E402
from app.db import Database, now  # noqa: E402
from app.models import SessionRecord, User  # noqa: E402
from app.settings import Settings  # noqa: E402

from rootsentinel_agent.client import GatewayClient  # noqa: E402


class RealBackend:
    def __init__(self, root: Path, bypass_throttles: bool = True):
        self.root, self.bypass = root, bypass_throttles
        self.counter = 0
        self._originals = []

    def start(self) -> "RealBackend":
        paths = StoragePaths(self.root / "runtime", self.root / "artifacts")
        key = self.root / "keys" / "audit-keys.json"
        key.parent.mkdir(parents=True)
        key.write_text(json.dumps({"version": 1, "active_id": "test", "keys": {"test": base64.b64encode(secrets.token_bytes(32)).decode()}}))
        if os.name != "nt":
            key.parent.chmod(0o700)
            key.chmod(0o600)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.origin = f"http://127.0.0.1:{port}"
        self.base_url = self.origin
        self.settings = Settings(paths, f"sqlite:///{paths.database.as_posix()}", "local", origin=self.origin,
                                 audit_key_file=key, checkpoint_root=self.root / "checkpoints")
        cfg = Config(str(REPO / "backend" / "alembic.ini"))
        cfg.attributes["settings"] = self.settings
        command.upgrade(cfg, "head")
        self.db = Database(self.settings.database_url)
        self.password = secrets.token_urlsafe(24)
        self._hash = HASHER.hash(self.password)
        self.admin = self.create_user("ADMIN", "rs-admin")
        self.analyst = self.create_user("ANALYST", "rs-analyst")
        if self.bypass:
            for owner, attribute in ((auth_module.LoginLimiter, "check"), (gateway_api.TransferLimiter, "check")):
                self._originals.append((owner, attribute, getattr(owner, attribute)))
            auth_module.LoginLimiter.check = lambda self_, peer, username: None
            gateway_api.TransferLimiter.check = lambda self_, actor_id: None
        self.app = create_app(self.settings)
        config = uvicorn.Config(self.app, host="127.0.0.1", port=port, log_level="warning", access_log=False, proxy_headers=False)
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("the test gateway did not start")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(15)
        for owner, attribute, original in self._originals:
            setattr(owner, attribute, original)
        self.db.engine.dispose()

    def create_user(self, role: str, name: str | None = None) -> str:
        self.counter += 1
        name = name or f"emp-{self.counter}"
        with self.db.transaction() as session:
            session.add(User(username=name, role=role, password_hash=self._hash))
        return name

    def client(self, username: str, **kw) -> GatewayClient:
        client = GatewayClient(self.base_url, self.origin, **kw)
        client.login(username, self.password)
        return client

    def revoke_sessions(self, username: str) -> None:
        with self.db.transaction() as session:
            user = session.query(User).filter_by(username=username).one()
            session.execute(update(SessionRecord).where(SessionRecord.user_id == user.id).values(revoked_at=now()))

    def write_credentials(self, path: Path, username: str) -> None:
        from rootsentinel_agent.fsutil import write_credentials
        write_credentials(path, username, self.password)
