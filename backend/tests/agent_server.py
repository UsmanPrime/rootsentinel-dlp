"""Ephemeral loopback gateway for the Phase 05 staging-agent demo and CI.

Run with ROOTSENTINEL_DEMO_STATE pointing to a NEW directory outside the repository and
OneDrive. It generates its own audit key, checkpoint root, database and random credentials
for one ADMIN, one ANALYST and several EMPLOYEE accounts, writes them to
``demo-session.json`` inside that directory (0600 on POSIX) and serves until stopped.
Backend settings are the defaults a real deployment uses (local mode, Secure cookies).
Nothing is persisted outside the state directory; never publish it.
"""
import json
import os
from pathlib import Path
import secrets
import tempfile

from alembic import command
from alembic.config import Config
import uvicorn

from app.api import create_app
from app.audit_keys import provision, provision_signing
from app.auth import HASHER
from app.config import StoragePaths, validate_external_path
from app.db import Database
from app.models import User
from app.settings import Settings, SOURCE_ROOT

EMPLOYEES = 12


def main():
    state = validate_external_path(Path(os.environ["ROOTSENTINEL_DEMO_STATE"]), SOURCE_ROOT)
    state.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(dir=state, prefix="gateway-") as external:
        paths = StoragePaths(Path(external) / "runtime", Path(external) / "artifacts")
        key_file = Path(external) / "secrets" / "audit-keys.json"
        provision(key_file)
        signing_file = key_file.parent / "transparency-key.json"
        provision_signing(signing_file)
        origin = os.environ.get("ROOTSENTINEL_ORIGIN", "http://127.0.0.1:5173")
        settings = Settings(paths, f"sqlite:///{paths.database.as_posix()}", "local", origin=origin,
                            audit_key_file=key_file, checkpoint_root=Path(external) / "checkpoints", transparency_key_file=signing_file)
        cfg = Config(str(SOURCE_ROOT / "backend/alembic.ini"))
        cfg.attributes["settings"] = settings
        command.upgrade(cfg, "head")
        password = secrets.token_urlsafe(32)
        accounts = [("demo-admin", "ADMIN"), ("demo-analyst", "ANALYST")] + [(f"demo-emp-{i}", "EMPLOYEE") for i in range(1, EMPLOYEES + 1)]
        db = Database(settings.database_url)
        hashed = HASHER.hash(password)
        with db.transaction() as s:
            for username, role in accounts:
                s.add(User(username=username, role=role, password_hash=hashed))
        db.engine.dispose()
        session_file = state / "demo-session.json"
        with session_file.open("x", encoding="utf-8") as handle:
            json.dump({"password": password, "accounts": dict(accounts), "origin": origin}, handle)
        if os.name != "nt":
            session_file.chmod(0o600)
        try:
            uvicorn.run(create_app(settings), host="127.0.0.1", port=int(os.environ.get("ROOTSENTINEL_API_PORT", "8000")),
                        access_log=False, proxy_headers=False)
        finally:
            session_file.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
