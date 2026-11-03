"""Ephemeral loopback browser-test harness. Credentials stay outside the repository.

Run with ROOTSENTINEL_BROWSER_STATE pointing to a new external directory. The
state file is for the local Playwright test only; never publish it. Stop with Ctrl-C.
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
from app.audit_keys import provision
from app.auth import HASHER
from app.config import StoragePaths, validate_external_path
from app.db import Database
from app.models import User
from app.settings import Settings, SOURCE_ROOT


def main():
    state = validate_external_path(Path(os.environ["ROOTSENTINEL_BROWSER_STATE"]), SOURCE_ROOT)
    state.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(dir=state, prefix="session-") as external:
        paths = StoragePaths(Path(external) / "runtime", Path(external) / "artifacts")
        key_file = Path(external) / "secrets" / "audit-keys.json"
        provision(key_file)
        settings = Settings(paths, f"sqlite:///{paths.database.as_posix()}", "local",
                            origin=os.environ.get("ROOTSENTINEL_ORIGIN", "http://127.0.0.1:5173"), secure_cookies=False, audit_key_file=key_file, checkpoint_root=Path(external) / "checkpoints")
        cfg = Config(str(SOURCE_ROOT / "backend/alembic.ini"))
        cfg.attributes["settings"] = settings
        command.upgrade(cfg, "head")
        password = secrets.token_urlsafe(32)
        db = Database(settings.database_url)
        with db.transaction() as s:
            s.add(User(username="browser-admin", role="ADMIN", password_hash=HASHER.hash(password)))
        db.engine.dispose()
        credential_file = state / "browser-session.json"
        with credential_file.open("x", encoding="utf-8") as handle:
            json.dump({"username": "browser-admin", "password": password}, handle)
        if os.name != "nt": credential_file.chmod(0o600)
        try:
            uvicorn.run(create_app(settings), host="127.0.0.1", port=int(os.environ.get("ROOTSENTINEL_API_PORT", "8000")), access_log=False, proxy_headers=False)
        finally:
            credential_file.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
