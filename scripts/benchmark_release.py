"""Release latency against the size of the audit log.

Measures the wall time of POST /transfers/{id}/release through the real ASGI application on a throwaway
SQLite database, after the audit log has been filled to a given number of events. It runs unchanged on a
tree with or without the transparency log, so the same script gives the "before" and "after" figures:

    python -B scripts/benchmark_release.py --events 0 2000 10000 --releases 15

Local SQLite on one machine: the numbers compare two versions of the code, they are not a hosted latency.
"""
import argparse
import base64
import json
from pathlib import Path
import secrets
import statistics
import sys
import tempfile
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.api import create_app  # noqa: E402
from app.auth import HASHER  # noqa: E402
from app.config import StoragePaths  # noqa: E402
from app.db import Database  # noqa: E402
from app.models import User  # noqa: E402
from app.settings import Settings  # noqa: E402

PAYLOAD = b"Synthetic benchmark delivery bytes.\n" * 100


def measure(events: int, releases: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="rootsentinel-release-benchmark-") as directory:
        external = Path(directory)
        paths = StoragePaths(external / "runtime", external / "artifacts")
        keys = external / "keys"
        keys.mkdir(mode=0o700)
        audit_key = keys / "audit-keys.json"
        audit_key.write_text(json.dumps({"version": 1, "active_id": "bench", "keys": {"bench": base64.b64encode(secrets.token_bytes(32)).decode()}}))
        audit_key.chmod(0o600)
        extra = {}
        if "transparency_key_file" in Settings.__dataclass_fields__:
            from app.crypto.transparency import key_id_for, public_key_of
            seed = secrets.token_bytes(32)
            key_id = key_id_for(public_key_of(seed))
            signing = keys / "transparency-key.json"
            signing.write_text(json.dumps({"version": 1, "algorithm": "Ed25519", "active_id": key_id, "keys": {key_id: base64.b64encode(seed).decode()}}))
            signing.chmod(0o600)
            extra["transparency_key_file"] = signing
        settings = Settings(paths, f"sqlite:///{paths.database.as_posix()}", "local", secure_cookies=False,
                            audit_key_file=audit_key, checkpoint_root=external / "checkpoints", transfer_rate_per_minute=120, **extra)
        cfg = Config(str(ROOT / "backend/alembic.ini"))
        cfg.attributes["settings"] = settings
        command.upgrade(cfg, "head")
        password = secrets.token_urlsafe(24)
        db = Database(settings.database_url)
        with db.transaction() as s:
            user = User(username="bench", role="ADMIN", password_hash=HASHER.hash(password))
            s.add(user)
            s.flush()
            actor_id = user.id
        db.engine.dispose()
        app = create_app(settings)
        with TestClient(app, base_url="http://127.0.0.1:5173") as client:
            client.headers["origin"] = settings.origin
            client.headers["x-csrf-token"] = client.post("/api/v1/auth/login", json={"username": "bench", "password": password}).json()["csrf_token"]
            audit = app.state.gateway.audit
            for start in range(0, events, 200):
                with app.state.db.transaction() as s:
                    for i in range(start, min(events, start + 200)):
                        audit.append(s, "AUDIT_VERIFIED", actor_id, revision=i)
            samples = []
            for _ in range(releases):
                item = client.post("/api/v1/transfers", params={"filename": "bench.bin"}, content=PAYLOAD,
                                   headers={"Content-Type": "application/octet-stream", "Idempotency-Key": str(uuid4())}).json()
                started = time.perf_counter()
                response = client.post(f"/api/v1/transfers/{item['id']}/release")
                samples.append((time.perf_counter() - started) * 1000)
                assert response.status_code == 200 and response.content == PAYLOAD, response.status_code
        samples.sort()
        return {"events_before": events, "releases": releases, "median_ms": round(statistics.median(samples), 2),
                "min_ms": round(samples[0], 2), "max_ms": round(samples[-1], 2)}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--events", type=int, nargs="+", default=[0, 2000, 10000])
    parser.add_argument("--releases", type=int, default=15)
    args = parser.parse_args()
    for events in args.events:
        print(json.dumps(measure(events, args.releases)), flush=True)


if __name__ == "__main__":
    main()
