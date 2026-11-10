"""Reproducible synthetic SQLite measurements, not an enterprise benchmark."""
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time
import tracemalloc
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from alembic import command
from alembic.config import Config
from sqlalchemy import event
from app.auth import AuthService, HASHER, csrf_for
from app.audit_keys import provision, provision_signing
from app.config import StoragePaths
from app.db import Database
from app.intake import FrozenInput
from app.models import User
from app.registry import register
from app.settings import Settings
from app.transfers import Gateway


def main():
    measurements = {}; count = [0]
    def measure(name, action):
        start_count = count[0]; started = time.perf_counter()
        result = action()
        measurements.setdefault(name, []).append({"ms": (time.perf_counter() - started) * 1000, "queries": count[0] - start_count})
        return result
    with tempfile.TemporaryDirectory(prefix="rootsentinel-gateway-benchmark-") as directory:
        external = Path(directory); paths = StoragePaths(external / "runtime", external / "artifacts")
        key_file = external / "keys" / "audit-keys.json"; provision(key_file)
        signing_file = external / "keys" / "transparency-key.json"; provision_signing(signing_file)
        settings = Settings(paths, f"sqlite:///{paths.database.as_posix()}", "local", secure_cookies=False,
            audit_key_file=key_file, checkpoint_root=external / "checkpoints", transparency_key_file=signing_file)
        cfg = Config(str(ROOT / "backend/alembic.ini")); cfg.attributes["settings"] = settings
        command.upgrade(cfg, "head"); db = Database(settings.database_url)
        @event.listens_for(db.engine, "before_cursor_execute")
        def counted(*_): count[0] += 1
        import secrets
        password = secrets.token_urlsafe(32)
        with db.transaction() as s: s.add(User(username="benchmark", role="ADMIN", password_hash=HASHER.hash(password)))
        auth = AuthService(db, settings); token, _ = auth.login("benchmark", password, "loopback", None)
        actor = auth.authenticate(token, csrf_for(token), True); gateway = Gateway(db, settings)
        with db.transaction() as s: register(s, actor, "Synthetic protected", b"P" * 2048)
        for size in (1024, 1048576, 10485760):
            data = (b"synthetic-public-benchmark-" * (size // 27 + 1))[:size]
            # Repeat exactly enough regardless of marker length.
            data = (data * 2)[:size]
            for _ in range(3):
                snapshot = FrozenInput(str(uuid4()), data)
                measure(f"snapshot_capture_{size}", lambda: gateway.store.save(snapshot))
                gateway.store.remove(snapshot.id)
                tracemalloc.start()
                transfer = measure(f"scan_to_decision_{size}", lambda: gateway.submit(actor, "synthetic.bin", snapshot, str(uuid4())))
                delivered = measure(f"release_preflight_{size}", lambda: gateway.release(actor, transfer.id))
                assert delivered == data
                _, peak = tracemalloc.get_traced_memory(); tracemalloc.stop()
                measurements.setdefault(f"python_peak_bytes_{size}", []).append(peak)
                gateway.finish(transfer.id, True)
        for _ in range(10):
            with db.transaction() as s:
                measure("hmac_append", lambda: gateway.audit.append(s, "AUDIT_VERIFIED", actor.id))
            with db.transaction() as s:
                assert measure("audit_verify", lambda: gateway.audit.verify(s))["valid"]
        for _ in range(3):
            transfer = measure("blocked_scan_with_incident", lambda: gateway.submit(actor, "protected.bin", FrozenInput(str(uuid4()), b"P" * 2048), str(uuid4())))
            assert transfer.state == "BLOCKED" and transfer.incident_id
        summary = {}
        for name, rows in measurements.items():
            if name.startswith("python_peak"):
                summary[name] = {"samples": len(rows), "maximum": max(rows)}
            else:
                summary[name] = {"samples": len(rows), "median_ms": round(statistics.median(r["ms"] for r in rows), 3),
                    "min_ms": round(min(r["ms"] for r in rows), 3), "max_ms": round(max(r["ms"] for r in rows), 3),
                    "query_counts": [r["queries"] for r in rows]}
        db.engine.dispose()
        report = {"observed_at_utc": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
            "os": platform.system(), "architecture": platform.machine(), "database": "SQLite external temporary database",
            "measurements": summary, "limitations": ["Single process, sequential samples, local filesystem; not a throughput SLA.",
            "Scan/release measured with tracemalloc enabled; Python peak is not process RSS.",
            "Preflight includes chain verification, digest checks, DB commit and external checkpoint; no network transport timing.",
            "Append timing excludes surrounding transaction commit; incident timing includes scan and decision.",
            "Query counts include transaction lock and audit operations; audit history grows during samples."]}
        (ROOT / "docs/evidence/phase-03-benchmark.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__": main()
