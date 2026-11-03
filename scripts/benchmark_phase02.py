"""Reproducible synthetic SQLite microbenchmark; temporary database is discarded."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import platform
import secrets
import sqlite3
import statistics
import sys
import tempfile
import time
import tracemalloc

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from alembic import command
from alembic.config import Config
from sqlalchemy import event, select
from app.auth import HASHER, Principal
from app.config import StoragePaths
from app.crypto import fingerprint_bytes
from app.db import Database
from app.detection import detect
from app.models import AssetVersion, RegistryState, User
from app.policy import active_policy, evaluate, policy_view
from app.registry import register
from app.settings import Settings


def payload(size):
    return b"".join(sha256(f"synthetic-benchmark-{i}".encode()).digest() * 32 for i in range((size + 1023) // 1024))[:size]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = []
    with tempfile.TemporaryDirectory(prefix="rootsentinel-bench-") as external:
        paths = StoragePaths(Path(external) / "runtime", Path(external) / "artifacts")
        settings = Settings(paths, f"sqlite:///{paths.database.as_posix()}", "local", secure_cookies=False)
        cfg = Config(str(ROOT / "backend/alembic.ini"))
        cfg.attributes["settings"] = settings
        command.upgrade(cfg, "head")
        db = Database(settings.database_url)
        with db.transaction() as s:
            user = User(username="benchmark", role="ADMIN", enabled=False, password_hash=HASHER.hash(secrets.token_urlsafe(32)))
            s.add(user); s.flush()
            actor = Principal(user.id, user.username, user.role, "internal-benchmark")
        for size in [1024, 65536, 1048576, 10485760]:
            data = payload(size)
            started = time.perf_counter()
            with db.transaction() as s:
                version = register(s, actor, f"Synthetic {size}", data)
            registration = (time.perf_counter() - started) * 1000
            started = time.perf_counter()
            fp = fingerprint_bytes(data)
            hashing = (time.perf_counter() - started) * 1000
            measurements, counts = [], []
            peak = 0
            for _ in range(3):
                queries = []
                def count(conn, cursor, sql, params, context, many): queries.append(sql)
                event.listen(db.engine, "before_cursor_execute", count)
                tracemalloc.start()
                started = time.perf_counter()
                with db.transaction() as s:
                    evidence = detect(s, fp, version.registry_revision)
                measurements.append((time.perf_counter() - started) * 1000)
                peak = max(peak, tracemalloc.get_traced_memory()[1])
                tracemalloc.stop()
                event.remove(db.engine, "before_cursor_execute", count)
                counts.append(len(queries))
            with db.transaction() as s:
                p = policy_view(active_policy(s, s.get(RegistryState, 1)))
                started = time.perf_counter()
                for _ in range(100): evaluate(evidence, p)
                policy_ms = (time.perf_counter() - started) * 10
                started = time.perf_counter()
                for _ in range(100):
                    s.scalars(select(AssetVersion.id).where(AssetVersion.profile_id == fp.manifest.profile_id,
                        AssetVersion.file_size == size, AssetVersion.file_sha256 == fp.manifest.file_sha256)).all()
                exact_ms = (time.perf_counter() - started) * 10
            rows.append({"bytes": size, "registration_ms": round(registration, 3), "fingerprinting_ms": round(hashing, 3),
                "detection_median_ms_with_tracemalloc": round(statistics.median(measurements), 3), "detection_queries": counts,
                "python_traced_peak_bytes": peak, "policy_mean_ms": round(policy_ms, 5),
                "exact_lookup_mean_ms": round(exact_ms, 5), "sqlite_file_bytes": paths.database.stat().st_size})
        db.engine.dispose()
    report = {"environment": {"python": platform.python_version(), "os": platform.system(), "architecture": platform.machine(), "sqlite": sqlite3.sqlite_version},
        "method": "Growing registry, unique deterministic blocks, 3 detector runs with tracemalloc; 100 exact/policy runs. Warm local SQLite; not a capacity or production claim.", "measurements": rows}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
