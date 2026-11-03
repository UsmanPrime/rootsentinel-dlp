import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from app.api import COOKIE, create_app
from app.crypto import fingerprint_bytes
from app.intake import FrozenInput, receive_snapshot
from app.models import PolicyVersion, RegistryState, ScanEvaluation
from app.policy import evaluate, policy_view
from app.registry import register
from app.scans import run_scan
from app.settings import Settings
from tests.test_api_security import upload


def test_concurrent_scans_are_independent(system):
    _, db, actors, _ = system
    with db.transaction() as s:
        register(s, actors["admin"], "Parallel", b"A" * 1024)
    def task(i):
        with db.transaction() as s:
            return run_scan(s, actors["employee"], f"candidate-{i}", FrozenInput(str(uuid4()), b"A" * 1024))
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(task, range(8)))
    assert len({r.id for r in results}) == 8
    assert {r.decision.outcome for r in results} == {"BLOCK"}
    assert {r.detection.registry_revision for r in results} == {1}


def test_historical_scan_rows_immutable(client, login, system):
    login(client)
    upload(client, "assets", label="Audit subject")
    upload(client, "scans")
    for table in ("scan_evaluations", "policy_decisions", "matching_evidence", "registry_revisions"):
        with pytest.raises(DatabaseError), system[1].transaction() as s:
            s.execute(text(f"DELETE FROM {table}"))


def test_incomplete_content_length(client, login, system):
    login(client)
    r = client.post("/api/v1/scans", headers={"content-type": "application/octet-stream", "content-length": "99"}, content=b"short")
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "INCOMPLETE_UPLOAD"
    assert not list(system[0].paths.snapshots.iterdir())


def test_upload_stream_uses_actual_bytes_without_content_length(system):
    async def chunks():
        for _ in range(11):
            yield b"A" * 1024
    with pytest.raises(Exception, match="INPUT_TOO_LARGE"):
        asyncio.run(receive_snapshot(chunks(), system[0].paths.snapshots, limit=10240))
    assert not list(system[0].paths.snapshots.iterdir())


@pytest.mark.parametrize("endpoint", ["scans", "transfers"])
def test_asgi_disconnect_is_not_a_scan(client, login, system, endpoint):
    login(client)
    cookie = client.cookies.get(COOKIE)
    headers = [(b"host", b"127.0.0.1:5173"), (b"origin", system[0].origin.encode()),
               (b"content-type", b"application/octet-stream"), (b"cookie", f"{COOKIE}={cookie}".encode()),
               (b"x-csrf-token", client.headers["x-csrf-token"].encode()), (b"idempotency-key", str(uuid4()).encode())]
    route = "/api/v1/" + endpoint
    scope = {"type": "http", "asgi": {"version": "3.0"}, "method": "POST", "path": route,
             "raw_path": route.encode(), "query_string": b"", "headers": headers, "http_version": "1.1",
             "scheme": "http", "server": ("127.0.0.1", 5173), "client": ("127.0.0.1", 4000)}
    async def exercise():
        messages = iter([{"type": "http.request", "body": b"partial", "more_body": True}, {"type": "http.disconnect"}])
        sent = []
        async def receive(): return next(messages)
        async def send(message): sent.append(message)
        await client.app(scope, receive, send)
        return sent
    sent = asyncio.run(exercise())
    assert sent[0]["status"] == 400
    assert b"INCOMPLETE_UPLOAD" in sent[1]["body"]
    assert not list(system[0].paths.snapshots.iterdir())
    with system[1].transaction() as s:
        assert not s.scalars(select(ScanEvaluation)).all()


def test_unexpected_exception_sanitized(client, login, monkeypatch, caplog):
    login(client)
    def broken(*args): raise RuntimeError("PRIVATE_SENTINEL")
    monkeypatch.setattr("app.api.run_scan", broken)
    response = upload(client, "scans")
    assert response.status_code == 503
    assert "PRIVATE_SENTINEL" not in response.text + caplog.text


def test_successful_scan_has_no_content_in_logs(client, login, caplog):
    login(client)
    assert upload(client, "scans", data=b"PRIVATE_PAYLOAD_SENTINEL").status_code == 201
    assert "PRIVATE_PAYLOAD_SENTINEL" not in caplog.text


def test_database_missing_registry_fails_closed(client, login, system):
    login(client)
    with system[1].transaction() as s:
        s.execute(text("DELETE FROM registry_state"))
    result = upload(client, "scans")
    assert result.status_code == 503
    assert result.json()["error"]["outcome"] == "INDETERMINATE"


def test_policy_no_combining_assets(system):
    _, db, actors, _ = system
    with db.transaction() as s:
        register(s, actors["admin"], "First small tail", b"Z" * 1024 + b"A" * 600)
        register(s, actors["admin"], "Second small tail", b"Y" * 1024 + b"A" * 600)
        result = run_scan(s, actors["employee"], "small", FrozenInput(str(uuid4()), b"A" * 600))
    assert len(result.detection.matches) == 2
    assert result.decision.outcome == "ALLOW"


def test_origin_settings_and_secure_cookie(system, credentials):
    with pytest.raises(ValueError):
        replace(system[0], origin="https://public.invalid", secure_cookies=False)
    with pytest.raises(ValueError):
        replace(system[0], origin="http://127.0.0.1:5173/path")
    settings = replace(system[0], origin="https://localhost:5173", secure_cookies=True)
    with TestClient(create_app(settings), base_url=settings.origin) as c:
        r = c.post("/api/v1/auth/login", headers={"origin": settings.origin}, json={"username": "admin", "password": credentials[0]})
        assert r.status_code == 200
        assert "Secure" in r.headers["set-cookie"]


def test_snapshot_link_rejected(system, monkeypatch):
    actual = Path.is_symlink
    target = system[0].paths.snapshots
    monkeypatch.setattr(Path, "is_symlink", lambda p: p == target or actual(p))
    with pytest.raises(ValueError, match="cannot be a link"):
        system[0].prepare_storage()


def test_disabled_user_and_api_version_conflict(client, login, system):
    login(client)
    v = upload(client, "assets", label="Versioned").json()
    new = upload(client, f"assets/{v['asset_id']}/versions", data=b"different", expected_version=1)
    assert new.status_code == 201
    assert upload(client, f"assets/{v['asset_id']}/versions", data=b"third", expected_version=1).status_code == 409
    from app.models import User
    with system[1].transaction() as s:
        s.get(User, system[2]["admin"].id).enabled = False
    assert client.get("/api/v1/auth/me").status_code == 401
