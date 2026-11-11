"""Adversarial gateway tests use real ASGI HTTP and isolated synthetic data."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError

from app.api import create_app
from app.audit import KeyRing
from app.db import now
from app.errors import DomainError
from app.gateway_models import AuditEvent, Incident, ReleaseAttempt, Transfer
from app.models import RegistryState
from app.transfers import transition

PROTECTED = b"SYNTHETIC-PROTECTED-" * 128
BENIGN = b"Public synthetic delivery bytes.\n" * 100


def submit(client, data=BENIGN, key=None, filename="test.bin"):
    return client.post("/api/v1/transfers", params={"filename": filename}, content=data,
        headers={"Content-Type": "application/octet-stream", "Idempotency-Key": key or str(uuid4())})


def release(client, identifier):
    return client.post(f"/api/v1/transfers/{identifier}/release")


def register(client):
    result = client.post("/api/v1/assets?label=Synthetic", content=PROTECTED, headers={"Content-Type": "application/octet-stream"})
    assert result.status_code == 201, result.text


def test_download_identical_single_use_and_checkpoint(client, login):
    login(client)
    result = submit(client)
    assert result.status_code == 201, result.text
    item = result.json()
    assert item["state"] == "ALLOWED"
    response = release(client, item["id"])
    assert response.status_code == 200, response.text
    assert response.content == BENIGN
    assert sha256(response.content).hexdigest() == item["scan"]["detection"]["manifest"]["file_sha256"]
    assert "attachment;" in response.headers["content-disposition"]
    assert "no-store" in response.headers["cache-control"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert release(client, item["id"]).status_code == 409
    assert client.get("/api/v1/transfers/" + item["id"]).json()["state"] == "STREAM_FINISHED"
    verification = client.post("/api/v1/audit/verify").json()
    assert verification["valid"] and verification["checkpoint_sequence"] > 0
    assert not list(client.app.state.gateway.store.root.iterdir())


def test_block_zero_content_incident_and_resolution(client, login):
    login(client); register(client)
    item = submit(client, PROTECTED).json()
    assert item["state"] == "BLOCKED"
    response = release(client, item["id"])
    assert response.status_code == 409 and PROTECTED not in response.content
    assert not list(client.app.state.gateway.store.root.iterdir())
    detail = client.get("/api/v1/incidents/" + item["incident_id"]).json()
    assert detail["scan"]["id"] == item["scan"]["id"]
    assert detail["severity"] == "HIGH"
    edited = client.patch("/api/v1/incidents/" + detail["id"], json={"expected_revision": 1,
        "status": "RESOLVED", "note": "Authorized synthetic test", "resolution": "Training exercise"})
    assert edited.status_code == 200, edited.text
    assert len(edited.json()["history"]) == 2
    assert release(client, item["id"]).status_code == 409
    exported = client.get("/api/v1/exports/incidents/" + detail["id"])
    assert exported.status_code == 200
    assert PROTECTED not in exported.content
    assert all(word not in exported.text for word in ("password", "token_digest", "audit-keys", "runtime/"))
    assert exported.json()["audit_references"]


@pytest.mark.parametrize("change", ["missing", "bytes", "length", "digest", "expired", "policy", "registry", "error"])
def test_preflight_fail_closed(client, login, change):
    login(client)
    item = submit(client).json(); identifier = item["id"]
    gateway = client.app.state.gateway
    with gateway.db.transaction() as s:
        t = s.get(Transfer, identifier)
        path = gateway.store.path(t.snapshot_id)
        if change == "missing": path.unlink()
        elif change == "bytes": path.write_bytes(b"tampered")
        elif change == "length": t.file_size += 1
        elif change == "digest": t.file_sha256 = "0" * 64
        elif change == "expired": t.expires_at = now() - timedelta(seconds=1)
        elif change == "registry": s.get(RegistryState, 1).revision += 1
        elif change == "error": transition(t, "ERROR", "FAULT_INJECTION")
    if change == "policy":
        policy = client.get("/api/v1/policies/active").json()
        assert client.post("/api/v1/policies", json={"expected_version": policy["id"], "threshold": 2048}).status_code == 201
    response = release(client, identifier)
    assert response.status_code in {409, 410, 503}
    assert BENIGN not in response.content


def test_ownership_roles_csrf_public_mode(client, login, system):
    login(client, "employee"); item = submit(client).json()
    login(client, "second")
    assert release(client, item["id"]).status_code == 404
    assert client.get("/api/v1/transfers/" + item["id"]).status_code == 404
    assert not client.get("/api/v1/transfers").json()["items"]
    assert client.get("/api/v1/incidents").status_code == 403
    assert client.post("/api/v1/audit/verify").status_code == 403
    login(client, "admin")
    assert release(client, item["id"]).status_code == 404  # no privileged payload access
    client.headers.pop("x-csrf-token")
    assert release(client, item["id"]).status_code == 403
    client.cookies.clear()
    assert release(client, item["id"]).status_code == 401
    public = create_app(replace(system[0], mode="public_demo", secure_cookies=True))
    with TestClient(public, base_url=system[0].origin) as other:
        assert submit(other).status_code == 403


@pytest.mark.parametrize("filename", ["../private", "a/b", "x\\secret", "evil\r\nheader", "<script>"])
def test_unsafe_filename(client, login, filename):
    login(client)
    assert submit(client, filename=filename).status_code == 422
    assert not list(client.app.state.gateway.store.root.iterdir())


def test_idempotency_and_invalid_identifiers(client, login):
    login(client); key = str(uuid4())
    first = submit(client, key=key).json()
    assert submit(client, key=key).json()["id"] == first["id"]
    assert submit(client, b"different", key=key).status_code == 409
    assert submit(client, key="not-a-uuid").status_code == 422
    assert release(client, "not-a-uuid").status_code == 422
    assert release(client, str(uuid4())).status_code == 404


def test_missing_key_and_audit_failure(client, login, monkeypatch):
    login(client)
    gateway = client.app.state.gateway
    item = submit(client).json()
    original = gateway.audit.keys
    gateway.audit.keys = KeyRing("missing", {})
    assert release(client, item["id"]).status_code == 503
    gateway.audit.keys = original
    original_append = gateway.audit.append
    def fail(s, kind, *args, **kwargs):
        if kind == "RELEASE_STARTED": raise DomainError("AUDIT_STORAGE_FAILURE", 503)
        return original_append(s, kind, *args, **kwargs)
    monkeypatch.setattr(gateway.audit, "append", fail)
    assert release(client, item["id"]).status_code == 503
    with gateway.db.transaction() as s:
        assert s.get(Transfer, item["id"]).state == "ALLOWED"
        assert not s.scalar(select(ReleaseAttempt))


def test_concurrent_release_and_append(client, login):
    login(client); item = submit(client).json()
    def attempt(_): return release(client, item["id"])
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(attempt, range(2)))
    assert sorted(r.status_code for r in responses) == [200, 409]
    assert sum(r.content == BENIGN for r in responses) == 1
    assert client.post("/api/v1/audit/verify").json()["valid"]


def test_expiry_cleanup_and_restart(client, login):
    login(client); item = submit(client).json()
    gateway = client.app.state.gateway
    with gateway.db.transaction() as s:
        s.get(Transfer, item["id"]).expires_at = now() - timedelta(seconds=1)
    unrelated = gateway.store.root / "unrelated.txt"; unrelated.write_text("keep")
    assert gateway.recover()["transitioned"] == 1
    assert unrelated.read_text() == "keep"
    assert release(client, item["id"]).status_code == 409
    second = submit(client).json()
    # Simulate committed preflight followed by process termination before HTTP send.
    actor = client.app.state.auth.authenticate(client.cookies["rs_session"], client.headers["x-csrf-token"], True)
    assert gateway.release(actor, second["id"]) == BENIGN
    assert gateway.recover(restart=True)["transitioned"] == 1
    assert client.get("/api/v1/transfers/" + second["id"]).json()["state"] == "DELIVERY_UNKNOWN"
    assert release(client, second["id"]).status_code == 409


def test_incident_notes_roles_and_conflicts(client, login):
    login(client); register(client); item = submit(client, PROTECTED).json()
    route = "/api/v1/incidents/" + item["incident_id"]
    login(client, "employee")
    assert client.patch(route, json={"expected_revision": 1, "status": "INVESTIGATING"}).status_code == 403
    login(client, "analyst")
    assert client.patch(route, json={"expected_revision": 1, "status": "INVESTIGATING", "note": "<script>"}).status_code == 422
    assert client.patch(route, json={"expected_revision": 1, "status": "INVESTIGATING"}).status_code == 200
    assert client.patch(route, json={"expected_revision": 1, "status": "RESOLVED", "resolution": "stale"}).status_code == 409


def test_buffer_survives_snapshot_change_after_capture(client, login, monkeypatch):
    login(client); item = submit(client).json()
    store = client.app.state.gateway.store
    original = store.capture
    def capture(identifier):
        data = original(identifier)
        store.path(identifier).write_bytes(b"changed after verified capture")
        return data
    monkeypatch.setattr(store, "capture", capture)
    assert release(client, item["id"]).content == BENIGN


def test_snapshot_deletion_during_preflight(client, login, monkeypatch):
    login(client); item = submit(client).json(); store = client.app.state.gateway.store
    def disappear(identifier):
        store.path(identifier).unlink()
        raise FileNotFoundError()
    monkeypatch.setattr(store, "capture", disappear)
    response = release(client, item["id"])
    assert response.status_code == 503 and BENIGN not in response.content


def test_empty_and_fixture_path(client, login):
    login(client)
    item = submit(client, b"").json()
    assert release(client, item["id"]).content == b""
    response = client.post("/api/v1/transfers/fixtures", json={"fixture": "benign"}, headers={"Idempotency-Key": str(uuid4())})
    assert response.status_code == 201
    assert release(client, response.json()["id"]).content == b"RootSentinel synthetic benign delivery\n"


def test_oversized_and_partial_upload(client, login):
    login(client)
    assert submit(client, b"X" * (10485760 + 1)).status_code == 413
    response = client.post("/api/v1/transfers", content=b"short", headers={"Content-Type": "application/octet-stream", "Content-Length": "99", "Idempotency-Key": str(uuid4())})
    assert response.status_code == 400
    assert client.get("/api/v1/transfers").json()["items"] == []


@pytest.mark.parametrize("failure", ["checkpoint", "database", "snapshot_permissions"])
def test_mandatory_pre_send_failures(client, login, monkeypatch, failure):
    login(client); item = submit(client).json(); gateway = client.app.state.gateway
    if failure == "checkpoint":
        def fail(*_): raise OSError("synthetic checkpoint failure")
        monkeypatch.setattr(gateway.audit, "retain_checkpoint", fail)
    elif failure == "snapshot_permissions":
        def fail(*_): raise PermissionError("synthetic permission failure")
        monkeypatch.setattr(gateway.store, "capture", fail)
    else:
        from contextlib import contextmanager
        original = gateway.db.transaction
        @contextmanager
        def fail_commit():
            with original() as s:
                yield s
                raise OperationalError("synthetic commit failure", {}, Exception())
        monkeypatch.setattr(gateway.db, "transaction", fail_commit)
    response = release(client, item["id"])
    assert response.status_code == 503 and BENIGN not in response.content


def test_concurrent_idempotent_creation(client, login):
    login(client); key = str(uuid4())
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: submit(client, key=key), range(2)))
    assert all(r.status_code == 201 for r in responses)
    assert len({r.json()["id"] for r in responses}) == 1
    assert len(client.get("/api/v1/transfers").json()["items"]) == 1


@pytest.mark.parametrize("mutation", ["policy", "registry"])
def test_revision_mutation_waits_for_release_acquisition(client, login, system, monkeypatch, mutation):
    from threading import Event
    from app.policy import change_policy
    from app.registry import register as register_service
    from app.schemas import PolicyInput
    login(client); item = submit(client).json(); gateway = client.app.state.gateway
    acquired, proceed, attempted, finished = Event(), Event(), Event(), Event()
    original = gateway.store.capture
    def capture(identifier):
        acquired.set()
        assert proceed.wait(10)
        return original(identifier)
    monkeypatch.setattr(gateway.store, "capture", capture)
    def change():
        attempted.set()
        with system[1].transaction() as s:
            if mutation == "policy":
                change_policy(s, system[2]["admin"], PolicyInput(expected_version=item["scan"]["policy_id"], threshold=2048))
            else:
                register_service(s, system[2]["admin"], "Concurrent registration", BENIGN)
        finished.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        response = pool.submit(release, client, item["id"])
        assert acquired.wait(10)
        updating = pool.submit(change)
        assert attempted.wait(10)
        assert not finished.wait(0.1)  # mutation cannot commit inside release acquisition
        proceed.set()
        assert response.result(timeout=15).content == BENIGN
        updating.result(timeout=15)
    assert finished.is_set()


def test_scanning_failure_and_restart_cleanup(client, login, monkeypatch):
    import app.transfers as module
    login(client); gateway = client.app.state.gateway
    def fail(*_): raise DomainError("DETECTOR_FAILED", 503)
    monkeypatch.setattr(module, "run_scan", fail)
    assert submit(client).status_code == 503
    item = client.get("/api/v1/transfers").json()["items"][0]
    assert item["state"] == "ERROR" and not item["release_eligible"]
    assert not list(gateway.store.root.iterdir())
    assert release(client, item["id"]).status_code == 409


def test_rate_and_capacity_bounds(client, login):
    from app.gateway_api import TransferLimiter
    current = [1.0]; limiter = TransferLimiter(lambda: current[0])
    for _ in range(30): limiter.check("actor")
    with pytest.raises(DomainError): limiter.check("actor")
    current[0] += 60
    limiter.check("actor")
    login(client)
    for _ in range(10): assert submit(client).status_code == 201
    assert submit(client).status_code == 429


def test_released_session_must_remain_authorized(client, login):
    from app.models import SessionRecord
    login(client); item = submit(client).json()
    gateway = client.app.state.gateway
    actor = client.app.state.auth.authenticate(client.cookies["rs_session"], client.headers["x-csrf-token"], True)
    with gateway.db.transaction() as s: s.get(SessionRecord, actor.session_id).revoked_at = now()
    with pytest.raises(DomainError) as exc: gateway.release(actor, item["id"])
    assert exc.value.status == 401


def test_response_disconnect_and_send_failure():
    import asyncio
    import anyio
    from app.gateway_api import VerifiedResponse
    async def run(disconnect):
        observations = []
        class Stub:
            def finish(self, identifier, completed): observations.append(completed)
        limiter = anyio.CapacityLimiter(2); borrower = object()
        limiter.acquire_on_behalf_of_nowait(borrower)
        response = VerifiedResponse(BENIGN, Stub(), str(uuid4()), limiter, borrower)
        async def send(message):
            if disconnect: await asyncio.sleep(10)
            else: raise OSError("synthetic disconnected send")
        async def receive():
            if not disconnect: await asyncio.sleep(10)
            return {"type": "http.disconnect"}
        try: await response({"type": "http"}, receive, send)
        except OSError: pass
        assert observations == [False]
        assert limiter.borrowed_tokens == 0
    asyncio.run(run(True)); asyncio.run(run(False))


def test_upgrade_phase02_preserves_existing_history(system, monkeypatch):
    from alembic import command
    from app import profiles
    from app.registry import register as register_service, version_view
    from app.models import AssetVersion
    settings, db, actors, cfg = system
    command.downgrade(cfg, "0001")
    # A registration made on the phase 02 schema: only the fixed profile existed, so nothing else is written.
    with monkeypatch.context() as phase02:
        phase02.setattr(profiles, "store_additional", lambda *_: None)
        phase02.setattr(profiles, "version_profiles", lambda s, versions: {v.id: [] for v in versions})
        with db.transaction() as s: version = register_service(s, actors["admin"], "Upgrade preserved", PROTECTED)
    command.upgrade(cfg, "head")
    with db.transaction() as s:
        assert s.get(AssetVersion, version.id).file_sha256 == sha256(PROTECTED).hexdigest()
        # The upgrade adds no fingerprints: the old version keeps only the fixed profile.
        assert [(p.profile_id, p.fingerprinted) for p in version_view(s, version.asset_id, version.id).profiles] == [
            ("rs-fixed-sha256-v1", True), ("rs-cdc-gear-v1", False)]


def test_tampered_database_audit_cannot_release(client, login):
    login(client); item = submit(client).json(); db = client.app.state.db
    with db.transaction() as s:
        if db.engine.dialect.name == "sqlite":
            s.execute(text("DROP TRIGGER immutable_audit_events_update"))
        else:
            s.execute(text("ALTER TABLE audit_events DISABLE TRIGGER immutable_audit_events"))
        s.execute(text("UPDATE audit_events SET mac = :bad WHERE sequence = 1"), {"bad": "0" * 64})
    response = release(client, item["id"])
    assert response.status_code == 503 and BENIGN not in response.content


def test_private_snapshot_symlink_and_permissions(client, login, tmp_path):
    import os
    login(client); item = submit(client).json(); gateway = client.app.state.gateway
    with gateway.db.transaction() as s: snapshot_id = s.get(Transfer, item["id"]).snapshot_id
    target = tmp_path / "unrelated-target"; target.write_bytes(b"Do not delete")
    target.chmod(0o600)
    path = gateway.store.path(snapshot_id); path.unlink()
    try: path.symlink_to(target)
    except OSError:
        assert os.name == "nt"  # native symlink privileges may be unavailable
        return
    response = release(client, item["id"])
    assert response.status_code == 503 and target.read_bytes() == b"Do not delete"


def test_missing_keys_roll_back_registry(client, login):
    from app.models import Asset
    login(client); gateway = client.app.state.gateway
    gateway.audit.keys = KeyRing("missing", {})
    response = client.post("/api/v1/assets?label=Unavailable", content=PROTECTED, headers={"Content-Type": "application/octet-stream"})
    assert response.status_code == 503
    with gateway.db.transaction() as s:
        assert not s.scalar(select(Asset))
        assert s.get(RegistryState, 1).revision == 0


def test_no_payload_or_secret_in_gateway_logs(client, login, caplog):
    login(client)
    sentinel = b"PRIVATE_SYNTHETIC_SENTINEL_DO_NOT_LOG"
    item = submit(client, sentinel).json()
    assert release(client, item["id"]).content == sentinel
    assert sentinel.decode() not in caplog.text
    assert client.cookies["rs_session"] not in caplog.text


def test_migration_matches_models(system):
    from alembic import command
    command.check(system[3])
