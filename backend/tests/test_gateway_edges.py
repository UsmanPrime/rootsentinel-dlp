"""Gateway edge cases: upload size boundaries, names, content types, release replay, expiry, staleness,
a wide parallel release race, and audit tampering (stored events and checkpoint files).

Each test drives the real application over ASGI with synthetic data only.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
import json
import threading
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text

from app.api import create_app
from app.db import now
from app.gateway_models import AuditEvent, Transfer

PROTECTED = b"SYNTHETIC-PROTECTED-" * 128
BENIGN = b"Edge-case synthetic delivery bytes.\n" * 30
OCTET = {"Content-Type": "application/octet-stream"}


def signed_in(app, origin, credentials, name="admin"):
    client = TestClient(app, base_url="http://127.0.0.1:5173", raise_server_exceptions=False)
    client.__enter__()
    client.headers["origin"] = origin
    result = client.post("/api/v1/auth/login", json={"username": name, "password": credentials[0]})
    assert result.status_code == 200, result.text
    client.headers["x-csrf-token"] = result.json()["csrf_token"]
    return client


def submit(client, data=BENIGN, filename="edge.bin", content_type="application/octet-stream"):
    headers = {"Idempotency-Key": str(uuid4())}
    if content_type is not None:
        headers["Content-Type"] = content_type
    return client.post("/api/v1/transfers", params={"filename": filename}, content=data, headers=headers)


def transfer_count(app):
    with app.state.db.transaction() as s:
        return s.scalar(select(func.count()).select_from(Transfer))


@pytest.fixture
def capped(system, credentials):
    """A gateway with a small upload cap so boundary values are cheap to send."""
    app = create_app(replace(system[0], max_upload_bytes=2048))
    client = signed_in(app, system[0].origin, credentials)
    yield app, client
    client.__exit__(None, None, None)


# ---------------------------------------------------------------------------------------------- size boundaries
@pytest.mark.parametrize("size,expected", [(2047, 201), (2048, 201), (2049, 413), (4096, 413)])
def test_upload_cap_boundary(capped, size, expected):
    app, client = capped
    before = transfer_count(app)
    response = submit(client, b"a" * size)
    assert response.status_code == expected, (size, response.text)
    if expected == 413:
        assert response.json()["error"]["code"] == "INPUT_TOO_LARGE"
        assert transfer_count(app) == before                       # nothing persisted for a refused upload
    else:
        assert response.json()["file_size"] == size


def test_a_lying_content_length_cannot_slip_past_the_cap(capped):
    _, client = capped
    response = client.post("/api/v1/transfers", content=b"b" * 4096,
                           headers={**OCTET, "Idempotency-Key": str(uuid4()), "Content-Length": "10"})
    assert response.status_code in {400, 413}


def test_an_empty_transfer_is_scanned_and_an_empty_asset_is_refused(capped):
    _, client = capped
    empty = submit(client, b"")
    assert empty.status_code == 201 and empty.json()["file_size"] == 0
    assert empty.json()["scan"]["detection"]["matches"] == []
    refused = client.post("/api/v1/assets?label=Empty", content=b"", headers=OCTET)
    assert refused.status_code == 422 and refused.json()["error"]["code"] == "EMPTY_PROTECTED_ASSET"


# ---------------------------------------------------------------------------------------------- names and types
@pytest.mark.parametrize("name", ["report.txt", "Quarterly report (final).pdf", "a.b-c_d", "9" * 120])
def test_safe_display_names_are_kept_as_labels(capped, name):
    _, client = capped
    response = submit(client, filename=name)
    assert response.status_code == 201, response.text
    assert response.json()["scan"]["filename"] == name


@pytest.mark.parametrize("name", ["../etc/passwd", "..\\windows\\win.ini", "/absolute", ".hidden", "naïve.txt", "名前.txt",
                                  "line\nbreak", "tab\tname", "semi;colon", "x" * 121, " leading-space", "-dash-first"])
def test_traversal_like_unicode_and_control_names_are_refused_before_storage(capped, name):
    app, client = capped
    before = transfer_count(app)
    response = submit(client, filename=name)
    assert response.status_code == 422 and response.json()["error"]["code"] == "INVALID_REQUEST", (name, response.text)
    assert transfer_count(app) == before


@pytest.mark.parametrize("content_type", [None, "application/json", "text/plain", "multipart/form-data; boundary=x",
                                          "application/octet-stream; charset=utf-8", "APPLICATION/OCTET-STREAM", "application/x-octet-stream"])
def test_only_the_exact_octet_stream_type_is_accepted(capped, content_type):
    app, client = capped
    before = transfer_count(app)
    response = submit(client, content_type=content_type)
    assert response.status_code == 415 and response.json()["error"]["code"] == "OCTET_STREAM_REQUIRED", content_type
    assert transfer_count(app) == before


# ---------------------------------------------------------------------------------------------- release rules
def test_release_replay_is_refused_without_content(capped):
    _, client = capped
    item = submit(client).json()
    first = client.post(f"/api/v1/transfers/{item['id']}/release")
    assert first.status_code == 200 and first.content == BENIGN
    for _ in range(3):
        again = client.post(f"/api/v1/transfers/{item['id']}/release")
        assert again.status_code == 409 and BENIGN not in again.content


def test_release_after_the_window_closes_delivers_nothing(capped):
    app, client = capped
    item = submit(client).json()
    with app.state.db.transaction() as s:
        s.get(Transfer, item["id"]).expires_at = now() - timedelta(seconds=1)
    response = client.post(f"/api/v1/transfers/{item['id']}/release")
    assert response.status_code in {409, 410} and BENIGN not in response.content
    assert response.json()["error"]["code"] in {"RELEASE_WINDOW_EXPIRED", "TRANSFER_EXPIRED", "TRANSFER_NOT_ALLOWED"}
    assert client.get(f"/api/v1/transfers/{item['id']}").json()["release_eligible"] is False


def test_a_policy_change_after_allow_makes_the_transfer_stale(capped):
    _, client = capped
    item = submit(client).json()
    active = client.get("/api/v1/policies/active").json()
    changed = client.post("/api/v1/policies", json={"threshold": 2048, "block_enabled": True, "expected_version": active["id"]})
    assert changed.status_code == 201
    response = client.post(f"/api/v1/transfers/{item['id']}/release")
    assert response.status_code == 409 and BENIGN not in response.content
    assert client.get(f"/api/v1/transfers/{item['id']}").json()["state"] == "STALE"


def test_a_registry_change_after_allow_makes_the_transfer_stale(capped):
    _, client = capped
    item = submit(client).json()
    assert client.post("/api/v1/assets?label=Later", content=PROTECTED[:1024], headers=OCTET).status_code == 201
    response = client.post(f"/api/v1/transfers/{item['id']}/release")
    assert response.status_code == 409 and BENIGN not in response.content


def test_a_block_never_delivers_however_often_it_is_asked(capped):
    _, client = capped
    assert client.post("/api/v1/assets?label=Edge", content=PROTECTED[:2048], headers=OCTET).status_code == 201
    item = submit(client, PROTECTED[:2048]).json()
    assert item["state"] == "BLOCKED" and item["incident_id"]
    for _ in range(3):
        response = client.post(f"/api/v1/transfers/{item['id']}/release")
        assert response.status_code == 409 and b"SYNTHETIC-PROTECTED-" not in response.content


def test_wide_parallel_release_race_delivers_exactly_once(system, credentials):
    app = create_app(system[0])
    owner = signed_in(app, system[0].origin, credentials, "employee")
    try:
        item = submit(owner).json()
        barrier = threading.Barrier(12)

        def attempt(_):
            barrier.wait()
            return owner.post(f"/api/v1/transfers/{item['id']}/release")

        with ThreadPoolExecutor(max_workers=12) as pool:
            responses = list(pool.map(attempt, range(12)))
        delivered = [r for r in responses if r.status_code == 200]
        assert len(delivered) == 1 and delivered[0].content == BENIGN
        assert sha256(delivered[0].content).hexdigest() == item["file_sha256"]
        assert all(r.status_code in {409, 429, 503} and BENIGN not in r.content for r in responses if r.status_code != 200)
        admin = signed_in(app, system[0].origin, credentials)
        try:
            assert admin.post("/api/v1/audit/verify").json()["valid"] is True
        finally:
            admin.__exit__(None, None, None)
    finally:
        owner.__exit__(None, None, None)


# ---------------------------------------------------------------------------------------------- audit tampering
def naive_tamper_is_refused(app, statement, parameters):
    """The immutability triggers refuse direct edits; a database administrator could still drop them."""
    from sqlalchemy.exc import IntegrityError, DBAPIError
    with pytest.raises((IntegrityError, DBAPIError)):
        with app.state.db.transaction() as s:
            s.execute(text(statement), parameters)


def bypass_audit_triggers(s, db):
    if db.engine.dialect.name == "sqlite":
        s.execute(text("DROP TRIGGER IF EXISTS immutable_audit_events_update"))
        s.execute(text("DROP TRIGGER IF EXISTS immutable_audit_events_delete"))
    else:
        s.execute(text("ALTER TABLE audit_events DISABLE TRIGGER immutable_audit_events"))

def test_editing_a_stored_event_is_detected_and_stops_release(capped):
    app, client = capped
    ready = submit(client).json()
    with app.state.db.transaction() as s:
        row = s.scalar(select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1))
        event = json.loads(row.canonical)
        event["kind"] = "TRANSFER_RELEASED" if event["kind"] != "TRANSFER_RELEASED" else "TRANSFER_CREATED"
        forged, sequence = json.dumps(event, sort_keys=True, separators=(",", ":")), row.sequence
    naive_tamper_is_refused(app, "UPDATE audit_events SET canonical = :c WHERE sequence = :q", {"c": forged, "q": sequence})
    with app.state.db.transaction() as s:
        bypass_audit_triggers(s, app.state.db)
        s.execute(text("UPDATE audit_events SET canonical = :c WHERE sequence = :q"), {"c": forged, "q": sequence})
    verification = client.post("/api/v1/audit/verify")
    assert verification.status_code in {200, 503}
    if verification.status_code == 200:
        assert verification.json()["valid"] is False
    response = client.post(f"/api/v1/transfers/{ready['id']}/release")
    assert response.status_code >= 400 and BENIGN not in response.content


def test_deleting_the_newest_event_is_detected_against_the_checkpoint(capped):
    app, client = capped
    submit(client)
    assert client.post("/api/v1/audit/checkpoint").status_code == 200
    with app.state.db.transaction() as s:
        newest = s.scalar(select(func.max(AuditEvent.sequence)))
    naive_tamper_is_refused(app, "DELETE FROM audit_events WHERE sequence = :q", {"q": newest})
    with app.state.db.transaction() as s:
        bypass_audit_triggers(s, app.state.db)
        s.execute(text("DELETE FROM audit_events WHERE sequence = :q"), {"q": newest})
    verification = client.post("/api/v1/audit/verify")
    assert verification.status_code in {200, 503}
    if verification.status_code == 200:
        assert verification.json()["valid"] is False


def test_a_tampered_checkpoint_file_is_detected(capped, system):
    app, client = capped
    submit(client)
    assert client.post("/api/v1/audit/checkpoint").status_code == 200
    files = sorted(system[0].checkpoint_root.glob("checkpoint-*.json"))
    assert files
    record = json.loads(files[-1].read_text(encoding="utf-8"))
    record["mac"] = ("0" if record["mac"][0] != "0" else "1") + record["mac"][1:]
    files[-1].chmod(0o600)
    files[-1].write_text(json.dumps(record), encoding="utf-8")
    verification = client.post("/api/v1/audit/verify")
    assert verification.status_code in {200, 503}
    if verification.status_code == 200:
        assert verification.json()["valid"] is False


def test_a_corrupt_checkpoint_file_fails_closed(capped, system):
    _, client = capped
    submit(client)
    assert client.post("/api/v1/audit/checkpoint").status_code == 200
    target = sorted(system[0].checkpoint_root.glob("checkpoint-*.json"))[-1]
    target.chmod(0o600)
    target.write_text("{not json", encoding="utf-8")
    verification = client.post("/api/v1/audit/verify")
    assert verification.status_code == 503 or verification.json()["valid"] is False
