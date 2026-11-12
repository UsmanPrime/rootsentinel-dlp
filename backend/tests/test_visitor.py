"""Visitor mode: entry, session lifetime, route allowlist, isolation, the real flow, caps, lazy cleanup, migration 0006.

Every refusal here is also checked for the rule that matters most: a rejected visitor request writes nothing to
the audit chain.
"""
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

from alembic import command
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import func, select, text, update
from sqlalchemy.exc import DatabaseError

import app.api as api_module
import app.visitors as visitors_module
from app.api import create_app
from app.audit import check_event, verify_records
from app.bootstrap import activate_rule_set, mark_synthetic, seed_assets
from app.config import VISITOR_ABSOLUTE_SECONDS, VISITOR_IDLE_SECONDS, VISITOR_SEEN_THROTTLE_SECONDS
from app.db import now
from app.gateway_models import AuditEvent, AuditHead
from app.models import Asset, SessionRecord, User, VisitorSession
from app.synthetic import protected_sample, source_sample
from app.visitors import VISITOR_ROUTES

from .test_idle import DatabaseCalls, count_ticks, wait_for

LOCAL = "http://127.0.0.1:5173"
OCTET = {"Content-Type": "application/octet-stream"}
BENIGN = b"Visitor benign synthetic bytes.\n" * 40
SHIFTED_SOURCE = b"// inserted header line\n" + source_sample()


class Env:
    def __init__(self, app, settings):
        self.app, self.settings, self.db = app, settings, app.state.db
        self.audit = app.state.gateway.audit

    def client(self, ip=None):
        client = TestClient(self.app, base_url=LOCAL, raise_server_exceptions=False)
        client.headers["origin"] = self.settings.origin
        if ip:
            client.headers["true-client-ip"] = ip
        return client

    def visitor(self, ip=None):
        client = self.client(ip)
        result = client.post("/api/v1/auth/visitor")
        assert result.status_code == 200, result.text
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        client.view = result.json()
        return client

    def signed_in(self, name, password):
        client = self.client()
        result = client.post("/api/v1/auth/login", json={"username": name, "password": password})
        assert result.status_code == 200, result.text
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        return client

    def sequence(self):
        with self.db.transaction() as s:
            return s.get(AuditHead, 1).sequence

    def kinds(self, actor_id=None):
        with self.db.transaction() as s:
            rows = s.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        import json
        events = [json.loads(r.canonical) for r in rows]
        return [e["kind"] for e in events if actor_id is None or e["actor_id"] == actor_id]


@pytest.fixture
def start(system):
    anchors = []

    def build(**overrides):
        settings = replace(system[0], visitor_mode_enabled=True, **overrides)
        app = create_app(settings)
        anchor = TestClient(app, base_url=LOCAL, raise_server_exceptions=False)
        anchor.__enter__()  # runs the lifespan once
        anchors.append(anchor)
        env = Env(app, settings)
        seed_assets(env.db, env.audit)
        mark_synthetic(env.db)
        assert activate_rule_set(env.db, env.audit)
        return env
    yield build
    for anchor in anchors:
        anchor.__exit__(None, None, None)


@pytest.fixture
def env(start):
    return start()


def submit(client, data, key=None):
    return client.post("/api/v1/transfers?filename=visitor.bin", content=data, headers={**OCTET, "Idempotency-Key": key or str(uuid4())})


def set_session(env, **values):
    with env.db.transaction() as s:
        s.execute(update(SessionRecord).values(**values))


# ------------------------------------------------------------------------------------------------ entry
def test_entry_is_404_when_the_mode_is_off_and_the_interface_is_told(system):
    app = create_app(replace(system[0], visitor_mode_enabled=False))
    with TestClient(app, base_url=LOCAL, raise_server_exceptions=False) as client:
        client.headers["origin"] = system[0].origin
        assert client.get("/health").json()["visitor_mode"] is False
        before = None
        response = client.post("/api/v1/auth/visitor")
        assert response.status_code == 404 and response.json()["error"]["code"] == "NOT_FOUND"
        assert "set-cookie" not in response.headers


def test_health_reports_the_mode_when_on(env):
    assert env.client().get("/health").json()["visitor_mode"] is True


def test_the_default_is_off():
    from app.settings import Settings
    import os
    assert os.environ.get("ROOTSENTINEL_VISITOR_MODE_ENABLED") is None
    assert Settings.__dataclass_fields__["visitor_mode_enabled"].default is False


def test_entry_checks_origin_and_sec_fetch_site(env):
    client = env.client()
    client.headers["origin"] = "https://attacker.example"
    assert client.post("/api/v1/auth/visitor").json()["error"]["code"] == "ORIGIN_REJECTED"
    client.headers["origin"] = env.settings.origin
    cross = client.post("/api/v1/auth/visitor", headers={"sec-fetch-site": "cross-site"})
    assert cross.status_code == 403 and cross.json()["error"]["code"] == "ORIGIN_REJECTED"
    assert client.post("/api/v1/auth/visitor", headers={"sec-fetch-site": "same-site"}).status_code == 403
    assert client.post("/api/v1/auth/visitor", headers={"sec-fetch-site": "same-origin"}).status_code == 200
    assert client.post("/api/v1/auth/visitor").status_code == 200  # a missing header is accepted when Origin passes


def test_entry_needs_no_password_and_does_no_argon2_work(env, monkeypatch):
    import app.auth as auth

    def boom(*_, **__):
        raise AssertionError("Argon2 work during visitor entry")
    monkeypatch.setattr(auth, "HASHER", SimpleNamespace(hash=boom, verify=boom, check_needs_rehash=boom))
    client = env.visitor()
    assert client.view["user"]["role"] == "VISITOR" and client.view["visitor"]["submissions_remaining"] == 3


def test_a_visitor_account_cannot_sign_in_with_any_password(env):
    client = env.visitor()
    name = client.view["user"]["username"]
    other = env.client()
    for password in ("!visitor-no-password", "x" * 12, "correct horse battery"):
        response = other.post("/api/v1/auth/login", json={"username": name, "password": password})
        assert response.status_code == 401 and response.json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_the_cookie_has_the_normal_flags_and_the_absolute_lifetime(system):
    origin = "https://rs-visitor.example"
    settings = replace(system[0], origin=origin, secure_cookies=True, visitor_mode_enabled=True)
    with TestClient(create_app(settings), base_url=origin, raise_server_exceptions=False) as client:
        client.headers["origin"] = origin
        result = client.post("/api/v1/auth/visitor")
    cookie = next(v for k, v in result.headers.multi_items() if k.lower() == "set-cookie" and v.startswith("rs_session="))
    flags = [part.strip().lower() for part in cookie.split(";")]
    assert {"httponly", "secure", "samesite=strict", "path=/api/v1", f"max-age={VISITOR_ABSOLUTE_SECONDS}"} <= set(flags)
    assert "csrf" not in cookie.lower()


def test_entry_is_limited_per_client_address(start):
    env = start(client_ip_header="true-client-ip", visitor_entries_per_ip_hour=2)
    for _ in range(2):
        env.visitor("203.0.113.7")
    before = env.sequence()
    refused = env.client("203.0.113.7").post("/api/v1/auth/visitor")
    assert refused.status_code == 429 and refused.json()["error"]["code"] == "VISITOR_RATE_LIMIT"
    assert env.sequence() == before                                  # a refusal is never audited
    env.visitor("203.0.113.8")                                       # another address has its own allowance


def test_the_global_concurrent_cap(start):
    env = start(visitor_max_concurrent=2)
    first, second = env.visitor(), env.visitor()
    before = env.sequence()
    refused = env.client().post("/api/v1/auth/visitor")
    assert refused.status_code == 429 and refused.json()["error"]["code"] == "VISITOR_CAPACITY"
    assert env.sequence() == before
    assert first.post("/api/v1/auth/logout").status_code == 204        # a freed slot is usable again
    env.visitor()


def test_the_daily_cap_and_password_accounts_keep_working(start, credentials):
    env = start(visitor_sessions_per_day=2)
    env.visitor(), env.visitor()
    before = env.sequence()
    refused = env.client().post("/api/v1/auth/visitor")
    assert refused.status_code == 429 and refused.json()["error"]["code"] == "VISITOR_DAILY_CAP"
    assert env.sequence() == before
    assert env.signed_in("admin", credentials[0]).get("/api/v1/auth/me").status_code == 200


def test_the_audit_ceiling_refuses_visitors_and_nobody_else(start, credentials):
    env = start()
    with env.db.transaction() as s:
        s.execute(update(AuditHead).values(sequence=env.settings.visitor_audit_ceiling))
    refused = env.client().post("/api/v1/auth/visitor")
    assert refused.status_code == 429 and refused.json()["error"]["code"] == "VISITOR_AUDIT_BUDGET"
    assert env.signed_in("employee", credentials[0]).get("/api/v1/auth/me").status_code == 200


def test_cap_settings_have_hard_bounds(system):
    for field, bad in (("visitor_entries_per_ip_hour", 61), ("visitor_max_concurrent", 0), ("visitor_sessions_per_day", 201),
                       ("visitor_scans_per_session", 11), ("visitor_upload_bytes", 262145), ("visitor_audit_ceiling", 18001),
                       ("visitor_audit_ceiling", 999)):
        with pytest.raises(ValueError):
            replace(system[0], **{field: bad})
    assert replace(system[0], max_upload_bytes=2048, visitor_upload_bytes=4096).visitor_upload_limit == 2048


def test_cap_environment_variables(monkeypatch, system):
    from app.settings import Settings
    monkeypatch.setenv("ROOTSENTINEL_VISITOR_MODE_ENABLED", "true")
    monkeypatch.setenv("ROOTSENTINEL_VISITOR_SESSIONS_PER_DAY", "12")
    monkeypatch.setenv("ROOTSENTINEL_VISITOR_AUDIT_CEILING", "15000")
    monkeypatch.setenv("ROOTSENTINEL_RUNTIME_ROOT", str(system[0].paths.runtime))
    monkeypatch.setenv("ROOTSENTINEL_ARTIFACT_ROOT", str(system[0].paths.artifacts))
    monkeypatch.setenv("ROOTSENTINEL_DATABASE_URL", system[0].database_url)
    monkeypatch.setenv("ROOTSENTINEL_ORIGIN", system[0].origin)
    monkeypatch.setenv("ROOTSENTINEL_MODE", "local")
    monkeypatch.setenv("ROOTSENTINEL_SECURE_COOKIES", "false")
    settings = Settings.from_environment()
    assert (settings.visitor_mode_enabled, settings.visitor_sessions_per_day, settings.visitor_audit_ceiling,
            settings.visitor_entries_per_ip_hour) == (True, 12, 15000, 6)
    monkeypatch.setenv("ROOTSENTINEL_VISITOR_SESSIONS_PER_DAY", "201")
    with pytest.raises(ValueError):
        Settings.from_environment()


# ------------------------------------------------------------------------------------------------ session
def test_idle_expiry_and_the_throttled_last_seen_write(env):
    visitor = env.visitor()
    with env.db.transaction() as s:
        first = s.scalar(select(SessionRecord.last_seen_at))
    assert visitor.get("/api/v1/auth/me").status_code == 200
    with env.db.transaction() as s:
        assert s.scalar(select(SessionRecord.last_seen_at)) == first      # inside the 60 s throttle: no write
    set_session(env, last_seen_at=now() - timedelta(seconds=VISITOR_SEEN_THROTTLE_SECONDS + 5))
    assert visitor.get("/api/v1/auth/me").status_code == 200
    with env.db.transaction() as s:
        assert now() - s.scalar(select(SessionRecord.last_seen_at)) < timedelta(seconds=5)   # written again
    set_session(env, last_seen_at=now() - timedelta(seconds=VISITOR_IDLE_SECONDS + 1))
    before = env.sequence()
    ended = visitor.get("/api/v1/auth/me")
    assert ended.status_code == 401 and ended.json()["error"]["code"] == "VISITOR_SESSION_ENDED"
    assert env.sequence() == before                                       # the rejection is not audited
    # A request just inside the idle window still works: the tolerance is the throttle, not more.
    again = env.visitor()
    set_session(env, last_seen_at=now() - timedelta(seconds=VISITOR_IDLE_SECONDS - 30))
    assert again.get("/api/v1/auth/me").status_code == 200


def test_absolute_expiry_is_never_extended(env):
    visitor = env.visitor()
    with env.db.transaction() as s:
        expires = s.scalar(select(SessionRecord.expires_at))
    for _ in range(3):
        set_session(env, last_seen_at=now() - timedelta(seconds=VISITOR_SEEN_THROTTLE_SECONDS + 1))
        assert visitor.get("/api/v1/auth/me").status_code == 200
    with env.db.transaction() as s:
        assert s.scalar(select(SessionRecord.expires_at)) == expires      # activity never moves the end
    assert expires - now() <= timedelta(seconds=VISITOR_ABSOLUTE_SECONDS)
    set_session(env, expires_at=now() - timedelta(seconds=1))
    assert visitor.get("/api/v1/auth/me").json()["error"]["code"] == "VISITOR_SESSION_ENDED"


def test_a_visitor_cannot_become_another_role(env, credentials):
    visitor = env.visitor()
    for path, kwargs in (("/api/v1/policies", {"json": {"threshold": 1, "block_enabled": True, "expected_version": "x"}}),
                         ("/api/v1/assets?label=x", {"content": b"abc", "headers": OCTET})):
        assert visitor.post(path, **kwargs).status_code == 403
    with env.db.transaction() as s:
        assert s.scalar(select(User.role).where(User.username == visitor.view["user"]["username"])) == "VISITOR"
    assert visitor.get("/api/v1/auth/me").json()["user"]["role"] == "VISITOR"


def test_the_kill_switch_ends_live_visitor_sessions(system, env):
    visitor = env.visitor()
    off = create_app(replace(system[0], visitor_mode_enabled=False))
    with TestClient(off, base_url=LOCAL, raise_server_exceptions=False) as client:
        client.cookies.set("rs_session", visitor.cookies["rs_session"], path="/api/v1")
        assert client.get("/api/v1/auth/me").status_code == 401


def test_sign_out_revokes_the_session_and_is_audited(env):
    visitor = env.visitor()
    token = visitor.cookies["rs_session"]
    assert visitor.post("/api/v1/auth/logout").status_code == 204
    visitor.cookies.set("rs_session", token, path="/api/v1")
    assert visitor.get("/api/v1/auth/me").status_code == 401
    assert env.kinds(visitor.view["user"]["id"]) == ["VISITOR_ENTERED", "VISITOR_ENDED"]


# ------------------------------------------------------------------------------------------------ allowlist
PUBLIC_ROUTES = {("GET", "/health"), ("POST", "/api/v1/auth/login"), ("POST", "/api/v1/auth/visitor")}
DENIED_TO_VISITORS = {
    ("GET", "/api/v1/assets"), ("POST", "/api/v1/assets"), ("POST", "/api/v1/assets/{asset_id}/versions"),
    ("GET", "/api/v1/assets/{asset_id}"), ("GET", "/api/v1/assets/{asset_id}/versions"),
    ("GET", "/api/v1/assets/{asset_id}/versions/{version_id}"), ("POST", "/api/v1/assets/{asset_id}/retire"),
    ("GET", "/api/v1/assets/{asset_id}/versions/{version_id}/proofs/{index}"),
    ("GET", "/api/v1/assets/{asset_id}/versions/{version_id}/tree"), ("POST", "/api/v1/integrity/verify"),
    ("GET", "/api/v1/policies/history"), ("POST", "/api/v1/policies"),
    ("GET", "/api/v1/incidents"), ("GET", "/api/v1/incidents/{identifier}"), ("PATCH", "/api/v1/incidents/{identifier}"),
    ("GET", "/api/v1/exports/incidents/{identifier}"), ("GET", "/api/v1/audit/events"), ("POST", "/api/v1/audit/verify"),
    ("POST", "/api/v1/audit/checkpoint"), ("POST", "/api/v1/transfers-maintenance/expire"),
    ("GET", "/api/v1/transparency/key"), ("GET", "/api/v1/transparency/sth"), ("POST", "/api/v1/transparency/sth"),
    ("GET", "/api/v1/transparency/sth/{size}"), ("GET", "/api/v1/transparency/proof/inclusion"),
    ("GET", "/api/v1/transparency/proof/consistency"),
}


def registered_routes(app):
    return {(method, route.path) for route in app.routes if isinstance(route, APIRoute) for method in route.methods
            if method not in {"HEAD", "OPTIONS"}}


def test_every_registered_route_is_classified_for_visitors(env):
    """A new route fails here until someone decides what a visitor may do with it."""
    registered = registered_routes(env.app)
    classified = set(VISITOR_ROUTES) | DENIED_TO_VISITORS | PUBLIC_ROUTES
    assert registered == classified, (sorted(registered - classified), sorted(classified - registered))
    assert not (VISITOR_ROUTES & DENIED_TO_VISITORS) and not (VISITOR_ROUTES & PUBLIC_ROUTES) and not (DENIED_TO_VISITORS & PUBLIC_ROUTES)


def test_a_visitor_gets_403_on_every_route_outside_the_allowlist_and_nothing_is_audited(env):
    visitor = env.visitor()
    before = env.sequence()
    ids = {"asset_id": str(uuid4()), "version_id": str(uuid4()), "index": 0, "size": 1, "identifier": str(uuid4())}
    for method, path in sorted(DENIED_TO_VISITORS):
        response = visitor.request(method, path.format(**ids), content=b"x", headers=OCTET if method != "GET" else {})
        assert response.status_code == 403 and response.json()["error"]["code"] == "FORBIDDEN", (method, path, response.status_code)
    assert env.sequence() == before


def test_the_default_deny_is_in_the_dependency_not_in_each_route(env, monkeypatch):
    """A route added later that uses the normal dependency is denied to visitors without any further code."""
    from fastapi import Depends
    app = env.app
    extra = [r for r in app.routes if isinstance(r, APIRoute) and r.path == "/api/v1/overview"][0]
    dependency = extra.dependant.dependencies[0].call

    @app.get("/api/v1/future-route")
    def future(actor=Depends(dependency)):
        return {"ok": True}
    visitor = env.visitor()
    assert visitor.get("/api/v1/future-route").status_code == 403


# ------------------------------------------------------------------------------------------------ isolation
def test_two_visitors_and_an_account_see_nothing_of_each_other(env, credentials):
    one, two = env.visitor(), env.visitor()
    employee = env.signed_in("employee", credentials[0])
    admin = env.signed_in("admin", credentials[0])
    scan = one.post("/api/v1/scans", content=BENIGN, headers=OCTET).json()
    sent = submit(one, BENIGN).json()
    blocked = submit(one, SHIFTED_SOURCE).json()
    assert sent["state"] == "ALLOWED" and blocked["state"] == "BLOCKED"
    mine = employee.get("/api/v1/transfers").json()["items"]
    assert mine == []
    # the second visitor
    assert two.get("/api/v1/scans").json()["items"] == [] and two.get("/api/v1/transfers").json()["items"] == []
    assert two.get(f"/api/v1/scans/{scan['id']}").status_code == 404
    assert two.get(f"/api/v1/transfers/{sent['id']}").status_code == 404
    released = two.post(f"/api/v1/transfers/{sent['id']}/release")
    assert released.status_code == 404 and BENIGN not in released.content
    assert two.get("/api/v1/visitor/audit/events").json()["events"][0]["event"]["actor_id"] == two.view["user"]["id"]
    ones_events = one.get("/api/v1/visitor/audit/events?limit=100").json()["events"]
    assert {e["event"]["actor_id"] for e in ones_events} == {one.view["user"]["id"]}
    assert not {e["event"]["id"] for e in ones_events} & {e["event"]["id"] for e in two.get("/api/v1/visitor/audit/events?limit=100").json()["events"]}
    # an inclusion proof is available for a visitor's own event only
    own = ones_events[0]["event"]["sequence"] - 1
    other = two.get("/api/v1/visitor/audit/events").json()["events"][0]["event"]["sequence"] - 1
    size = env.sequence()
    assert one.get(f"/api/v1/visitor/transparency/proof/inclusion?leaf_index={own}&tree_size={size}").status_code == 200
    assert one.get(f"/api/v1/visitor/transparency/proof/inclusion?leaf_index={other}&tree_size={size}").status_code == 404
    # real users: hidden by default, visible to an administrator who asks, never to an analyst
    for client in (admin, employee):
        assert client.get("/api/v1/scans").json()["items"] == []
    assert {i["id"] for i in admin.get("/api/v1/transfers").json()["items"]} == set()
    assert admin.get("/api/v1/incidents").json()["items"] == []
    assert admin.get("/api/v1/overview").json()["total_transfers"] == 0
    assert len(admin.get("/api/v1/scans?include_visitors=true").json()["items"]) == 3
    assert {i["id"] for i in admin.get("/api/v1/transfers?include_visitors=true").json()["items"]} == {sent["id"], blocked["id"]}
    assert len(admin.get("/api/v1/incidents?include_visitors=true").json()["items"]) == 1
    assert admin.get("/api/v1/overview?include_visitors=true").json()["total_transfers"] == 2
    analyst = env.signed_in("analyst", credentials[0])
    for path in ("scans", "transfers", "incidents", "overview"):
        assert analyst.get(f"/api/v1/{path}?include_visitors=true").status_code == 403
    # the audit chain is shown whole, with visitor events labelled
    page = admin.get("/api/v1/audit/events?limit=100").json()["events"]
    assert {e["actor_kind"] for e in page} >= {"VISITOR", "ACCOUNT"} or {e["actor_kind"] for e in page} >= {"VISITOR", "SYSTEM"}
    assert [e["event"]["sequence"] for e in page] == list(range(1, len(page) + 1))


# ------------------------------------------------------------------------------------------------ the real flow
def test_the_real_flow_for_a_visitor(env, credentials):
    visitor = env.visitor()
    admin = env.signed_in("admin", credentials[0])
    assert admin.get("/api/v1/policies/active").json()["rule_set"] == "rs-policy-v2"
    allowed = submit(visitor, BENIGN).json()
    assert allowed["state"] == "ALLOWED" and allowed["scan"]["decision"]["outcome"] == "ALLOW"
    blocked = submit(visitor, SHIFTED_SOURCE).json()
    assert blocked["state"] == "BLOCKED" and blocked["scan"]["decision"]["outcome"] == "BLOCK"
    assert blocked["scan"]["decision"]["reason"] == "CDC_THRESHOLD_MET"          # a shifted copy: only rs-policy-v2 sees it
    denied = visitor.post(f"/api/v1/transfers/{blocked['id']}/release")
    assert denied.status_code == 409 and SHIFTED_SOURCE not in denied.content    # BLOCK never delivers
    first = visitor.post(f"/api/v1/transfers/{allowed['id']}/release")
    assert first.status_code == 200 and first.content == BENIGN
    again = visitor.post(f"/api/v1/transfers/{allowed['id']}/release")
    assert again.status_code == 429 or again.status_code == 409                   # single use (the attempt cap may apply first)
    assert BENIGN not in again.content
    # the scan itself is not a release credential
    scan = visitor.post("/api/v1/scans", content=BENIGN, headers=OCTET)
    assert scan.status_code == 201 and scan.content != BENIGN
    kinds = env.kinds(visitor.view["user"]["id"])
    assert {"VISITOR_ENTERED", "TRANSFER_SUBMITTED", "DECISION_ALLOWED", "DECISION_BLOCKED", "RELEASE_STARTED",
            "STREAM_FINISHED", "RELEASE_DENIED"} <= set(kinds)
    verified = admin.post("/api/v1/audit/verify").json()
    assert verified["valid"] is True
    head = visitor.get("/api/v1/visitor/transparency/sth").json()
    assert head["tree_size"] >= 1 and visitor.get("/api/v1/visitor/transparency/key").status_code == 200


def test_a_visitor_matches_the_synthetic_set_only(env, credentials):
    admin = env.signed_in("admin", credentials[0])
    secret = b"REAL-LOOKING-CONFIDENTIAL-" * 100
    assert admin.post("/api/v1/assets?label=not-synthetic", content=secret, headers=OCTET).status_code == 201
    visitor = env.visitor()
    employee = env.signed_in("employee", credentials[0])
    assert submit(employee, secret).json()["state"] == "BLOCKED"                  # a real user is protected against it
    seen = submit(visitor, secret).json()
    assert seen["state"] == "ALLOWED"                                              # the visitor's scan never touches it
    assert seen["scan"]["detection"]["matches"] == []
    assert submit(visitor, protected_sample()).json()["state"] == "BLOCKED"       # the synthetic seed still matches


def test_per_session_caps_upload_size_and_no_audit_for_refusals(start):
    env = start(visitor_scans_per_session=2, visitor_upload_bytes=2048)
    visitor = env.visitor()
    assert submit(visitor, BENIGN[:1000]).status_code == 201
    assert visitor.post("/api/v1/scans", content=BENIGN[:1000], headers=OCTET).status_code == 201
    before = env.sequence()
    refused = submit(visitor, BENIGN[:1000])
    assert refused.status_code == 429 and refused.json()["error"]["code"] == "VISITOR_SCAN_CAP"
    assert visitor.post("/api/v1/scans", content=BENIGN[:1000], headers=OCTET).json()["error"]["code"] == "VISITOR_SCAN_CAP"
    assert env.sequence() == before
    other = env.visitor()
    big = submit(other, b"A" * 2049)
    assert big.status_code == 413 and big.json()["error"]["code"] == "INPUT_TOO_LARGE"


def test_release_attempts_are_capped_so_denials_cannot_flood_the_chain(start):
    env = start(visitor_scans_per_session=2)
    visitor = env.visitor()
    sent = submit(visitor, BENIGN).json()
    assert visitor.post(f"/api/v1/transfers/{sent['id']}/release").status_code == 200
    assert visitor.post(f"/api/v1/transfers/{sent['id']}/release").status_code == 409     # attempt 2, denied and audited
    before = env.sequence()
    refused = visitor.post(f"/api/v1/transfers/{sent['id']}/release")
    assert refused.status_code == 429 and refused.json()["error"]["code"] == "VISITOR_RELEASE_CAP"
    assert env.sequence() == before


def test_the_worst_case_session_stays_within_the_audit_budget(env):
    """Three released transfers, a refused fourth attempt, sign out: 1 + 3x3 + 3x3 + 1 events."""
    visitor = env.visitor()
    start_sequence = env.sequence()
    for i in range(3):
        sent = submit(visitor, BENIGN + bytes([i])).json()
        assert visitor.post(f"/api/v1/transfers/{sent['id']}/release").status_code == 200
    assert submit(visitor, BENIGN + b"4").status_code == 429
    assert visitor.post("/api/v1/auth/logout").status_code == 204
    mine = len(env.kinds(visitor.view["user"]["id"]))
    assert mine == 20 and env.sequence() - start_sequence + 1 >= 19


# ------------------------------------------------------------------------------------------------ cleanup and idle
def test_lazy_cleanup_expires_sandboxes_in_bounded_batches(env, monkeypatch):
    monkeypatch.setattr(visitors_module, "VISITOR_CLEANUP_BATCH", 2)
    visitors = [env.visitor() for _ in range(3)]
    ids = [v.view["user"]["id"] for v in visitors]
    set_session(env, expires_at=now() - timedelta(seconds=5))
    assert env.app.state.visitors.cleanup() == 2                        # bounded
    assert env.app.state.visitors.cleanup() == 1
    assert env.app.state.visitors.cleanup() == 0
    with env.db.transaction() as s:
        assert s.scalar(select(func.count()).select_from(SessionRecord)) == 0      # token digests are gone
        assert s.scalar(select(func.count()).select_from(VisitorSession).where(VisitorSession.ended_at.is_not(None))) == 3
        assert s.scalar(select(func.count()).select_from(User).where(User.id.in_(ids))) == 3   # accounts and history stay
    assert [k for k in env.kinds() if k == "VISITOR_EXPIRED"] == ["VISITOR_EXPIRED"] * 3
    with pytest.raises(DatabaseError), env.db.transaction() as s:
        s.execute(text("DELETE FROM audit_events"))                      # cleanup never deletes from append-only tables


def test_a_password_sign_in_runs_the_lazy_cleanup(env, credentials):
    visitor = env.visitor()
    set_session(env, expires_at=now() - timedelta(seconds=5))
    env.signed_in("employee", credentials[0])
    assert "VISITOR_EXPIRED" in env.kinds(visitor.view["user"]["id"])


def test_a_failing_cleanup_never_blocks_a_password_sign_in(env, credentials, monkeypatch):
    env.visitor()
    set_session(env, expires_at=now() - timedelta(seconds=5))
    monkeypatch.setattr(env.audit, "append", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("audit down")))
    assert env.signed_in("employee", credentials[0]).get("/api/v1/auth/me").status_code == 200


def test_an_idle_process_with_visitors_makes_no_database_call(env, monkeypatch):
    env.visitor()
    set_session(env, expires_at=now() - timedelta(seconds=5))           # an expired sandbox waits for the next entry
    monkeypatch.setattr(api_module, "MAINTENANCE_SECONDS", 0.002)
    app = create_app(env.settings)                                        # restart
    ticks = count_ticks(app.state.gateway, monkeypatch)
    with TestClient(app, base_url=LOCAL) as client:
        with DatabaseCalls(app.state.db.engine) as calls:
            for minute in range(10, 61, 10):
                assert wait_for(lambda: len(ticks) >= minute), "the maintenance loop stopped"
                assert client.get("/health").status_code == 200
            assert calls.statements == [] and calls.checkouts == 0          # no timer touches the database; cleanup is lazy


# ------------------------------------------------------------------------------------------------ audit actor column
def stored_event(env, kind):
    with env.db.transaction() as s:
        return s.scalar(select(AuditEvent).join(AuditHead, AuditHead.stream_id == AuditEvent.stream_id).where(
            AuditEvent.canonical.contains(f'"kind":"{kind}"')))


def test_integrity_verification_checks_the_actor_column_against_the_payload(env):
    visitor = env.visitor()
    row = stored_event(env, "VISITOR_ENTERED")
    assert row.actor_id == visitor.view["user"]["id"]
    forged = SimpleNamespace(id=row.id, stream_id=row.stream_id, sequence=row.sequence, resource_id=row.resource_id,
                             canonical=row.canonical, mac=row.mac, actor_id=str(uuid4()))
    previous = None
    with env.db.transaction() as s:
        before = s.scalar(select(AuditEvent).where(AuditEvent.sequence == row.sequence - 1)) if row.sequence > 1 else None
        previous = before.mac if before else "0" * 64
    check_event(row, env.audit.keys, previous)                           # the real row passes
    with pytest.raises(ValueError, match="ACTOR_MISMATCH"):
        check_event(forged, env.audit.keys, previous)
    with env.db.transaction() as s:
        head = s.get(AuditHead, 1)
        rows = s.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        good = verify_records(rows, env.audit.keys, head.stream_id, head.sequence, head.mac)
        swapped = [forged if r.sequence == row.sequence else r for r in rows]
        bad = verify_records(swapped, env.audit.keys, head.stream_id, head.sequence, head.mac)
    assert good["valid"] is True and bad["valid"] is False


# ------------------------------------------------------------------------------------------------ migration 0006
def schema_facts(db):
    with db.transaction() as s:
        tables = [r[0] for r in s.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"))]
        facts = {"triggers": sorted(r[0] for r in s.execute(text("SELECT name FROM sqlite_master WHERE type='trigger'")))}
        facts["foreign_keys"] = {t: sorted((r[2], r[3], r[4]) for r in s.execute(text(f"PRAGMA foreign_key_list({t})"))) for t in tables}
        facts["indexes"] = {t: sorted((r[1], r[2]) for r in s.execute(text(f"PRAGMA index_list({t})")) if not r[1].startswith("sqlite_autoindex")) for t in tables}
        facts["unique_autoindexes"] = {t: len([1 for r in s.execute(text(f"PRAGMA index_list({t})")) if r[1].startswith("sqlite_autoindex")]) for t in tables}
        return facts


def test_migration_0006_rebuilds_users_without_losing_keys_triggers_or_rows(system):
    settings, db, actors, cfg = system
    from sqlalchemy.exc import IntegrityError
    if db.engine.dialect.name != "sqlite":
        # PostgreSQL: the migration ran in the fixture. The users check now allows VISITOR and still refuses other roles,
        # and the append-only triggers of the table that gained a column are in place.
        row = "INSERT INTO users (id, username, password_hash, role, enabled, created_at) VALUES ('{}','{}','!','{}',true,CURRENT_TIMESTAMP)"
        with db.transaction() as s:
            s.execute(text(row.format("v1", "visitor-x", "VISITOR")))
        with pytest.raises(IntegrityError), db.transaction() as s:
            s.execute(text(row.format("v2", "visitor-y", "ROOT")))
        with db.transaction() as s:
            names = {r[0] for r in s.execute(text("SELECT tgname FROM pg_trigger WHERE NOT tgisinternal"))}
        assert any(n.startswith("immutable_audit_events") for n in names)
        return
    command.downgrade(cfg, "0005")
    with db.transaction() as s:
        s.execute(text("INSERT INTO assets (id, label, current_version, retired, created_at) VALUES ('a1', 'pre-existing', 1, 0, CURRENT_TIMESTAMP)"))
        s.execute(text("INSERT INTO assets (id, label, current_version, retired, created_at) VALUES ('a2', 'synthetic-source-sample', 1, 0, CURRENT_TIMESTAMP)"))
    before = schema_facts(db)
    with db.transaction() as s:
        users_before = s.execute(text("SELECT id, username, role, password_hash FROM users ORDER BY id")).all()
        sessions_before = s.scalar(text("SELECT COUNT(*) FROM sessions"))
    command.upgrade(cfg, "head")
    after = schema_facts(db)
    # every foreign key and every trigger (including the append-only UPDATE and DELETE triggers) survives
    new_tables = {"visitor_sessions"}
    assert {t: v for t, v in after["foreign_keys"].items() if t not in new_tables} == before["foreign_keys"]
    assert after["triggers"] == before["triggers"] and any(t.startswith("immutable_audit_events") for t in after["triggers"])
    assert {t: v for t, v in after["indexes"].items() if t not in new_tables}.keys() == before["indexes"].keys()
    for table, indexes in before["indexes"].items():
        assert set(indexes) <= set(after["indexes"][table]), table
    assert after["unique_autoindexes"]["users"] == before["unique_autoindexes"]["users"]       # UNIQUE(username) kept
    with db.transaction() as s:
        assert s.execute(text("PRAGMA foreign_key_check")).all() == []
        assert s.execute(text("SELECT id, username, role, password_hash FROM users ORDER BY id")).all() == users_before
        assert s.scalar(text("SELECT COUNT(*) FROM sessions")) == sessions_before
        assert dict(s.execute(text("SELECT label, synthetic FROM assets WHERE id IN ('a1','a2')")).all()) == {
            "pre-existing": 0, "synthetic-source-sample": 1}
        assert s.scalar(text("PRAGMA foreign_keys")) == 1
    # the new role is accepted, an unknown one is not, and a duplicate username is still refused
    with db.transaction() as s:
        s.execute(text("INSERT INTO users (id, username, password_hash, role, enabled, created_at) VALUES ('v1','visitor-x','!','VISITOR',1,CURRENT_TIMESTAMP)"))
    for sql in ("INSERT INTO users (id, username, password_hash, role, enabled, created_at) VALUES ('v2','visitor-y','!','ROOT',1,CURRENT_TIMESTAMP)",
                "INSERT INTO users (id, username, password_hash, role, enabled, created_at) VALUES ('v3','visitor-x','!','VISITOR',1,CURRENT_TIMESTAMP)"):
        with pytest.raises(IntegrityError), db.transaction() as s:
            s.execute(text(sql))
    # the foreign keys still bite
    with pytest.raises(IntegrityError), db.transaction() as s:
        s.execute(text("INSERT INTO sessions (id, user_id, token_digest, csrf_digest, created_at, expires_at) VALUES ('s','nobody','t','c',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
    # the append-only triggers still bite, on the old table and on the table that gained a column
    with db.transaction() as s:      # row triggers fire on rows, so give the append-only tables one each
        stream = s.scalar(text("SELECT stream_id FROM audit_heads"))
        s.execute(text("INSERT INTO audit_events (id, stream_id, sequence, canonical, mac) VALUES ('e1', :stream, 1, '{}', 'm')"), {"stream": stream})
        s.execute(text("INSERT INTO transparency_heads (tree_size, log_id, root_hash, timestamp, key_id, signature) VALUES (1, :stream, 'r', 't', 'k', 's')"), {"stream": stream})
    for sql in ("UPDATE audit_events SET mac = 'x'", "UPDATE audit_events SET actor_id = 'x'", "DELETE FROM audit_events",
                "UPDATE transparency_heads SET root_hash = 'x'", "DELETE FROM transparency_heads",
                "UPDATE policy_versions SET threshold = 1", "DELETE FROM policy_versions"):
        with pytest.raises(DatabaseError), db.transaction() as s:
            s.execute(text(sql))
    # upgrading again is a no-op, and the downgrade used by disposable test databases refuses when visitors exist
    command.upgrade(cfg, "head")
    with pytest.raises(Exception):
        command.downgrade(cfg, "0005")
