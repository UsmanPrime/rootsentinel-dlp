"""Authorization matrix generated from docs/openapi.json, plus CSRF, Origin, Host and session sweeps.

Every documented operation must appear in ACCESS below; a new route fails the test until its access rule is written
down. For each operation and each caller (anonymous, EMPLOYEE, ANALYST, ADMIN) the expected result is checked against
the real application. Requests that change state use bodies that end in a conflict (a stale policy version or incident
revision) so an allowed caller proves access without changing what later checks depend on.
"""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api import create_app

OPENAPI = json.loads((Path(__file__).resolve().parents[2] / "docs" / "openapi.json").read_text(encoding="utf-8"))
ROLES = ("EMPLOYEE", "ANALYST", "ADMIN")
ACCOUNT = {"EMPLOYEE": "employee", "ANALYST": "analyst", "ADMIN": "admin"}
ANY, PRIVILEGED, ADMIN_ONLY, OWNER, PUBLIC, VISITOR_ONLY = "any", "privileged", "admin", "owner", "public", "visitor"
ALLOWED = {ANY: set(ROLES), PRIVILEGED: {"ANALYST", "ADMIN"}, ADMIN_ONLY: {"ADMIN"}, OWNER: {"EMPLOYEE"}, PUBLIC: set(ROLES),
           VISITOR_ONLY: set()}

# The access rule of every operation. OWNER: only the account that created the transfer (here the EMPLOYEE); other
# roles get 404, admins included, because release has no administrative bypass.
ACCESS = {
    ("get", "/health"): PUBLIC,
    ("post", "/api/v1/auth/login"): PUBLIC,
    ("get", "/api/v1/auth/session"): PUBLIC,
    ("get", "/api/v1/auth/me"): ANY,
    ("post", "/api/v1/auth/logout"): ANY,
    ("get", "/api/v1/assets"): PRIVILEGED,
    ("post", "/api/v1/assets"): ADMIN_ONLY,
    ("get", "/api/v1/assets/{asset_id}"): PRIVILEGED,
    ("get", "/api/v1/assets/{asset_id}/versions"): PRIVILEGED,
    ("post", "/api/v1/assets/{asset_id}/versions"): ADMIN_ONLY,
    ("get", "/api/v1/assets/{asset_id}/versions/{version_id}"): PRIVILEGED,
    ("post", "/api/v1/assets/{asset_id}/retire"): ADMIN_ONLY,
    ("get", "/api/v1/assets/{asset_id}/versions/{version_id}/proofs/{index}"): PRIVILEGED,
    ("get", "/api/v1/assets/{asset_id}/versions/{version_id}/tree"): PRIVILEGED,
    ("post", "/api/v1/integrity/verify"): PRIVILEGED,
    ("get", "/api/v1/detection/profiles"): ANY,
    ("get", "/api/v1/policies/active"): ANY,
    ("get", "/api/v1/policies/history"): PRIVILEGED,
    ("post", "/api/v1/policies"): ADMIN_ONLY,
    ("post", "/api/v1/scans"): ANY,
    ("get", "/api/v1/scans"): ANY,
    ("get", "/api/v1/scans/{scan_id}"): ANY,
    ("post", "/api/v1/transfers"): ANY,
    ("post", "/api/v1/transfers/fixtures"): ANY,
    ("get", "/api/v1/transfers"): ANY,
    ("get", "/api/v1/transfers/{identifier}"): ANY,
    ("post", "/api/v1/transfers/{identifier}/release"): OWNER,
    ("get", "/api/v1/incidents"): PRIVILEGED,
    ("get", "/api/v1/incidents/{identifier}"): PRIVILEGED,
    ("patch", "/api/v1/incidents/{identifier}"): PRIVILEGED,
    ("get", "/api/v1/exports/incidents/{identifier}"): PRIVILEGED,
    ("get", "/api/v1/audit/events"): PRIVILEGED,
    ("post", "/api/v1/audit/verify"): PRIVILEGED,
    ("post", "/api/v1/audit/checkpoint"): ADMIN_ONLY,
    ("post", "/api/v1/transfers-maintenance/expire"): ADMIN_ONLY,
    ("get", "/api/v1/transparency/key"): PRIVILEGED,
    ("get", "/api/v1/transparency/sth"): PRIVILEGED,
    ("post", "/api/v1/transparency/sth"): ADMIN_ONLY,
    ("get", "/api/v1/transparency/sth/{size}"): PRIVILEGED,
    ("get", "/api/v1/transparency/proof/inclusion"): PRIVILEGED,
    ("get", "/api/v1/transparency/proof/consistency"): PRIVILEGED,
    ("get", "/api/v1/overview"): ANY,
    # Visitor mode (Chunk V). Entry is public (404 while the mode is off); the visitor views belong to visitors only.
    ("post", "/api/v1/auth/visitor"): PUBLIC,
    ("get", "/api/v1/visitor/audit/events"): VISITOR_ONLY,
    ("get", "/api/v1/visitor/transparency/key"): VISITOR_ONLY,
    ("get", "/api/v1/visitor/transparency/sth"): VISITOR_ONLY,
    ("get", "/api/v1/visitor/transparency/proof/inclusion"): VISITOR_ONLY,
}
PROTECTED = b"SYNTHETIC-PROTECTED-" * 128
BENIGN = b"Public synthetic matrix bytes.\n" * 40
OCTET = {"Content-Type": "application/octet-stream"}


def error_code(response):
    try:
        body = response.json()
    except ValueError:
        return None
    return body.get("error", {}).get("code") if isinstance(body, dict) else None


def documented_operations():
    return {(method, path) for path, item in OPENAPI["paths"].items() for method in item if method in {"get", "post", "patch", "put", "delete"}}


def test_every_documented_operation_has_an_access_rule():
    assert documented_operations() == set(ACCESS), "add the new operation to ACCESS with its intended rule"


@pytest.fixture
def world(system, credentials):
    """One app, one signed-in client per role, and real records owned by the EMPLOYEE."""
    app = create_app(system[0])
    clients = {}

    def signed_in(role):
        client = TestClient(app, base_url="http://127.0.0.1:5173", raise_server_exceptions=False)
        client.__enter__()
        client.headers["origin"] = system[0].origin
        result = client.post("/api/v1/auth/login", json={"username": ACCOUNT[role], "password": credentials[0]})
        assert result.status_code == 200, result.text
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        return client

    for role in ROLES:
        clients[role] = signed_in(role)
    admin, employee = clients["ADMIN"], clients["EMPLOYEE"]
    asset = admin.post("/api/v1/assets?label=Matrix", content=PROTECTED, headers=OCTET).json()
    spare = admin.post("/api/v1/assets?label=Spare", content=PROTECTED + b"x", headers=OCTET).json()
    scan = employee.post("/api/v1/scans", content=BENIGN, headers=OCTET).json()
    allowed = employee.post("/api/v1/transfers", content=BENIGN, headers={**OCTET, "Idempotency-Key": str(uuid4())}).json()
    blocked = employee.post("/api/v1/transfers", content=PROTECTED, headers={**OCTET, "Idempotency-Key": str(uuid4())}).json()
    assert allowed["state"] == "ALLOWED" and blocked["state"] == "BLOCKED"
    ids = {"asset_id": asset["asset_id"], "version_id": asset["id"], "index": 0, "scan_id": scan["id"],
           "transfer": allowed["id"], "incident": blocked["incident_id"], "spare": spare["asset_id"]}
    yield {"app": app, "clients": clients, "ids": ids, "signed_in": signed_in, "settings": system[0]}
    for client in clients.values():
        client.__exit__(None, None, None)


def call(client, method, path, ids, fresh_transfer=None):
    """One request per operation with a body that is valid but ends in a conflict where it would change state."""
    route = path.format(asset_id=ids["asset_id"], version_id=ids["version_id"], index=ids["index"], scan_id=ids["scan_id"], size=1,
                        identifier=ids["incident"] if "incidents" in path else (fresh_transfer or ids["transfer"]))
    if path == "/api/v1/assets/{asset_id}/retire":
        route = f"/api/v1/assets/{ids['spare']}/retire"
    key = {"Idempotency-Key": str(uuid4())}
    bodies = {
        ("post", "/api/v1/auth/login"): {"json": {"username": "nobody-matrix", "password": "wrong"}},
        ("post", "/api/v1/assets"): {"content": b"matrix asset " + uuid4().bytes, "headers": OCTET, "params": {"label": "M" + uuid4().hex[:8]}},
        ("post", "/api/v1/assets/{asset_id}/versions"): {"content": PROTECTED, "headers": OCTET, "params": {"expected_version": 1}},
        ("post", "/api/v1/integrity/verify"): {"json": {"asset_id": ids["asset_id"], "version_id": ids["version_id"], "proof": {}}},
        ("post", "/api/v1/policies"): {"json": {"threshold": 1024, "block_enabled": True, "expected_version": str(uuid4())}},
        ("post", "/api/v1/scans"): {"content": BENIGN, "headers": OCTET},
        ("post", "/api/v1/transfers"): {"content": BENIGN, "headers": {**OCTET, **key}},
        ("post", "/api/v1/transfers/fixtures"): {"json": {"fixture": "benign"}, "headers": key},
        ("patch", "/api/v1/incidents/{identifier}"): {"json": {"expected_revision": 999, "status": "INVESTIGATING", "note": ""}},
        ("get", "/api/v1/transparency/proof/inclusion"): {"params": {"leaf_index": 0, "tree_size": 1}},
        ("get", "/api/v1/visitor/transparency/proof/inclusion"): {"params": {"leaf_index": 0, "tree_size": 1}},
        ("get", "/api/v1/transparency/proof/consistency"): {"params": {"first": 1, "second": 1}},
    }
    return client.request(method.upper(), route, **bodies.get((method, path), {}))


@pytest.mark.parametrize("method,path", sorted(ACCESS))
def test_authorization_matrix(world, method, path):
    rule, ids = ACCESS[(method, path)], world["ids"]
    for role in ROLES:
        client = world["clients"][role]
        if (method, path) == ("post", "/api/v1/auth/logout"):
            client = world["signed_in"](role)                     # a disposable session: logging out must not end the others
        fresh = None
        if rule == OWNER:                                          # each release needs its own unreleased ALLOWED transfer
            fresh = world["clients"]["EMPLOYEE"].post("/api/v1/transfers", content=BENIGN,
                headers={**OCTET, "Idempotency-Key": str(uuid4())}).json()["id"]
        response = call(client, method, path, ids, fresh)
        code = error_code(response)
        if (method, path) == ("post", "/api/v1/auth/login"):
            # Sign-in is public; the deliberately wrong password proves the credential check, not authorization.
            assert response.status_code == 401 and code == "INVALID_CREDENTIALS", (role, response.status_code, code)
        elif role in ALLOWED[rule]:
            assert response.status_code not in {401, 403} and response.status_code < 500, (role, method, path, response.status_code, code)
            if rule == OWNER:
                assert response.status_code == 200 and response.content == BENIGN
        elif rule == OWNER:
            # Not the owner: indistinguishable from a missing transfer, and no byte of the payload.
            assert response.status_code == 404 and code == "NOT_FOUND" and BENIGN not in response.content, (role, path)
        else:
            assert response.status_code == 403 and code == "FORBIDDEN", (role, method, path, response.status_code, code)


@pytest.mark.parametrize("method,path", sorted(op for op, rule in ACCESS.items() if rule != PUBLIC))
def test_anonymous_callers_are_refused_everywhere_but_sign_in(system, method, path):
    with TestClient(create_app(system[0]), base_url="http://127.0.0.1:5173", raise_server_exceptions=False) as client:
        client.headers["origin"] = system[0].origin
        ids = {"asset_id": str(uuid4()), "version_id": str(uuid4()), "index": 0, "scan_id": str(uuid4()),
               "transfer": str(uuid4()), "incident": str(uuid4()), "spare": str(uuid4())}
        response = call(client, method, path, ids)
    assert response.status_code == 401 and response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED", (method, path)


MUTATIONS = sorted(op for op in ACCESS if op[0] != "get" and op not in {("post", "/api/v1/auth/login"), ("post", "/api/v1/auth/visitor")})


@pytest.mark.parametrize("method,path", MUTATIONS)
def test_every_mutation_without_the_csrf_token_is_refused(world, method, path):
    client = world["clients"]["ADMIN"]
    token = client.headers.pop("x-csrf-token")
    try:
        response = call(client, method, path, world["ids"])
    finally:
        client.headers["x-csrf-token"] = token
    assert response.status_code == 403 and response.json()["error"]["code"] == "CSRF_REJECTED", (method, path)


@pytest.mark.parametrize("method,path", sorted(op for op in ACCESS if op[0] != "get"))
def test_every_mutation_from_another_origin_is_refused(world, method, path):
    client = world["clients"]["ADMIN"]
    client.headers["origin"] = "https://attacker.example"
    try:
        response = call(client, method, path, world["ids"])
    finally:
        client.headers["origin"] = world["settings"].origin
    assert response.status_code == 403 and response.json()["error"]["code"] == "ORIGIN_REJECTED", (method, path)


@pytest.mark.parametrize("method,path", sorted(ACCESS))
def test_every_operation_with_a_foreign_host_is_refused(world, method, path):
    with TestClient(world["app"], base_url="http://attacker.example", raise_server_exceptions=False) as foreign:
        foreign.headers["origin"] = world["settings"].origin
        response = call(foreign, method, path, world["ids"])
    assert response.status_code == 400 and response.json()["error"]["code"] == "HOST_REJECTED", (method, path)


def test_another_employee_cannot_see_or_release_the_first_employees_records(world, credentials):
    other = TestClient(world["app"], base_url="http://127.0.0.1:5173", raise_server_exceptions=False)
    with other:
        other.headers["origin"] = world["settings"].origin
        result = other.post("/api/v1/auth/login", json={"username": "second", "password": credentials[0]})
        other.headers["x-csrf-token"] = result.json()["csrf_token"]
        ids = world["ids"]
        assert other.get(f"/api/v1/transfers/{ids['transfer']}").status_code == 404
        assert other.get(f"/api/v1/scans/{ids['scan_id']}").status_code == 404
        response = other.post(f"/api/v1/transfers/{ids['transfer']}/release")
        assert response.status_code == 404 and BENIGN not in response.content
        listed = other.get("/api/v1/transfers").json()["items"]
        assert ids["transfer"] not in {item["id"] for item in listed}
    # The owner can still release it once: the probes above did not consume the single use.
    owner = world["clients"]["EMPLOYEE"].post(f"/api/v1/transfers/{ids['transfer']}/release")
    assert owner.status_code == 200 and owner.content == BENIGN


# ---------------------------------------------------------------------------------------------- sessions
def test_the_session_check_answers_204_without_a_valid_session_and_never_401(system, credentials):
    from datetime import timedelta
    from sqlalchemy import update
    from app.db import now
    from app.models import SessionRecord
    app = create_app(system[0])
    with TestClient(app, base_url="http://127.0.0.1:5173", raise_server_exceptions=False) as client:
        client.headers["origin"] = system[0].origin
        assert client.get("/api/v1/auth/session").status_code == 204                          # no cookie
        client.cookies.set("rs_session", "B" * 43, path="/api/v1")
        assert client.get("/api/v1/auth/session").status_code == 204                          # forged cookie
        client.cookies.clear()
        result = client.post("/api/v1/auth/login", json={"username": "analyst", "password": credentials[0]})
        session = client.get("/api/v1/auth/session")
        assert session.status_code == 200 and session.json()["user"]["role"] == "ANALYST"
        assert session.json()["csrf_token"] == result.json()["csrf_token"]
        assert "set-cookie" not in session.headers
        with app.state.db.transaction() as s:
            s.execute(update(SessionRecord).values(expires_at=now() - timedelta(seconds=1)))
        assert client.get("/api/v1/auth/session").status_code == 204                          # expired
        assert client.get("/api/v1/auth/me").status_code == 401                                # unchanged contract

def cookie_of(response):
    return next(v for k, v in response.headers.multi_items() if k.lower() == "set-cookie" and v.startswith("rs_session="))


def test_a_client_chosen_session_id_is_never_adopted(system, credentials):
    with TestClient(create_app(system[0]), base_url="http://127.0.0.1:5173", raise_server_exceptions=False) as client:
        client.headers["origin"] = system[0].origin
        planted = "A" * 43
        client.cookies.set("rs_session", planted, path="/api/v1")
        result = client.post("/api/v1/auth/login", json={"username": "employee", "password": credentials[0]})
        assert result.status_code == 200
        issued = cookie_of(result).split(";", 1)[0].split("=", 1)[1]
        assert issued != planted and len(issued) == 43
        client.cookies.clear()
        client.cookies.set("rs_session", planted, path="/api/v1")
        assert client.get("/api/v1/auth/me").status_code == 401


def test_logout_ends_the_session_and_its_cookie(system, credentials):
    with TestClient(create_app(system[0]), base_url="http://127.0.0.1:5173", raise_server_exceptions=False) as client:
        client.headers["origin"] = system[0].origin
        result = client.post("/api/v1/auth/login", json={"username": "analyst", "password": credentials[0]})
        token = client.cookies["rs_session"]
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        assert client.post("/api/v1/auth/logout").status_code == 204
        client.cookies.set("rs_session", token, path="/api/v1")     # replaying the old cookie must not work
        assert client.get("/api/v1/auth/me").status_code == 401
        assert client.post("/api/v1/audit/verify").status_code == 401


def test_an_expired_session_is_refused(system, credentials):
    from datetime import timedelta
    from sqlalchemy import update
    from app.db import now
    from app.models import SessionRecord
    app = create_app(system[0])
    with TestClient(app, base_url="http://127.0.0.1:5173", raise_server_exceptions=False) as client:
        client.headers["origin"] = system[0].origin
        client.post("/api/v1/auth/login", json={"username": "admin", "password": credentials[0]})
        assert client.get("/api/v1/auth/me").status_code == 200
        with app.state.db.transaction() as s:
            s.execute(update(SessionRecord).values(expires_at=now() - timedelta(seconds=1)))
        assert client.get("/api/v1/auth/me").status_code == 401


def test_hosted_session_cookie_flags(system, credentials):
    from dataclasses import replace
    origin = "https://rs-matrix.example"
    settings = replace(system[0], origin=origin, secure_cookies=True, session_seconds=900)
    with TestClient(create_app(settings), base_url=origin, raise_server_exceptions=False) as client:
        client.headers["origin"] = origin
        result = client.post("/api/v1/auth/login", json={"username": "admin", "password": credentials[0]})
    flags = [part.strip().lower() for part in cookie_of(result).split(";")]
    assert "httponly" in flags and "secure" in flags and "samesite=strict" in flags
    assert "path=/api/v1" in flags and "max-age=900" in flags
    assert "csrf" not in cookie_of(result).lower()               # the CSRF token is never a cookie


def test_concurrent_sessions_are_independent(system, credentials):
    app = create_app(system[0])
    with TestClient(app, base_url="http://127.0.0.1:5173", raise_server_exceptions=False) as first, \
         TestClient(app, base_url="http://127.0.0.1:5173", raise_server_exceptions=False) as second:
        tokens = []
        for client in (first, second):
            client.headers["origin"] = system[0].origin
            result = client.post("/api/v1/auth/login", json={"username": "admin", "password": credentials[0]})
            client.headers["x-csrf-token"] = result.json()["csrf_token"]
            tokens.append(client.headers["x-csrf-token"])
        assert tokens[0] != tokens[1]
        assert first.get("/api/v1/auth/me").status_code == 200 and second.get("/api/v1/auth/me").status_code == 200
        # A CSRF token belongs to its own session only.
        first.headers["x-csrf-token"], second.headers["x-csrf-token"] = tokens[1], tokens[0]
        assert first.post("/api/v1/audit/verify").json()["error"]["code"] == "CSRF_REJECTED"
        first.headers["x-csrf-token"], second.headers["x-csrf-token"] = tokens[0], tokens[1]
        assert first.post("/api/v1/auth/logout").status_code == 204
        assert first.get("/api/v1/auth/me").status_code == 401
        assert second.get("/api/v1/auth/me").status_code == 200
