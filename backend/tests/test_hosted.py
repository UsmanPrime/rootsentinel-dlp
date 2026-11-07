"""Phase 06A: hosted presenter-demo configuration (https origin, same-origin frontend, proxy hops, bootstrap).

The gateway invariants are re-proved here in the hosted configuration. Everything is synthetic, uses
generated credentials and writes only below pytest's temporary directory.
"""
from dataclasses import replace
from hashlib import sha256
import json
import os
import re
from uuid import uuid4

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select, text

from app import bootstrap
from app.api import create_app, forwarded_client
from app.audit import KeyRing
from app.errors import DomainError
from app.gateway_models import AuditEvent, Transfer
from app.models import Asset, User
from app.settings import Settings

PROTECTED = b"SYNTHETIC-PROTECTED-" * 128
BENIGN_FIXTURE = b"RootSentinel synthetic benign delivery\n"
ORIGIN = "https://rs-test.example"


def fixture_transfer(client, name):
    return client.post("/api/v1/transfers/fixtures", json={"fixture": name}, headers={"Idempotency-Key": str(uuid4())})


def release(client, identifier):
    return client.post(f"/api/v1/transfers/{identifier}/release")


def write_accounts(path, entries):
    path.write_text(json.dumps({"version": 1, "accounts": entries}), encoding="utf-8")
    path.chmod(0o600)
    return path


def build_dist(root):
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text('<!doctype html><title>RootSentinel</title><div id="root"></div>', encoding="utf-8")
    (root / "assets" / "app.js").write_text("console.log('synthetic');", encoding="utf-8")
    (root / "assets" / "app.css").write_text("body{margin:0}", encoding="utf-8")
    (root.parent / "secret.txt").write_text("outside the frontend directory", encoding="utf-8")
    return root


def hosted_settings(system, tmp_path, **override):
    settings, *_ = system
    values = dict(origin=ORIGIN, secure_cookies=True, mode="local", frontend_dir=build_dist(tmp_path / "dist"))
    values.update(override)
    return replace(settings, **values)


@pytest.fixture
def hosted(system, tmp_path):
    settings = hosted_settings(system, tmp_path, extra_hosts=("alt.example",))
    with TestClient(create_app(settings), base_url=ORIGIN, raise_server_exceptions=False) as client:
        client.headers["origin"] = ORIGIN
        yield client


def sign_in(client, credentials, name="employee"):
    result = client.post("/api/v1/auth/login", json={"username": name, "password": credentials[0]})
    assert result.status_code == 200, result.text
    client.headers["x-csrf-token"] = result.json()["csrf_token"]


# ---------------------------------------------------------------------------------------------- settings
def test_new_settings_default_to_the_earlier_behavior(system):
    settings = system[0]
    assert (settings.extra_hosts, settings.trusted_proxy_hops, settings.frontend_dir) == ((), 0, None)
    assert (settings.max_upload_bytes, settings.transfer_rate_per_minute, settings.session_seconds, settings.retention_seconds) == (10485760, 30, 3600, 900)
    assert settings.hosted is False and replace(settings, origin=ORIGIN, secure_cookies=True).hosted is True


@pytest.mark.parametrize("override", [
    {"extra_hosts": ("*.example.com",)}, {"extra_hosts": ("https://example.com",)}, {"extra_hosts": ("Example.com",)},
    {"extra_hosts": ("a b",)}, {"trusted_proxy_hops": 6}, {"trusted_proxy_hops": -1}, {"max_upload_bytes": 1023},
    {"max_upload_bytes": 10485761}, {"transfer_rate_per_minute": 0}, {"transfer_rate_per_minute": 121},
    {"session_seconds": 59}, {"retention_seconds": 901},
])
def test_invalid_hosted_settings_are_rejected(system, override):
    with pytest.raises(ValueError):
        replace(system[0], **override)


def test_environment_overrides_are_parsed_and_errors_do_not_echo_values(system, monkeypatch, tmp_path):
    settings = system[0]
    for key, value in {"ROOTSENTINEL_RUNTIME_ROOT": settings.paths.runtime, "ROOTSENTINEL_ARTIFACT_ROOT": settings.paths.artifacts,
                       "ROOTSENTINEL_MODE": "local", "ROOTSENTINEL_ORIGIN": ORIGIN, "ROOTSENTINEL_SESSION_SECONDS": "600",
                       "ROOTSENTINEL_RETENTION_SECONDS": "120", "ROOTSENTINEL_EXTRA_HOSTS": "alt.example, other.example:8443",
                       "ROOTSENTINEL_TRUSTED_PROXY_HOPS": "2", "ROOTSENTINEL_FRONTEND_DIR": str(tmp_path / "dist"),
                       "ROOTSENTINEL_MAX_UPLOAD_BYTES": "1048576", "ROOTSENTINEL_TRANSFER_RATE_PER_MINUTE": "6"}.items():
        monkeypatch.setenv(key, str(value))
    loaded = Settings.from_environment()
    assert (loaded.session_seconds, loaded.retention_seconds, loaded.trusted_proxy_hops, loaded.max_upload_bytes, loaded.transfer_rate_per_minute) == (600, 120, 2, 1048576, 6)
    assert loaded.extra_hosts == ("alt.example", "other.example:8443") and loaded.hosted
    monkeypatch.setenv("ROOTSENTINEL_TRUSTED_PROXY_HOPS", "two-secret-looking-value")
    with pytest.raises(ValueError) as error:
        Settings.from_environment()
    assert "two-secret-looking-value" not in str(error.value)


# ---------------------------------------------------------------------------------------------- static site and headers
def test_frontend_is_served_with_spa_fallback_and_security_headers(hosted):
    index = hosted.get("/")
    assert index.status_code == 200 and index.headers["content-type"].startswith("text/html") and "RootSentinel" in index.text
    assert hosted.get("/transfers/12345").text == index.text          # client-side route
    script = hosted.get("/assets/app.js")
    assert script.status_code == 200 and "javascript" in script.headers["content-type"] and script.text == "console.log('synthetic');"
    for response in (index, script, hosted.get("/health")):
        assert response.headers["cache-control"] == "no-store" and response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY" and response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["strict-transport-security"].startswith("max-age=")
        csp = response.headers["content-security-policy-report-only"]
        assert "default-src 'none'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert "content-security-policy" not in response.headers            # report-only for now


def test_local_http_deployment_gets_no_hsts_or_csp(client):
    response = client.get("/health")
    assert "strict-transport-security" not in response.headers and "content-security-policy-report-only" not in response.headers
    assert client.get("/openapi.json").status_code == 200                     # development documentation is unchanged


def test_unknown_files_and_api_paths_get_typed_json_404(hosted):
    for path in ("/assets/missing.js", "/api/v1/unknown", "/api/unknown", "/api", "/openapi.json", "/.env", "/assets/.hidden"):
        response = hosted.get(path)
        assert response.status_code == 404, path
        assert response.json() == {"error": {"code": "NOT_FOUND", "outcome": "INDETERMINATE", "release_authorized": False}}


@pytest.mark.parametrize("path", ["/../secret.txt", "/%2e%2e/secret.txt", "/assets/..%2f..%2fsecret.txt", "/assets/%2e%2e/%2e%2e/secret.txt",
                                  "/assets\\..\\..\\secret.txt", "/%00", "//etc/passwd"])
def test_static_serving_cannot_leave_the_frontend_directory(hosted, path):
    response = hosted.get(path)
    assert "outside the frontend directory" not in response.text
    assert response.status_code in (200, 404, 400)
    if response.status_code == 200:                                          # only the SPA shell may ever answer
        assert "RootSentinel" in response.text


def test_static_serving_does_not_follow_a_symlink_out_of_the_directory(system, tmp_path):
    settings = hosted_settings(system, tmp_path)
    link = settings.frontend_dir / "assets" / "leak.txt"
    try:
        link.symlink_to(tmp_path / "secret.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links need a privilege this account lacks")
    with TestClient(create_app(settings), base_url=ORIGIN, raise_server_exceptions=False) as client:
        assert "outside the frontend directory" not in client.get("/assets/leak.txt").text


def test_only_get_and_head_reach_the_frontend_and_documentation_is_off(hosted, system, tmp_path):
    assert hosted.post("/").status_code == 405 and hosted.delete("/assets/app.js").status_code == 405
    assert "swagger" not in hosted.get("/docs").text.lower() and "redoc" not in hosted.get("/redoc").text.lower()
    public = replace(system[0], mode="public_demo", secure_cookies=True, origin=ORIGIN)
    with TestClient(create_app(public), base_url=ORIGIN, raise_server_exceptions=False) as client:
        assert client.get("/openapi.json").status_code == 404 and client.get("/docs").status_code == 404


def test_frontend_requires_a_built_index(system, tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(RuntimeError):
        create_app(replace(system[0], frontend_dir=tmp_path / "empty"))


def test_host_and_origin_checks_apply_to_static_files_and_extra_hosts_are_exact(hosted):
    assert hosted.get("/", headers={"host": "evil.example"}).json()["error"]["code"] == "HOST_REJECTED"
    assert hosted.get("/", headers={"host": "rs-test.example:8443"}).json()["error"]["code"] == "HOST_REJECTED"
    assert hosted.get("/health", headers={"host": "alt.example"}).status_code == 200
    assert hosted.get("/health", headers={"host": "sub.alt.example"}).json()["error"]["code"] == "HOST_REJECTED"
    assert hosted.post("/api/v1/auth/login", json={"username": "x", "password": "y" * 12}, headers={"origin": "https://evil.example"}).json()["error"]["code"] == "ORIGIN_REJECTED"


# ---------------------------------------------------------------------------------------------- anonymous surface
def test_every_anonymous_api_route_is_denied_and_nothing_unexpected_is_exposed(hosted):
    app = hosted.app
    outside_api = sorted(r.path for r in app.routes if getattr(r, "path", "").startswith("/api/v1") is False)
    assert outside_api == ["/health", "/{path:path}"], "a new unauthenticated route must be reviewed on purpose"
    checked = 0
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/api/v1") or route.path == "/api/v1/auth/login":
            continue
        url = re.sub(r"\{index\}", "0", re.sub(r"\{[a-z_]+\}", str(uuid4()), route.path))
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            response = hosted.request(method, url, json={} if method in {"POST", "PATCH"} else None)
            body = response.json()
            assert response.status_code == 401 and body["error"]["code"] == "AUTHENTICATION_REQUIRED", (method, route.path, response.status_code)
            checked += 1
    assert checked >= 28
    wrong = hosted.post("/api/v1/auth/login", json={"username": "nobody", "password": "wrong-password-value"})
    assert wrong.status_code == 401 and "set-cookie" not in wrong.headers and wrong.json()["error"]["code"] == "INVALID_CREDENTIALS"
    assert hosted.get("/health").json()["status"] == "ok"


def test_public_demo_still_denies_every_api_route(system):
    public = replace(system[0], mode="public_demo", secure_cookies=True, origin=ORIGIN)
    with TestClient(create_app(public), base_url=ORIGIN, raise_server_exceptions=False) as client:
        client.headers["origin"] = ORIGIN
        paths = [r.path for r in client.app.routes if isinstance(r, APIRoute) and r.path.startswith("/api/v1")]
        assert len(paths) >= 30
        for path in paths:
            response = client.request("POST" if "release" in path or "login" in path else "GET", re.sub(r"\{[a-z_]+\}", "0", path))
            assert response.status_code == 403 and response.json()["error"]["code"] == "PUBLIC_DEMO_NOT_READY", path


# ---------------------------------------------------------------------------------------------- trusted proxy hops
@pytest.mark.parametrize("hops,header,expected", [
    (0, "1.2.3.4", None), (1, "1.2.3.4", "1.2.3.4"), (1, "9.9.9.9, 5.6.7.8", "5.6.7.8"), (2, "9.9.9.9, 5.6.7.8, 10.0.0.1", "5.6.7.8"),
    (2, "5.6.7.8", None), (1, "not-an-address", None), (1, "1.2.3.4:5555", None), (1, "2001:db8::1", "2001:db8::1"), (1, "", None),
    (3, "a, b", None),
])
def test_forwarded_client_takes_the_entry_n_from_the_right_and_fails_closed(hops, header, expected):
    assert forwarded_client([(b"x-forwarded-for", header.encode())], hops) == expected


def test_forwarded_client_joins_repeated_headers_and_ignores_other_headers():
    headers = [(b"x-forwarded-for", b"9.9.9.9"), (b"x-forwarded-for", b"5.6.7.8"), (b"x-real-ip", b"7.7.7.7"), (b"x-forwarded-proto", b"http")]
    assert forwarded_client(headers, 1) == "5.6.7.8" and forwarded_client(headers, 2) == "9.9.9.9" and forwarded_client(headers, 0) is None


def attempts(client, count, forwarded):
    return [client.post("/api/v1/auth/login", json={"username": f"nobody-{i}", "password": "wrong-password-value"},
                        headers={"x-forwarded-for": forwarded(i)}).status_code for i in range(count)]


def test_login_throttle_keys_on_the_trusted_forwarded_address_and_ignores_spoofing(system, tmp_path):
    settings = hosted_settings(system, tmp_path, trusted_proxy_hops=1)
    with TestClient(create_app(settings), base_url=ORIGIN, raise_server_exceptions=False) as client:
        client.headers["origin"] = ORIGIN
        # The client invents a new leftmost address each time; the proxy-appended rightmost one is constant.
        codes = attempts(client, 16, lambda i: f"203.0.113.{i}, 198.51.100.7")
        assert codes[:15] == [401] * 15 and codes[15] == 429                # per-IP limit of 15 reached
        other = client.post("/api/v1/auth/login", json={"username": "someone-else", "password": "wrong-password-value"},
                            headers={"x-forwarded-for": "203.0.113.1, 198.51.100.8"})
        assert other.status_code == 401                                      # a different real client is not locked out


def test_forwarded_headers_are_ignored_when_hops_is_zero(hosted):
    codes = attempts(hosted, 16, lambda i: f"203.0.113.{i}")
    assert codes[15] == 429                                                  # all attempts share the socket peer


# ---------------------------------------------------------------------------------------------- overrides
def test_upload_cap_session_lifetime_retention_and_rate_overrides(system, tmp_path, credentials):
    settings = hosted_settings(system, tmp_path, max_upload_bytes=2048, session_seconds=600, retention_seconds=60, transfer_rate_per_minute=2)
    with TestClient(create_app(settings), base_url=ORIGIN, raise_server_exceptions=False) as client:
        client.headers["origin"] = ORIGIN
        result = client.post("/api/v1/auth/login", json={"username": "employee", "password": credentials[0]})
        assert "Max-Age=600" in result.headers["set-cookie"] and "Secure" in result.headers["set-cookie"] and "HttpOnly" in result.headers["set-cookie"]
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        raw = {"Content-Type": "application/octet-stream"}
        assert client.post("/api/v1/scans", content=b"x" * 2049, headers=raw).json()["error"]["code"] == "INPUT_TOO_LARGE"
        assert client.post("/api/v1/scans", content=b"y" * 2048, headers=raw).status_code == 201
        item = fixture_transfer(client, "benign").json()
        seconds = (_parse(item["expires_at"]) - _parse(item["created_at"])).total_seconds()
        assert 55 <= seconds <= 65                                          # retention override applied
        assert fixture_transfer(client, "benign").status_code == 201
        assert fixture_transfer(client, "benign").json()["error"]["code"] == "TRANSFER_RATE_LIMIT"


def _parse(value):
    from datetime import datetime
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------------------------- bootstrap
def bootstrap_environment(monkeypatch, system, tmp_path, accounts):
    settings = system[0]
    values = {"ROOTSENTINEL_RUNTIME_ROOT": settings.paths.runtime, "ROOTSENTINEL_ARTIFACT_ROOT": settings.paths.artifacts,
              "ROOTSENTINEL_MODE": "local", "ROOTSENTINEL_ORIGIN": ORIGIN, "ROOTSENTINEL_DATABASE_URL": settings.database_url,
              "ROOTSENTINEL_AUDIT_KEY_FILE": settings.audit_key_file, "ROOTSENTINEL_CHECKPOINT_ROOT": settings.checkpoint_root}
    for key, value in values.items():
        monkeypatch.setenv(key, str(value))
    return ["--accounts", str(accounts)]


def entry(name, role, password_hash, **extra):
    return {"username": name, "role": role, "password_hash": password_hash, **extra}


def test_bootstrap_is_idempotent_prints_no_secrets_and_seeds_through_the_audit_chain(system, monkeypatch, tmp_path, credentials, capsys):
    password, digest = credentials
    accounts = write_accounts(tmp_path / "accounts.json", [entry("presenter-admin", "ADMIN", digest), entry("class-user", "EMPLOYEE", digest)])
    args = bootstrap_environment(monkeypatch, system, tmp_path, accounts)
    assert bootstrap.main(args) == 0
    first = capsys.readouterr()
    assert "created=2 updated=0 unchanged=0" in first.out and "seeded=1 existing=0" in first.out
    assert bootstrap.main(args) == 0
    second = capsys.readouterr()
    assert "created=0 updated=0 unchanged=2" in second.out and "seeded=0 existing=1" in second.out
    for text_ in (first.out + first.err + second.out + second.err):
        assert password not in text_ and digest not in text_ and "presenter-admin" not in text_ and "class-user" not in text_
    db = system[1]
    with db.transaction() as s:
        assert s.scalar(select(Asset.label)) == "synthetic-protected-sample"
        kinds = [json.loads(e.canonical)["kind"] for e in s.scalars(select(AuditEvent).order_by(AuditEvent.sequence))]
        assert kinds == ["ASSET_REGISTERED"]                                  # exactly once across two runs
        system_user = s.scalar(select(User).where(User.username == bootstrap.SYSTEM_USERNAME))
        assert system_user.enabled is False and system_user.role == "ADMIN"
        ring = KeyRing.load(system[0].audit_key_file)
        assert hosted_audit(system, ring, s)["valid"] is True
    assert (system[0].checkpoint_root / "checkpoint-0000000001.json").exists()


def hosted_audit(system, ring, s):
    from app.audit import AuditService
    return AuditService(ring, system[0].checkpoint_root).verify(s)


def test_bootstrap_source_of_truth_rotation_disable_and_session_revocation(system, monkeypatch, tmp_path, credentials, hosted):
    password, digest = credentials
    accounts = tmp_path / "accounts.json"
    write_accounts(accounts, [entry("class-user", "EMPLOYEE", digest)])
    args = bootstrap_environment(monkeypatch, system, tmp_path, accounts)
    assert bootstrap.main(args) == 0
    sign_in(hosted, credentials, "class-user")
    assert hosted.get("/api/v1/auth/me").status_code == 200
    from app.auth import HASHER
    new_hash = HASHER.hash("a-different-password-123")
    write_accounts(accounts, [entry("class-user", "EMPLOYEE", new_hash)])
    assert bootstrap.main(args) == 0
    assert hosted.get("/api/v1/auth/me").status_code == 401                   # old sessions revoked on rotation
    fresh = TestClient(hosted.app, base_url=ORIGIN, raise_server_exceptions=False)
    fresh.headers["origin"] = ORIGIN
    assert fresh.post("/api/v1/auth/login", json={"username": "class-user", "password": password}).status_code == 401
    assert fresh.post("/api/v1/auth/login", json={"username": "class-user", "password": "a-different-password-123"}).status_code == 200
    write_accounts(accounts, [entry("class-user", "EMPLOYEE", new_hash, enabled=False)])
    assert bootstrap.main(args) == 0
    assert fresh.post("/api/v1/auth/login", json={"username": "class-user", "password": "a-different-password-123"}).status_code == 401


@pytest.mark.parametrize("content", [
    {"version": 1, "accounts": [{"username": "u-one", "role": "ADMIN", "password_hash": "plaintext-password-123"}]},
    {"version": 1, "accounts": [{"username": "u-one", "role": "ADMIN", "password_hash": "$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"}]},
    {"version": 2, "accounts": []}, {"version": 1, "accounts": [], "extra": 1},
    {"version": 1, "accounts": [{"username": "UPPER", "role": "ADMIN", "password_hash": "x"}]},
    {"version": 1, "accounts": [{"username": "system-bootstrap", "role": "ADMIN", "password_hash": "x"}]},
])
def test_bootstrap_rejects_invalid_account_files(system, monkeypatch, tmp_path, credentials, capsys, content):
    if content["accounts"] and content["accounts"][0]["password_hash"] == "x":
        content["accounts"][0]["password_hash"] = credentials[1]
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(content), encoding="utf-8"); path.chmod(0o600)
    assert bootstrap.main(bootstrap_environment(monkeypatch, system, tmp_path, path)) == 1
    out = capsys.readouterr()
    assert "not valid" in out.err and "plaintext-password-123" not in out.out + out.err
    with system[1].transaction() as s:
        assert s.scalar(select(User.id).where(User.username == "u-one")) is None


def test_bootstrap_rejects_duplicate_names_and_unsafe_or_missing_files(system, monkeypatch, tmp_path, credentials, capsys):
    digest = credentials[1]
    path = write_accounts(tmp_path / "dup.json", [entry("u-one", "ADMIN", digest), entry("u-one", "EMPLOYEE", digest)])
    assert bootstrap.main(bootstrap_environment(monkeypatch, system, tmp_path, path)) == 1
    assert bootstrap.main(bootstrap_environment(monkeypatch, system, tmp_path, tmp_path / "missing.json")) == 1
    if os.name != "nt":
        loose = write_accounts(tmp_path / "loose.json", [entry("u-two", "ADMIN", digest)])
        loose.chmod(0o644)
        assert bootstrap.main(bootstrap_environment(monkeypatch, system, tmp_path, loose)) == 1
        assert "UNSAFE_STORAGE_PERMISSIONS" in capsys.readouterr().err


def test_bootstrap_without_audit_configuration_does_nothing(system, monkeypatch, tmp_path, capsys):
    bootstrap_environment(monkeypatch, system, tmp_path, tmp_path / "unused.json")
    monkeypatch.delenv("ROOTSENTINEL_AUDIT_KEY_FILE")
    assert bootstrap.main([]) == 2
    with system[1].transaction() as s:
        assert s.scalar(select(Asset.id)) is None


# ---------------------------------------------------------------------------------------------- invariants, hosted configuration
@pytest.fixture
def seeded(hosted, system, monkeypatch, tmp_path):
    bootstrap_environment(monkeypatch, system, tmp_path, tmp_path / "unused.json")
    assert bootstrap.main([]) == 0
    return hosted


def test_hosted_benign_release_is_byte_identical_and_single_use(seeded, credentials):
    sign_in(seeded, credentials)
    item = fixture_transfer(seeded, "benign").json()
    assert item["state"] == "ALLOWED" and item["release_eligible"] is True
    first = release(seeded, item["id"])
    assert first.status_code == 200 and first.content == BENIGN_FIXTURE
    assert sha256(first.content).hexdigest() == item["file_sha256"]
    second = release(seeded, item["id"])
    assert second.status_code == 409 and second.json()["error"]["code"] == "TRANSFER_NOT_ALLOWED" and BENIGN_FIXTURE not in second.content


def test_hosted_block_never_delivers_and_the_seeded_asset_is_what_blocks(seeded, credentials):
    sign_in(seeded, credentials)
    item = fixture_transfer(seeded, "protected").json()
    assert item["state"] == "BLOCKED" and item["release_eligible"] is False
    assert item["scan"]["decision"]["outcome"] == "BLOCK" and item["scan"]["release_authorized"] is False
    denied = release(seeded, item["id"])
    assert denied.status_code == 409 and denied.headers["content-type"].startswith("application/json") and PROTECTED not in denied.content
    with seeded.app.state.db.transaction() as s:
        assert s.get(Transfer, item["id"]).state == "BLOCKED"


def test_hosted_scan_allow_is_not_a_release_credential(seeded, credentials):
    sign_in(seeded, credentials)
    scan = seeded.post("/api/v1/scans", content=b"harmless synthetic bytes " * 60, headers={"Content-Type": "application/octet-stream"})
    assert scan.status_code == 201 and scan.json()["decision"]["outcome"] == "ALLOW" and scan.json()["release_authorized"] is False
    assert release(seeded, scan.json()["id"]).status_code == 404            # a scan id is not a transfer
    assert "/api/v1/scans/{scan_id}/release" not in {r.path for r in seeded.app.routes if hasattr(r, "path")}


def test_hosted_release_is_owner_only_even_for_an_allowed_transfer(seeded, credentials):
    sign_in(seeded, credentials, "employee")
    item = fixture_transfer(seeded, "benign").json()
    other = TestClient(seeded.app, base_url=ORIGIN, raise_server_exceptions=False)
    other.headers["origin"] = ORIGIN
    sign_in(other, credentials, "second")
    assert release(other, item["id"]).status_code == 404 and other.get(f"/api/v1/transfers/{item['id']}").status_code == 404
    assert release(seeded, item["id"]).content == BENIGN_FIXTURE


def test_hosted_audit_failure_fails_closed(seeded, credentials):
    sign_in(seeded, credentials)
    item = fixture_transfer(seeded, "benign").json()
    db = seeded.app.state.db
    with db.transaction() as s:
        s.execute(text("DROP TRIGGER immutable_audit_events_update" if db.engine.dialect.name == "sqlite"
                       else "ALTER TABLE audit_events DISABLE TRIGGER immutable_audit_events"))
        s.execute(text("UPDATE audit_events SET mac = :bad WHERE sequence = 1"), {"bad": "0" * 64})
    response = release(seeded, item["id"])
    assert response.status_code == 503 and BENIGN_FIXTURE not in response.content
    with db.transaction() as s:
        assert s.get(Transfer, item["id"]).state == "ALLOWED"               # nothing was consumed or delivered


def test_hosted_without_checkpoint_storage_refuses_new_transfers(system, tmp_path, credentials):
    settings = hosted_settings(system, tmp_path, checkpoint_root=None)
    with TestClient(create_app(settings), base_url=ORIGIN, raise_server_exceptions=False) as client:
        client.headers["origin"] = ORIGIN
        sign_in(client, credentials)
        response = fixture_transfer(client, "benign")
        assert response.status_code == 503 and BENIGN_FIXTURE not in response.content
        assert client.get("/health").json()["release_configured"] is False
