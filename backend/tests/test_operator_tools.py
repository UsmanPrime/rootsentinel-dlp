"""Operator command lines: account bootstrap (app.cli) and audit key provisioning (app.audit_keys).

Both take secrets only through hidden prompts or generate them, and must never print secret material.
"""
import base64
import json
import os
import sys

import pytest
from sqlalchemy import select

from app import audit_keys, cli
from app.auth import HASHER
from app.db import Database
from app.models import SessionRecord, User

GOOD_PASSWORD = "correct-horse-battery-1"


@pytest.fixture
def local_environment(system, monkeypatch):
    settings = system[0]
    monkeypatch.setenv("ROOTSENTINEL_MODE", "local")
    monkeypatch.setenv("ROOTSENTINEL_ORIGIN", "http://127.0.0.1:5173")
    monkeypatch.setenv("ROOTSENTINEL_SECURE_COOKIES", "false")
    monkeypatch.setenv("ROOTSENTINEL_RUNTIME_ROOT", str(settings.paths.runtime))
    monkeypatch.setenv("ROOTSENTINEL_ARTIFACT_ROOT", str(settings.paths.artifacts))
    monkeypatch.setenv("ROOTSENTINEL_DATABASE_URL", settings.database_url)
    return settings


def run_cli(monkeypatch, *argv, answers=(GOOD_PASSWORD, GOOD_PASSWORD)):
    prompts = iter(answers)
    monkeypatch.setattr(sys, "argv", ["app.cli", *argv])
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": next(prompts))
    cli.main()


def user(settings, name):
    db = Database(settings.database_url)
    try:
        with db.transaction() as s:
            row = s.scalar(select(User).where(User.username == name))
            return (row.role, row.password_hash, row.id) if row else None
    finally:
        db.engine.dispose()


def test_create_user_hashes_the_prompted_password_and_prints_nothing_secret(local_environment, monkeypatch, capsys):
    run_cli(monkeypatch, "create-user", "operator-one", "--role", "ANALYST")
    role, password_hash, _ = user(local_environment, "operator-one")
    assert role == "ANALYST" and HASHER.verify(password_hash, GOOD_PASSWORD)
    out = capsys.readouterr()
    assert GOOD_PASSWORD not in out.out + out.err and password_hash not in out.out + out.err
    assert "No credentials were printed" in out.out


def test_create_user_defaults_to_the_least_privileged_role(local_environment, monkeypatch):
    run_cli(monkeypatch, "create-user", "operator-two")
    assert user(local_environment, "operator-two")[0] == "EMPLOYEE"


@pytest.mark.parametrize("answers", [("short", "short"), (GOOD_PASSWORD, GOOD_PASSWORD + "x"), ("x" * 129, "x" * 129)])
def test_weak_or_unconfirmed_passwords_are_refused(local_environment, monkeypatch, answers):
    with pytest.raises(SystemExit) as exit_info:
        run_cli(monkeypatch, "create-user", "operator-three", answers=answers)
    assert exit_info.value.code == 2 and user(local_environment, "operator-three") is None


def test_existing_users_are_never_overwritten(local_environment, monkeypatch):
    before = user(local_environment, "admin")
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "create-user", "admin", "--role", "EMPLOYEE")
    assert user(local_environment, "admin") == before


def test_reset_password_changes_the_hash_and_revokes_sessions(local_environment, monkeypatch, client, login):
    login(client, "analyst")
    assert client.get("/api/v1/auth/me").status_code == 200
    run_cli(monkeypatch, "reset-password", "analyst", answers=(GOOD_PASSWORD, GOOD_PASSWORD))
    assert HASHER.verify(user(local_environment, "analyst")[1], GOOD_PASSWORD)
    assert client.get("/api/v1/auth/me").status_code == 401


def test_revoke_sessions_needs_no_password_and_ends_every_session(local_environment, monkeypatch, client, login):
    login(client, "employee")
    run_cli(monkeypatch, "revoke-sessions", "employee", answers=())
    assert client.get("/api/v1/auth/me").status_code == 401
    db = Database(local_environment.database_url)
    try:
        with db.transaction() as s:
            employee_id = user(local_environment, "employee")[2]
            open_sessions = s.scalars(select(SessionRecord).where(SessionRecord.user_id == employee_id, SessionRecord.revoked_at.is_(None))).all()
        assert open_sessions == []
    finally:
        db.engine.dispose()


def test_unknown_users_and_invalid_names_are_refused(local_environment, monkeypatch):
    with pytest.raises(SystemExit):
        run_cli(monkeypatch, "revoke-sessions", "nobody-here", answers=())
    with pytest.raises(Exception):
        run_cli(monkeypatch, "create-user", "Not A Valid Name")


def test_the_cli_refuses_to_run_outside_local_mode(local_environment, monkeypatch):
    monkeypatch.setenv("ROOTSENTINEL_MODE", "public_demo")
    monkeypatch.setenv("ROOTSENTINEL_SECURE_COOKIES", "true")
    with pytest.raises(SystemExit) as exit_info:
        run_cli(monkeypatch, "create-user", "operator-four")
    assert exit_info.value.code == 2


# ---------------------------------------------------------------------------------------------- audit keys
def test_init_creates_a_private_keyring_and_prints_only_the_identifier(tmp_path, monkeypatch, capsys):
    path = tmp_path / "keys" / "audit-keys.json"
    monkeypatch.setattr(sys, "argv", ["app.audit_keys", "init", str(path)])
    audit_keys.main()
    ring = json.loads(path.read_text(encoding="ascii"))
    assert ring["version"] == 1 and list(ring["keys"]) == [ring["active_id"]]
    assert len(base64.b64decode(ring["keys"][ring["active_id"]])) == 32
    out = capsys.readouterr().out
    assert ring["active_id"] in out and ring["keys"][ring["active_id"]] not in out
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0


def test_init_never_overwrites_an_existing_keyring(tmp_path):
    path = tmp_path / "keys" / "audit-keys.json"
    audit_keys.provision(path)
    original = path.read_bytes()
    with pytest.raises(Exception):
        audit_keys.provision(path)
    assert path.read_bytes() == original


def test_rotation_keeps_old_keys_for_verification_and_activates_a_new_one(tmp_path):
    path = tmp_path / "keys" / "audit-keys.json"
    first = audit_keys.provision(path)
    second = audit_keys.provision(path, rotate=True)
    ring = json.loads(path.read_text(encoding="ascii"))
    assert first != second and ring["active_id"] == second and set(ring["keys"]) == {first, second}
    assert not list(path.parent.glob("key-rotation-*.tmp"))


def test_rotation_stops_at_the_retention_capacity(tmp_path):
    path = tmp_path / "keys" / "audit-keys.json"
    audit_keys.provision(path)
    for _ in range(31):
        audit_keys.provision(path, rotate=True)
    before = path.read_bytes()
    with pytest.raises(ValueError):
        audit_keys.provision(path, rotate=True)
    assert path.read_bytes() == before
