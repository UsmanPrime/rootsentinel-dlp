"""The ADMIN register tool against a scripted fake client: retries, duplicates, failures and exit codes.

The real-gateway behaviour is covered in test_cli_ready_register.py; these tests reach the branches a healthy
gateway never takes (capacity retries, unexpected codes, an unreachable gateway, a non-ADMIN account).
"""
from pathlib import Path

import pytest

from rootsentinel_agent import register
from rootsentinel_agent.client import ApiError, ProtocolViolation, Unavailable


class ScriptedClient:
    def __init__(self, outcomes, role="ADMIN"):
        self.outcomes, self.role, self.calls, self.logged_out = list(outcomes), role, [], False

    def login(self, username, password):
        return {"role": self.role, "username": username}

    def logout(self):
        self.logged_out = True

    def register_asset(self, label, data):
        self.calls.append(label)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return {"label": label}


def folder_with(tmp_path, names):
    folder = tmp_path / "corpus"
    folder.mkdir()
    for name in names:
        (folder / name).write_bytes(b"synthetic " + name.encode())
    return folder


def test_capacity_answers_are_retried_and_other_outcomes_are_counted(tmp_path):
    folder = folder_with(tmp_path, ["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"])
    client = ScriptedClient([
        ApiError(503, "SCAN_CAPACITY"), ApiError(503, "LOGIN_CAPACITY"), {"ok": 1},     # a.txt: two retries, then registered
        ApiError(409, "DUPLICATE_ASSET_LABEL"),                                          # b.txt: already registered
        ApiError(422, "EMPTY_PROTECTED_ASSET"),                                          # c.txt: refused
        Unavailable("timeout"),                                                          # d.txt: gateway unreachable
        ProtocolViolation("bad body"),                                                   # e.txt: malformed answer
    ])
    sleeps = []
    summary = register.register_folder(client, folder, sleep=sleeps.append)
    assert (summary["registered"], summary["existing"], summary["failed"]) == (1, 1, 3)
    assert sleeps == [1.0, 1.0]
    outcomes = {item["label"]: item["outcome"] for item in summary["items"]}
    assert outcomes == {"a.txt": "registered", "b.txt": "existing", "c.txt": "failed:EMPTY_PROTECTED_ASSET",
                        "d.txt": "failed:UNAVAILABLE", "e.txt": "failed:UNAVAILABLE"}


def test_capacity_retries_are_bounded(tmp_path):
    folder = folder_with(tmp_path, ["only.txt"])
    client = ScriptedClient([ApiError(503, "SCAN_CAPACITY")] * 30)
    summary = register.register_folder(client, folder, sleep=lambda _: None)
    assert summary["failed"] == 1 and len(client.calls) == 30


def test_colliding_labels_get_numbered_suffixes(tmp_path):
    folder = tmp_path / "corpus"
    (folder / "x").mkdir(parents=True)
    (folder / "x_y.txt").write_bytes(b"one")
    (folder / "x" / "y.txt").write_bytes(b"two")                                         # also sanitizes to x_y.txt
    labels = [label for label, _ in register.collect_files(folder)]
    assert len(labels) == 2 and len({label.lower() for label in labels}) == 2


def test_empty_files_are_skipped(tmp_path):
    folder = folder_with(tmp_path, ["kept.txt"])
    (folder / "empty.txt").write_bytes(b"")
    assert [label for label, _ in register.collect_files(folder)] == ["kept.txt"]


@pytest.fixture
def scripted(monkeypatch):
    holder = {}

    def factory(outcomes, role="ADMIN"):
        client = ScriptedClient(outcomes, role)
        holder["client"] = client
        monkeypatch.setattr(register, "GatewayClient", lambda base_url, origin: client)
        monkeypatch.setattr(register.getpass, "getpass", lambda prompt="": "not-printed-password")
        monkeypatch.setattr(register, "check_location", lambda path, name: None)
        return client
    return factory


def test_main_succeeds_and_reports_without_the_password(tmp_path, scripted, capsys):
    folder = folder_with(tmp_path, ["a.txt"])
    client = scripted([{"ok": 1}])
    assert register.main(["--username", "admin", "--folder", str(folder)]) == 0
    out = capsys.readouterr()
    assert "registered=1 existing=0 failed=0" in out.out and client.logged_out
    assert "not-printed-password" not in out.out + out.err


def test_main_exit_code_is_one_when_any_registration_fails(tmp_path, scripted):
    folder = folder_with(tmp_path, ["a.txt"])
    scripted([ApiError(422, "EMPTY_PROTECTED_ASSET")])
    assert register.main(["--username", "admin", "--folder", str(folder)]) == 1


def test_main_refuses_a_non_admin_account(tmp_path, scripted, capsys):
    folder = folder_with(tmp_path, ["a.txt"])
    client = scripted([{"ok": 1}], role="ANALYST")
    assert register.main(["--username", "analyst", "--folder", str(folder)]) == 2
    assert client.calls == [] and "role ADMIN" in capsys.readouterr().err


def test_main_stops_cleanly_when_the_gateway_is_unreachable(tmp_path, monkeypatch, capsys):
    folder = folder_with(tmp_path, ["a.txt"])
    monkeypatch.setattr(register, "check_location", lambda path, name: None)
    monkeypatch.setattr(register.getpass, "getpass", lambda prompt="": "pw")

    class Down:
        def __init__(self, *args):
            pass

        def login(self, *args):
            raise Unavailable("connection")
    monkeypatch.setattr(register, "GatewayClient", Down)
    assert register.main(["--username", "admin", "--folder", str(folder)]) == 2
    assert "registration stopped: Unavailable" in capsys.readouterr().err
