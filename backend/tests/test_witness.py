"""scripts/witness.py against a real local server (uvicorn on a loopback port, real HTTP), and offline bundles.

The witness shares no code with the application, so these tests also check the application's proofs and
signatures with a second, independent implementation.
"""
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import socket
import sys
import threading
import time

import pytest
from sqlalchemy import select, text
import uvicorn

from app import audit_keys
from app.api import create_app
from app.gateway_models import AuditEvent

from .test_transparency_log import bypass_triggers, truncate_events

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "witness.py"
spec = importlib.util.spec_from_file_location("witness_under_test", SCRIPT)
witness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(witness)


class Running:
    """The application served by uvicorn in a thread on a free loopback port."""
    def __init__(self, settings):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.settings = replace(settings, origin=self.url)
        self.app = create_app(self.settings)
        self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=self.port, log_level="error", access_log=False))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 30
        while not self.server.started:
            assert time.monotonic() < deadline and self.thread.is_alive(), "the test server did not start"
            time.sleep(0.02)
        return self

    def __exit__(self, *_):
        self.server.should_exit = True
        self.thread.join(timeout=30)

    def fill(self, actor, count):
        audit = self.app.state.gateway.audit
        for i in range(count):
            with self.app.state.db.transaction() as s:
                audit.append(s, "AUDIT_VERIFIED", actor.id, revision=i)

    def sign(self):
        with self.app.state.db.transaction() as s:
            return self.app.state.gateway.audit.sign_head(s)


@pytest.fixture
def files(system, credentials, tmp_path, monkeypatch, capsys):
    """The witness's own files: the pinned public key (from the operator tool), its state and a password file."""
    monkeypatch.setattr(sys, "argv", ["app.audit_keys", "public-transparency", str(system[0].transparency_key_file)])
    audit_keys.main()
    out = capsys.readouterr().out
    secret = json.loads(system[0].transparency_key_file.read_text())
    assert all(seed not in out for seed in secret["keys"].values())      # the tool prints public keys only
    public = tmp_path / "pinned-keys.txt"
    public.write_text(out, encoding="ascii")
    password = tmp_path / "witness-password"
    password.write_text(credentials[0] + "\n", encoding="utf-8")
    return {"public": public, "state": tmp_path / "witness-state.json", "password": password}


def run(server, files, capsys, username="analyst"):
    code = witness.main(["check", "--base-url", server.url, "--public-key", str(files["public"]), "--state", str(files["state"]),
                         "--username", username, "--password-file", str(files["password"])])
    captured = capsys.readouterr()
    return code, captured.out + captured.err


def test_the_witness_follows_a_growing_log_over_real_http(system, credentials, files, capsys):
    admin = system[2]["admin"]
    with Running(system[0]) as server:
        server.fill(admin, 5)
        first = server.sign()
        code, out = run(server, files, capsys)
        assert code == 0 and "first head accepted: size 5" in out
        assert json.loads(files["state"].read_text()) == first
        assert credentials[0] not in out and "rs_session" not in out

        code, out = run(server, files, capsys)
        assert code == 0 and "unchanged: size 5" in out

        server.fill(admin, 70)                                           # crosses a 64-event head
        latest = server.sign()
        code, out = run(server, files, capsys)
        assert code == 0 and "consistent: the log grew from size 5 to 75" in out
        assert json.loads(files["state"].read_text()) == latest


def test_the_witness_detects_a_rollback_and_keeps_its_saved_head(system, files, capsys):
    admin = system[2]["admin"]
    with Running(system[0]) as server:
        server.fill(admin, 70)
        server.sign()
        assert run(server, files, capsys)[0] == 0
        saved = files["state"].read_text()
        truncate_events(server.app.state.db, 60, heads_too=True)         # the database is rolled back, heads included
    with Running(system[0]) as server:                                   # the gateway restarts and notices nothing
        assert server.app.state.gateway.audit.log.failure is None
        server.fill(admin, 3)
        server.sign()
        code, out = run(server, files, capsys)
        assert code == 1 and "rollback" in out and files["state"].read_text() == saved
        server.fill(admin, 20)                                           # the log grows past the saved size again
        server.sign()
        code, out = run(server, files, capsys)
        assert code == 1 and "history was rewritten" in out and files["state"].read_text() == saved


def test_the_witness_rejects_a_head_signed_by_an_unpinned_key(system, files, capsys, tmp_path):
    with Running(system[0]) as server:
        server.fill(system[2]["admin"], 3)
        server.sign()
        other = tmp_path / "other" / "transparency-key.json"
        audit_keys.provision_signing(other)
        from app.transparency import SigningKeys
        files["public"].write_text("# another gateway's key\n" + next(iter(SigningKeys.load(other).public.values())).hex() + "\n", encoding="ascii")
        code, out = run(server, files, capsys)
        assert code == 1 and "not pinned" in out and not files["state"].exists()


def test_the_witness_reports_what_it_could_not_do_without_guessing(system, files, capsys, tmp_path):
    with Running(system[0]) as server:
        code, out = run(server, files, capsys)                           # no head has been signed yet
        assert code == 2 and "HTTP 404" in out and not files["state"].exists()
        server.fill(system[2]["admin"], 3)
        server.sign()
        assert run(server, files, capsys, username="employee") == (2, "ERROR GET /api/v1/transparency/sth answered HTTP 403\n")
        files["password"].write_text("wrong-password-value\n", encoding="utf-8")
        code, out = run(server, files, capsys)
        assert code == 2 and "sign-in was refused" in out and "wrong-password-value" not in out
    assert witness.main(["check", "--base-url", "http://192.0.2.1:9", "--public-key", str(files["public"]), "--state", str(files["state"]),
                         "--username", "analyst", "--password-file", str(files["password"])]) == 2
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n", encoding="ascii")
    assert witness.main(["bundle", "--public-key", str(empty), str(empty)]) == 2
    empty.write_text("not-hex\n", encoding="ascii")
    assert witness.main(["bundle", "--public-key", str(empty), str(empty)]) == 2
    assert witness.main(["bundle", "--public-key", str(tmp_path / "missing.txt"), str(empty)]) == 2
    capsys.readouterr()


# ---------------------------------------------------------------------------------------------- decisions, no network
def test_a_fork_another_log_and_a_tampered_state_are_rejected(system, files, capsys):
    with Running(system[0]) as server:
        server.fill(system[2]["admin"], 6)
        head = server.sign()
        assert run(server, files, capsys)[0] == 0
    keys = witness.load_pinned_keys(files["public"])
    assert witness.checked_head(head, keys) == head
    proof = lambda first, second: pytest.fail("no proof is needed for these cases")
    with pytest.raises(witness.Rejected, match="fork"):
        witness.advance({**head, "root_hash": "0" * 64}, head, proof)
    with pytest.raises(witness.Rejected, match="different log"):
        witness.advance({**head, "log_id": "another"}, head, proof)
    with pytest.raises(witness.Rejected, match="rollback"):
        witness.advance({**head, "tree_size": head["tree_size"] + 1}, head, proof)
    with pytest.raises(witness.Rejected, match="other tree sizes"):
        witness.advance({**head, "tree_size": 2}, head, lambda first, second: {"first": 1, "second": second, "path": []})
    with pytest.raises(witness.Rejected, match="rewritten"):
        witness.advance({**head, "tree_size": 2, "root_hash": "0" * 64}, head, lambda first, second: {"first": first, "second": second, "path": ["0" * 64]})
    for change in ({"tree_size": head["tree_size"] + 1}, {"root_hash": "1" * 64}, {"timestamp": "2020-01-01T00:00:00.000000Z"},
                   {"signature": "0" * 128}, {"signature": "zz"}, {"tree_size": 0}, {"tree_size": "6"}, {"key_id": "0" * 64}, {"extra": 1}):
        with pytest.raises(witness.Rejected):
            witness.checked_head({**head, **change}, keys)
    for path in (None, ["zz"], ["00"], [1], ["0" * 64] * 65):
        with pytest.raises(witness.Rejected):
            witness.hex_path(path)
    # A state file that was edited is refused and never silently replaced.
    state = json.loads(files["state"].read_text())
    files["state"].write_text(json.dumps({**state, "tree_size": 2}), encoding="ascii")
    with pytest.raises(witness.Rejected, match="no longer verifies"):
        witness.load_state(files["state"], keys)
    files["state"].write_text("{not json", encoding="ascii")
    with pytest.raises(witness.Rejected, match="unreadable"):
        witness.load_state(files["state"], keys)


def test_the_witness_proof_checks_agree_with_the_published_vectors():
    roots = ["6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
             None, None, "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
             "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef", None,
             "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"]
    h = bytes.fromhex
    path_1_of_8 = [h("96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7"), h("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"),
                   h("6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4")]
    six_to_eight = [h("0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a"), h("ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0"),
                    h("d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7")]
    two_to_five = [h("5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e"), h("bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b")]
    assert witness.verify_inclusion(h(roots[0]), 0, 8, path_1_of_8, h(roots[7]))
    assert not witness.verify_inclusion(h(roots[0]), 1, 8, path_1_of_8, h(roots[7]))
    assert witness.verify_consistency(1, 8, h(roots[0]), h(roots[7]), path_1_of_8)
    assert witness.verify_consistency(6, 8, h(roots[5]), h(roots[7]), six_to_eight)
    assert witness.verify_consistency(2, 5, h(roots[1]), h(roots[4]), two_to_five)
    assert not witness.verify_consistency(2, 5, h(roots[1]), h(roots[7]), two_to_five)
    assert not witness.verify_consistency(6, 8, h(roots[5]), h(roots[7]), six_to_eight[:2])
    assert witness.verify_consistency(8, 8, h(roots[7]), h(roots[7]), []) and not witness.verify_consistency(0, 8, h(roots[0]), h(roots[7]), [])


# ---------------------------------------------------------------------------------------------- evidence bundle, offline
def exported_bundle(client, login):
    from .test_gateway import PROTECTED, register, submit
    login(client)
    register(client)
    item = submit(client, PROTECTED).json()
    return client.get("/api/v1/exports/incidents/" + item["incident_id"]).json()


def test_an_exported_bundle_verifies_offline_and_every_change_is_caught(client, login, files, tmp_path, capsys):
    export = exported_bundle(client, login)
    path = tmp_path / "export.json"
    path.write_text(json.dumps(export), encoding="utf-8")
    assert witness.main(["bundle", "--public-key", str(files["public"]), str(path)]) == 0
    assert "bundle verified" in capsys.readouterr().out
    keys = witness.load_pinned_keys(files["public"])
    assert "event(s) are in the tree" in witness.verify_bundle(export["transparency"], keys)       # the section alone works too

    def changed(mutate):
        copy = json.loads(json.dumps(export))
        mutate(copy["transparency"])
        return copy

    cases = {
        "an edited event": lambda b: b["events"][0].update(canonical=b["events"][0]["canonical"].replace("TRANSFER_SUBMITTED", "AUDIT_VERIFIED")),
        "an edited MAC": lambda b: b["events"][0].update(mac="0" * 64),
        "a swapped sequence": lambda b: b["events"][0].update(sequence=b["events"][1]["sequence"]),
        "a shortened proof": lambda b: b["events"][-1].update(path=b["events"][-1]["path"][:-1]),
        "another root": lambda b: b["sth"].update(root_hash="0" * 64),
        "another size": lambda b: b["sth"].update(tree_size=b["sth"]["tree_size"] + 1),
        "a forged signature": lambda b: b["sth"].update(signature="0" * 128),
        "another key id": lambda b: b.update(key_id="0" * 64),
        "no events": lambda b: b.update(events=[]),
        "another format": lambda b: b.update(format="something-else"),
    }
    for name, mutate in cases.items():
        with pytest.raises(witness.Rejected):
            witness.verify_bundle(changed(mutate), keys)
            pytest.fail(name + " was accepted")
    # The key printed inside the bundle is never trusted: with a different pinned key the same bundle is refused.
    other = tmp_path / "other" / "transparency-key.json"
    audit_keys.provision_signing(other)
    from app.transparency import SigningKeys
    unpinned = tmp_path / "unpinned.txt"
    unpinned.write_text(next(iter(SigningKeys.load(other).public.values())).hex() + "\n", encoding="ascii")
    assert witness.main(["bundle", "--public-key", str(unpinned), str(path)]) == 1
    path.write_text(json.dumps({"schema_version": 1, "transparency": None}), encoding="utf-8")
    assert witness.main(["bundle", "--public-key", str(files["public"]), str(path)]) == 1
    path.write_text("{not json", encoding="utf-8")
    assert witness.main(["bundle", "--public-key", str(files["public"]), str(path)]) == 2
    capsys.readouterr()


def test_an_event_edited_in_the_database_cannot_be_exported_as_included(system, credentials, files, capsys):
    """The export reads events from the database and proofs from the tree: an edited row no longer fits."""
    from fastapi.testclient import TestClient
    from .test_gateway import PROTECTED, register, submit
    with TestClient(create_app(system[0]), base_url="http://127.0.0.1:5173", raise_server_exceptions=False) as client:
        client.headers["origin"] = system[0].origin
        result = client.post("/api/v1/auth/login", json={"username": "admin", "password": credentials[0]})
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        register(client)
        item = submit(client, PROTECTED).json()
        db = client.app.state.db
        with db.transaction() as s:
            row = s.scalar(select(AuditEvent).where(AuditEvent.resource_id == item["id"]).order_by(AuditEvent.sequence).limit(1))
            forged = row.canonical.replace('"kind":"TRANSFER_SUBMITTED"', '"kind":"AUDIT_VERIFIED"')
            bypass_triggers(s, db, "audit_events")
            s.execute(text("UPDATE audit_events SET canonical = :c WHERE sequence = :q"), {"c": forged, "q": row.sequence})
        export = client.get("/api/v1/exports/incidents/" + item["incident_id"])
        if export.status_code == 200:
            with pytest.raises(witness.Rejected, match="not in the signed tree"):
                witness.verify_bundle(export.json(), witness.load_pinned_keys(files["public"]))
        else:
            assert export.status_code == 503
