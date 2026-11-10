"""The audit transparency log end to end: signed tree heads, the release requirement, restart rebuild, tampering,
the API and its bounds, the signed evidence export and the key provisioning tool.

Proofs returned by the API are checked here with the functions in app.crypto.transparency, which
test_transparency_tree.py checks against an independent reference and the published vectors.
"""
import base64
from dataclasses import replace
import json
import logging
import os
import secrets
import sys

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError

import app.transparency as transparency_module
from app import audit_keys
from app.api import create_app
from app.audit import AuditService, KeyRing
from app.crypto import transparency as t
from app.errors import DomainError
from app.gateway_models import AuditEvent, AuditHead, Transfer, TransparencyHead
from app.transparency import STH_INTERVAL, SigningKeys

from .conftest import write_signing_key
from .test_gateway import BENIGN, PROTECTED, register, release, submit

LOCAL = "http://127.0.0.1:5173"


def signed_in(settings, credentials, name="admin"):
    client = TestClient(create_app(settings), base_url=LOCAL, raise_server_exceptions=False)
    client.__enter__()
    client.headers["origin"] = settings.origin
    result = client.post("/api/v1/auth/login", json={"username": name, "password": credentials[0]})
    assert result.status_code == 200, result.text
    client.headers["x-csrf-token"] = result.json()["csrf_token"]
    return client


def log_of(client):
    return client.app.state.gateway.audit.log


def stored(client):
    with client.app.state.db.transaction() as s:
        events = s.scalars(select(AuditEvent).order_by(AuditEvent.sequence)).all()
        heads = s.scalars(select(TransparencyHead).order_by(TransparencyHead.tree_size)).all()
    return events, heads


def reference_root(events, size):
    built = t.MerkleLog()
    for row in events[:size]:
        built.append(t.leaf_hash(t.event_leaf(row.canonical, row.mac)))
    return built.root().hex()


def head_is_valid(client, head):
    keys = {k["key_id"]: bytes.fromhex(k["public_key"]) for k in client.get("/api/v1/transparency/key").json()["keys"]}
    fields = {name: head[name] for name in t.STH_FIELDS}
    return head["key_id"] in keys and t.verify_head(keys[head["key_id"]], fields, bytes.fromhex(head["signature"]))


def fill(client, actor, count):
    audit = client.app.state.gateway.audit
    for i in range(count):
        with client.app.state.db.transaction() as s:
            audit.append(s, "AUDIT_VERIFIED", actor.id, revision=i)


def bypass_triggers(s, db, table):
    if db.engine.dialect.name == "sqlite":
        s.execute(text(f"DROP TRIGGER IF EXISTS immutable_{table}_update"))
        s.execute(text(f"DROP TRIGGER IF EXISTS immutable_{table}_delete"))
    else:
        s.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER immutable_{table}"))


# ---------------------------------------------------------------------------------------------- when heads are written
def test_a_head_is_signed_at_every_64th_event_and_matches_an_independent_tree(client, login, system):
    login(client)
    fill(client, system[2]["admin"], 2 * STH_INTERVAL + 5)
    events, heads = stored(client)
    assert [h.tree_size for h in heads] == [STH_INTERVAL, 2 * STH_INTERVAL]
    for head in heads:
        assert head.root_hash == reference_root(events, head.tree_size)
        assert head.log_id == events[0].stream_id and head.key_id == log_of(client).signing.active_id
        assert head_is_valid(client, client.get(f"/api/v1/transparency/sth/{head.tree_size}").json())
    assert client.get("/api/v1/transparency/sth").json()["tree_size"] == 2 * STH_INTERVAL


def test_every_release_writes_a_head_that_covers_its_own_event(client, login):
    login(client)
    assert client.get("/api/v1/transparency/sth").status_code == 404       # nothing signed yet
    item = submit(client).json()
    assert release(client, item["id"]).content == BENIGN
    events, heads = stored(client)
    started = [e for e in events if json.loads(e.canonical)["kind"] == "RELEASE_STARTED"]
    assert len(started) == 1 and [h.tree_size for h in heads] == [started[0].sequence]
    head = client.get("/api/v1/transparency/sth").json()
    assert head_is_valid(client, head) and head["root_hash"] == reference_root(events, head["tree_size"])
    proof = client.get("/api/v1/transparency/proof/inclusion", params={"leaf_index": started[0].sequence - 1, "tree_size": head["tree_size"]}).json()
    leaf = t.leaf_hash(t.event_leaf(started[0].canonical, started[0].mac))
    assert proof["leaf_hash"] == leaf.hex()
    assert t.verify_inclusion(leaf, proof["leaf_index"], proof["tree_size"], [bytes.fromhex(p) for p in proof["path"]], bytes.fromhex(head["root_hash"]))


def test_an_administrator_can_sign_on_demand_and_asking_twice_returns_the_same_head(client, login, system):
    login(client)
    assert client.post("/api/v1/transparency/sth").status_code == 409      # an empty log has no head
    fill(client, system[2]["admin"], 3)
    first = client.post("/api/v1/transparency/sth")
    assert first.status_code == 200 and first.json()["tree_size"] == 3 and head_is_valid(client, first.json())
    assert client.post("/api/v1/transparency/sth").json() == first.json()
    assert len(stored(client)[1]) == 1


# ---------------------------------------------------------------------------------------------- API and bounds
def test_proofs_from_the_api_verify_between_every_pair_of_stored_heads(client, login, system):
    login(client)
    fill(client, system[2]["admin"], 70)
    client.post("/api/v1/transparency/sth")
    fill(client, system[2]["admin"], 7)
    client.post("/api/v1/transparency/sth")
    events, heads = stored(client)
    assert [h.tree_size for h in heads] == [64, 70, 77]
    for older in heads:
        for newer in heads:
            if older.tree_size > newer.tree_size:
                continue
            proof = client.get("/api/v1/transparency/proof/consistency", params={"first": older.tree_size, "second": newer.tree_size}).json()
            assert t.verify_consistency(older.tree_size, newer.tree_size, bytes.fromhex(older.root_hash), bytes.fromhex(newer.root_hash),
                                        [bytes.fromhex(p) for p in proof["path"]])
    for index in (0, 1, 63, 64, 76):
        proof = client.get("/api/v1/transparency/proof/inclusion", params={"leaf_index": index, "tree_size": 77}).json()
        leaf = t.leaf_hash(t.event_leaf(events[index].canonical, events[index].mac))
        assert t.verify_inclusion(leaf, index, 77, [bytes.fromhex(p) for p in proof["path"]], bytes.fromhex(heads[-1].root_hash))


@pytest.mark.parametrize("route,params,status", [
    ("proof/inclusion", {"leaf_index": 5, "tree_size": 5}, 422),          # the index must be inside the tree
    ("proof/inclusion", {"leaf_index": -1, "tree_size": 5}, 422),
    ("proof/inclusion", {"leaf_index": 0, "tree_size": 0}, 422),
    ("proof/inclusion", {"leaf_index": 0, "tree_size": 20001}, 422),
    ("proof/inclusion", {"leaf_index": 20000, "tree_size": 20000}, 422),
    ("proof/inclusion", {"leaf_index": 0}, 422),
    ("proof/inclusion", {"leaf_index": "x", "tree_size": 5}, 422),
    ("proof/inclusion", {"leaf_index": 0, "tree_size": 11}, 404),         # larger than the log
    ("proof/inclusion", {"leaf_index": 0, "tree_size": 20000}, 404),
    ("proof/consistency", {"first": 6, "second": 5}, 422),
    ("proof/consistency", {"first": 0, "second": 5}, 422),
    ("proof/consistency", {"first": 1, "second": 20001}, 422),
    ("proof/consistency", {"first": 1}, 422),
    ("proof/consistency", {"first": 1, "second": 11}, 404),
    ("sth/0", {}, 422), ("sth/20001", {}, 422), ("sth/abc", {}, 422), ("sth/-1", {}, 422),
    ("sth/7", {}, 404),                                                    # no head was signed at this size
    ("proof/inclusion", {"leaf_index": 0, "tree_size": 10}, 200),
    ("proof/consistency", {"first": 10, "second": 10}, 200),
])
def test_every_parameter_is_bounded(client, login, system, route, params, status):
    login(client)
    fill(client, system[2]["admin"], 10)
    response = client.get("/api/v1/transparency/" + route, params=params)
    assert response.status_code == status, response.text
    if status != 200:
        assert response.json()["error"]["release_authorized"] is False


def test_the_key_route_shows_public_keys_only(client, login, system):
    login(client, "analyst")
    body = client.get("/api/v1/transparency/key")
    assert body.status_code == 200
    view = body.json()
    assert view["algorithm"] == "Ed25519" and [k["key_id"] for k in view["keys"]] == [view["active_key_id"]]
    assert t.key_id_for(bytes.fromhex(view["keys"][0]["public_key"])) == view["active_key_id"]
    secret = json.loads(system[0].transparency_key_file.read_text())["keys"][view["active_key_id"]]
    assert secret not in body.text and base64.b64decode(secret).hex() not in body.text
    assert client.post("/api/v1/transparency/sth").status_code == 403      # signing on demand is ADMIN only


# ---------------------------------------------------------------------------------------------- append-only table
def test_stored_heads_cannot_be_updated_or_deleted(client, login, system):
    login(client)
    fill(client, system[2]["admin"], 3)
    assert client.post("/api/v1/transparency/sth").status_code == 200
    for statement in ("UPDATE transparency_heads SET root_hash = :v", "UPDATE transparency_heads SET signature = :v",
                      "UPDATE transparency_heads SET tree_size = 2 WHERE :v = :v", "DELETE FROM transparency_heads WHERE :v = :v"):
        with pytest.raises((IntegrityError, DBAPIError)):
            with client.app.state.db.transaction() as s:
                s.execute(text(statement), {"v": "0" * 64})
    assert len(stored(client)[1]) == 1
    # A second head at the same size (a fork) cannot be inserted either.
    with pytest.raises((IntegrityError, DBAPIError)):
        with client.app.state.db.transaction() as s:
            s.execute(text("INSERT INTO transparency_heads (tree_size, log_id, root_hash, timestamp, key_id, signature) "
                           "SELECT tree_size, log_id, :v, timestamp, key_id, signature FROM transparency_heads"), {"v": "0" * 64})


# ---------------------------------------------------------------------------------------------- restart
def test_a_restart_rebuilds_the_same_tree_and_signs_the_unsigned_tail(system, credentials):
    first = signed_in(system[0], credentials)
    fill(first, system[2]["admin"], 70)
    before = log_of(first)
    root, proof = before.tree.root().hex(), before.inclusion(40, 70)
    assert [h.tree_size for h in stored(first)[1]] == [64]
    first.__exit__(None, None, None)

    second = signed_in(system[0], credentials)                       # a new process: nothing in memory
    try:
        after = log_of(second)
        assert after is not before and after.failure is None and after.loaded
        assert after.tree.size == 70 and after.tree.root().hex() == root and after.inclusion(40, 70) == proof
        heads = stored(second)[1]
        assert [h.tree_size for h in heads] == [64, 70]                # the tail was checked and signed at startup
        assert heads[-1].root_hash == root and head_is_valid(second, second.get("/api/v1/transparency/sth").json())
        item = submit(second).json()
        assert release(second, item["id"]).content == BENIGN           # and releases work
    finally:
        second.__exit__(None, None, None)


def refused_after_restart(system, credentials, caplog, expected_reason):
    with caplog.at_level(logging.ERROR, logger="rootsentinel.transparency"):
        client = signed_in(system[0], credentials)
    try:
        log = log_of(client)
        assert log.failure and expected_reason in log.failure
        messages = [r.getMessage() for r in caplog.records if r.name == "rootsentinel.transparency"]
        assert any("audit transparency log check failed" in m and "refused" in m for m in messages)
        response = submit(client)
        assert response.status_code == 503 and response.json()["error"]["code"] == "AUDIT_LOG_INVALID"
        assert client.post("/api/v1/transparency/sth").status_code == 503
        assert client.get("/api/v1/transparency/proof/inclusion", params={"leaf_index": 0, "tree_size": 1}).status_code == 503
        assert client.get("/health").status_code == 200                # the service stays up to be inspected
        return client
    except BaseException:
        client.__exit__(None, None, None)
        raise


def test_a_stored_event_altered_before_the_last_head_fails_closed_at_restart(system, credentials, caplog):
    first = signed_in(system[0], credentials)
    item = submit(first).json()
    fill(first, system[2]["admin"], 70)
    db = first.app.state.db
    with db.transaction() as s:
        row = s.scalar(select(AuditEvent).where(AuditEvent.sequence == 2))
        forged = row.canonical.replace('"kind":"SCAN_COMPLETED"', '"kind":"AUDIT_VERIFIED"')
        assert forged != row.canonical
        bypass_triggers(s, db, "audit_events")
        s.execute(text("UPDATE audit_events SET canonical = :c WHERE sequence = 2"), {"c": forged})
    first.__exit__(None, None, None)
    client = refused_after_restart(system, credentials, caplog, "does not match the stored events")
    try:
        response = release(client, item["id"])
        assert response.status_code == 503 and BENIGN not in response.content
    finally:
        client.__exit__(None, None, None)


@pytest.mark.parametrize("column,value", [("root_hash", "0" * 64), ("signature", "0" * 128), ("timestamp", "2020-01-01T00:00:00.000000Z"),
                                          ("key_id", "0" * 64)])
def test_an_altered_stored_head_fails_closed_at_restart(system, credentials, caplog, column, value):
    first = signed_in(system[0], credentials)
    fill(first, system[2]["admin"], 5)
    assert first.post("/api/v1/transparency/sth").status_code == 200
    db = first.app.state.db
    with db.transaction() as s:
        bypass_triggers(s, db, "transparency_heads")
        s.execute(text(f"UPDATE transparency_heads SET {column} = :v"), {"v": value})
    first.__exit__(None, None, None)
    if column == "key_id":
        # An unknown key id cannot be checked at all: refused, without declaring the stored log altered.
        client = signed_in(system[0], credentials)
        try:
            assert submit(client).status_code == 503 and log_of(client).tree.size == 0
        finally:
            client.__exit__(None, None, None)
        return
    refused_after_restart(system, credentials, caplog, "does not match the stored events").__exit__(None, None, None)


def truncate_events(db, keep, heads_too):
    with db.transaction() as s:
        bypass_triggers(s, db, "audit_events")
        mac = s.scalar(select(AuditEvent.mac).where(AuditEvent.sequence == keep))
        s.execute(text("DELETE FROM audit_events WHERE sequence > :k"), {"k": keep})
        s.execute(text("UPDATE audit_heads SET sequence = :k, mac = :m"), {"k": keep, "m": mac})
        if heads_too:
            bypass_triggers(s, db, "transparency_heads")
            s.execute(text("DELETE FROM transparency_heads WHERE tree_size > :k"), {"k": keep})


def test_truncating_the_events_behind_a_stored_head_fails_closed_at_restart(system, credentials, caplog):
    first = signed_in(system[0], credentials)
    fill(first, system[2]["admin"], 70)
    truncate_events(first.app.state.db, 60, heads_too=False)           # the head at 64 now covers events that are gone
    first.__exit__(None, None, None)
    refused_after_restart(system, credentials, caplog, "does not match the stored events").__exit__(None, None, None)


def test_a_rollback_that_also_removes_the_heads_is_detected_only_with_a_head_kept_outside(system, credentials):
    """The documented limit: a party with no earlier head cannot detect a rollback, a party holding one can."""
    first = signed_in(system[0], credentials)
    fill(first, system[2]["admin"], 70)
    kept = first.post("/api/v1/transparency/sth").json()                # a witness saves this head (size 70)
    truncate_events(first.app.state.db, 60, heads_too=True)            # roll the database back, heads included
    first.__exit__(None, None, None)

    second = signed_in(system[0], credentials)
    try:
        assert log_of(second).failure is None                           # the gateway itself has nothing to compare with
        fill(second, system[2]["admin"], 15)                            # the log grows again, differently, past size 70
        current = second.post("/api/v1/transparency/sth").json()
        assert current["tree_size"] > kept["tree_size"]
        proof = second.get("/api/v1/transparency/proof/consistency", params={"first": kept["tree_size"], "second": current["tree_size"]}).json()
        assert not t.verify_consistency(kept["tree_size"], current["tree_size"], bytes.fromhex(kept["root_hash"]),
                                        bytes.fromhex(current["root_hash"]), [bytes.fromhex(p) for p in proof["path"]])
    finally:
        second.__exit__(None, None, None)


def test_a_database_rolled_back_under_a_running_process_is_refused(client, login, system):
    login(client)
    item = submit(client).json()
    fill(client, system[2]["admin"], 10)
    truncate_events(client.app.state.db, 5, heads_too=True)
    response = release(client, item["id"])
    assert response.status_code == 503 and response.json()["error"]["code"] == "AUDIT_LOG_ROLLBACK"
    assert submit(client).status_code == 503


# ---------------------------------------------------------------------------------------------- release requirement
def test_without_a_signing_key_nothing_is_accepted_for_release(system, credentials):
    client = signed_in(replace(system[0], transparency_key_file=None), credentials)
    try:
        assert client.get("/health").json()["release_configured"] is False
        response = submit(client)
        assert response.status_code == 503 and response.json()["error"]["code"] == "TRANSPARENCY_KEY_UNAVAILABLE"
        assert not list(client.app.state.gateway.store.root.iterdir())
        assert client.get("/api/v1/transparency/key").status_code == 503
    finally:
        client.__exit__(None, None, None)


def test_release_is_refused_when_the_signing_key_disappears(client, login):
    login(client)
    item = submit(client).json()
    log = log_of(client)
    original = log.signing
    log.signing = SigningKeys.load(None)
    response = release(client, item["id"])
    assert response.status_code == 503 and response.json()["error"]["code"] == "TRANSPARENCY_KEY_UNAVAILABLE"
    assert BENIGN not in response.content
    assert client.get("/api/v1/transfers/" + item["id"]).json()["state"] == "ALLOWED"
    log.signing = original
    assert release(client, item["id"]).content == BENIGN


@pytest.mark.parametrize("fault", ["raises", "garbage", "other_key"])
def test_release_is_refused_when_signing_fails_and_nothing_is_left_half_done(client, login, monkeypatch, fault):
    login(client)
    item = submit(client).json()
    log = log_of(client)
    size_before, events_before = log.tree.size, len(stored(client)[0])

    def broken(seed, head):
        if fault == "raises":
            raise RuntimeError("synthetic signing failure")
        if fault == "garbage":
            return bytes(64)
        return t.sign_head(secrets.token_bytes(32), head)             # a valid signature, by a key that is not ours
    monkeypatch.setattr(transparency_module, "sign_head", broken)
    response = release(client, item["id"])
    assert response.status_code == 503 and BENIGN not in response.content
    assert response.json()["error"]["code"] == ("TRANSPARENCY_SIGNING_FAILED" if fault == "raises" else "TREE_HEAD_INVALID")
    # The whole transaction was undone: no event, no head, the transfer still ALLOWED, memory equal to the database.
    events, heads = stored(client)
    assert len(events) == events_before and heads == [] and log.tree.size == size_before
    assert client.get("/api/v1/transfers/" + item["id"]).json()["state"] == "ALLOWED"
    assert list(client.app.state.gateway.store.root.iterdir())           # the snapshot is still held
    monkeypatch.undo()
    assert release(client, item["id"]).content == BENIGN


def test_only_the_events_after_the_last_head_are_read_again_at_release(client, login, system):
    """The trade stated in the audit spec: events under a signed head are covered by its root, which the tree in
    memory reproduces. An edit there is caught at the next restart and by a full verify, not by this release."""
    login(client)
    fill(client, system[2]["admin"], 70)                                # a head at 64
    item = submit(client).json()                                        # events 71 to 73, after the head
    db = client.app.state.db
    with db.transaction() as s:
        bypass_triggers(s, db, "audit_events")
        s.execute(text("UPDATE audit_events SET mac = :m WHERE sequence = 72"), {"m": "0" * 64})
    refused = release(client, item["id"])
    assert refused.status_code == 503 and refused.json()["error"]["code"] == "AUDIT_VERIFICATION_FAILED"
    assert BENIGN not in refused.content


def test_an_edit_under_a_signed_head_is_caught_by_full_verify_and_at_restart(system, credentials, caplog):
    client = signed_in(system[0], credentials)
    fill(client, system[2]["admin"], 70)
    db = client.app.state.db
    with db.transaction() as s:
        bypass_triggers(s, db, "audit_events")
        s.execute(text("UPDATE audit_events SET mac = :m WHERE sequence = 10"), {"m": "0" * 64})
    verification = client.post("/api/v1/audit/verify")
    assert verification.status_code == 503 or verification.json()["valid"] is False
    client.__exit__(None, None, None)
    refused_after_restart(system, credentials, caplog, "does not match the stored events").__exit__(None, None, None)


# ---------------------------------------------------------------------------------------------- memory equals database
def test_a_failed_transaction_leaves_no_leaf_behind(client, login, system):
    login(client)
    fill(client, system[2]["admin"], 3)
    audit, db, log = client.app.state.gateway.audit, client.app.state.db, log_of(client)
    with pytest.raises(RuntimeError):
        with db.transaction() as s:
            audit.append(s, "AUDIT_VERIFIED", system[2]["admin"].id, revision=1)
            audit.append(s, "AUDIT_VERIFIED", system[2]["admin"].id, revision=2)
            assert log.tree.size == 5
            raise RuntimeError("synthetic failure before commit")
    assert log.tree.size == 3 and log.committed == 3 and len(log.macs) == 3
    fill(client, system[2]["admin"], 1)
    events, _ = stored(client)
    assert log.tree.size == 4 and log.tree.root().hex() == reference_root(events, 4)


def test_events_written_by_another_process_are_picked_up_and_checked(client, login, system):
    login(client)
    fill(client, system[2]["admin"], 2)
    settings, db, actors, _ = system
    other = AuditService(KeyRing.load(settings.audit_key_file), settings.checkpoint_root, SigningKeys.load(settings.transparency_key_file))
    for i in range(3):
        with db.transaction() as s:
            other.append(s, "AUDIT_VERIFIED", actors["admin"].id, revision=i)
    assert log_of(client).tree.size == 2                                # not seen yet
    item = submit(client).json()
    assert release(client, item["id"]).content == BENIGN
    events, heads = stored(client)
    assert log_of(client).tree.size == len(events) and heads[-1].root_hash == reference_root(events, heads[-1].tree_size)
    assert other.log.tree.size == 5 < len(events)                                     # the other instance is behind, and catches up
    with db.transaction() as s:
        other.synced(s)
    assert other.log.tree.root() == log_of(client).tree.root()


def test_an_event_with_a_bad_mac_from_another_process_is_refused_without_poisoning_the_log(client, login, system):
    login(client)
    fill(client, system[2]["admin"], 2)
    db = client.app.state.db
    with db.transaction() as s:
        head = s.get(AuditHead, 1)
        last = s.scalar(select(AuditEvent).where(AuditEvent.sequence == 2))
        forged = last.canonical.replace('"sequence":2', '"sequence":3').replace(last.id, "00000000-0000-4000-8000-000000000003")
        s.execute(text("INSERT INTO audit_events (id, stream_id, sequence, resource_id, canonical, mac) VALUES (:i, :s, 3, NULL, :c, :m)"),
                  {"i": "00000000-0000-4000-8000-000000000003", "s": head.stream_id, "c": forged, "m": "1" * 64})
        head.sequence, head.mac = 3, "1" * 64
    assert submit(client).status_code == 503
    assert log_of(client).failure is None and log_of(client).tree.size == 2


# ---------------------------------------------------------------------------------------------- evidence export
def test_the_evidence_export_verifies_offline_with_the_public_key_alone(client, login):
    login(client)
    register(client)
    item = submit(client, PROTECTED).json()
    exported = client.get("/api/v1/exports/incidents/" + item["incident_id"]).json()
    bundle = exported["transparency"]
    assert bundle["format"] == "rootsentinel-evidence-v1" and len(bundle["events"]) == len(exported["audit_references"]) >= 3
    public = bytes.fromhex(bundle["public_key"])
    head = bundle["sth"]
    assert bundle["key_id"] == head["key_id"] == t.key_id_for(public)
    assert t.verify_head(public, {name: head[name] for name in t.STH_FIELDS}, bytes.fromhex(head["signature"]))
    for entry in bundle["events"]:
        leaf = t.leaf_hash(t.event_leaf(entry["canonical"], entry["mac"]))
        assert entry["leaf_hash"] == leaf.hex() and entry["leaf_index"] == entry["sequence"] - 1 and entry["tree_size"] == head["tree_size"]
        assert t.verify_inclusion(leaf, entry["leaf_index"], head["tree_size"], [bytes.fromhex(p) for p in entry["path"]], bytes.fromhex(head["root_hash"]))
        assert json.loads(entry["canonical"])["resource_id"] == item["id"]
    # The head covers the export event itself, which was written by this request.
    events, _ = stored(client)
    assert head["tree_size"] == len(events) and json.loads(events[-1].canonical)["kind"] == "EVIDENCE_EXPORTED"
    assert PROTECTED not in json.dumps(exported).encode() and "transparency-key" not in json.dumps(exported)
    # A changed event no longer fits its proof.
    entry = bundle["events"][0]
    altered = t.leaf_hash(t.event_leaf(entry["canonical"].replace("TRANSFER_SUBMITTED", "AUDIT_VERIFIED"), entry["mac"]))
    assert not t.verify_inclusion(altered, entry["leaf_index"], head["tree_size"], [bytes.fromhex(p) for p in entry["path"]], bytes.fromhex(head["root_hash"]))


def test_the_export_without_a_signing_key_says_it_is_unsigned(system, credentials):
    settings, db, actors, _ = system
    from app.incidents import export_incident
    client = signed_in(settings, credentials)
    try:
        register(client)
        item = submit(client, PROTECTED).json()
        unsigned = AuditService(KeyRing.load(settings.audit_key_file), settings.checkpoint_root)
        with db.transaction() as s:
            result = export_incident(s, actors["admin"], item["incident_id"], unsigned)
        assert result["transparency"] is None and "not signed" in result["authentication"]
    finally:
        client.__exit__(None, None, None)


# ---------------------------------------------------------------------------------------------- key file and tool
def run_tool(monkeypatch, capsys, *arguments):
    monkeypatch.setattr(sys, "argv", ["app.audit_keys", *arguments])
    audit_keys.main()
    return capsys.readouterr().out


def test_the_tool_creates_a_private_key_file_and_prints_only_the_key_id_and_path(tmp_path, monkeypatch, capsys):
    path = tmp_path / "keys" / "transparency-key.json"
    out = run_tool(monkeypatch, capsys, "init-transparency", str(path))
    stored_file = json.loads(path.read_text(encoding="ascii"))
    key_id = stored_file["active_id"]
    seed = stored_file["keys"][key_id]
    assert stored_file["version"] == 1 and stored_file["algorithm"] == "Ed25519" and list(stored_file["keys"]) == [key_id]
    assert key_id == t.key_id_for(t.public_key_of(base64.b64decode(seed)))
    assert key_id in out and str(path) in out
    assert seed not in out and base64.b64decode(seed).hex() not in out
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600 and path.parent.stat().st_mode & 0o777 == 0o700
    keys = SigningKeys.load(path)
    assert keys.available and keys.active_id == key_id and "seeds" not in repr(keys)
    with pytest.raises(FileExistsError):
        run_tool(monkeypatch, capsys, "init-transparency", str(path))  # never overwrites
    assert json.loads(path.read_text(encoding="ascii")) == stored_file


def test_rotation_keeps_earlier_keys_so_older_heads_still_verify(system, credentials, monkeypatch, capsys):
    settings = system[0]
    path = settings.transparency_key_file.parent / "rotating" / "transparency-key.json"
    first_id = run_tool(monkeypatch, capsys, "init-transparency", str(path)).split("key_id:")[1].split()[0]
    rotating = replace(settings, transparency_key_file=path)
    client = signed_in(rotating, credentials)
    fill(client, system[2]["admin"], 4)
    old_head = client.post("/api/v1/transparency/sth").json()
    assert old_head["key_id"] == first_id
    client.__exit__(None, None, None)

    second_id = run_tool(monkeypatch, capsys, "rotate-transparency", str(path)).split("key_id:")[1].split()[0]
    assert second_id != first_id and set(json.loads(path.read_text())["keys"]) == {first_id, second_id}
    client = signed_in(rotating, credentials)                         # restart: the head signed by the old key still verifies
    try:
        assert log_of(client).failure is None
        view = client.get("/api/v1/transparency/key").json()
        assert view["active_key_id"] == second_id and {k["key_id"] for k in view["keys"]} == {first_id, second_id}
        fill(client, system[2]["admin"], 2)
        new_head = client.post("/api/v1/transparency/sth").json()
        assert new_head["key_id"] == second_id and head_is_valid(client, new_head)
        assert head_is_valid(client, client.get(f"/api/v1/transparency/sth/{old_head['tree_size']}").json())
    finally:
        client.__exit__(None, None, None)


@pytest.mark.parametrize("content", [
    "{not json", "[]", '{"version": 1}',
    json.dumps({"version": 2, "algorithm": "Ed25519", "active_id": "a", "keys": {"a": base64.b64encode(bytes(32)).decode()}}),
    json.dumps({"version": 1, "algorithm": "RSA", "active_id": "a", "keys": {"a": base64.b64encode(bytes(32)).decode()}}),
    json.dumps({"version": 1, "algorithm": "Ed25519", "active_id": "a", "keys": {}}),
    json.dumps({"version": 1, "algorithm": "Ed25519", "active_id": "a", "keys": {"a": base64.b64encode(bytes(32)).decode()}}),   # id is not the key hash
    json.dumps({"version": 1, "algorithm": "Ed25519", "active_id": "a", "keys": {"a": base64.b64encode(bytes(31)).decode()}}),
    json.dumps({"version": 1, "algorithm": "Ed25519", "active_id": "a", "keys": {"a": "not base64!"}}),
])
def test_a_malformed_key_file_is_refused_without_echoing_it(tmp_path, content):
    path = tmp_path / "transparency-key.json"
    path.write_text(content)
    path.chmod(0o600)
    with pytest.raises(DomainError) as error:
        SigningKeys.load(path)
    assert error.value.code == "TRANSPARENCY_KEY_UNAVAILABLE" and error.value.__cause__ is None


def test_an_active_id_that_is_not_in_the_file_is_refused(tmp_path):
    seed = secrets.token_bytes(32)
    path = write_signing_key(tmp_path / "transparency-key.json", [seed])
    value = json.loads(path.read_text())
    value["active_id"] = "0" * 64
    path.write_text(json.dumps(value))
    with pytest.raises(DomainError):
        SigningKeys.load(path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_key_file_readable_by_others_is_refused(tmp_path):
    path = write_signing_key(tmp_path / "transparency-key.json")
    path.chmod(0o644)
    with pytest.raises(DomainError):
        SigningKeys.load(path)


def test_the_key_file_setting_must_be_outside_runtime_storage(system):
    with pytest.raises(ValueError):
        replace(system[0], transparency_key_file=system[0].paths.runtime / "transparency-key.json")


def test_settings_read_the_key_file_from_the_environment(system, monkeypatch):
    settings = system[0]
    for key, value in {"ROOTSENTINEL_RUNTIME_ROOT": settings.paths.runtime, "ROOTSENTINEL_ARTIFACT_ROOT": settings.paths.artifacts,
                       "ROOTSENTINEL_MODE": "local", "ROOTSENTINEL_TRANSPARENCY_KEY_FILE": settings.transparency_key_file}.items():
        monkeypatch.setenv(key, str(value))
    from app.settings import Settings
    assert Settings.from_environment().transparency_key_file == settings.transparency_key_file
    monkeypatch.delenv("ROOTSENTINEL_TRANSPARENCY_KEY_FILE")
    assert Settings.from_environment().transparency_key_file is None


def test_the_log_is_bounded_like_the_audit_stream(client, login, system, monkeypatch):
    import app.audit as audit_module
    login(client)
    fill(client, system[2]["admin"], 3)
    monkeypatch.setattr(audit_module, "MAX_EVENTS", 3)
    with pytest.raises(DomainError) as error:
        fill(client, system[2]["admin"], 1)
    assert error.value.code == "AUDIT_CAPACITY" and log_of(client).tree.size == 3
    with client.app.state.db.transaction() as s:
        assert s.scalar(select(func.count()).select_from(AuditEvent)) == 3
        assert s.scalar(select(func.count()).select_from(Transfer)) == 0
