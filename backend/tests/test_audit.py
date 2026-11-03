from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import hmac
import json
from types import SimpleNamespace

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from app.audit import AuditService, EventPayload, KeyRing, ZERO, canonical, mac_for, verify_records
from app.audit_keys import provision
from app.db import uid
from app.errors import DomainError
from app.gateway_models import AuditEvent, AuditHead
from app.private_files import read_private


def records():
    # Reference construction independent of AuditService.append/mac_for.
    key = bytes(range(32)); stream = uid(); previous = ZERO; result = []
    for sequence in range(1, 4):
        body = {"schema_version": 1, "id": uid(), "stream_id": stream, "sequence": sequence,
            "timestamp": "2026-01-01T00:00:00.000000Z", "kind": "AUDIT_VERIFIED", "actor_id": None,
            "resource_id": None, "key_id": "reference", "previous_mac": previous, "details": {}}
        encoded = json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        raw = encoded.encode("ascii")
        previous = hmac.new(key, b"RootSentinelAudit\x00\x01" + len(raw).to_bytes(4, "big") + raw, sha256).hexdigest()
        result.append(SimpleNamespace(id=body["id"], stream_id=stream, sequence=sequence, resource_id=None, canonical=encoded, mac=previous))
    return result, KeyRing("reference", {"reference": key}), stream, previous


def test_reference_encoding():
    rows, keys, stream, tail = records()
    assert verify_records(rows, keys, stream, 3, tail)["valid"]
    assert mac_for(keys.key("reference"), rows[0].canonical) == rows[0].mac


@pytest.mark.parametrize("attack", ["content", "sequence", "reorder", "delete_middle", "previous", "mac", "key_id", "canonical", "wrong_key", "missing_key", "tail_checkpoint"])
def test_tamper_detection(attack):
    rows, keys, stream, tail = records(); checkpoint = None; sequence = 3
    body = json.loads(rows[1].canonical)
    if attack == "content": body["details"] = {"reason": "ALTERED"}
    elif attack == "sequence": body["sequence"] = 8
    elif attack == "previous": body["previous_mac"] = ZERO
    elif attack == "key_id": body["key_id"] = "unknown"
    if attack in {"content", "sequence", "previous", "key_id"}: rows[1].canonical = canonical(body)
    if attack == "reorder": rows.reverse()
    elif attack == "delete_middle": rows.pop(1)
    elif attack == "mac": rows[1].mac = ZERO
    elif attack == "canonical": rows[1].canonical += " "
    elif attack == "wrong_key": keys = KeyRing("reference", {"reference": b"X" * 32})
    elif attack == "missing_key": keys = KeyRing("reference", {})
    elif attack == "tail_checkpoint":
        checkpoint = {"stream_id": stream, "sequence": 3, "mac": tail}
        rows.pop(); sequence = 2; tail = rows[-1].mac
    result = verify_records(rows, keys, stream, sequence, tail, checkpoint)
    assert not result["valid"] and result["first_invalid_sequence"] is not None


def test_tail_without_checkpoint_limitation():
    rows, keys, stream, _ = records(); rows.pop()
    assert verify_records(rows, keys, stream, 2, rows[-1].mac)["valid"]


def test_key_rotation_and_historical_verification(system, tmp_path):
    settings, db, _, _ = system
    audit = AuditService(KeyRing.load(settings.audit_key_file), settings.checkpoint_root)
    with db.transaction() as s: audit.append(s, "AUDIT_VERIFIED")
    old = audit.keys.active_id
    new = provision(settings.audit_key_file, rotate=True)
    audit.keys = KeyRing.load(settings.audit_key_file)
    assert new != old and old in audit.keys.keys
    with db.transaction() as s:
        audit.append(s, "AUDIT_VERIFIED")
        assert audit.verify(s)["valid"]
    with pytest.raises(FileExistsError): provision(settings.audit_key_file)


def test_concurrent_appends_and_immutability(system):
    settings, db, _, _ = system
    audit = AuditService(KeyRing.load(settings.audit_key_file), settings.checkpoint_root)
    def append(_):
        with db.transaction() as s: audit.append(s, "AUDIT_VERIFIED")
    with ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(append, range(8)))
    with db.transaction() as s:
        assert audit.verify(s)["valid"]
        assert s.get(AuditHead, 1).sequence == 8
    for sql in ("DELETE FROM audit_events", "UPDATE audit_events SET mac = 'bad'"):
        with pytest.raises(DatabaseError), db.transaction() as s: s.execute(text(sql))


def test_checkpoint_detects_rewritten_database_head(system):
    settings, db, _, _ = system
    audit = AuditService(KeyRing.load(settings.audit_key_file), settings.checkpoint_root)
    with db.transaction() as s: audit.append(s, "AUDIT_VERIFIED")
    with db.transaction() as s: audit.retain_checkpoint(s)
    # A DB administrator can bypass triggers. The independent checkpoint remains.
    with db.transaction() as s:
        if db.engine.dialect.name == "sqlite":
            s.execute(text("DROP TRIGGER immutable_audit_events_delete"))
        else:
            s.execute(text("ALTER TABLE audit_events DISABLE TRIGGER immutable_audit_events"))
        s.execute(text("DELETE FROM audit_events"))
        head = s.get(AuditHead, 1); head.sequence = 0; head.mac = ZERO
    with db.transaction() as s: assert not audit.verify(s)["valid"]


def test_log_injection_is_not_event(system):
    settings, db, _, _ = system
    audit = AuditService(KeyRing.load(settings.audit_key_file), settings.checkpoint_root)
    with pytest.raises(ValueError), db.transaction() as s:
        audit.append(s, "AUDIT_VERIFIED", reason="ok\nforged-event")
    with db.transaction() as s: assert s.get(AuditHead, 1).sequence == 0


def test_private_symlink_and_hardlink(tmp_path):
    original = tmp_path / "data"; original.write_bytes(b"synthetic")
    link = tmp_path / "link"
    try: link.hardlink_to(original)
    except OSError: pytest.skip("Filesystem does not support hardlinks")
    with pytest.raises(DomainError): read_private(link, 100)
    link.unlink()
    try: link.symlink_to(original)
    except OSError: return  # Windows privilege restriction; POSIX CI covers symlinks.
    with pytest.raises(DomainError): read_private(link, 100)
