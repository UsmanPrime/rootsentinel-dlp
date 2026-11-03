from dataclasses import replace
from pathlib import Path
import sys
from uuid import uuid4
import base64
import zlib

import pytest
from sqlalchemy import event, select

from app.crypto import fingerprint_bytes
from app.detection import detect
from app.errors import DomainError, Indeterminate
from app.intake import FrozenInput
from app.models import PolicyVersion, RegistryState
from app.policy import active_policy, change_policy, evaluate, policy_view
from app.registry import register, retire, version_view
from app.scans import get_scan, run_scan
from app.schemas import PolicyInput

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from fixtures import synthetic_inputs


def registered(system, payload=None, label="Synthetic IP"):
    _, db, actors, _ = system
    with db.transaction() as s:
        return register(s, actors["admin"], label, synthetic_inputs()["protected"] if payload is None else payload)


def scan(system, payload, filename="candidate.txt"):
    _, db, actors, _ = system
    with db.transaction() as s:
        return run_scan(s, actors["employee"], filename, FrozenInput(str(uuid4()), payload))


@pytest.mark.parametrize("fixture,outcome,matched,exact", [
    ("protected", "BLOCK", 8192, True), ("renamed", "BLOCK", 8192, True),
    ("benign", "ALLOW", 0, False), ("empty", "ALLOW", 0, False),
    ("single_byte_change", "BLOCK", 7168, False), ("aligned_partial", "BLOCK", 2048, False),
    ("aligned_embedding", "BLOCK", 8192, False), ("shifted", "ALLOW", 0, False),
    ("crlf", "ALLOW", 0, False), ("utf16", "ALLOW", 0, False), ("small", "ALLOW", 0, False),
])
def test_synthetic_evaluation_matrix(system, fixture, outcome, matched, exact):
    version = registered(system)
    payload = synthetic_inputs()[fixture]
    result = scan(system, payload, "renamed.txt")
    assert result.decision.outcome == outcome
    assert result.release_authorized is False
    assert result.detection.registry_revision == 1
    evidence = result.detection.matches
    assert sum(m.matched_bytes for m in evidence) == matched
    if matched:
        assert evidence[0].version_id == version.id
        assert evidence[0].exact is exact
        assert evidence[0].coverage.denominator == len(payload)
        assert evidence[0].coverage.numerator == matched
    with system[1].transaction() as s:
        assert get_scan(s, system[2]["employee"], result.id) == result


@pytest.mark.parametrize("size", [1, 1023, 1024, 1025, 10485760])
def test_exact_sizes_and_boundary(system, size):
    payload = b"A" * size
    registered(system, payload)
    result = scan(system, payload)
    assert result.decision.reason == "EXACT_PROTECTED_FILE"
    assert result.detection.matches[0].matched_bytes == size


def test_empty_registry_registration_rejected(system):
    with pytest.raises(DomainError, match="EMPTY_PROTECTED_ASSET"):
        registered(system, b"")
    with system[1].transaction() as s:
        assert s.get(RegistryState, 1).revision == 0


def test_one_byte_modification_and_small_tail(system):
    registered(system, b"A" * 1024)
    assert scan(system, b"B" + b"A" * 1023).decision.outcome == "ALLOW"
    assert scan(system, b"A" * 1024 + b"Z").detection.matches[0].matched_bytes == 1024
    assert scan(system, b"A" * 1023).decision.outcome == "ALLOW"


@pytest.mark.parametrize("transform", [zlib.compress, base64.b64encode])
def test_opaque_transforms_are_documented_misses(system, transform):
    protected = synthetic_inputs()["protected"]
    registered(system, protected)
    result = scan(system, transform(protected))
    assert result.decision.outcome == "ALLOW"
    assert not result.detection.matches


def test_repetition_and_shared_assets_no_overcount(system):
    registered(system, b"A" * 3072, "First")
    registered(system, b"A" * 2048 + b"B" * 1024, "Second")
    result = scan(system, b"A" * 2048 + b"C" * 1024)
    assert len(result.detection.matches) == 2
    for match in result.detection.matches:
        assert match.matched_bytes == 2048
        assert match.intervals == [(0, 1024), (1024, 2048)]
        assert match.blocks[0].outbound_indices == [0, 1]
    assert sorted(len(m.blocks[0].source_indices) for m in result.detection.matches) == [2, 3]


def test_small_matching_tail_below_threshold(system):
    registered(system, b"A" * 1024 + b"tiny")
    result = scan(system, b"tiny")
    assert result.detection.matches[0].matched_bytes == 4
    assert result.decision.outcome == "ALLOW"


def test_versions_retirement_and_historical_decisions(system):
    first = registered(system, b"A" * 1024)
    before = scan(system, b"A" * 1024)
    _, db, actors, _ = system
    with db.transaction() as s:
        second = register(s, actors["admin"], "ignored", b"B" * 1024, first.asset_id, 1)
    assert second.number == 2
    assert scan(system, b"A" * 1024).decision.outcome == "ALLOW"
    assert scan(system, b"B" * 1024).decision.outcome == "BLOCK"
    with db.transaction() as s:
        retire(s, actors["admin"], first.asset_id)
    after = scan(system, b"B" * 1024)
    assert after.decision.outcome == "ALLOW"
    assert after.detection.registry_revision == 3
    with db.transaction() as s:
        assert version_view(s, first.asset_id, first.id) == first
        assert get_scan(s, actors["admin"], before.id) == before


def test_duplicate_and_stale_version(system):
    first = registered(system)
    with pytest.raises(DomainError, match="DUPLICATE_ASSET_LABEL"):
        registered(system)
    with system[1].transaction() as s:
        with pytest.raises(DomainError, match="ASSET_VERSION_CONFLICT"):
            register(s, system[2]["admin"], "ignored", b"new", first.asset_id, 9)
        with pytest.raises(DomainError, match="DUPLICATE_ASSET_VERSION"):
            register(s, system[2]["admin"], "ignored", synthetic_inputs()["protected"], first.asset_id, 1)


@pytest.mark.parametrize("threshold,enabled,expected", [(1023, True, "BLOCK"), (1024, True, "BLOCK"), (1025, True, "ALLOW"), (1024, False, "ALLOW")])
def test_policy_threshold_and_disable(system, threshold, enabled, expected):
    registered(system, b"A" * 2048)
    with system[1].transaction() as s:
        old = active_policy(s, s.get(RegistryState, 1))
        changed = change_policy(s, system[2]["admin"], PolicyInput(threshold=threshold, block_enabled=enabled, expected_version=old.id))
    result = scan(system, b"A" * 1024)
    assert result.decision.outcome == expected
    assert result.policy_id == changed.id
    assert scan(system, b"A" * 2048).decision.reason == "EXACT_PROTECTED_FILE"
    with system[1].transaction() as s:
        assert len(s.scalars(select(PolicyVersion)).all()) == 2


@pytest.mark.parametrize("threshold", [0, -1, 10485761, True, 1.5, "1024"])
def test_invalid_threshold(threshold):
    with pytest.raises(ValueError):
        PolicyInput(threshold=threshold, expected_version="x")


def test_indeterminate_context():
    assert evaluate(None, None).outcome == "INDETERMINATE"


def test_unsupported_profile_fail_closed(system):
    fp = fingerprint_bytes(b"A")
    object.__setattr__(fp.manifest, "profile_id", "unsupported-test")
    with system[1].transaction() as s, pytest.raises(Indeterminate, match="UNSUPPORTED_PROFILE"):
        detect(s, fp, 0)


def test_indexed_query_count_and_evidence_cap(system, monkeypatch):
    registered(system)
    queries = []
    def record(conn, cursor, statement, params, context, many):
        queries.append(statement)
    event.listen(system[1].engine, "before_cursor_execute", record)
    with system[1].transaction() as s:
        result = detect(s, fingerprint_bytes(synthetic_inputs()["protected"]), 1)
    event.remove(system[1].engine, "before_cursor_execute", record)
    assert len(queries) == 2  # one exact lookup, one batched chunk lookup
    assert result.matches
    monkeypatch.setattr("app.detection.MAX_REFERENCES", 1)
    with pytest.raises(Indeterminate, match="EVIDENCE_LIMIT"):
        scan(system, synthetic_inputs()["protected"])
