"""The detection profile registry, rs-cdc-gear-v1 storage and matching, and policy rule set rs-policy-v2.

The rs-policy-v1 tests in test_detection_policy.py are untouched and keep asserting the fixed profile's misses.
Here the same synthetic inputs are judged under both rule sets, side by side.
"""
from hashlib import sha256
import json
from pathlib import Path
import sys
from uuid import uuid4

import pytest
from sqlalchemy import event, select

from app import bootstrap, detection, profiles
from app.crypto import fingerprint_bytes
from app.crypto.cdc import cdc_chunks
from app.errors import DomainError, Indeterminate
from app.gateway_models import AuditEvent, Incident
from app.intake import FrozenInput
from app.models import Asset, AssetCdcChunk, AssetChunk, AssetVersion, PolicyVersion, RegistryRevision, RegistryState, ScanEvaluation
from app.policy import (DEFAULT_CDC_THRESHOLD, RULE_SET_V1, RULE_SET_V2, RULE_SETS, active_policy, change_policy,
                        evaluate, policy_view, profiles_for)
from app.registry import add_missing_profiles, register, retire, version_view
from app.scans import get_scan, run_scan
from app.schemas import DetectionView, PolicyInput, PolicyView, ProfileEvidence, ProfileMatch
from app.synthetic import SOURCE_SAMPLE_SHA256, protected_sample, source_sample

from .test_gateway import release, submit
from .test_hosted import bootstrap_environment

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import cdc_vectors  # noqa: E402
from fixtures import synthetic_inputs  # noqa: E402
import source_corpus  # noqa: E402

FIXED, CDC = "rs-fixed-sha256-v1", "rs-cdc-gear-v1"
CORPUS = source_corpus.corpus()
PROTECTED_FILES = {name: data for name, data in CORPUS.items() if name.startswith("protected/")}
OCTET = {"Content-Type": "application/octet-stream"}


def stream(seed, size):
    return cdc_vectors.counter_stream(seed, size)


def add(system, label, payload):
    _, db, actors, _ = system
    with db.transaction() as s:
        return register(s, actors["admin"], label, payload)


def scan(system, payload, filename="candidate.txt"):
    _, db, actors, _ = system
    with db.transaction() as s:
        return run_scan(s, actors["employee"], filename, FrozenInput(str(uuid4()), payload))


def use_rule_set(system, rule_set, **values):
    _, db, actors, _ = system
    with db.transaction() as s:
        current = active_policy(s, s.get(RegistryState, 1))
        return change_policy(s, actors["admin"], PolicyInput(expected_version=current.id, rule_set=rule_set, **values))


def evidence(result, profile_id):
    found = [e for e in result.detection.profiles if e.profile_id == profile_id]
    return found[0] if found else None


def matched(result, profile_id):
    return sum(m.matched_bytes for m in evidence(result, profile_id).matches)


# ---------------------------------------------------------------------------------------------- the registry
def test_the_registry_lists_the_fixed_profile_first_and_refuses_replacement():
    assert [p.id for p in profiles.registered()] == [FIXED, CDC]
    assert profiles.get(FIXED) is profiles.FIXED and profiles.get(CDC) is profiles.CDC
    assert profiles.FIXED.fingerprint is fingerprint_bytes and profiles.CDC.fingerprint is cdc_chunks
    with pytest.raises(ValueError, match="never replaced"):
        profiles.register_profile(profiles.FIXED)
    with pytest.raises(Indeterminate, match="UNSUPPORTED_PROFILE"):
        profiles.get("rs-unknown-v9")
    with pytest.raises(TypeError):
        profiles.CDC.parameters["min_size"] = 1


def test_published_parameters():
    fixed, content = (p.view() for p in profiles.registered())
    assert (fixed.id, fixed.version, fixed.parameters) == (FIXED, 1, {"chunk_size": 1024, "chunk_hash": "SHA-256"})
    assert (content.id, content.version) == (CDC, 1)
    assert content.parameters == {
        "min_size": 512, "normal_size": 2048, "max_size": 8192, "normalization_level": 2,
        "mask_s": "0x0000d93003530000", "mask_l": "0x0000d90003500000", "chunk_hash": "SHA-256",
        "gear_table_sha256": "6a80b73d855e1aaaba9dc9b54d5e9bd4047e1d2b1ea9803fb0e4b33ee28c1d13"}


def test_merged_intervals_are_the_union():
    assert profiles.merged([]) == []
    assert profiles.merged([(10, 20), (0, 5), (5, 8), (15, 30), (16, 17), (40, 41)]) == [(0, 8), (10, 30), (40, 41)]


def test_the_fixed_profile_is_registered_unchanged():
    # Same function, same manifests as the tracked Phase 01 manifest, for every synthetic input.
    manifest = json.loads((ROOT / "fixtures" / "manifest.json").read_text(encoding="utf-8"))
    for name, data in synthetic_inputs().items():
        assert profiles.FIXED.fingerprint(data).manifest.to_dict() == manifest["fixtures"][name]


# ---------------------------------------------------------------------------------------------- storage
def test_a_new_version_is_fingerprinted_with_every_profile_and_fixed_rows_are_as_before(system):
    data = PROTECTED_FILES["protected/billing/invoice_engine.py"]
    version = add(system, "Invoice", data)
    fp = fingerprint_bytes(data)
    with system[1].transaction() as s:
        row = s.get(AssetVersion, version.id)
        assert (row.profile_id, row.file_size, row.file_sha256, row.merkle_root, row.chunk_count) == (
            FIXED, len(data), fp.manifest.file_sha256, fp.manifest.merkle_root, fp.manifest.chunk_count)
        fixed_rows = s.scalars(select(AssetChunk).where(AssetChunk.version_id == version.id).order_by(AssetChunk.index)).all()
        assert [(c.index, c.length, c.sha256) for c in fixed_rows] == [(c.index, c.length, c.sha256) for c in fp.chunks]
        rows = s.scalars(select(AssetCdcChunk).where(AssetCdcChunk.version_id == version.id).order_by(AssetCdcChunk.offset)).all()
        assert [(c.offset, c.length, c.sha256) for c in rows] == [(c.offset, c.length, c.sha256) for c in cdc_chunks(data)]
        assert sum(c.length for c in rows) == len(data)
    assert [p.model_dump() for p in version.profiles] == [
        {"profile_id": FIXED, "fingerprinted": True, "chunk_count": 9},
        {"profile_id": CDC, "fingerprinted": True, "chunk_count": 4}]
    assert version.manifest.profile_id == FIXED and [c.model_dump() for c in version.chunks] == [c.to_dict() for c in fp.chunks]


def test_cdc_rows_are_insert_only(system):
    from sqlalchemy import text
    from sqlalchemy.exc import DatabaseError
    add(system, "Immutable", source_sample())
    for sql in ("UPDATE asset_cdc_chunks SET sha256 = 'changed'", "DELETE FROM asset_cdc_chunks"):
        with pytest.raises(DatabaseError), system[1].transaction() as s:
            s.execute(text(sql))


def test_a_version_without_cdc_rows_reports_it_and_can_be_completed_only_from_the_same_bytes(system, monkeypatch):
    _, db, actors, _ = system
    data = source_sample()
    with monkeypatch.context() as before:      # a version registered before the profile existed
        before.setattr(profiles, "store_additional", lambda *_: None)
        version = add(system, "Old", data)
    assert [(p.profile_id, p.fingerprinted, p.chunk_count) for p in version.profiles] == [(FIXED, True, 7), (CDC, False, 0)]
    with db.transaction() as s:
        with pytest.raises(DomainError, match="FORBIDDEN|ROLE"):
            add_missing_profiles(s, actors["analyst"], version.asset_id, data)
    with db.transaction() as s, pytest.raises(DomainError, match="ASSET_CONTENT_MISMATCH"):
        add_missing_profiles(s, actors["admin"], version.asset_id, data + b"x")
    with db.transaction() as s, pytest.raises(DomainError, match="NOT_FOUND"):
        add_missing_profiles(s, actors["admin"], str(uuid4()), data)
    with db.transaction() as s:
        assert add_missing_profiles(s, actors["admin"], version.asset_id, data) == 2
    with db.transaction() as s:
        assert add_missing_profiles(s, actors["admin"], version.asset_id, data) is None      # nothing missing now
        assert s.get(RegistryState, 1).revision == 2
        assert [r.action for r in s.scalars(select(RegistryRevision).order_by(RegistryRevision.number))] == ["REGISTER", "PROFILE_ADDED"]
        after = version_view(s, version.asset_id, version.id)
        assert after.model_dump(exclude={"profiles"}) == version.model_dump(exclude={"profiles"})   # nothing else changed
        assert [(p.profile_id, p.fingerprinted, p.chunk_count) for p in after.profiles] == [(FIXED, True, 7), (CDC, True, 4)]


def test_a_retired_asset_is_not_completed(system, monkeypatch):
    _, db, actors, _ = system
    with monkeypatch.context() as before:
        before.setattr(profiles, "store_additional", lambda *_: None)
        version = add(system, "Retired", source_sample())
    with db.transaction() as s:
        retire(s, actors["admin"], version.asset_id)
    with db.transaction() as s:
        assert add_missing_profiles(s, actors["admin"], version.asset_id, source_sample()) is None


# ---------------------------------------------------------------------------------------------- rule set v1 is unchanged
def test_under_rule_set_v1_only_the_fixed_profile_is_evaluated_and_nothing_new_is_stored(system):
    data = PROTECTED_FILES["protected/billing/invoice_engine.py"]
    add(system, "Invoice", data)
    statements = []
    def record(conn, cursor, statement, params, context, many):
        statements.append(statement)
    event.listen(system[1].engine, "before_cursor_execute", record)
    result = scan(system, b"!" + data)
    event.remove(system[1].engine, "before_cursor_execute", record)
    assert not [s for s in statements if "asset_cdc_chunks" in s]
    assert result.decision.outcome == "ALLOW" and result.decision.reason == "NO_QUALIFYING_MATCH"
    assert [e.profile_id for e in result.detection.profiles] == [FIXED] and result.detection.matches == []
    with system[1].transaction() as s:
        assert s.get(ScanEvaluation, result.id).profiles is None
        policy = active_policy(s, s.get(RegistryState, 1))
        assert (policy.number, policy.rule_set, policy.cdc_threshold) == (1, RULE_SET_V1, None)
        assert get_scan(s, system[2]["employee"], result.id) == result


def test_fixed_evidence_in_the_per_profile_shape_equals_the_legacy_evidence(system):
    protected = synthetic_inputs()["protected"]
    version = add(system, "Synthetic IP", protected)
    result = scan(system, synthetic_inputs()["aligned_embedding"])
    legacy = result.detection.matches[0]
    fixed = evidence(result, FIXED)
    assert fixed.chunk_count == result.detection.manifest.chunk_count == 10
    assert [m.model_dump() for m in fixed.matches] == [{
        "asset_id": version.asset_id, "version_id": version.id, "matched_bytes": legacy.matched_bytes == 8192 and 8192,
        "matched_chunks": 8, "coverage": {"numerator": 8192, "denominator": 10240}, "intervals": [(1024, 9216)]}]
    assert len(legacy.intervals) == 8


# ---------------------------------------------------------------------------------------------- the evasion fixtures
V1 = {"exact_renamed": "BLOCK", "aligned_partial": "BLOCK", "single_aligned_block": "BLOCK", "sub_threshold_tail": "ALLOW",
      "shifted": "ALLOW", "inserted": "ALLOW", "crlf": "ALLOW", "utf16": "ALLOW", "zipped": "ALLOW"}
V2 = {**V1, "shifted": "BLOCK", "inserted": "BLOCK"}
REASON = {"exact_renamed": "EXACT_PROTECTED_FILE", "aligned_partial": "BLOCK_THRESHOLD_MET", "single_aligned_block": "BLOCK_THRESHOLD_MET"}


@pytest.mark.parametrize("name", sorted(PROTECTED_FILES))
def test_shifted_and_inserted_copies_block_under_rule_set_v2_while_the_fixed_profile_still_misses_them(system, name):
    data = PROTECTED_FILES[name]
    for label, payload in PROTECTED_FILES.items():
        add(system, label.replace("/", " "), payload)
    variants = source_corpus.variants(data)
    assert set(variants) == set(V1)
    first = {variant: scan(system, payload) for variant, payload in variants.items()}
    for variant, result in first.items():
        assert result.decision.outcome == V1[variant], variant
        assert [e.profile_id for e in result.detection.profiles] == [FIXED]
    policy = use_rule_set(system, RULE_SET_V2)
    assert (policy.rule_set, policy.cdc_threshold) == (RULE_SET_V2, DEFAULT_CDC_THRESHOLD)
    for variant, payload in variants.items():
        result = scan(system, payload)
        assert result.decision.outcome == V2[variant], variant
        assert [e.profile_id for e in result.detection.profiles] == [FIXED, CDC]
        # The fixed profile's own evidence does not depend on the rule set.
        assert result.detection.matches == first[variant].detection.matches
        assert evidence(result, FIXED) == evidence(first[variant], FIXED)
        if variant in {"shifted", "inserted"}:
            assert matched(result, FIXED) == 0                                  # still a miss of the fixed profile
            assert result.decision.reason == "CDC_THRESHOLD_MET"
            found = evidence(result, CDC).matches
            assert len(found) == 1 and found[0].matched_bytes >= DEFAULT_CDC_THRESHOLD
            assert result.decision.qualifying_versions == [found[0].version_id]
            assert found[0].coverage.model_dump() == {"numerator": found[0].matched_bytes, "denominator": len(payload)}
            assert found[0].matched_bytes == sum(end - begin for begin, end in found[0].intervals)
            assert 1 <= found[0].matched_chunks <= evidence(result, CDC).chunk_count == len(cdc_chunks(payload))
        elif V2[variant] == "BLOCK":
            assert result.decision.reason == REASON[variant]                    # the earlier rules keep their precedence
        else:
            assert result.decision.reason == "NO_QUALIFYING_MATCH"
        if variant in {"crlf", "utf16", "zipped"}:
            assert matched(result, FIXED) == 0 and matched(result, CDC) == 0    # re-encoding is still open
        assert result.release_authorized is False
        with system[1].transaction() as s:
            assert get_scan(s, system[2]["employee"], result.id) == result


def test_matched_bytes_of_the_corpus_under_both_profiles(system):
    """The numbers reported in docs/detection-spec.md, for the shifted and the inserted copy of every protected file."""
    for label, payload in PROTECTED_FILES.items():
        add(system, label.replace("/", " "), payload)
    use_rule_set(system, RULE_SET_V2)
    table = {}
    for name, data in sorted(PROTECTED_FILES.items()):
        variants = source_corpus.variants(data)
        table[name.rsplit("/", 1)[1]] = tuple((matched(r, FIXED), matched(r, CDC)) for r in (scan(system, variants["shifted"]), scan(system, variants["inserted"])))
    assert table == {
        "invoice_engine.py": ((0, 7379), (0, 7379)), "tax_rules.py": ((0, 3542), (0, 3542)),
        "margin_model.py": ((0, 2416), (0, 2416)), "token_vault.py": ((0, 7216), (0, 7216)),
        "ranking_core.py": ((0, 7251), (0, 7251))}


@pytest.mark.parametrize("rule_set", [RULE_SET_V1, RULE_SET_V2])
def test_benign_corpus_files_stay_allowed(system, rule_set):
    for label, payload in PROTECTED_FILES.items():
        add(system, label.replace("/", " "), payload)
    add(system, "Source sample", source_sample())
    if rule_set == RULE_SET_V2:
        use_rule_set(system, RULE_SET_V2)
    benign = {name: data for name, data in CORPUS.items() if name.startswith("benign/")}
    assert len(benign) == 3
    for name, data in {**benign, "note": synthetic_inputs()["benign"], "small": synthetic_inputs()["small"], "empty": b""}.items():
        result = scan(system, data)
        assert (result.decision.outcome, result.decision.reason) == ("ALLOW", "NO_QUALIFYING_MATCH"), name
        assert all(not e.matches for e in result.detection.profiles)


@pytest.mark.parametrize("fixture,outcome,fixed_bytes,cdc_bytes", [
    ("protected", "BLOCK", 8192, 8192), ("renamed", "BLOCK", 8192, 8192), ("benign", "ALLOW", 0, 0), ("empty", "ALLOW", 0, 0),
    ("single_byte_change", "BLOCK", 7168, 0), ("aligned_partial", "BLOCK", 2048, 0), ("aligned_embedding", "BLOCK", 8192, 0),
    # Documented limitation: the eight-block fixture repeats one line per block, has no cut point and is a single
    # maximum-size chunk, so its shifted copy is missed by both profiles.
    ("shifted", "ALLOW", 0, 0), ("crlf", "ALLOW", 0, 0), ("utf16", "ALLOW", 0, 0), ("small", "ALLOW", 0, 0),
])
def test_the_synthetic_matrix_under_rule_set_v2(system, fixture, outcome, fixed_bytes, cdc_bytes):
    add(system, "Synthetic IP", synthetic_inputs()["protected"])
    use_rule_set(system, RULE_SET_V2)
    result = scan(system, synthetic_inputs()[fixture])
    assert result.decision.outcome == outcome
    assert (matched(result, FIXED), matched(result, CDC)) == (fixed_bytes, cdc_bytes)


def test_the_source_sample_seed_and_its_copies(system):
    data = source_sample()
    assert sha256(data).hexdigest() == SOURCE_SAMPLE_SHA256 and len(data) == 6954
    assert data.startswith(b"# SYNTHETIC RootSentinel demo source sample") and b"Not real intellectual property" in data
    assert protected_sample() == b"SYNTHETIC-PROTECTED-" * 128
    add(system, "Source", data)
    use_rule_set(system, RULE_SET_V2)
    cut = data.index(b"\n\ndef quote_engine_step_28") + 1
    copies = {"shifted": b"!" + data, "inserted": data[:cut] + b"# reviewed\n" + data[cut:]}
    assert {k: (matched(r, FIXED) >= 1024, matched(r, CDC), r.decision.reason) for k, r in ((k, scan(system, v)) for k, v in copies.items())} == {
        "shifted": (False, 5480, "CDC_THRESHOLD_MET"), "inserted": (True, 4677, "BLOCK_THRESHOLD_MET")}


# ---------------------------------------------------------------------------------------------- scoring and scope
def test_matched_bytes_are_a_union_and_assets_are_never_summed(system):
    common, other = stream("common", 20000), stream("other", 20000)
    first = add(system, "First", common)
    second = add(system, "Second", common + other)
    use_rule_set(system, RULE_SET_V2)
    upload = b"!" + common + common            # the protected content twice, shifted
    result = scan(system, upload)
    found = {m.version_id: m for m in evidence(result, CDC).matches}
    assert set(found) == {first.id, second.id}
    for match in found.values():
        assert match.intervals == profiles.merged(match.intervals)
        assert match.matched_bytes == sum(end - begin for begin, end in match.intervals) <= len(upload)
        assert match.coverage.denominator == len(upload) == 40001
        assert all(0 <= begin < end <= len(upload) for begin, end in match.intervals)
    # Each asset is judged alone: the same upload bytes explain both, and neither count includes the other's.
    # The first asset also owns the final chunk of the upload (its own last chunk); the second does not.
    assert 30000 < found[second.id].matched_bytes < found[first.id].matched_bytes <= len(upload)
    assert sorted(result.decision.qualifying_versions) == sorted(found)
    # A chunk that repeats in the upload counts at each position; one that repeats in the registry counts once.
    twice = add(system, "Twice", common + common)
    once = {m.version_id: m.matched_bytes for m in evidence(scan(system, b"!" + common), CDC).matches}
    assert set(once) == {first.id, second.id, twice.id} and max(once.values()) < len(common)
    assert once[twice.id] <= once[first.id] < found[first.id].matched_bytes


def test_only_the_current_version_of_an_active_asset_matches(system):
    _, db, actors, _ = system
    old, new = stream("old", 12000), stream("new", 12000)
    first = add(system, "Versioned", old)
    use_rule_set(system, RULE_SET_V2)
    assert scan(system, b"!" + old).decision.reason == "CDC_THRESHOLD_MET"
    with db.transaction() as s:
        second = register(s, actors["admin"], "ignored", new, first.asset_id, 1)
    assert scan(system, b"!" + old).decision.outcome == "ALLOW"
    after = scan(system, b"!" + new)
    assert after.decision.qualifying_versions == [second.id]
    with db.transaction() as s:
        retire(s, actors["admin"], first.asset_id)
    assert scan(system, b"!" + new).decision.outcome == "ALLOW"
    with db.transaction() as s:
        assert get_scan(s, actors["admin"], after.id) == after       # history is not rewritten


def test_a_version_without_cdc_rows_is_matched_by_the_fixed_profile_only(system, monkeypatch):
    data = stream("legacy", 12000)
    with monkeypatch.context() as before:
        before.setattr(profiles, "store_additional", lambda *_: None)
        add(system, "Legacy", data)
    use_rule_set(system, RULE_SET_V2)
    assert scan(system, data).decision.reason == "EXACT_PROTECTED_FILE"
    shifted = scan(system, b"!" + data)
    assert shifted.decision.outcome == "ALLOW" and matched(shifted, CDC) == 0


def test_evidence_limits_fail_closed_for_the_content_defined_profile(system, monkeypatch):
    data = stream("limits", 20000)
    add(system, "One", data)
    add(system, "Two", data + b"tail")
    use_rule_set(system, RULE_SET_V2)
    assert scan(system, b"!" + data).decision.outcome == "BLOCK"
    monkeypatch.setattr(detection, "MAX_MATCHED_VERSIONS", 1)
    with pytest.raises(Indeterminate, match="EVIDENCE_LIMIT"):
        scan(system, b"!" + data)
    monkeypatch.setattr(detection, "MAX_MATCHED_VERSIONS", 1000)
    monkeypatch.setattr(detection, "MAX_REFERENCES", 3)
    with pytest.raises(Indeterminate, match="EVIDENCE_LIMIT"):
        scan(system, b"!" + data)
    with system[1].transaction() as s:
        assert len(s.scalars(select(ScanEvaluation)).all()) == 1      # a failed evaluation persists nothing


def test_lookups_are_batched_and_a_hash_with_another_length_is_not_a_match(system, monkeypatch):
    data = stream("batch", 40000)
    version = add(system, "Batch", data)
    other = add(system, "Other", stream("unrelated", 3000))
    chunks = cdc_chunks(b"!" + data)
    with system[1].transaction() as s:      # the same digest stored with a different length must not count
        s.add(AssetCdcChunk(version_id=other.id, offset=9000000, length=chunks[3].length - 1, sha256=chunks[3].sha256))
    monkeypatch.setattr(profiles, "CDC_LOOKUP_BATCH", 4)
    statements = []
    def record(conn, cursor, statement, params, context, many):
        statements.append(statement)
    event.listen(system[1].engine, "before_cursor_execute", record)
    with system[1].transaction() as s:
        found = profiles.CDC.match(s, chunks)
    event.remove(system[1].engine, "before_cursor_execute", record)
    assert len([s for s in statements if "asset_cdc_chunks" in s]) == -(-len({c.sha256 for c in chunks}) // 4)
    assert [m.version_id for m in found.matches] == [version.id] and found.chunk_count == len(chunks)
    with system[1].transaction() as s:
        assert profiles.CDC.match(s, ()) == ProfileEvidence(profile_id=CDC, chunk_count=0, matches=[])
        assert profiles.FIXED.match(s, fingerprint_bytes(data)).matches[0].matched_bytes == 40000


def test_extend_requires_the_fixed_profile_and_known_profiles(system):
    view = DetectionView(manifest=fingerprint_bytes(b"x").manifest.to_dict(), registry_revision=0, matches=[])
    with system[1].transaction() as s:
        with pytest.raises(Indeterminate, match="UNSUPPORTED_PROFILE"):
            profiles.extend(s, b"x", view, (CDC,))
        with pytest.raises(Indeterminate, match="UNSUPPORTED_PROFILE"):
            profiles.extend(s, b"x", view, (FIXED, "rs-unknown-v9"))
        assert [e.profile_id for e in profiles.extend(s, b"x", view, (FIXED, CDC)).profiles] == [FIXED, CDC]


# ---------------------------------------------------------------------------------------------- the pure evaluator
def detection_view(fixed=(), content=(), with_cdc=True, exact=False):
    manifest = fingerprint_bytes(b"A" * 10000).manifest.to_dict()
    matches = [{"asset_id": "a", "version_id": v, "exact": exact, "matched_bytes": n, "coverage": {"numerator": n, "denominator": 10000},
                "intervals": [], "blocks": []} for v, n in fixed]
    view = DetectionView(manifest=manifest, registry_revision=1, matches=matches)
    reports = [profiles.fixed_evidence(view)]
    if with_cdc:
        reports.append(ProfileEvidence(profile_id=CDC, chunk_count=5, matches=[ProfileMatch(
            asset_id="a", version_id=v, matched_bytes=n, matched_chunks=1, coverage={"numerator": n, "denominator": 10000},
            intervals=[(0, n)]) for v, n in content]))
    return view.model_copy(update={"profiles": reports})


def policy(rule_set=RULE_SET_V2, threshold=1024, cdc_threshold=2048, enabled=True):
    from app.db import now
    return PolicyView(id="p", number=2, threshold=threshold, block_enabled=enabled, actor_id=None, created_at=now(),
                      rule_set=rule_set, cdc_threshold=cdc_threshold)


@pytest.mark.parametrize("view,rules,expected", [
    (detection_view(), policy(), ("ALLOW", "NO_QUALIFYING_MATCH", [])),
    (detection_view(content=[("v1", 2047)]), policy(), ("ALLOW", "NO_QUALIFYING_MATCH", [])),
    (detection_view(content=[("v2", 2048), ("v1", 9000), ("v3", 100)]), policy(), ("BLOCK", "CDC_THRESHOLD_MET", ["v1", "v2"])),
    (detection_view(content=[("v1", 600)]), policy(cdc_threshold=600), ("BLOCK", "CDC_THRESHOLD_MET", ["v1"])),
    # Earlier rules first: an exact file, then the fixed threshold, each with its own qualifying versions.
    (detection_view(fixed=[("v9", 10000)], content=[("v1", 9000)], exact=True), policy(), ("BLOCK", "EXACT_PROTECTED_FILE", ["v9"])),
    (detection_view(fixed=[("v9", 1024)], content=[("v1", 9000)]), policy(), ("BLOCK", "BLOCK_THRESHOLD_MET", ["v9"])),
    (detection_view(fixed=[("v9", 1023)], content=[("v1", 9000)]), policy(), ("BLOCK", "CDC_THRESHOLD_MET", ["v1"])),
    # Partial matching switched off covers both partial rules; an exact file still blocks.
    (detection_view(fixed=[("v9", 5000)], content=[("v1", 9000)]), policy(enabled=False), ("ALLOW", "NO_QUALIFYING_MATCH", [])),
    (detection_view(fixed=[("v9", 10000)], exact=True), policy(enabled=False), ("BLOCK", "EXACT_PROTECTED_FILE", ["v9"])),
    # Fail closed: missing profile evidence, a missing or invalid threshold and an unknown rule set never allow.
    (detection_view(with_cdc=False), policy(), ("INDETERMINATE", "INVALID_EVALUATION_CONTEXT", [])),
    (detection_view(content=[("v1", 9000)]), policy(cdc_threshold=None), ("INDETERMINATE", "INVALID_EVALUATION_CONTEXT", [])),
    (detection_view(), policy(cdc_threshold=0), ("INDETERMINATE", "INVALID_EVALUATION_CONTEXT", [])),
    (detection_view(), policy(cdc_threshold=10485761), ("INDETERMINATE", "INVALID_EVALUATION_CONTEXT", [])),
    (detection_view(), policy(rule_set="rs-policy-v9"), ("INDETERMINATE", "INVALID_EVALUATION_CONTEXT", [])),
    # rs-policy-v1 ignores evidence of the content-defined profile even when it is present.
    (detection_view(content=[("v1", 9000)]), policy(rule_set=RULE_SET_V1, cdc_threshold=None), ("ALLOW", "NO_QUALIFYING_MATCH", [])),
])
def test_rule_set_v2_evaluation(view, rules, expected):
    decision = evaluate(view, rules)
    assert (decision.outcome, decision.reason, decision.qualifying_versions) == expected
    assert evaluate(view, rules, authorized=False).outcome == "INDETERMINATE"


def test_rule_sets_name_their_profiles():
    assert RULE_SETS == {RULE_SET_V1: (FIXED,), RULE_SET_V2: (FIXED, CDC)}
    assert profiles_for(RULE_SET_V1) == (FIXED,) and profiles_for(RULE_SET_V2) == (FIXED, CDC)
    with pytest.raises(Indeterminate, match="POLICY_UNAVAILABLE"):
        profiles_for("rs-policy-v9")


# ---------------------------------------------------------------------------------------------- policy versions
def test_policy_versions_carry_their_rule_set(system):
    _, db, actors, _ = system
    second = use_rule_set(system, RULE_SET_V2)
    assert (second.number, second.rule_set, second.cdc_threshold, second.threshold, second.block_enabled) == (2, RULE_SET_V2, 2048, 1024, True)
    third = use_rule_set(system, None, threshold=4096)                       # an omitted rule set is inherited
    assert (third.rule_set, third.cdc_threshold, third.threshold) == (RULE_SET_V2, 2048, 4096)
    fourth = use_rule_set(system, None, cdc_threshold=5000)
    assert (fourth.rule_set, fourth.cdc_threshold) == (RULE_SET_V2, 5000)
    fifth = use_rule_set(system, RULE_SET_V1)
    assert (fifth.number, fifth.rule_set, fifth.cdc_threshold) == (5, RULE_SET_V1, None)
    with db.transaction() as s, pytest.raises(DomainError, match="INVALID_REQUEST"):
        change_policy(s, actors["admin"], PolicyInput(expected_version=fifth.id, cdc_threshold=2048))
    with db.transaction() as s:
        rows = s.scalars(select(PolicyVersion).order_by(PolicyVersion.number)).all()
        assert [(p.rule_set, p.cdc_threshold) for p in rows] == [
            (RULE_SET_V1, None), (RULE_SET_V2, 2048), (RULE_SET_V2, 2048), (RULE_SET_V2, 5000), (RULE_SET_V1, None)]
        assert policy_view(rows[0]).rule_set == RULE_SET_V1


@pytest.mark.parametrize("value", [0, -1, 10485761, True, 1.5, "2048"])
def test_invalid_cdc_threshold_and_rule_set_inputs(value):
    with pytest.raises(ValueError):
        PolicyInput(expected_version="x", rule_set=RULE_SET_V2, cdc_threshold=value)
    with pytest.raises(ValueError):
        PolicyInput(expected_version="x", rule_set="rs-policy-v9")


@pytest.mark.parametrize("rule_set,cdc_threshold", [("rs-policy-v9", None), (RULE_SET_V2, None), (RULE_SET_V1, 2048), (RULE_SET_V2, 0)])
def test_an_inconsistent_stored_policy_is_unavailable(system, rule_set, cdc_threshold):
    with system[1].transaction() as s:
        broken = PolicyVersion(number=2, threshold=1024, block_enabled=True, rule_set=rule_set, cdc_threshold=cdc_threshold)
        s.add(broken)
        s.flush()
        state = s.get(RegistryState, 1)
        state.policy_id = broken.id
        with pytest.raises(Indeterminate, match="POLICY_UNAVAILABLE"):
            active_policy(s, state)
    with pytest.raises(Indeterminate, match="POLICY_UNAVAILABLE"):
        scan(system, b"anything")


# ---------------------------------------------------------------------------------------------- over HTTP
def activate_over_http(client):
    current = client.get("/api/v1/policies/active").json()
    assert (current["rule_set"], current["cdc_threshold"]) == (RULE_SET_V1, None)
    changed = client.post("/api/v1/policies", json={"expected_version": current["id"], "threshold": current["threshold"],
                                                    "block_enabled": True, "rule_set": RULE_SET_V2})
    assert changed.status_code == 201, changed.text
    return changed.json()


def test_api_registration_policy_scan_and_blocked_transfer(client, login):
    login(client)
    listed = client.get("/api/v1/detection/profiles")
    assert listed.status_code == 200 and [p["id"] for p in listed.json()] == [FIXED, CDC]
    assert listed.json()[1]["parameters"]["gear_table_sha256"].startswith("6a80b73d")
    data = PROTECTED_FILES["protected/auth/token_vault.py"]
    version = client.post("/api/v1/assets?label=Token vault", content=data, headers=OCTET).json()
    assert version["profiles"] == [{"profile_id": FIXED, "fingerprinted": True, "chunk_count": 9},
                                   {"profile_id": CDC, "fingerprinted": True, "chunk_count": 4}]
    summaries = client.get(f"/api/v1/assets/{version['asset_id']}/versions").json()
    assert summaries[0]["profiles"] == version["profiles"]
    assert client.get(f"/api/v1/assets/{version['asset_id']}/versions/{version['id']}").json() == version
    shifted = source_corpus.variants(data)["shifted"]

    allowed = client.post("/api/v1/scans", content=shifted, headers=OCTET).json()            # rule set v1: the known miss
    assert allowed["decision"]["outcome"] == "ALLOW" and [e["profile_id"] for e in allowed["detection"]["profiles"]] == [FIXED]

    policy = activate_over_http(client)
    assert (policy["number"], policy["rule_set"], policy["cdc_threshold"]) == (2, RULE_SET_V2, 2048)
    assert client.get("/api/v1/policies/history").json()["items"][0]["rule_set"] == RULE_SET_V2
    rejected = client.post("/api/v1/policies", json={"expected_version": policy["id"], "rule_set": RULE_SET_V1, "cdc_threshold": 2048})
    assert rejected.status_code == 422 and rejected.json()["error"]["code"] == "INVALID_REQUEST"
    assert client.post("/api/v1/policies", json={"expected_version": policy["id"], "rule_set": "other"}).status_code == 422

    blocked = submit(client, shifted).json()
    assert blocked["state"] == "BLOCKED" and blocked["reason"] == "CDC_THRESHOLD_MET" and blocked["release_eligible"] is False
    report = blocked["scan"]["detection"]["profiles"]
    assert [(e["profile_id"], e["chunk_count"], len(e["matches"])) for e in report] == [(FIXED, 9, 0), (CDC, 4, 1)]
    assert report[1]["matches"][0] == {"asset_id": version["asset_id"], "version_id": version["id"], "matched_bytes": 7216,
                                       "matched_chunks": 3, "coverage": {"numerator": 7216, "denominator": 8503},
                                       "intervals": [[1287, 8503]]}
    assert blocked["scan"]["release_authorized"] is False
    refused = release(client, blocked["id"])                                                   # BLOCK never delivers
    assert refused.status_code == 409 and shifted not in refused.content
    assert client.get("/api/v1/scans/" + blocked["scan"]["id"]).json() == blocked["scan"]
    with client.app.state.db.transaction() as s:
        incident = s.scalar(select(Incident).where(Incident.transfer_id == blocked["id"]))
        assert incident.severity == "MEDIUM"
        kinds = [json.loads(e.canonical)["kind"] for e in s.scalars(select(AuditEvent).order_by(AuditEvent.sequence))]
        assert kinds.count("POLICY_CHANGED") == 1 and kinds[-4:] == ["DECISION_BLOCKED", "INCIDENT_CREATED", "RELEASE_ATTEMPT", "RELEASE_DENIED"]
    assert client.post("/api/v1/audit/verify").json()["valid"] is True
    # A benign upload is still allowed and released once under rule set v2.
    benign = submit(client, CORPUS["benign/docs/readme_notes.txt"]).json()
    assert benign["state"] == "ALLOWED" and release(client, benign["id"]).status_code == 200


def test_changing_the_rule_set_makes_a_pending_approval_stale(client, login):
    login(client)
    pending = submit(client).json()
    assert pending["state"] == "ALLOWED"
    activate_over_http(client)
    assert release(client, pending["id"]).json()["error"]["code"] == "TRANSFER_STALE"


def test_every_role_can_read_the_profiles_and_none_can_without_a_session(client, login):
    assert client.get("/api/v1/detection/profiles").status_code == 401
    for role in ("employee", "analyst", "admin"):
        login(client, role)
        assert client.get("/api/v1/detection/profiles").status_code == 200


# ---------------------------------------------------------------------------------------------- bootstrap
def run_bootstrap(system, monkeypatch, tmp_path, capsys):
    bootstrap_environment(monkeypatch, system, tmp_path, tmp_path / "unused.json")
    assert bootstrap.main([]) == 0
    return capsys.readouterr().out


def test_bootstrap_seeds_both_profiles_and_activates_rule_set_v2_once(system, monkeypatch, tmp_path, capsys):
    _, db, actors, _ = system
    out = run_bootstrap(system, monkeypatch, tmp_path, capsys)
    assert "assets: seeded=2 existing=0" in out and "missing fingerprints=0" in out and "rule set rs-policy-v2 activated" in out
    with db.transaction() as s:
        policy = active_policy(s, s.get(RegistryState, 1))
        system_user = s.scalar(select(bootstrap.User).where(bootstrap.User.username == bootstrap.SYSTEM_USERNAME))
        assert (policy.number, policy.rule_set, policy.cdc_threshold, policy.threshold, policy.actor_id) == (2, RULE_SET_V2, 2048, 1024, system_user.id)
        counts = {label: len(s.scalars(select(AssetCdcChunk).join(AssetVersion, AssetCdcChunk.version_id == AssetVersion.id)
                                       .join(Asset, AssetVersion.asset_id == Asset.id).where(Asset.label == label)).all())
                  for label in bootstrap.SEEDS}
        assert counts == {"synthetic-protected-sample": 1, "synthetic-source-sample": 4}
    # The demo: a shifted copy of the source sample is blocked by the content-defined profile.
    result = scan(system, b"!" + source_sample())
    assert (result.decision.outcome, result.decision.reason, matched(result, FIXED), matched(result, CDC)) == ("BLOCK", "CDC_THRESHOLD_MET", 0, 5480)
    assert scan(system, protected_sample()).decision.reason == "EXACT_PROTECTED_FILE"
    # An administrator's later choice is never overridden by a restart.
    use_rule_set(system, RULE_SET_V1)
    out = run_bootstrap(system, monkeypatch, tmp_path, capsys)
    assert "assets: seeded=0 existing=2" in out and "missing fingerprints=0" in out and "rule set rs-policy-v2 not changed" in out
    with db.transaction() as s:
        assert active_policy(s, s.get(RegistryState, 1)).rule_set == RULE_SET_V1
        assert len(s.scalars(select(PolicyVersion)).all()) == 3


def test_bootstrap_rebuilds_a_seed_registered_before_the_profile_existed(system, monkeypatch, tmp_path, capsys):
    _, db, actors, _ = system
    with monkeypatch.context() as before:      # the hosted database as it is today: one seed, fixed rows only
        before.setattr(profiles, "store_additional", lambda *_: None)
        old = add(system, "synthetic-protected-sample", protected_sample())
    out = run_bootstrap(system, monkeypatch, tmp_path, capsys)
    assert "assets: seeded=1 existing=1" in out and "missing fingerprints=1" in out and "rule set rs-policy-v2 activated" in out
    with db.transaction() as s:
        rows = s.scalars(select(AssetCdcChunk).where(AssetCdcChunk.version_id == old.id)).all()
        assert [(r.offset, r.length, r.sha256) for r in rows] == [(0, 2560, sha256(protected_sample()).hexdigest())]
        assert s.get(AssetVersion, old.id).registry_revision == 1                        # the version row is untouched
        assert [r.action for r in s.scalars(select(RegistryRevision).order_by(RegistryRevision.number))] == ["REGISTER", "REGISTER", "PROFILE_ADDED"]
        events = [json.loads(e.canonical) for e in s.scalars(select(AuditEvent).order_by(AuditEvent.sequence))]
        assert [e["kind"] for e in events] == ["ASSET_REGISTERED", "ASSET_PROFILE_ADDED", "POLICY_CHANGED"]
        assert events[1]["resource_id"] == old.asset_id and events[1]["details"] == {"registry_revision": 3}
        from app.audit import AuditService, KeyRing
        assert AuditService(KeyRing.load(system[0].audit_key_file), system[0].checkpoint_root).verify(s)["valid"] is True
    out = run_bootstrap(system, monkeypatch, tmp_path, capsys)
    assert "assets: seeded=0 existing=2" in out and "missing fingerprints=0" in out and "not changed" in out


def test_bootstrap_leaves_a_seed_alone_when_its_current_version_is_other_content(system, monkeypatch, tmp_path, capsys):
    _, db, actors, _ = system
    with monkeypatch.context() as before:
        before.setattr(profiles, "store_additional", lambda *_: None)
        old = add(system, "synthetic-protected-sample", b"operator replaced this seed with other synthetic bytes")
    out = run_bootstrap(system, monkeypatch, tmp_path, capsys)
    assert "assets: seeded=1 existing=1" in out and "missing fingerprints=0" in out
    with db.transaction() as s:
        assert not s.scalars(select(AssetCdcChunk).where(AssetCdcChunk.version_id == old.id)).all()
