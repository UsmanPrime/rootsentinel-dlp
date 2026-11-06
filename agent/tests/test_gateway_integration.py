"""Acceptance criteria 1-9 against a REAL gateway (real HTTP, real database, real audit chain).

Every test uses its own EMPLOYEE account and its own directories. The protected corpus is
synthetic (scripts/source_corpus.py) and is registered by an ADMIN client before the agent runs.
"""
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")
pytest.importorskip("alembic")

import source_corpus  # noqa: E402
from backend_fixture import RealBackend  # noqa: E402
from rootsentinel_agent.client import GatewayClient  # noqa: E402
from rootsentinel_agent.fsutil import Credentials, write_credentials  # noqa: E402
from rootsentinel_agent.journal import Journal  # noqa: E402
from rootsentinel_agent.pipeline import Agent, Failpoints, Fatal  # noqa: E402
from support import fast_config, finish, listing, make_dirs, put  # noqa: E402

DRIVER = Path(__file__).resolve().parent / "driver.py"
CORPUS = source_corpus.corpus()
INVOICE = CORPUS["protected/billing/invoice_engine.py"]
BENIGN = CORPUS["benign/utils/string_helpers.py"]


@pytest.fixture(scope="module")
def backend(tmp_path_factory):
    server = RealBackend(tmp_path_factory.mktemp("gateway")).start()
    admin = server.client(server.admin)
    for name, data in CORPUS.items():
        if name.startswith("protected/"):
            admin.register_asset(name.replace("/", "_"), data)
    yield server
    server.stop()


class Employee:
    def __init__(self, backend, tmp_path):
        self.backend, self.name = backend, backend.create_user("EMPLOYEE")
        self.dirs = make_dirs(tmp_path / "agent")
        self.creds_file = tmp_path / "secrets" / "agent.json"
        write_credentials(self.creds_file, self.name, backend.password)

    def agent(self, failpoints=None, **override) -> Agent:
        journal = Journal(self.dirs["state"] / "journal.jsonl")
        journal.open()
        client = GatewayClient(self.backend.base_url, self.backend.origin)
        config = fast_config(self.dirs, self.name, **override)
        config.credentials = Credentials(self.name, self.backend.password)
        return Agent(config, client, journal, failpoints or Failpoints())

    def run(self, **kw) -> int:
        agent = self.agent(**kw)
        try:
            return agent.run(once=True, max_wait=40)
        finally:
            finish(agent)

    def transfers(self) -> list[dict]:
        return self.backend.client(self.name).get_json("/api/v1/transfers?limit=100")["items"]

    def crash_at(self, point: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-B", str(DRIVER), "--root", str(self.dirs["staging"].parent),
                               "--base-url", self.backend.base_url, "--origin", self.backend.origin,
                               "--credentials-file", str(self.creds_file), "--crash", point],
                              capture_output=True, timeout=120)

    def journal_events(self) -> list[dict]:
        return [json.loads(line) for line in (self.dirs["state"] / "journal.jsonl").read_text().splitlines()]


@pytest.fixture
def emp(backend, tmp_path):
    return Employee(backend, tmp_path)


def analyst_view(backend):
    return backend.client(backend.analyst)


def _hook_once(hook):
    state = {"done": False}

    def run(**_):
        if not state["done"]:
            state["done"] = True
            hook()
    return run


# --------------------------------------------------------------------------- criterion 1
def test_c1_benign_file_is_delivered_byte_identical_and_staging_is_emptied(emp):
    put(emp.dirs, "string helpers (copy).py", BENIGN)
    assert emp.run() == 0
    assert listing(emp.dirs["staging"]) == [] and listing(emp.dirs["outbound"]) == ["string helpers (copy).py"]
    assert (emp.dirs["outbound"] / "string helpers (copy).py").read_bytes() == BENIGN
    assert [t["state"] for t in emp.transfers()] == ["STREAM_FINISHED"]


# --------------------------------------------------------------------------- criterion 2
def test_c2_renamed_protected_copy_never_reaches_outbound_and_opens_a_high_incident(emp, backend):
    put(emp.dirs, "holiday-photos.txt", INVOICE)
    assert emp.run() == 0
    assert listing(emp.dirs["outbound"]) == [] and listing(emp.dirs["staging"]) == []
    names = listing(emp.dirs["quarantine"])
    report_name = next(n for n in names if n.endswith(".report.json"))
    report = json.loads((emp.dirs["quarantine"] / report_name).read_text())
    assert report["decision_outcome"] == "BLOCK" and report["decision_reason"] == "EXACT_PROTECTED_FILE" and report["exact_match"]
    assert (emp.dirs["quarantine"] / next(n for n in names if n.endswith(".held"))).read_bytes() == INVOICE
    # No protected block exists anywhere the consumer or the report could reach it.
    block = INVOICE[1024:2048]
    for folder in ("outbound", "state"):
        for path in emp.dirs[folder].rglob("*"):
            assert path.is_dir() or block not in path.read_bytes()
    text = (emp.dirs["quarantine"] / report_name).read_text()
    assert block not in (emp.dirs["quarantine"] / report_name).read_bytes()
    assert str(emp.dirs["staging"]) not in text and "orig" not in report and report["label"] == "holiday-photos.txt"   # label only: no path, no raw name field
    # The analyst sees a HIGH incident for exactly this transfer, and the audit chain verifies.
    analyst = analyst_view(backend)
    incidents = analyst.get_json("/api/v1/incidents?severity=HIGH&status=OPEN&limit=100")["items"]
    assert report["incident_id"] in {i["id"] for i in incidents} and report["transfer_id"] in {i["transfer_id"] for i in incidents}
    assert analyst.post_json("/api/v1/audit/verify")["valid"] is True
    assert [t["state"] for t in emp.transfers()] == ["BLOCKED"]


# --------------------------------------------------------------------------- criterion 3
@pytest.mark.parametrize("variant,expected", [
    ("aligned_partial", "quarantined"),        # two whole aligned blocks >= threshold 1024: follows policy
    ("single_aligned_block", "quarantined"),   # exactly the threshold
    ("sub_threshold_tail", "delivered"),       # below threshold: policy allows
    ("shifted", "delivered"),                  # KNOWN MISS: one byte shift moves every block boundary
    ("crlf", "delivered"),                     # KNOWN MISS: line-ending change alters every block
    ("utf16", "delivered"),                    # KNOWN MISS: re-encoding
    ("zipped", "delivered"),                   # KNOWN MISS: compression
])
def test_c3_partial_follows_policy_and_transformed_copies_are_documented_known_misses(emp, variant, expected):
    data = source_corpus.variants(INVOICE)[variant]
    put(emp.dirs, "copy.bin", data)
    assert emp.run() == 0
    if expected == "quarantined":
        assert listing(emp.dirs["outbound"]) == [] and any(n.endswith(".held") for n in listing(emp.dirs["quarantine"]))
    else:
        # This is a LIMITATION of fixed 1 KiB block matching, asserted so it can never be hidden.
        assert (emp.dirs["outbound"] / "copy.bin").read_bytes() == data and listing(emp.dirs["quarantine"]) == []


# --------------------------------------------------------------------------- criterion 4
def test_c4_growing_file_is_not_submitted_until_it_is_stable(emp):
    path = emp.dirs["staging"] / "growing.log"
    done, seen_complete = threading.Event(), {}
    full = bytearray()

    handle = open(path, "wb")                                   # the file exists (and is still open) before the agent scans

    def append(index):
        chunk = f"line {index} ".encode() * 50
        full.extend(chunk); handle.write(chunk); handle.flush()

    def writer():
        for index in range(1, 8):
            time.sleep(0.12)
            append(index)
        handle.close()
        done.set()
    append(0)
    agent = emp.agent(settle_seconds=0.4)
    agent.failpoints.hooks["before_submit"] = lambda **_: seen_complete.setdefault("complete", done.is_set())
    thread = threading.Thread(target=writer); thread.start()
    try:
        assert agent.run(once=True, max_wait=40) == 0
    finally:
        thread.join(); finish(agent)
    assert seen_complete["complete"] is True                       # the first submission happened after the writer finished
    assert (emp.dirs["outbound"] / "growing.log").read_bytes() == bytes(full)
    assert len(emp.transfers()) == 1


# --------------------------------------------------------------------------- criterion 5
def test_c5_unsafe_entries_are_rejected_or_held_and_never_submitted(emp):
    original = put(emp.dirs, "real.bin", INVOICE)
    try:
        os.link(original, emp.dirs["staging"] / "hardlink.bin")
    except OSError:
        pytest.skip("hard links unsupported")
    (emp.dirs["staging"] / "folder").mkdir()
    (emp.dirs["staging"] / "folder" / "nested.txt").write_bytes(INVOICE)
    put(emp.dirs, "empty.bin", b"")
    (emp.dirs["staging"] / "huge.bin").write_bytes(b"\0" * (10 * 1024 * 1024 + 1))
    expected = {"HARDLINK", "DIRECTORY_NOT_SCANNED", "EMPTY_FILE", "TOO_LARGE"}
    if os.name != "nt":
        (emp.dirs["staging"] / "link").symlink_to(emp.dirs["state"].parent / "elsewhere")
        os.mkfifo(emp.dirs["staging"] / "pipe")
        expected |= {"LINK_OR_REPARSE_POINT", "SPECIAL_FILE"}
    else:
        target = emp.dirs["state"].parent / "junction-target"; target.mkdir()
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(emp.dirs["staging"] / "junc"), str(target)], capture_output=True)
        if made.returncode == 0:
            expected.add("LINK_OR_REPARSE_POINT")
    assert emp.run() == 0
    assert emp.transfers() == [] and listing(emp.dirs["outbound"]) == [] and listing(emp.dirs["quarantine"]) == []
    reasons = {e["reason"] for e in emp.journal_events() if e["ev"] == "REJECTED"}
    assert reasons == expected
    assert "nested.txt" not in json.dumps(emp.journal_events())    # nonrecursive: nested files are never even seen
    assert len(listing(emp.dirs["staging"])) >= 5                  # everything is left exactly where it was


# --------------------------------------------------------------------------- criterion 6 (real gateway)
def test_c6_revoked_session_is_handled_and_a_non_employee_account_is_refused(emp, backend):
    put(emp.dirs, "a.py", BENIGN)
    agent = emp.agent()
    agent.failpoints.hooks["before_submit"] = _hook_once(lambda: backend.revoke_sessions(emp.name))
    assert agent.run(once=True, max_wait=40) == 0
    finish(agent)
    assert (emp.dirs["outbound"] / "a.py").read_bytes() == BENIGN and len(emp.transfers()) == 1
    analyst_agent = emp.agent()
    analyst_agent.cfg.credentials = Credentials(backend.analyst, backend.password)
    with pytest.raises(Fatal, match="EMPLOYEE"):
        analyst_agent.run(once=True, max_wait=10)
    finish(analyst_agent)


def test_c6_wrong_origin_is_a_fatal_configuration_error_and_delivers_nothing(emp, backend):
    put(emp.dirs, "a.py", BENIGN)
    agent = emp.agent()
    agent.client.origin = "http://127.0.0.1:1"
    with pytest.raises(Fatal, match="origin"):
        agent.run(once=True, max_wait=10)
    finish(agent)
    assert listing(emp.dirs["outbound"]) == [] and emp.transfers() == []


# --------------------------------------------------------------------------- criterion 7
@pytest.mark.parametrize("point,transfers_expected", [
    ("after_prepared", 1),            # before anything was sent: the journaled key is used for the first time
    ("after_submit_journal", 1),      # decided and journaled: resume by GET
    ("after_stage", 1),               # bytes safely on disk: resume WITHOUT a second release
    ("after_replace", 1),             # placed but not journaled: recognised from the outbound file
    ("before_source_remove", 1),      # delivered, source still there: removed, never resubmitted
    ("after_release_response", 2),    # bytes were in memory only: single use consumed, a fresh transfer is needed
])
def test_c7_crash_neither_loses_nor_silently_duplicates(emp, backend, point, transfers_expected):
    put(emp.dirs, "report.py", BENIGN)
    crashed = emp.crash_at(point)
    assert crashed.returncode == 77, crashed.stderr.decode(errors="ignore")[-400:]
    assert (emp.dirs["staging"] / "report.py").exists()                                       # never lost
    assert emp.run() == 0
    assert listing(emp.dirs["staging"]) == [] and listing(emp.dirs["outbound"]) == ["report.py"]   # exactly one copy
    assert (emp.dirs["outbound"] / "report.py").read_bytes() == BENIGN
    states = sorted(t["state"] for t in emp.transfers())
    assert len(states) == transfers_expected
    if transfers_expected == 2:
        assert states[0] in {"DELIVERY_UNKNOWN", "STREAM_FINISHED"} and states[1] == "STREAM_FINISHED"   # the spent release stays visible
    assert listing(emp.dirs["state"] / "tmp") == []
    assert analyst_view(backend).post_json("/api/v1/audit/verify")["valid"] is True


# --------------------------------------------------------------------------- criterion 8
@pytest.mark.parametrize("change", ["registry", "policy"])
def test_c8_stale_decision_delivers_nothing_and_a_fresh_transfer_rescans(emp, backend, change):
    put(emp.dirs, "stale.py", BENIGN)
    admin = backend.client(backend.admin)

    def change_state():
        if change == "registry":
            admin.register_asset(f"unrelated-{time.time_ns()}", b"an unrelated synthetic asset " * 80)
        else:
            current = admin.get_json("/api/v1/policies/active")
            admin.post_json("/api/v1/policies", {"threshold": current["threshold"], "block_enabled": current["block_enabled"], "expected_version": current["id"]}, expected=201)
    agent = emp.agent()
    agent.failpoints.hooks["before_release_call"] = _hook_once(change_state)
    assert agent.run(once=True, max_wait=40) == 0
    finish(agent)
    states = [t["state"] for t in emp.transfers()]
    assert sorted(states) == ["STALE", "STREAM_FINISHED"]              # the stale one released nothing
    assert listing(emp.dirs["outbound"]) == ["stale.py"]


def test_c8_a_file_allowed_a_moment_ago_is_blocked_once_the_registry_changes(emp, backend):
    secret = b"SYNTHETIC late-registered asset " * 90
    put(emp.dirs, "late.py", secret)
    admin = backend.client(backend.admin)
    agent = emp.agent()
    agent.failpoints.hooks["before_release_call"] = _hook_once(lambda: admin.register_asset(f"late-{time.time_ns()}", secret))
    assert agent.run(once=True, max_wait=40) == 0
    finish(agent)
    assert listing(emp.dirs["outbound"]) == [] and any(n.endswith(".held") for n in listing(emp.dirs["quarantine"]))
    assert sorted(t["state"] for t in emp.transfers()) == ["BLOCKED", "STALE"]


# --------------------------------------------------------------------------- criterion 9
def test_c9_kill_during_the_outbound_write_leaves_no_partial_visible_file(emp, backend):
    big = bytes(range(256)) * 1200                                   # ~300 KiB, several write chunks
    put(emp.dirs, "big.bin", big)
    crashed = emp.crash_at("mid_write")
    assert crashed.returncode == 77
    assert listing(emp.dirs["outbound"]) == []                       # nothing partial is ever visible to the consumer
    assert len(listing(emp.dirs["state"] / "tmp")) == 1              # the half-written temp file lives only in state
    assert emp.run() == 0
    assert listing(emp.dirs["outbound"]) == ["big.bin"] and (emp.dirs["outbound"] / "big.bin").read_bytes() == big
    assert listing(emp.dirs["state"] / "tmp") == []


def test_agent_never_changes_what_the_gateway_scans_or_releases(emp, backend):
    """The released and delivered bytes are the exact scanned bytes (digest bound by the gateway)."""
    put(emp.dirs, "digest.py", BENIGN)
    assert emp.run() == 0
    import hashlib
    item = backend.client(emp.name).get_json(f"/api/v1/transfers/{emp.transfers()[0]['id']}")
    assert item["file_sha256"] == hashlib.sha256((emp.dirs["outbound"] / "digest.py").read_bytes()).hexdigest()
