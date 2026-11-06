"""Criteria 1, 6 and 10 against a stateful fake gateway with fault injection.

Every test asserts the safety property first: nothing reaches outbound unless the gateway
allowed it AND released bytes that match the locally computed digest.
"""
import json
import logging
import os

import pytest

from rootsentinel_agent.client import GatewayClient
from rootsentinel_agent.fsutil import Credentials
from rootsentinel_agent.pipeline import Fatal, RateBudget
from support import PASSWORD, SENTINEL_COOKIE, SENTINEL_CSRF, MiniGateway, finish, listing, make_agent, put

DATA = b"ordinary synthetic business note\n" * 40


def run(agent, **kw):
    try:
        return agent.run(once=True, max_wait=kw.pop("max_wait", 20.0))
    finally:
        finish(agent)


def keys(mini):
    return [entry[1] for entry in mini.log if entry[0] == "submit"]


def test_happy_path_delivers_identical_bytes_and_empties_staging(dirs, mini):
    put(dirs, "Quarterly Notes (v2).txt", DATA)
    assert run(make_agent(dirs, mini.client())) == 0
    assert listing(dirs["staging"]) == [] and listing(dirs["outbound"]) == ["Quarterly Notes (v2).txt"]
    assert (dirs["outbound"] / "Quarterly Notes (v2).txt").read_bytes() == DATA
    assert listing(dirs["state"] / "tmp") == [] and listing(dirs["quarantine"]) == []
    assert mini.count("submit") == 1 and mini.count("release") == 1 and mini.count("login") == 1


def test_blocked_file_is_quarantined_with_a_payload_free_report_and_never_released(dirs):
    mini = MiniGateway(decision=lambda data: "BLOCKED")
    try:
        put(dirs, "notes.txt", DATA)
        assert run(make_agent(dirs, mini.client())) == 0
        assert listing(dirs["outbound"]) == [] and listing(dirs["staging"]) == []
        names = listing(dirs["quarantine"])
        held = next(n for n in names if n.endswith(".held")); report = next(n for n in names if n.endswith(".report.json"))
        assert (dirs["quarantine"] / held).read_bytes() == DATA
        text = (dirs["quarantine"] / report).read_text()
        body = json.loads(text)
        assert body["decision_outcome"] == "BLOCK" and body["exact_match"] is True and body["incident_id"]
        assert "ordinary synthetic" not in text and str(dirs["staging"]) not in text and "notes.txt" not in text.replace(body["label"], "")
        assert mini.count("release") == 0                      # a BLOCK never reaches the release call
    finally:
        mini.close()


@pytest.mark.parametrize("fault", [
    ("status", 401, "AUTHENTICATION_REQUIRED"), ("status", 429, "TRANSFER_RATE_LIMIT"), ("status", 429, "PENDING_TRANSFER_CAPACITY"),
    ("status", 503, "SCAN_CAPACITY"), ("status", 503, "DATABASE_UNAVAILABLE"), ("status", 400, "INCOMPLETE_UPLOAD"),
    ("drop",), ("sleep", 0.6)], ids=lambda f: "-".join(map(str, f)))
def test_submit_faults_deliver_nothing_early_and_recover_with_one_idempotency_key(dirs, mini, fault):
    mini.faults["submit"] = [fault, fault]
    put(dirs, "a.txt", DATA)
    agent = make_agent(dirs, mini.client(timeout=0.25, submit_timeout=0.25))
    assert run(agent) == 0
    assert set(keys(mini)) and len(set(keys(mini))) == 1       # every retry replayed the SAME key
    assert len(mini.transfers) == 1                            # recovery caused no duplicate transfer
    assert listing(dirs["outbound"]) == ["a.txt"] and (dirs["outbound"] / "a.txt").read_bytes() == DATA
    assert mini.count("release") == 1


def test_backend_down_delivers_nothing_then_recovery_has_no_duplicates(dirs, mini):
    dead = GatewayClient("http://127.0.0.1:9", "http://127.0.0.1:5173", timeout=0.2)   # nothing listens on the discard port
    put(dirs, "a.txt", DATA)
    assert run(make_agent(dirs, dead), max_wait=0.5) == 3     # gave up waiting, nothing delivered
    assert listing(dirs["outbound"]) == [] and listing(dirs["staging"]) == ["a.txt"]
    assert run(make_agent(dirs, mini.client())) == 0          # restart: replays the journaled key
    assert listing(dirs["outbound"]) == ["a.txt"] and len(mini.transfers) == 1 and len(set(keys(mini))) == 1


def test_forbidden_origin_stops_the_agent_without_delivering(dirs, mini):
    put(dirs, "a.txt", DATA)
    agent = make_agent(dirs, mini.client())
    agent.client.origin = "http://evil.example"
    with pytest.raises(Fatal, match="origin"):
        agent.run(once=True, max_wait=5)
    finish(agent)
    assert listing(dirs["outbound"]) == [] and mini.count("submit") == 0


def test_wrong_credentials_and_wrong_role_stop_the_agent(dirs, mini):
    put(dirs, "a.txt", DATA)
    agent = make_agent(dirs, mini.client())
    agent.cfg.credentials = Credentials("emp-test", "not-the-password")
    with pytest.raises(Fatal, match="rejected"):
        agent.run(once=True, max_wait=5)
    finish(agent)
    admin = MiniGateway(role="ADMIN")
    try:
        agent = make_agent(dirs, admin.client())
        with pytest.raises(Fatal, match="EMPLOYEE"):
            agent.run(once=True, max_wait=5)
        finish(agent)
        assert admin.count("submit") == 0 and listing(dirs["outbound"]) == []
    finally:
        admin.close()


def test_release_503_is_retried_and_stale_causes_a_fresh_transfer(dirs, mini):
    mini.faults["release"] = [("status", 503, "TRANSFER_CAPACITY"), ("status", 409, "TRANSFER_STALE")]
    put(dirs, "a.txt", DATA)
    assert run(make_agent(dirs, mini.client())) == 0
    assert len(mini.transfers) == 2 and len(set(keys(mini))) == 2        # STALE => new evaluation, new key
    assert listing(dirs["outbound"]) == ["a.txt"] and (dirs["outbound"] / "a.txt").read_bytes() == DATA


def test_release_consumed_but_connection_lost_never_delivers_partial_or_duplicates(dirs, mini):
    mini.faults["release"] = [("consume",)]
    put(dirs, "a.txt", DATA)
    assert run(make_agent(dirs, mini.client())) == 0
    states = sorted(t["state"] for t in mini.transfers.values())
    assert states == ["DELIVERY_UNKNOWN", "STREAM_FINISHED"]             # the lost release is visible, not hidden
    assert listing(dirs["outbound"]) == ["a.txt"] and (dirs["outbound"] / "a.txt").read_bytes() == DATA


def test_released_bytes_that_do_not_match_the_local_digest_are_never_delivered(dirs, mini):
    mini.tamper_release = lambda data: data[:-1] + b"X"
    put(dirs, "a.txt", DATA)
    assert run(make_agent(dirs, mini.client(), max_attempts=2)) == 0
    assert listing(dirs["outbound"]) == [] and listing(dirs["staging"]) == ["a.txt"]
    held = [e for e in json.loads("[" + ",".join(open(dirs["state"] / "journal.jsonl")).replace("}\n,", "},") + "]") if e["ev"] == "HELD"]
    assert held and held[-1]["reason"] == "ATTEMPTS_EXHAUSTED:RELEASE_BYTES_MISMATCH"


def test_truncated_release_body_is_never_delivered(dirs, mini):
    def short_read(data):
        return data[:10]
    mini.tamper_release = short_read
    put(dirs, "a.txt", DATA)
    assert run(make_agent(dirs, mini.client(), max_attempts=2)) == 0
    assert listing(dirs["outbound"]) == [] and listing(dirs["staging"]) == ["a.txt"]


def test_gateway_that_hashed_different_bytes_is_not_asked_to_release(dirs, mini):
    mini.lie_digest = True
    put(dirs, "a.txt", DATA)
    assert run(make_agent(dirs, mini.client())) == 0
    assert mini.count("release") == 0 and listing(dirs["outbound"]) == []
    assert listing(dirs["staging"]) == ["a.txt"]


def test_file_edited_after_it_was_read_delivers_only_the_scanned_bytes_and_keeps_the_edit(dirs, mini):
    path = put(dirs, "a.txt", DATA)
    agent = make_agent(dirs, mini.client())
    edited = DATA + b"edited after observation\n"
    state = {"done": False}

    def tamper(**_):
        if not state["done"]:
            state["done"] = True
            path.write_bytes(edited)
    agent.failpoints.hooks["before_submit"] = tamper
    assert agent.run(once=True, max_wait=20) == 0
    finish(agent)
    # Both versions are delivered, each exactly as it was scanned; the edit was never lost or merged.
    delivered = sorted(p.read_bytes() for p in dirs["outbound"].iterdir())
    assert delivered == sorted([DATA, edited]) and listing(dirs["staging"]) == []


def test_changed_source_after_restart_is_abandoned_and_the_new_content_is_rescanned(dirs, mini):
    dead = GatewayClient("http://127.0.0.1:9", "http://127.0.0.1:5173", timeout=0.2)
    path = put(dirs, "a.txt", DATA)
    assert run(make_agent(dirs, dead), max_wait=0.4) == 3                    # journaled PREPARED, nothing sent
    path.write_bytes(b"completely different content\n")
    os.utime(path, (os.stat(path).st_atime, os.stat(path).st_mtime - 5))
    assert run(make_agent(dirs, mini.client())) == 0
    assert [p.read_bytes() for p in dirs["outbound"].iterdir()] == [b"completely different content\n"]
    states = [json.loads(line)["ev"] for line in (dirs["state"] / "journal.jsonl").read_text().splitlines()]
    assert "ABANDONED" in states and len(mini.transfers) == 1                 # the old content never reached the gateway


def test_rate_budget_never_exceeds_its_window():
    clock = {"now": 0.0}
    slept = []
    budget = RateBudget(3, sleep=lambda s: (slept.append(s), clock.__setitem__("now", clock["now"] + s)))
    import rootsentinel_agent.pipeline as pipeline
    real = pipeline.time.monotonic
    pipeline.time.monotonic = lambda: clock["now"]
    try:
        for _ in range(7):
            budget.acquire()
    finally:
        pipeline.time.monotonic = real
    assert slept, "the budget must make the caller wait once its window is full"


def test_non_loopback_plain_http_is_refused():
    with pytest.raises(ValueError, match="loopback"):
        GatewayClient("http://gateway.example.com", "http://127.0.0.1:5173")
    GatewayClient("https://gateway.example.com", "https://gateway.example.com")


def test_no_credentials_cookies_or_tokens_leak_into_logs_journal_reports_or_names(dirs, mini, caplog):
    caplog.set_level(logging.DEBUG)
    mini.faults["submit"] = [("status", 503, "SCAN_CAPACITY"), ("status", 401, "AUTHENTICATION_REQUIRED")]
    put(dirs, "secret-looking name.txt", DATA)
    put(dirs, "second.txt", DATA + b"2")
    mini.decision = lambda data: "BLOCKED" if data.endswith(b"2") else "ALLOWED"
    assert run(make_agent(dirs, mini.client())) == 0
    haystack = [caplog.text, (dirs["state"] / "journal.jsonl").read_text()]
    for folder in ("quarantine", "outbound", "state"):
        haystack += [str(p) for p in dirs[folder].rglob("*")]
        haystack += [p.read_text(errors="ignore") for p in dirs[folder].rglob("*.json")]
    joined = "\n".join(haystack)
    for secret in (PASSWORD, SENTINEL_COOKIE, SENTINEL_CSRF):
        assert secret not in joined
