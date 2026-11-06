import random

import pytest

from rootsentinel_agent.admission import StabilityTracker, rejection_key, scan_directory
from rootsentinel_agent.fsutil import DirHandle, Observation
from rootsentinel_agent.journal import Journal, JournalCorrupt
from rootsentinel_agent.labels import SERVER_PATTERN, outbound_name, sanitize_label, strip_ready
from support import put


# ------------------------------------------------------------------ labels
TRICKY = ["report.pdf", "  weird name!!.docx", "CON.txt", "con", "LPT1.log", ".hidden", "-x", "..", "", ".ready",
          "données.txt", "日本語.txt", "a" * 300 + ".tar.gz", "trail. ", "x" * 119 + ".ab", "a/b\\c:d*e?.txt", "name\n.txt", "\x00bad"]


@pytest.mark.parametrize("name", TRICKY)
def test_sanitized_label_is_accepted_by_the_gateway_pattern(name):
    label = sanitize_label(strip_ready(name))
    assert SERVER_PATTERN.fullmatch(label) and 1 <= len(label) <= 120
    assert sanitize_label(label) == label                      # idempotent
    assert not label.endswith((".", " "))                      # safe as a Windows file name
    assert label.split(".")[0].upper() not in {"CON", "PRN", "AUX", "NUL", "COM1", "LPT1"}


def test_sanitizer_fuzz_never_produces_a_rejected_label():
    rng = random.Random(20261106)
    alphabet = "abcXYZ019 ._()-/\\:*?\"<>|\x00\n\t日é!@#$%^&+=[]{};,'`~"
    for _ in range(3000):
        name = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 200)))
        label = sanitize_label(name)
        assert SERVER_PATTERN.fullmatch(label) and len(label) <= 120, repr(name)


def test_ready_suffix_is_stripped_only_as_a_suffix():
    assert strip_ready("a.txt.ready") == "a.txt" and strip_ready("a.READY") == "a" and strip_ready("ready.txt") == "ready.txt"


def test_outbound_name_collision_is_resolved_case_insensitively():
    taken = {"report.pdf"}
    name = outbound_name("Report.PDF", "12345678-aaaa", lambda n: n in taken)
    assert name != "Report.PDF" and name.endswith(".PDF") and "12345678" in name
    taken.add(name.lower())
    assert outbound_name("Report.PDF", "12345678-aaaa", lambda n: n in taken) not in {"Report.PDF", name}


# ------------------------------------------------------------------ journal
def test_journal_round_trip_and_allowlist(tmp_path):
    journal = Journal(tmp_path / "j.jsonl"); journal.open()
    journal.append("e1", "PREPARED", key="k", label="a.txt", out="a.txt", orig="a.txt", src=[1, 2, 3, 4], sha256="0" * 64, size=3, attempt=1)
    journal.append("e1", "SUBMITTED", transfer="t1", tstate="ALLOWED")
    with pytest.raises(ValueError):
        journal.append("e1", "SUBMITTED", password="nope")       # unknown field names are refused
    with pytest.raises(ValueError):
        journal.append("e1", "NOT_AN_EVENT")
    journal.close()
    again = Journal(tmp_path / "j.jsonl"); again.open()
    assert again.entries["e1"]["state"] == "SUBMITTED" and again.entries["e1"]["transfer"] == "t1"
    assert again.known_source(Observation(1, 2, 3, 4)) and not again.known_source(Observation(9, 9, 9, 9))
    again.close()


def test_torn_final_record_is_discarded_and_previous_state_stands(tmp_path):
    path = tmp_path / "j.jsonl"
    journal = Journal(path); journal.open()
    journal.append("e1", "PREPARED", key="k", label="a", out="a", orig="a", src=[1, 2, 3, 4], sha256="0" * 64, size=3, attempt=1)
    journal.append("e1", "SUBMITTED", transfer="t1", tstate="ALLOWED")
    journal.close()
    with open(path, "ab") as handle:
        handle.write(b'{"v":1,"seq":99,"ev":"RELEAS')              # crash mid-write
    reloaded = Journal(path); reloaded.open()
    assert reloaded.entries["e1"]["state"] == "SUBMITTED"
    reloaded.append("e1", "RELEASING"); reloaded.close()
    final = Journal(path); final.open()
    assert final.entries["e1"]["state"] == "RELEASING"
    final.close()


def test_damaged_middle_record_fails_closed(tmp_path):
    path = tmp_path / "j.jsonl"
    journal = Journal(path); journal.open()
    for state in ("PREPARED", "SUBMITTED", "RELEASING"):
        journal.append("e1", state, **({"key": "k"} if state == "PREPARED" else {}))
    journal.close()
    lines = path.read_bytes().split(b"\n")
    lines[1] = lines[1].replace(b'"SUBMITTED"', b'"DELIVERED"')     # content no longer matches its CRC
    path.write_bytes(b"\n".join(lines))
    with pytest.raises(JournalCorrupt):
        Journal(path).open()


# ------------------------------------------------------------------ admission
def test_stability_requires_consecutive_identical_observations_and_quiet_time():
    tracker = StabilityTracker(stable_polls=2, settle_seconds=1.0)
    old = 0
    ob = Observation(1, 10, 100, old)
    assert tracker.step({"a.txt": ob}, now_ns=10**9 * 5) == ([], ["a.txt"])      # first sighting
    assert tracker.step({"a.txt": ob}, now_ns=10**9 * 6) == (["a.txt"], [])      # stable twice and quiet
    grown = Observation(1, 10, 200, old)
    assert tracker.step({"a.txt": grown}, now_ns=10**9 * 7) == ([], ["a.txt"])   # growth resets the count
    fresh = Observation(1, 11, 100, 10**9 * 7)
    tracker.step({"b.txt": fresh}, now_ns=10**9 * 7)
    assert tracker.step({"b.txt": fresh}, now_ns=int(10**9 * 7.2)) == ([], ["b.txt"])   # identical but not quiet long enough


def test_ready_hint_is_admitted_at_once_and_require_ready_ignores_others():
    ob = Observation(1, 10, 100, 10**9 * 5)
    tracker = StabilityTracker(2, 100.0)
    assert tracker.step({"x.txt.ready": ob}, now_ns=10**9 * 5)[0] == ["x.txt.ready"]
    strict = StabilityTracker(2, 0.0, require_ready=True)
    for _ in range(3):
        ready, waiting = strict.step({"x.txt": ob, "y.ready": Observation(1, 11, 5, 0)}, now_ns=10**12)
    assert ready == ["y.ready"] and waiting == []


def test_scan_is_nonrecursive_and_reports_unadmissible_entries(dirs):
    put(dirs, "ok.txt", b"data")
    put(dirs, "empty.txt", b"")
    (dirs["staging"] / "sub").mkdir()
    (dirs["staging"] / "sub" / "inner.txt").write_bytes(b"nested files are never read")
    handle = DirHandle(dirs["staging"])
    try:
        scan = scan_directory(handle)
    finally:
        handle.close()
    assert set(scan.observations) == {"ok.txt"}
    assert {name: reason for name, (reason, _) in scan.rejections.items()} == {"empty.txt": "EMPTY_FILE", "sub": "DIRECTORY_NOT_SCANNED"}
    assert "inner.txt" not in scan.observations and "inner.txt" not in scan.rejections
    reason, st = scan.rejections["sub"]
    assert rejection_key(reason, st) == rejection_key(reason, st)
