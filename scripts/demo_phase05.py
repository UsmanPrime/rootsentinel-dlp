"""Reproducible end-to-end demonstration of the staging gateway agent.

Starts a DISPOSABLE gateway (temporary runtime, generated key, generated random credentials),
registers a synthetic source corpus as ADMIN, then drives the real agent through the
acceptance scenarios and checks each outcome. It creates nothing persistent: no keys, users or
directories under %LOCALAPPDATA%\\RootSentinel, and everything is removed at the end.

    python -B scripts/demo_phase05.py [--evidence PATH]

Needs the backend dependencies (the same environment as the backend tests). The output and
the evidence JSON contain hashes, states, counts and timings only: no paths or credentials.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))
sys.path.insert(0, str(ROOT / "scripts"))

import source_corpus  # noqa: E402
from rootsentinel_agent.client import GatewayClient  # noqa: E402
from rootsentinel_agent.fsutil import check_location, write_credentials  # noqa: E402
from rootsentinel_agent.journal import Journal  # noqa: E402
from rootsentinel_agent.pipeline import Agent, AgentConfig, Failpoints  # noqa: E402
from rootsentinel_agent.register import register_folder  # noqa: E402

PYTHON = sys.executable
RESULTS: list[dict] = []
ACCOUNT_INDEX = iter(range(1, 100))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check(name: str, ok: bool, **facts):
    RESULTS.append({"check": name, "result": "PASS" if ok else "FAIL", **facts})
    print(("PASS  " if ok else "FAIL  ") + name + ("  " + json.dumps(facts) if facts else ""))
    if not ok:
        raise SystemExit(1)


def free_port_pair() -> tuple[int, str]:
    """Prefer the documented 8000/5173 pair; otherwise any free port with a matching origin."""
    for port in (8000, 0):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            chosen = probe.getsockname()[1]
        return chosen, "http://127.0.0.1:5173" if chosen == 8000 else f"http://127.0.0.1:{chosen}"
    raise RuntimeError("no free loopback port")


class Scenario:
    """One employee account with its own staging/outbound/quarantine/state directories."""

    def __init__(self, demo, name: str):
        self.demo, self.name, self.index = demo, name, next(ACCOUNT_INDEX)
        self.username = f"demo-emp-{self.index}"
        self.root = demo.work / name
        self.dirs = {n: self.root / n for n in ("staging", "outbound", "quarantine", "state")}
        for path in self.dirs.values():
            path.mkdir(parents=True)
            if os.name != "nt":
                path.chmod(0o700)
        (self.dirs["state"] / "tmp").mkdir()
        if os.name != "nt":
            (self.dirs["state"] / "tmp").chmod(0o700)
        self.creds = self.root / "agent-credentials" / "agent.json"
        write_credentials(self.creds, self.username, demo.password)

    def drop(self, name: str, data: bytes, age: float = 5.0) -> None:
        path = self.dirs["staging"] / name
        path.write_bytes(data)
        old = time.time() - age
        os.utime(path, (old, old))

    def cli(self, *extra: str, timeout: float = 180.0) -> subprocess.CompletedProcess:
        command = [PYTHON, "-B", "-m", "rootsentinel_agent", "run", "--root", str(self.root), "--base-url", self.demo.base_url,
                   "--origin", self.demo.origin, "--credentials-file", str(self.creds), "--once", "--poll-interval", "0.2",
                   "--settle", "0.5", "--rate-per-minute", "25", "--max-wait", "150", *extra]
        return subprocess.run(command, cwd=ROOT / "agent", capture_output=True, text=True, timeout=timeout)

    def agent(self, failpoints=None) -> Agent:
        from rootsentinel_agent.fsutil import Credentials
        journal = Journal(self.dirs["state"] / "journal.jsonl")
        journal.open()
        config = AgentConfig(self.dirs["staging"], self.dirs["outbound"], self.dirs["quarantine"], self.dirs["state"],
                             Credentials(self.username, self.demo.password), poll_interval=0.1, settle_seconds=0.3,
                             rate_per_minute=25, wait_scale=0.1, min_relogin=0.0)
        return Agent(config, GatewayClient(self.demo.base_url, self.demo.origin), journal, failpoints or Failpoints())

    def outbound(self) -> dict[str, bytes]:
        return {p.name: p.read_bytes() for p in self.dirs["outbound"].iterdir()}

    def quarantined(self) -> int:
        return sum(1 for p in self.dirs["quarantine"].iterdir() if p.name.endswith(".held"))

    def transfers(self) -> list[str]:
        return sorted(t["state"] for t in self.demo.client(self.username).get_json("/api/v1/transfers?limit=100")["items"])


class Demo:
    def __init__(self):
        self.work = Path(tempfile.mkdtemp(prefix="rs-demo-"))
        check_location(self.work, "demo work directory")
        self.server = None

    def start(self):
        port, self.origin = free_port_pair()
        self.base_url = f"http://127.0.0.1:{port}"
        state = self.work / "gateway-state"
        env = dict(os.environ, ROOTSENTINEL_DEMO_STATE=str(state), ROOTSENTINEL_API_PORT=str(port), ROOTSENTINEL_ORIGIN=self.origin,
                   PYTHONDONTWRITEBYTECODE="1")
        self.log = open(self.work / "gateway.log", "wb")
        self.server = subprocess.Popen([PYTHON, "-B", "-m", "tests.agent_server"], cwd=ROOT / "backend", env=env,
                                       stdout=self.log, stderr=subprocess.STDOUT)
        session = state / "demo-session.json"
        deadline = time.time() + 90
        while time.time() < deadline:
            if self.server.poll() is not None:
                raise RuntimeError("the disposable gateway exited; see its log")
            try:
                with urllib.request.urlopen(self.base_url + "/health", timeout=2) as response:
                    if response.status == 200 and session.exists():
                        break
            except OSError:
                time.sleep(0.4)
        else:
            raise RuntimeError("the disposable gateway did not become ready")
        self.password = json.loads(session.read_text())["password"]

    def client(self, username: str) -> GatewayClient:
        client = GatewayClient(self.base_url, self.origin)
        client.login(username, self.password)
        return client

    def stop(self):
        if self.server and self.server.poll() is None:
            self.server.terminate()
            try:
                self.server.wait(15)
            except subprocess.TimeoutExpired:
                self.server.kill()
        if getattr(self, "log", None):
            self.log.close()
        shutil.rmtree(self.work, ignore_errors=True)


def run(evidence: Path | None) -> int:
    corpus = source_corpus.corpus()
    protected = {n: d for n, d in corpus.items() if n.startswith("protected/")}
    invoice = protected["protected/billing/invoice_engine.py"]
    variants = source_corpus.variants(invoice)
    demo = Demo()
    started = time.time()
    try:
        demo.start()
        health = json.loads(urllib.request.urlopen(demo.base_url + "/health", timeout=5).read())
        check("gateway is local mode and release is configured", health["mode"] == "local" and health["release_configured"], mode=health["mode"])

        folder = demo.work / "corpus"
        for name, data in protected.items():
            (folder / name).parent.mkdir(parents=True, exist_ok=True)
            (folder / name).write_bytes(data)
        admin = demo.client("demo-admin")
        summary = register_folder(admin, folder / "protected")
        check("ADMIN registered the synthetic protected corpus (serial, one request per file)", summary["registered"] == len(protected) and not summary["failed"], registered=summary["registered"])

        # 1. benign delivered byte-identical -----------------------------------------------------------
        one = Scenario(demo, "benign")
        benign = corpus["benign/utils/string_helpers.py"]
        one.drop("string helpers.py", benign)
        t0 = time.time()
        done = one.cli()
        elapsed = round(time.time() - t0, 2)
        check("benign file delivered byte-identical and staging emptied", done.returncode == 0 and one.outbound() == {"string helpers.py": benign} and not list(one.dirs["staging"].iterdir()),
              sha256=sha(benign), seconds_including_startup=elapsed, transfer_states=one.transfers())

        # 2 + 3. protected copies are blocked; known misses are delivered and say so --------------------------
        two = Scenario(demo, "protected")
        two.drop("holiday photos.txt", variants["exact_renamed"])
        two.drop("part.dat", variants["aligned_partial"])
        two.drop("block.dat", variants["single_aligned_block"])
        done = two.cli()
        check("renamed, partial and single-block copies were quarantined and NOTHING reached outbound", done.returncode == 0 and two.outbound() == {} and two.quarantined() == 3,
              quarantined=two.quarantined(), transfer_states=two.transfers())
        analyst = demo.client("demo-analyst")
        incidents = analyst.get_json("/api/v1/incidents?status=OPEN&limit=100")["items"]
        severities = sorted(i["severity"] for i in incidents)
        check("the gateway opened one HIGH (exact) and two MEDIUM (threshold) incidents", severities == ["HIGH", "MEDIUM", "MEDIUM"], severities=severities)
        verify = analyst.post_json("/api/v1/audit/verify")
        check("HMAC audit chain verifies after the blocks", verify["valid"] is True, through_sequence=verify["through_sequence"])

        three = Scenario(demo, "known-misses")
        misses = {"shifted.dat": "shifted", "crlf.dat": "crlf", "utf16.dat": "utf16", "zipped.dat": "zipped", "tail.dat": "sub_threshold_tail"}
        for name, variant in misses.items():
            three.drop(name, variants[variant])
        done = three.cli()
        delivered = three.outbound()
        check("KNOWN MISSES: shifted, CRLF, UTF-16, zipped and sub-threshold copies are delivered (documented limitation of fixed 1 KiB blocks)",
              done.returncode == 0 and all(delivered[n] == variants[v] for n, v in misses.items()), delivered=sorted(delivered))

        # 4. a growing file is not submitted until stable ---------------------------------------------------
        four = Scenario(demo, "growing")
        path = four.dirs["staging"] / "growing.log"
        handle = open(path, "wb")
        full = bytearray()

        def append(i):
            chunk = f"entry {i} ".encode() * 60
            full.extend(chunk); handle.write(chunk); handle.flush()
        append(0)

        def writer():
            for i in range(1, 9):
                time.sleep(0.25); append(i)
            handle.close()
            writer.finished = time.time()
        writer.finished = None
        thread = threading.Thread(target=writer); thread.start()
        done = four.cli("--settle", "1.0")
        thread.join()
        from datetime import datetime
        prepared = next((e for e in map(json.loads, (four.dirs["state"] / "journal.jsonl").read_text().splitlines()) if e["ev"] == "PREPARED"), None)
        prepared_after_writer = prepared is not None and datetime.fromisoformat(prepared["t"].replace("Z", "+00:00")).timestamp() > writer.finished
        check("growing file was admitted only after it stopped growing and delivered whole", done.returncode == 0 and four.outbound() == {"growing.log": bytes(full)} and prepared_after_writer,
              sha256=sha(bytes(full)), transfers=len(four.transfers()))

        # 5. unsafe inputs ---------------------------------------------------------------------------------------
        five = Scenario(demo, "unsafe")
        five.drop("real.bin", invoice)
        try:
            os.link(five.dirs["staging"] / "real.bin", five.dirs["staging"] / "hardlink.bin")
        except OSError:
            pass
        (five.dirs["staging"] / "folder").mkdir()
        (five.dirs["staging"] / "folder" / "nested.txt").write_bytes(invoice)
        five.drop("empty.bin", b"")
        done = five.cli()
        reasons = sorted({json.loads(l)["reason"] for l in (five.dirs["state"] / "journal.jsonl").read_text().splitlines() if json.loads(l)["ev"] == "REJECTED"})
        check("hardlink, directory and empty file were rejected, left in place and never submitted",
              done.returncode == 0 and five.outbound() == {} and five.transfers() == [] and "DIRECTORY_NOT_SCANNED" in reasons and "EMPTY_FILE" in reasons, reasons=reasons)

        # 6. STALE: the registry changes between the ALLOW and the release ----------------------------------------------
        six = Scenario(demo, "stale")
        late = b"SYNTHETIC late registered asset " * 90
        six.drop("late.py", late)
        agent = six.agent()
        fired = {"done": False}

        def register_now(**_):
            if not fired["done"]:
                fired["done"] = True
                admin.register_asset(f"late-{time.time_ns()}", late)
        agent.failpoints.hooks["before_release_call"] = register_now
        code = agent.run(once=True, max_wait=120)
        agent.journal.close(); agent.close()
        check("a file ALLOWED a moment earlier was STALE at release, delivered nothing, and the rescan BLOCKED it",
              code == 0 and six.outbound() == {} and six.quarantined() == 1 and six.transfers() == ["BLOCKED", "STALE"], transfer_states=six.transfers())

        # 7. crash after the single-use release, before the write ---------------------------------------------------------
        seven = Scenario(demo, "crash")
        payload = corpus["benign/docs/readme_notes.txt"]
        seven.drop("notes.txt", payload)
        crash = subprocess.run([PYTHON, "-B", str(ROOT / "agent" / "tests" / "driver.py"), "--root", str(seven.root), "--base-url", demo.base_url,
                                "--origin", demo.origin, "--credentials-file", str(seven.creds), "--crash", "after_release_response"],
                               capture_output=True, text=True, timeout=180)
        check("agent was killed after receiving the released bytes: nothing delivered, source kept", crash.returncode == 77 and seven.outbound() == {} and (seven.dirs["staging"] / "notes.txt").exists())
        done = seven.cli()
        states = seven.transfers()
        check("restart delivered exactly one copy; the spent release stays visible in the audit trail",
              done.returncode == 0 and seven.outbound() == {"notes.txt": payload} and len(states) == 2 and states[-1] == "STREAM_FINISHED", transfer_states=states)

        final = analyst.post_json("/api/v1/audit/verify")
        check("audit chain still verifies after every scenario", final["valid"] is True, through_sequence=final["through_sequence"])
        print(f"\nAll {len(RESULTS)} checks passed in {time.time() - started:.1f}s")
        if evidence:
            evidence.write_text(json.dumps({"script": "scripts/demo_phase05.py", "platform": sys.platform, "python": sys.version.split()[0],
                                            "duration_seconds": round(time.time() - started, 1), "checks": RESULTS,
                                            "note": "Disposable gateway, generated credentials, synthetic corpus. Hashes, states and counts only."}, indent=2) + "\n", encoding="utf-8")
        return 0
    finally:
        demo.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, help="write a sanitized JSON record of the checks here")
    raise SystemExit(run(parser.parse_args().evidence))
