"""CLI wiring, the .ready hint, hold/requeue/status, the ADMIN register tool, and Linux-only uid separation."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

import source_corpus
from rootsentinel_agent import cli
from rootsentinel_agent.register import collect_files, register_folder
from support import MiniGateway, finish, listing, make_agent, make_dirs, put

DATA = b"plain synthetic business note\n" * 30


def run(agent, **kw):
    try:
        return agent.run(once=True, max_wait=kw.pop("max_wait", 20.0))
    finally:
        finish(agent)


# ------------------------------------------------------------------ .ready hint and --require-ready
def test_ready_files_are_admitted_at_once_and_the_suffix_is_not_delivered(dirs, mini):
    put(dirs, "export.csv.ready", DATA, age=0.0)                       # just renamed: no settle time needed
    assert run(make_agent(dirs, mini.client(), settle_seconds=60.0)) == 0
    assert listing(dirs["outbound"]) == ["export.csv"] and (dirs["outbound"] / "export.csv").read_bytes() == DATA


def test_ordinary_files_wait_for_the_settle_time(dirs, mini):
    put(dirs, "export.csv", DATA, age=0.0)
    agent = make_agent(dirs, mini.client(), settle_seconds=60.0)
    assert run(agent, max_wait=0.5) == 3                              # still "being written" as far as the agent can tell
    assert mini.count("submit") == 0 and listing(dirs["outbound"]) == []


def test_require_ready_never_touches_other_files(dirs, mini):
    put(dirs, "plain.txt", DATA)
    put(dirs, "signalled.txt.ready", DATA + b"x")
    assert run(make_agent(dirs, mini.client(), require_ready=True)) == 0
    assert listing(dirs["outbound"]) == ["signalled.txt"] and listing(dirs["staging"]) == ["plain.txt"]
    assert mini.count("submit") == 1


# ------------------------------------------------------------------ hold, status, requeue
def test_held_file_stays_put_status_shows_it_and_requeue_delivers_it_after_the_fault_clears(dirs, mini, capsys):
    mini.tamper_release = lambda data: data[:-1] + b"X"
    put(dirs, "a.txt", DATA)
    assert run(make_agent(dirs, mini.client(), max_attempts=2)) == 0
    assert listing(dirs["outbound"]) == [] and listing(dirs["staging"]) == ["a.txt"]
    root = dirs["staging"].parent
    assert cli.main(["status", "--root", str(root)]) == 0
    out = capsys.readouterr().out
    assert "HELD=1" in out and "ATTEMPTS_EXHAUSTED:RELEASE_BYTES_MISMATCH" in out
    assert run(make_agent(dirs, mini.client(), max_attempts=2)) == 0   # a restart alone does NOT retry a held file
    assert listing(dirs["outbound"]) == []
    mini.tamper_release = None                                         # the fault is repaired
    assert cli.main(["requeue", "--root", str(root), "--all-held"]) == 0
    assert run(make_agent(dirs, mini.client(), max_attempts=2)) == 0
    assert (dirs["outbound"] / "a.txt").read_bytes() == DATA and listing(dirs["staging"]) == []


def test_second_instance_cannot_use_the_same_state_directory(dirs, mini):
    from rootsentinel_agent.fsutil import AlreadyRunning, InstanceLock
    with InstanceLock(dirs["state"] / "lock"):
        with pytest.raises(AlreadyRunning):
            with InstanceLock(dirs["state"] / "lock"):
                pass


# ------------------------------------------------------------------ ADMIN registration tool
@pytest.fixture(scope="module")
def backend(tmp_path_factory):
    pytest.importorskip("fastapi")
    from backend_fixture import RealBackend
    server = RealBackend(tmp_path_factory.mktemp("registry-gateway")).start()
    yield server
    server.stop()


def test_register_folder_is_serial_idempotent_and_skips_unsafe_files(backend, tmp_path):
    folder = tmp_path / "corpus"
    for name, data in source_corpus.corpus().items():
        if name.startswith("protected/"):
            target = folder / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    (folder / "empty.py").write_bytes(b"")
    if os.name != "nt":
        (folder / "link.py").symlink_to(folder / "protected" / "ml" / "ranking_core.py")
    labels = [label for label, _ in collect_files(folder)]
    assert len(labels) == len(set(map(str.lower, labels))) == 5        # unique labels; empty and linked files skipped
    admin = backend.client(backend.admin)
    first = register_folder(admin, folder, prefix="demo-")
    assert first["registered"] == 5 and first["failed"] == 0
    second = register_folder(admin, folder, prefix="demo-")
    assert second["existing"] == 5 and second["registered"] == 0       # re-running changes nothing
    assets = admin.get_json("/api/v1/assets?limit=100")["items"]
    assert sum(1 for a in assets if a["label"].startswith("demo-")) == 5


def test_a_non_admin_cannot_register_assets(backend, tmp_path):
    folder = tmp_path / "x"; folder.mkdir(); (folder / "a.py").write_bytes(b"synthetic " * 50)
    summary = register_folder(backend.client(backend.create_user("EMPLOYEE")), folder)
    assert summary["registered"] == 0 and summary["failed"] == 1


# ------------------------------------------------------------------ the CLI end to end against the real gateway
def test_cli_run_once_with_a_credentials_file_against_the_real_gateway(backend, tmp_path, capsys):
    from rootsentinel_agent.fsutil import write_credentials
    name = backend.create_user("EMPLOYEE")
    creds = tmp_path / "private-cred" / "agent.json"
    write_credentials(creds, name, backend.password)
    root = tmp_path / "layout"
    base = ["--root", str(root), "--base-url", backend.base_url, "--origin", backend.origin, "--credentials-file", str(creds)]
    assert cli.main(["init", "--root", str(root)]) == 0
    assert cli.main(["check", *base]) == 0
    (root / "staging" / "cli-note.txt").write_bytes(DATA)
    old = __import__("time").time() - 5
    os.utime(root / "staging" / "cli-note.txt", (old, old))
    assert cli.main(["run", *base, "--once", "--poll-interval", "0.02", "--settle", "0.05", "--max-wait", "40"]) == 0
    assert (root / "outbound" / "cli-note.txt").read_bytes() == DATA and listing(root / "staging") == []
    text = capsys.readouterr()
    assert backend.password not in text.out + text.err


def test_cli_check_refuses_a_gateway_that_is_not_ready(tmp_path, capsys):
    gateway = MiniGateway()
    try:
        # MiniGateway reports release_configured=true; make the account an ADMIN to show the role rule in `check`.
        gateway.role = "ADMIN"
        from rootsentinel_agent.fsutil import write_credentials
        creds = tmp_path / "c" / "agent.json"
        write_credentials(creds, "emp-test", __import__("support").PASSWORD)
        code = cli.main(["check", "--root", str(tmp_path / "l"), "--base-url", gateway.base_url, "--origin", gateway.origin, "--credentials-file", str(creds)])
        assert code == 2 and "EMPLOYEE" in capsys.readouterr().err
    finally:
        gateway.close()


# ------------------------------------------------------------------ Linux CI: permission separation with a second uid
@pytest.mark.posix
@pytest.mark.sudo_user
def test_a_second_uid_can_fill_staging_but_cannot_write_outbound_while_the_agent_delivers(tmp_path_factory):
    import secrets
    import tempfile
    if shutil.which("sudo") is None or subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        pytest.skip("passwordless sudo is not available")
    user = "rsprod" + secrets.token_hex(3)
    if subprocess.run(["sudo", "-n", "useradd", "-M", "-s", "/usr/sbin/nologin", user], capture_output=True).returncode != 0:
        pytest.skip("cannot create a second user here")
    base = Path(tempfile.mkdtemp(prefix="rs-sep-", dir="/tmp"))
    gateway = MiniGateway()
    try:
        base.chmod(0o755)
        dirs = make_dirs(base / "agent")
        (base / "agent").chmod(0o755)
        dirs["staging"].chmod(0o777)       # the employee drops files here
        dirs["outbound"].chmod(0o755)      # others may read but not write: only the agent delivers
        write = lambda target: subprocess.run(["sudo", "-n", "-u", user, sys.executable, "-c",
                                                f"open({str(target)!r}, 'w').write('payload')"], capture_output=True)
        assert write(dirs["staging"] / "from-employee.txt").returncode == 0
        denied = write(dirs["outbound"] / "bypass.txt")
        assert denied.returncode != 0 and b"Permission" in denied.stderr and not (dirs["outbound"] / "bypass.txt").exists()
        # The file belongs to the second user, so only that user (or root) may change its timestamps.
        aged = subprocess.run(["sudo", "-n", "-u", user, "touch", "-d", "10 seconds ago", str(dirs["staging"] / "from-employee.txt")],
                              capture_output=True)
        assert aged.returncode == 0, aged.stderr
        assert __import__("time").time() - (dirs["staging"] / "from-employee.txt").stat().st_mtime > 5
        assert (dirs["staging"] / "from-employee.txt").stat().st_uid != os.getuid()     # still owned by the producer
        assert run(make_agent(dirs, gateway.client())) == 0
        assert (dirs["outbound"] / "from-employee.txt").read_bytes() == b"payload"
        assert (dirs["outbound"] / "from-employee.txt").stat().st_uid == os.getuid()   # delivered by the agent, not by the producer
    finally:
        gateway.close()
        subprocess.run(["sudo", "-n", "userdel", user], capture_output=True)
        shutil.rmtree(base, ignore_errors=True)
