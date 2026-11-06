"""Criterion 5 (unsafe inputs), criterion 9 helpers, criterion 10 (credentials and CLI)."""
import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

from rootsentinel_agent import cli
from rootsentinel_agent.fsutil import (AlreadyRunning, DirHandle, InstanceLock, MAX_FILE_SIZE, PathRuleError, REPO_ROOT,
                                       Unstable, check_location, classify, observation_of, read_credentials, read_verified,
                                       write_credentials, write_exclusive)
from support import put


def lstat_reason(path: Path):
    return classify(os.lstat(path))


# ------------------------------------------------------------------ path rules
def test_path_rules(tmp_path):
    with pytest.raises(PathRuleError, match="absolute"):
        check_location(Path("relative/dir"), "x")
    with pytest.raises(PathRuleError, match="repository"):
        check_location(REPO_ROOT / "agent" / "staging", "x")
    with pytest.raises(PathRuleError, match="OneDrive"):
        check_location(tmp_path / "OneDrive - Test University" / "staging", "x")
    assert check_location(tmp_path / "ok" / "dir", "x")


def test_link_component_in_a_path_is_refused(tmp_path):
    real = tmp_path / "real"; real.mkdir()
    link = tmp_path / "link"
    if os.name == "nt":
        made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(real)], capture_output=True)
        if made.returncode:
            pytest.skip("junction could not be created")
    else:
        link.symlink_to(real, target_is_directory=True)
    with pytest.raises(PathRuleError, match="link"):
        check_location(link / "child", "x")


# ------------------------------------------------------------------ classification (criterion 5)
def test_regular_file_is_admissible_and_empty_oversized_directory_are_not(dirs):
    put(dirs, "ok.bin", b"x")
    put(dirs, "empty.bin", b"")
    big = dirs["staging"] / "big.bin"
    with open(big, "wb") as handle:
        handle.write(b"\0" * (MAX_FILE_SIZE + 1))
    (dirs["staging"] / "folder").mkdir()
    assert lstat_reason(dirs["staging"] / "ok.bin") is None
    assert lstat_reason(dirs["staging"] / "empty.bin") == "EMPTY_FILE"
    assert lstat_reason(big) == "TOO_LARGE"
    assert lstat_reason(dirs["staging"] / "folder") == "DIRECTORY_NOT_SCANNED"
    exactly = dirs["staging"] / "exact.bin"
    exactly.write_bytes(b"\0" * MAX_FILE_SIZE)
    assert lstat_reason(exactly) is None                       # the limit itself is allowed


def test_hardlink_is_rejected(dirs):
    original = put(dirs, "a.bin", b"protected-looking")
    try:
        os.link(original, dirs["staging"] / "b.bin")
    except OSError:
        pytest.skip("hard links unsupported")
    assert lstat_reason(original) == "HARDLINK" and lstat_reason(dirs["staging"] / "b.bin") == "HARDLINK"


@pytest.mark.posix
def test_symlink_fifo_and_symlink_swap_are_rejected_without_reading(dirs):
    target = dirs["state"].parent / "outside.txt"; target.write_bytes(b"outside secret")
    (dirs["staging"] / "link").symlink_to(target)
    os.mkfifo(dirs["staging"] / "pipe")
    assert lstat_reason(dirs["staging"] / "link") == "LINK_OR_REPARSE_POINT"
    assert lstat_reason(dirs["staging"] / "pipe") == "SPECIAL_FILE"
    # A regular file swapped for a symlink between observation and read must not be followed.
    victim = put(dirs, "victim.bin", b"original")
    observed = observation_of(os.lstat(victim))
    victim.unlink(); victim.symlink_to(target)
    handle = DirHandle(dirs["staging"])
    try:
        with pytest.raises(Unstable):
            read_verified(handle, "victim.bin", observed)
    finally:
        handle.close()


def test_symlink_is_rejected_where_creatable(dirs):
    if os.name != "nt":
        pytest.skip("covered by the POSIX test")
    target = put(dirs, "t.bin", b"x")
    try:
        os.symlink(target, dirs["staging"] / "s.bin")
    except OSError:
        pytest.skip("symlink privilege not held (expected on an unprivileged Windows account)")
    assert lstat_reason(dirs["staging"] / "s.bin") == "LINK_OR_REPARSE_POINT"


@pytest.mark.windows
def test_junction_is_rejected_as_a_reparse_point(dirs):
    target = dirs["state"].parent / "junction-target"; target.mkdir()
    made = subprocess.run(["cmd", "/c", "mklink", "/J", str(dirs["staging"] / "junc"), str(target)], capture_output=True)
    if made.returncode:
        pytest.skip("junction could not be created")
    assert lstat_reason(dirs["staging"] / "junc") == "LINK_OR_REPARSE_POINT"


def test_lstat_identity_is_usable_on_this_platform(dirs):
    a, b = put(dirs, "a", b"1"), put(dirs, "b", b"2")
    sa, sb = os.lstat(a), os.lstat(b)
    assert sa.st_ino != 0 and sa.st_dev != 0 and sa.st_ino != sb.st_ino
    handle = DirHandle(dirs["staging"])
    try:
        fd = handle.open_read("a")
        opened = os.fstat(fd); os.close(fd)
    finally:
        handle.close()
    assert (opened.st_dev, opened.st_ino) == (sa.st_dev, sa.st_ino)


# ------------------------------------------------------------------ read, write, lock
def test_read_verified_detects_change(dirs):
    path = put(dirs, "f.bin", b"abc")
    handle = DirHandle(dirs["staging"])
    try:
        observed = observation_of(os.lstat(path))
        assert read_verified(handle, "f.bin", observed) == b"abc"
        path.write_bytes(b"abcd")                                 # grew after it was observed
        with pytest.raises(Unstable):
            read_verified(handle, "f.bin", observed)
    finally:
        handle.close()


def test_write_exclusive_never_overwrites_and_cleans_up_on_failure(tmp_path):
    target = tmp_path / "out.bin"
    write_exclusive(target, b"first")
    with pytest.raises(FileExistsError):
        write_exclusive(target, b"second")
    assert target.read_bytes() == b"first"
    partial = tmp_path / "partial.bin"

    def boom(written):
        raise RuntimeError("disk full")
    with pytest.raises(RuntimeError):
        write_exclusive(partial, b"x" * 200000, on_chunk=boom)
    assert not partial.exists()


def test_instance_lock_is_exclusive(tmp_path):
    with InstanceLock(tmp_path / "lock"):
        with pytest.raises(AlreadyRunning):
            with InstanceLock(tmp_path / "lock"):
                pass
    with InstanceLock(tmp_path / "lock"):
        pass


# ------------------------------------------------------------------ credentials and CLI (criterion 10)
def test_credentials_file_rules_and_redaction(tmp_path):
    path = tmp_path / "secrets" / "agent.json"
    write_credentials(path, "emp-test", "correct horse battery")
    creds, verified = read_credentials(path)
    assert creds.username == "emp-test" and verified is (os.name != "nt")
    assert "correct horse" not in repr(creds) and "redacted" in repr(creds)
    if os.name != "nt":
        assert stat.S_IMODE(os.lstat(path).st_mode) == 0o600
        path.chmod(0o640)
        with pytest.raises(PathRuleError, match="0600"):
            read_credentials(path)
        path.chmod(0o600)
    with pytest.raises(FileExistsError):
        write_credentials(path, "emp-test", "again")             # never overwritten
    path.write_text(json.dumps({"username": "emp-test", "password": "x", "extra": 1}))
    with pytest.raises(PathRuleError, match="only username and password"):
        read_credentials(path)
    with pytest.raises(PathRuleError, match="repository"):
        read_credentials(REPO_ROOT / "README.md")


def test_cli_has_no_password_option_and_rejects_abbreviations():
    for flag in ("--password", "--pass", "--pw"):
        with pytest.raises(SystemExit) as stop:
            cli.parser().parse_args(["run", "--root", "x", flag, "secret"])
        assert stop.value.code == 2


def test_run_refuses_unsafe_directory_layouts(tmp_path, capsys):
    base = tmp_path / "a"
    overlapping = ["run", "--root", str(base), "--staging", str(base / "outbound" / "in"), "--prompt", "--username", "emp-test"]
    assert cli.main(overlapping) == 2
    inside_repo = ["init", "--root", str(REPO_ROOT / "agent" / "should-not-exist")]
    assert cli.main(inside_repo) == 2
    assert not (REPO_ROOT / "agent" / "should-not-exist").exists()
    assert "repository" in capsys.readouterr().err


def test_init_creates_private_layout_and_status_is_empty(tmp_path, capsys):
    root = tmp_path / "layout"
    assert cli.main(["init", "--root", str(root)]) == 0
    assert {p.name for p in root.iterdir()} == {"staging", "outbound", "quarantine", "state"} and (root / "state" / "tmp").is_dir()
    if os.name != "nt":
        assert stat.S_IMODE(os.lstat(root / "state").st_mode) == 0o700
    assert cli.main(["status", "--root", str(root)]) == 0
    assert "(none)" in capsys.readouterr().out
