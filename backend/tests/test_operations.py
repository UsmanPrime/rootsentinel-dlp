"""Operational signals: what /health reports (hosted flag, deployed commit, upload cap) and the peak-memory log.

/health is public, so every field must be safe to show anyone: no secret, no path, no raw environment text.
"""
from dataclasses import replace
import logging
import time

from fastapi.testclient import TestClient
import pytest

import app.api as api_module
from app.api import create_app, log_peak_memory, peak_memory_kib
from app.settings import Settings, build_commit

HOSTED_ORIGIN = "https://rs-ops.example"
SHA = "0123456789abcdef0123456789abcdef01234567"


def health(settings, base_url):
    with TestClient(create_app(settings), base_url=base_url) as client:
        response = client.get("/health")
    assert response.status_code == 200
    return response.json()


# ---------------------------------------------------------------------------------------------- /health
def test_health_reports_a_local_deployment_with_unknown_commit_by_default(system):
    body = health(system[0], "http://127.0.0.1:5173")
    assert body == {"status": "ok", "mode": "local", "release_configured": True, "hosted": False,
                    "commit": "unknown", "max_upload_bytes": 10485760, "visitor_mode": False,
                    "visitor_upload_bytes": 65536}


def test_health_reports_a_hosted_deployment_its_commit_and_upload_cap(system):
    settings = replace(system[0], origin=HOSTED_ORIGIN, secure_cookies=True, commit=SHA, max_upload_bytes=1048576)
    body = health(settings, HOSTED_ORIGIN)
    assert body["hosted"] is True and body["commit"] == SHA and body["max_upload_bytes"] == 1048576


def test_hosted_flag_comes_from_the_server_origin_not_the_request_host(system):
    # The browser cannot make the server claim "hosted" by choosing a Host: http origin stays local even through an
    # allowed extra host, and an https origin stays hosted when reached over the loopback host used by CI.
    local = replace(system[0], extra_hosts=("demo.example",))
    assert health(local, "http://demo.example")["hosted"] is False
    hosted = replace(system[0], origin=HOSTED_ORIGIN, secure_cookies=True)
    assert health(hosted, "http://127.0.0.1:8000")["hosted"] is True


@pytest.mark.parametrize("value", ["not-a-sha", "ABCDEF", "0123456789abcdef0123456789abcdef012345678", "abc def1", "$(whoami)", ""])
def test_a_malformed_commit_is_reported_as_unknown_and_never_echoed(system, value):
    settings = replace(system[0], commit=value) if value else system[0]
    assert health(settings, "http://127.0.0.1:5173")["commit"] == "unknown"


def test_build_commit_prefers_the_build_argument_then_the_platform_value():
    assert build_commit({"ROOTSENTINEL_COMMIT": SHA, "RENDER_GIT_COMMIT": "1111111"}) == SHA
    assert build_commit({"ROOTSENTINEL_COMMIT": "unknown", "RENDER_GIT_COMMIT": "ABCDEF1234"}) == "abcdef1234"
    assert build_commit({"ROOTSENTINEL_COMMIT": " " + SHA.upper() + " "}) == SHA
    assert build_commit({"RENDER_GIT_COMMIT": "main; rm -rf /"}) == "unknown"
    assert build_commit({}) == "unknown"


def test_settings_from_environment_reads_the_commit(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOTSENTINEL_RUNTIME_ROOT", str(tmp_path / "runtime"))
    monkeypatch.setenv("ROOTSENTINEL_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    monkeypatch.setenv("ROOTSENTINEL_COMMIT", "Deadbeef")
    monkeypatch.delenv("RENDER_GIT_COMMIT", raising=False)
    assert Settings.from_environment().commit == "deadbeef"


# ---------------------------------------------------------------------------------------------- peak memory
def test_peak_memory_reads_vmhwm_from_a_proc_status_file(tmp_path):
    status = tmp_path / "status"
    status.write_text("Name:\tpython\nVmPeak:\t  300000 kB\nVmHWM:\t  123456 kB\nVmRSS:\t  100000 kB\n", encoding="ascii")
    assert peak_memory_kib(status) == 123456


@pytest.mark.parametrize("content", ["Name:\tpython\n", "VmHWM:\n", "VmHWM:\tlots kB\n"])
def test_peak_memory_is_none_when_the_value_is_missing_or_malformed(tmp_path, content):
    status = tmp_path / "status"
    status.write_text(content, encoding="ascii")
    assert peak_memory_kib(status) is None


def test_peak_memory_is_none_without_proc(tmp_path):
    assert peak_memory_kib(tmp_path / "does-not-exist") is None


def test_peak_memory_is_logged_at_info(tmp_path, caplog):
    status = tmp_path / "status"
    status.write_text("VmHWM:\t  204800 kB\n", encoding="ascii")
    with caplog.at_level(logging.INFO, logger="rootsentinel.memory"):
        assert log_peak_memory("at startup", status) == 204800
    records = [r for r in caplog.records if r.name == "rootsentinel.memory"]
    assert [r.levelno for r in records] == [logging.INFO]
    assert records[0].getMessage() == "peak resident memory (VmHWM) at startup: 204800 KiB (200.0 MiB)"


def test_nothing_is_logged_where_proc_is_unavailable(tmp_path, caplog):
    with caplog.at_level(logging.INFO, logger="rootsentinel.memory"):
        assert log_peak_memory("at startup", tmp_path / "missing") is None
    assert not [r for r in caplog.records if r.name == "rootsentinel.memory"]


def test_startup_and_every_tenth_maintenance_run_log_peak_memory(system, monkeypatch, caplog):
    monkeypatch.setattr(api_module, "peak_memory_kib", lambda status_path="/proc/self/status": 4096)
    monkeypatch.setattr(api_module, "MAINTENANCE_SECONDS", 0.001)
    with caplog.at_level(logging.INFO, logger="rootsentinel.memory"):
        with TestClient(create_app(system[0]), base_url="http://127.0.0.1:5173"):
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                messages = [r.getMessage() for r in caplog.records if r.name == "rootsentinel.memory"]
                if any("after 20 minutes" in m for m in messages):
                    break
                time.sleep(0.05)
    messages = [r.getMessage() for r in caplog.records if r.name == "rootsentinel.memory"]
    assert messages[0] == "peak resident memory (VmHWM) at startup: 4096 KiB (4.0 MiB)"
    assert "peak resident memory (VmHWM) after 10 minutes: 4096 KiB (4.0 MiB)" in messages
    assert "peak resident memory (VmHWM) after 20 minutes: 4096 KiB (4.0 MiB)" in messages
    assert not any("after 5 minutes" in m or "after 15 minutes" in m for m in messages)
