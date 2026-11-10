"""An awake application with no users makes no database call.

The maintenance loop wakes once a minute but touches the database only when an expiry is due (an in-memory
time, set at startup by one recovery query and by every ALLOWED submission) or when snapshot files exist.
/health never touches the database. The counters below listen on the engine itself: a cursor execution is a
statement, and a pool checkout is any use of a connection at all (including the pre-ping).
"""
from dataclasses import replace
from datetime import timedelta
import os
import time
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import event

import app.api as api_module
import app.transfers as transfers_module
from app.api import create_app
from app.db import Database, now
from app.gateway_models import Transfer

from .test_gateway import BENIGN, release, submit

LOCAL = "http://127.0.0.1:5173"


class DatabaseCalls:
    """Counts statements and connection checkouts on one engine while attached."""
    def __init__(self, engine):
        self.engine, self.statements, self.checkouts = engine, [], 0

    def _statement(self, connection, cursor, statement, parameters, context, executemany):
        self.statements.append(statement)

    def _checkout(self, connection, record, proxy):
        self.checkouts += 1

    def __enter__(self):
        event.listen(self.engine, "before_cursor_execute", self._statement)
        event.listen(self.engine, "checkout", self._checkout)
        return self

    def __exit__(self, *_):
        event.remove(self.engine, "before_cursor_execute", self._statement)
        event.remove(self.engine, "checkout", self._checkout)

    @property
    def writes(self):
        return [s for s in self.statements if s.lstrip().upper().startswith(("UPDATE", "INSERT", "DELETE"))]


def count_ticks(gateway, monkeypatch):
    """Wrap Gateway.maintain so the test can follow the maintenance loop; the real method still runs."""
    ticks = []
    original = gateway.maintain

    def counted():
        ticks.append(1)
        return original()
    monkeypatch.setattr(gateway, "maintain", counted)
    return ticks


def wait_for(condition, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.005)
    return False


def set_clock(monkeypatch, moment):
    monkeypatch.setattr(transfers_module, "now", lambda: moment)


def state_of(gateway, identifier):
    with gateway.db.transaction() as s:
        return s.get(Transfer, identifier).state


# ---------------------------------------------------------------------------------------------- the idle proof
def test_an_idle_hour_with_health_requests_every_ten_minutes_makes_no_database_call(system, monkeypatch):
    # One maintenance wake-up stands for one minute: 60 wake-ups are an hour, with a /health request every 10.
    monkeypatch.setattr(api_module, "MAINTENANCE_SECONDS", 0.002)
    app = create_app(system[0])
    ticks = count_ticks(app.state.gateway, monkeypatch)
    with TestClient(app, base_url=LOCAL) as client:
        assert app.state.gateway.next_due is None                     # startup recovery found nothing pending
        with DatabaseCalls(app.state.db.engine) as calls:
            health_requests = 0
            for minute in range(10, 61, 10):
                assert wait_for(lambda: len(ticks) >= minute), "the maintenance loop stopped"
                assert client.get("/health").status_code == 200
                health_requests += 1
            assert len(ticks) >= 60 and health_requests == 6
            assert calls.statements == [] and calls.checkouts == 0


def test_health_makes_no_database_call_in_any_configuration(system):
    hosted = replace(system[0], origin="https://rs-idle.example", secure_cookies=True, client_ip_header="True-Client-IP")
    for settings, base in ((system[0], LOCAL), (hosted, "https://rs-idle.example")):
        app = create_app(settings)
        with TestClient(app, base_url=base) as client:
            with DatabaseCalls(app.state.db.engine) as calls:
                for headers in ({}, {"true-client-ip": "198.51.100.7"}, {"cookie": "rs_session=not-a-session"}):
                    assert client.get("/health", headers=headers).status_code == 200
                assert client.head("/health").status_code in {200, 405}
                assert calls.statements == [] and calls.checkouts == 0


def test_the_counter_does_see_a_database_call(client):
    # The control for the two tests above: a request that reads the database is counted.
    with DatabaseCalls(client.app.state.db.engine) as calls:
        assert client.get("/api/v1/auth/session", headers={"cookie": "rs_session=" + "x" * 43}).status_code == 204
        assert calls.statements and calls.checkouts >= 1


# ---------------------------------------------------------------------------------------------- expiry on time
def test_expiry_waits_for_the_due_time_then_fires_and_goes_quiet(client, login, monkeypatch):
    login(client)
    item = submit(client).json()
    gateway = client.app.state.gateway
    with gateway.db.transaction() as s:
        expires = s.get(Transfer, item["id"]).expires_at
    assert item["state"] == "ALLOWED" and gateway.next_due == expires

    # One second before the due time: the snapshot file exists, so cleanup looks, but nothing is transitioned
    # and the registry lock (the former per-minute no-op UPDATE) is not taken.
    set_clock(monkeypatch, expires - timedelta(seconds=1))
    with DatabaseCalls(gateway.db.engine) as calls:
        assert gateway.maintain() == {"transitioned": 0}
        assert calls.statements and calls.writes == []
    assert state_of(gateway, item["id"]) == "ALLOWED" and gateway.store.pending()

    # At the due time the pass transitions the transfer and removes its snapshot.
    set_clock(monkeypatch, expires)
    assert gateway.maintain() == {"transitioned": 1}
    assert state_of(gateway, item["id"]) == "EXPIRED" and not gateway.store.pending()
    assert gateway.next_due is None
    monkeypatch.undo()
    assert release(client, item["id"]).status_code == 409           # an expired transfer is still refused

    # Nothing is left: later wake-ups make no database call.
    with DatabaseCalls(gateway.db.engine) as calls:
        for _ in range(5):
            assert gateway.maintain() is None
        assert calls.statements == [] and calls.checkouts == 0


def test_the_maintenance_loop_itself_expires_a_due_transfer(system, credentials, monkeypatch):
    monkeypatch.setattr(api_module, "MAINTENANCE_SECONDS", 0.002)
    app = create_app(replace(system[0], retention_seconds=1))
    with TestClient(app, base_url=LOCAL, raise_server_exceptions=False) as client:
        client.headers["origin"] = system[0].origin
        result = client.post("/api/v1/auth/login", json={"username": "admin", "password": credentials[0]})
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        item = submit(client).json()
        assert item["state"] == "ALLOWED"
        assert wait_for(lambda: state_of(app.state.gateway, item["id"]) == "EXPIRED", seconds=20)
        assert wait_for(lambda: not app.state.gateway.store.pending() and app.state.gateway.next_due is None)


def test_the_earliest_of_several_transfers_is_the_due_time(client, login, monkeypatch):
    login(client)
    gateway = client.app.state.gateway
    first = submit(client).json()
    with gateway.db.transaction() as s:
        early = s.get(Transfer, first["id"]).expires_at
    second = submit(client).json()
    with gateway.db.transaction() as s:
        late = s.get(Transfer, second["id"]).expires_at
    assert early < late and gateway.next_due == early
    set_clock(monkeypatch, early)
    assert gateway.maintain() == {"transitioned": 1}
    assert gateway.next_due == late                                   # recomputed from what remains
    assert state_of(gateway, second["id"]) == "ALLOWED"
    set_clock(monkeypatch, late)
    assert gateway.maintain() == {"transitioned": 1}
    assert gateway.next_due is None


def test_a_blocked_transfer_sets_no_due_time(client, login):
    login(client)
    protected = b"SYNTHETIC-PROTECTED-" * 128
    assert client.post("/api/v1/assets?label=Synthetic", content=protected,
                       headers={"Content-Type": "application/octet-stream"}).status_code == 201
    assert submit(client, data=protected).json()["state"] == "BLOCKED"
    gateway = client.app.state.gateway
    assert gateway.next_due is None and not gateway.store.pending()
    with DatabaseCalls(gateway.db.engine) as calls:
        assert gateway.maintain() is None
        assert calls.checkouts == 0


def test_a_released_transfer_costs_one_pass_at_its_old_due_time_then_nothing(client, login, monkeypatch):
    login(client)
    item = submit(client).json()
    gateway = client.app.state.gateway
    assert release(client, item["id"]).content == BENIGN
    due = gateway.next_due
    assert due is not None and not gateway.store.pending()            # the time stays; it may be early, never late
    with DatabaseCalls(gateway.db.engine) as calls:
        assert gateway.maintain() is None                             # before that time: no database call
        assert calls.checkouts == 0
    set_clock(monkeypatch, due)
    assert gateway.maintain() == {"transitioned": 0}
    assert gateway.next_due is None
    with DatabaseCalls(gateway.db.engine) as calls:
        assert gateway.maintain() is None
        assert calls.checkouts == 0


def test_a_failed_pass_is_retried_on_the_next_wake_up(client, login, monkeypatch):
    login(client)
    item = submit(client).json()
    gateway = client.app.state.gateway
    due = gateway.next_due
    set_clock(monkeypatch, due)
    original = gateway.audit.append

    def broken(*args, **kwargs):
        raise OSError("synthetic audit failure")
    monkeypatch.setattr(gateway.audit, "append", broken)
    try:
        gateway.maintain()
        raise AssertionError("the pass should have failed")
    except OSError:
        pass
    assert state_of(gateway, item["id"]) == "ALLOWED"                 # rolled back, nothing half done
    assert gateway.next_due is not None and gateway.next_due <= due   # still due
    monkeypatch.setattr(gateway.audit, "append", original)
    assert gateway.maintain() == {"transitioned": 1}
    assert state_of(gateway, item["id"]) == "EXPIRED" and gateway.next_due is None


# ---------------------------------------------------------------------------------------------- restart
def test_restart_recovery_sets_the_due_time_from_one_query(system, credentials, monkeypatch):
    with TestClient(create_app(system[0]), base_url=LOCAL, raise_server_exceptions=False) as client:
        client.headers["origin"] = system[0].origin
        result = client.post("/api/v1/auth/login", json={"username": "admin", "password": credentials[0]})
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        item = submit(client).json()
        with client.app.state.db.transaction() as s:
            expires = s.get(Transfer, item["id"]).expires_at

    restarted = create_app(system[0])                                 # a new process: nothing in memory
    assert restarted.state.gateway.next_due is None
    with TestClient(restarted, base_url=LOCAL):
        gateway = restarted.state.gateway
        assert gateway.next_due == expires
        assert state_of(gateway, item["id"]) == "ALLOWED"             # not yet due: still releasable
        set_clock(monkeypatch, expires + timedelta(seconds=1))
        assert gateway.maintain() == {"transitioned": 1}
        assert state_of(gateway, item["id"]) == "EXPIRED" and gateway.next_due is None


def test_startup_without_restart_recovery_still_loads_the_due_time(system, credentials):
    with TestClient(create_app(system[0]), base_url=LOCAL, raise_server_exceptions=False) as client:
        client.headers["origin"] = system[0].origin
        result = client.post("/api/v1/auth/login", json={"username": "admin", "password": credentials[0]})
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        item = submit(client).json()
        with client.app.state.db.transaction() as s:
            expires = s.get(Transfer, item["id"]).expires_at
    unconfigured = create_app(replace(system[0], checkpoint_root=None))
    with TestClient(unconfigured, base_url=LOCAL):
        assert unconfigured.state.gateway.next_due == expires


# ---------------------------------------------------------------------------------------------- snapshot files
def test_snapshot_files_trigger_cleanup_without_the_registry_lock(client):
    gateway = client.app.state.gateway
    assert gateway.next_due is None
    old = gateway.store.root / f"{uuid4()}.blob"
    fresh = gateway.store.root / f"{uuid4()}.blob"
    unrelated = gateway.store.root / "unrelated.txt"
    for path in (old, fresh, unrelated):
        path.write_bytes(b"synthetic orphan")
    os.utime(old, (time.time() - 901, time.time() - 901))            # orphans are removed after 900 s

    with DatabaseCalls(gateway.db.engine) as calls:
        assert gateway.maintain() == {"transitioned": 0}
        assert calls.statements and calls.writes == []                # it looked, without the no-op UPDATE
    assert not old.exists() and fresh.exists() and unrelated.exists()

    fresh.unlink()
    with DatabaseCalls(gateway.db.engine) as calls:
        assert gateway.maintain() is None                             # an unrelated file is not a snapshot
        assert calls.statements == [] and calls.checkouts == 0


def test_a_terminal_transfers_leftover_snapshot_is_removed(client, login):
    login(client)
    item = submit(client).json()
    gateway = client.app.state.gateway
    assert release(client, item["id"]).status_code == 200
    with gateway.db.transaction() as s:
        leftover = gateway.store.path(s.get(Transfer, item["id"]).snapshot_id)
    leftover.write_bytes(b"synthetic leftover")
    assert gateway.maintain() == {"transitioned": 0}
    assert not leftover.exists()


def test_the_administrator_expiry_route_still_runs_a_full_pass(client, login):
    login(client)
    item = submit(client).json()
    gateway = client.app.state.gateway
    with gateway.db.transaction() as s:
        s.get(Transfer, item["id"]).expires_at = now() - timedelta(seconds=1)
    # The in-memory time is now later than the edited row; the explicit route does not depend on it.
    assert client.post("/api/v1/transfers-maintenance/expire").json() == {"transitioned": 1}
    assert gateway.next_due is None


# ---------------------------------------------------------------------------------------------- pool
def test_the_connection_pool_is_small_recycled_and_checked(system):
    pool = Database(system[0].database_url).engine.pool
    assert pool.size() == 2 and pool._max_overflow == 2
    assert pool._recycle == 280 and pool._pre_ping is True


# ---------------------------------------------------------------------------------------------- snapshot store
class Frozen:
    def __init__(self, data, identifier=None):
        self.id, self.data = identifier or str(uuid4()), data


def test_the_snapshot_store_accepts_only_generated_names_and_bounded_bytes(client):
    import pytest
    from app.errors import DomainError
    store = client.app.state.gateway.store
    for identifier in (str(uuid4()).upper(), "../" + str(uuid4()), "{" + str(uuid4()) + "}"):
        with pytest.raises((DomainError, ValueError)):
            store.path(identifier)
    with pytest.raises(DomainError, match="INPUT_TOO_LARGE"):
        store.save(Frozen(bytearray(b"not immutable bytes")))
    assert not store.pending()


def test_a_snapshot_is_never_overwritten_and_a_failed_save_leaves_no_file(client, monkeypatch):
    import pytest
    import app.snapshots as snapshots_module
    store = client.app.state.gateway.store
    first = Frozen(b"first synthetic bytes")
    store.save(first)
    with pytest.raises(OSError):
        store.save(Frozen(b"second synthetic bytes", first.id))
    assert store.capture(first.id) == b"first synthetic bytes"       # the earlier snapshot is intact
    store.remove(first.id)

    def broken(_):
        raise OSError("synthetic directory sync failure")
    monkeypatch.setattr(snapshots_module, "sync_directory", broken)
    with pytest.raises(OSError):
        store.save(Frozen(b"third synthetic bytes"))
    assert not store.pending()                                        # the half-saved file was removed


def test_snapshot_listing_is_bounded_and_ignores_other_names(client):
    store = client.app.state.gateway.store
    names = sorted(str(uuid4()) for _ in range(3))
    for name in names:
        (store.root / f"{name}.blob").write_bytes(b"synthetic")
    (store.root / ("-" * 36 + ".blob")).write_bytes(b"matches the pattern, is not a UUID")
    (store.root / "notes.txt").write_bytes(b"unrelated")
    assert sorted(identifier for identifier, _ in store.candidates()) == names
    assert len(store.candidates(2)) == 2 and store.pending()
    for name in names:
        store.remove(name)
    assert not store.pending()
    for index in range(1001):                                         # at most 1,000 directory entries are examined
        (store.root / f"filler-{index:04d}.txt").write_bytes(b"")
    (store.root / f"{uuid4()}.blob").write_bytes(b"synthetic")
    assert len(store.candidates()) <= 1


# ---------------------------------------------------------------------------------------------- transparency log
def test_an_idle_hour_with_a_populated_transparency_log_makes_no_database_call(system, credentials, monkeypatch):
    """Signed tree heads are written only inside audited requests and at startup. With events, heads and the
    tree in memory, an idle process still makes no database call: nothing signs or checks on a timer."""
    with TestClient(create_app(system[0]), base_url=LOCAL, raise_server_exceptions=False) as client:
        client.headers["origin"] = system[0].origin
        result = client.post("/api/v1/auth/login", json={"username": "admin", "password": credentials[0]})
        client.headers["x-csrf-token"] = result.json()["csrf_token"]
        assert release(client, submit(client).json()["id"]).content == BENIGN
        assert client.get("/api/v1/transparency/sth").status_code == 200

    monkeypatch.setattr(api_module, "MAINTENANCE_SECONDS", 0.002)
    app = create_app(system[0])                                       # restart: the tree is rebuilt at startup
    ticks = count_ticks(app.state.gateway, monkeypatch)
    with TestClient(app, base_url=LOCAL) as client:
        log = app.state.gateway.audit.log
        assert log.loaded and log.failure is None and log.tree.size >= 5
        with DatabaseCalls(app.state.db.engine) as calls:
            for minute in range(10, 61, 10):
                assert wait_for(lambda: len(ticks) >= minute), "the maintenance loop stopped"
                assert client.get("/health").status_code == 200
            assert len(ticks) >= 60
            assert calls.statements == [] and calls.checkouts == 0
