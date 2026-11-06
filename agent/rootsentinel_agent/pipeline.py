"""The delivery state machine. The gateway decides; this module only enforces the outcome.

A file reaches the outbound directory only after: the gateway persisted ALLOW, the single-use
release returned bytes, and those bytes matched the SHA-256 computed locally from the one
read of the source. Every other path (BLOCKED, STALE, EXPIRED, ERROR, DELIVERY_UNKNOWN, any
transport or integrity failure) delivers nothing and either quarantines or holds the file.

Journal states and resume points are specified in docs/staging-spec.md.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import logging
import os
from pathlib import Path
import random
import time
from uuid import uuid4

from .admission import StabilityTracker, rejection_key, scan_directory
from .client import ApiError, GatewayClient, ProtocolViolation, Unavailable
from .fsutil import (Credentials, DirHandle, Observation, Unstable, classify, fsync_dir, observation_of,
                     read_verified, rename_between, sha256_file, write_exclusive)
from .journal import TERMINAL, Journal
from .labels import outbound_name, sanitize_label, strip_ready
from .report import build_report

LOG = logging.getLogger("rootsentinel_agent")
CAPACITY_CODES = {"SCAN_CAPACITY", "TRANSFER_CAPACITY", "LOGIN_CAPACITY"}
AUDIT_CODES = {"AUDIT_VERIFICATION_FAILED", "CHECKPOINT_PERSISTENCE_FAILED", "AUDIT_KEY_UNAVAILABLE",
               "CHECKPOINT_STORAGE_UNAVAILABLE", "CHECKPOINT_CAPACITY"}
EXPIRY_MARGIN_SECONDS = 3.0


class Backoff(Exception):
    """Pause the whole loop; nothing about any entry is concluded."""

    def __init__(self, seconds: float, reason: str):
        super().__init__(reason)
        self.seconds, self.reason = seconds, reason


class Fatal(Exception):
    """Retrying cannot help (configuration, credentials, integrity). The agent stops."""


class SimulatedCrash(BaseException):
    """Test seam: unwinds like a crash without being caught by ``except Exception``."""


class Failpoints:
    """Injectable test seam. Production code constructs this with no arguments (a no-op)."""

    def __init__(self, name: str | None = None, mode: str = "raise", hooks: dict | None = None):
        self.name, self.mode, self.hooks = name, mode, hooks or {}

    def hit(self, point: str, **context) -> None:
        hook = self.hooks.get(point)
        if hook is not None:
            hook(**context)
        if self.name == point and (point != "mid_write" or context.get("written", 0) < context.get("total", 0)):
            if self.mode == "exit":
                os._exit(77)
            raise SimulatedCrash(point)


@dataclass
class AgentConfig:
    staging: Path
    outbound: Path
    quarantine: Path
    state: Path
    credentials: Credentials
    poll_interval: float = 1.0
    settle_seconds: float = 2.0
    stable_polls: int = 2
    require_ready: bool = False
    max_attempts: int = 5
    rate_per_minute: int = 20
    retry_base: float = 2.0
    retry_cap: float = 120.0
    wait_scale: float = 1.0
    unavailable_wait: float = 5.0
    min_relogin: float = 15.0
    required_role: str = "EMPLOYEE"

    @property
    def tmp(self) -> Path:
        return self.state / "tmp"


class RateBudget:
    """Sliding-window budget below the gateway's 30 counted calls/minute/account."""

    def __init__(self, per_minute: int, sleep=time.sleep):
        self.limit, self.sleep, self.stamps = per_minute, sleep, deque()

    def acquire(self) -> None:
        while True:
            now = time.monotonic()
            while self.stamps and now - self.stamps[0] >= 60:
                self.stamps.popleft()
            if len(self.stamps) < self.limit:
                self.stamps.append(now)
                return
            self.sleep(max(0.05, 60 - (now - self.stamps[0])))


def _epoch(text: str) -> float:
    moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).timestamp()


@dataclass
class Agent:
    cfg: AgentConfig
    client: GatewayClient
    journal: Journal
    failpoints: Failpoints = field(default_factory=Failpoints)
    sleep: object = time.sleep

    def __post_init__(self):
        self.staging = DirHandle(self.cfg.staging)
        self.quarantine = DirHandle(self.cfg.quarantine)
        self.tracker = StabilityTracker(self.cfg.stable_polls, self.cfg.settle_seconds, self.cfg.require_ready)
        self.budget = RateBudget(self.cfg.rate_per_minute, lambda s: self.sleep(s))
        self.data: dict[str, bytes] = {}
        self.views: dict[str, dict] = {}
        self.release_fresh: set[str] = set()
        self.local_failures: dict[str, int] = {}
        self.last_login = 0.0
        self.rl_hits = 0
        self.audit_failures = 0

    # ----------------------------------------------------------------- plumbing
    def close(self) -> None:
        self.staging.close()
        self.quarantine.close()

    def fp(self, point: str, **context) -> None:
        self.failpoints.hit(point, **context)

    @staticmethod
    def short(entry: dict) -> str:
        return entry["id"][:8]

    def ensure_session(self) -> None:
        if self.client.authenticated:
            return
        since = time.monotonic() - self.last_login
        if self.last_login and since < self.cfg.min_relogin:
            raise Backoff(self.cfg.min_relogin - since, "RELOGIN_SPACING")
        try:
            user = self.client.login(self.cfg.credentials.username, self.cfg.credentials.password)
        except ApiError as error:
            self.last_login = time.monotonic()
            if error.status == 401:
                raise Fatal("the gateway rejected the agent credentials") from None
            if error.status == 403:
                raise Fatal(f"the gateway refused the login ({error.code}); check origin, host and mode") from None
            if error.status == 429:
                raise Backoff(60, error.code) from None
            raise Backoff(3 if error.status == 503 else 10, error.code) from None
        except Unavailable:
            raise Backoff(self.cfg.unavailable_wait, "GATEWAY_UNAVAILABLE") from None
        except ProtocolViolation:
            raise Backoff(10, "LOGIN_PROTOCOL") from None
        self.last_login = time.monotonic()
        if user.get("role") != self.cfg.required_role:
            self.client.logout()
            raise Fatal(f"the agent account must have role {self.cfg.required_role} (least privilege)")

    def api(self, call, *, counted: bool = False):
        """Run one gateway call with session handling; a 401 means re-login once, then retry."""
        for attempt in (1, 2):
            self.ensure_session()
            if counted:
                self.budget.acquire()
            try:
                return call()
            except ApiError as error:
                if error.status == 401 and attempt == 1:
                    self.client.clear_session()
                    continue
                raise
            except Unavailable:
                raise Backoff(self.cfg.unavailable_wait, "GATEWAY_UNAVAILABLE") from None
        raise Backoff(10, "SESSION")  # pragma: no cover

    def environment_error(self, error: ApiError) -> None:
        """Raise for errors that say nothing about one file (limits, config)."""
        if error.status == 403 or error.code in {"HOST_REJECTED", "PUBLIC_DEMO_NOT_READY"}:
            raise Fatal(f"the gateway refused the request ({error.code}); check origin, host, mode and role")
        if error.status == 401:  # still unauthenticated after one automatic re-login
            self.client.clear_session()
            raise Backoff(10, error.code)
        if error.code == "INCOMPLETE_UPLOAD":
            raise Backoff(5, error.code)
        if error.status == 429:
            self.rl_hits += 1
            raise Backoff(15 if self.rl_hits == 1 else 60, error.code)
        if error.status == 503 and error.code in CAPACITY_CODES:
            raise Backoff(3, error.code)

    # ------------------------------------------------------------------ journal helpers
    def drop_caches(self, entry_id: str) -> None:
        self.data.pop(entry_id, None)
        self.views.pop(entry_id, None)
        self.release_fresh.discard(entry_id)
        self.local_failures.pop(entry_id, None)

    def remove_tmp(self, entry: dict) -> None:
        for name in {entry.get("tmp"), f"{entry['id']}.{entry.get('attempt', 1)}.part"} - {None}:
            (self.cfg.tmp / name).unlink(missing_ok=True)

    def hold(self, entry: dict, reason: str) -> None:
        self.remove_tmp(entry)
        self.journal.append(entry["id"], "HELD", reason=reason)
        LOG.warning("held %s (%s): nothing was delivered", self.short(entry), reason)
        self.drop_caches(entry["id"])

    def abandon(self, entry: dict, reason: str) -> None:
        self.remove_tmp(entry)
        self.journal.append(entry["id"], "ABANDONED", reason=reason)
        LOG.warning("abandoned %s (%s); the changed file will be admitted as new", self.short(entry), reason)
        self.drop_caches(entry["id"])

    def retry(self, entry: dict, reason: str) -> None:
        self.remove_tmp(entry)
        attempt = entry.get("attempt", 1)
        if attempt >= self.cfg.max_attempts:
            return self.hold(entry, "ATTEMPTS_EXHAUSTED:" + reason)
        delay = min(self.cfg.retry_cap, self.cfg.retry_base * 2 ** (attempt - 1)) * (1 + random.random() * 0.25)
        self.journal.append(entry["id"], "RETRY", reason=reason, not_before=time.time() + delay * self.cfg.wait_scale)
        self.release_fresh.discard(entry["id"])
        LOG.info("retry %s attempt %d failed (%s); a fresh transfer will be created", self.short(entry), attempt, reason)

    def local_failure(self, entry: dict, reason: str) -> None:
        count = self.local_failures.get(entry["id"], 0) + 1
        self.local_failures[entry["id"]] = count
        if count >= self.cfg.max_attempts:
            return self.hold(entry, reason)
        raise Backoff(1.0, reason)

    # -------------------------------------------------------------------- entry steps
    def get_data(self, entry: dict) -> bytes | None:
        cached = self.data.get(entry["id"])
        if cached is not None:
            return cached
        try:
            data = read_verified(self.staging, entry["orig"], Observation(*entry["src"]))
        except (FileNotFoundError, Unstable):
            self.abandon(entry, "SOURCE_CHANGED_OR_GONE")
            return None
        except PermissionError:
            raise Backoff(1.0, "SOURCE_LOCKED") from None
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            self.abandon(entry, "SOURCE_CHANGED_OR_GONE")
            return None
        self.data[entry["id"]] = data
        return data

    def get_view(self, entry: dict) -> dict | None:
        try:
            return self.api(lambda: self.client.get_transfer(entry["transfer"]))
        except ApiError as error:
            self.environment_error(error)
            if error.status == 404:
                self.retry(entry, "TRANSFER_NOT_FOUND")
                return None
            raise Backoff(10, error.code) from None
        except ProtocolViolation:
            raise Backoff(10, "PROTOCOL") from None

    def expiring(self, view: dict) -> bool:
        return _epoch(view["expires_at"]) - time.time() < EXPIRY_MARGIN_SECONDS

    def step_submit(self, entry: dict) -> None:
        data = self.get_data(entry)
        if data is None:
            return
        self.fp("before_submit")
        try:
            view = self.api(lambda: self.client.submit(entry["label"], data, entry["key"]), counted=True)
        except ApiError as error:
            self.environment_error(error)
            if error.status == 503:
                raise Backoff(10, error.code) from None  # the same key is replayed later
            return self.hold(entry, "SUBMIT_REJECTED:" + error.code)
        except ProtocolViolation:
            raise Backoff(10, "PROTOCOL") from None
        if view.get("file_sha256") != entry["sha256"] or view.get("file_size") != entry["size"]:
            return self.hold(entry, "DIGEST_MISMATCH")  # the gateway saw different bytes: do not release
        self.rl_hits = 0
        self.views[entry["id"]] = view
        self.journal.append(entry["id"], "SUBMITTED", transfer=view["id"], tstate=view["state"],
                            expires=view["expires_at"], incident=view.get("incident_id"))
        self.fp("after_submit_journal")

    def step_after_submit(self, entry: dict) -> None:
        view = self.views.pop(entry["id"], None) or self.get_view(entry)
        if view is None:
            return
        state = view["state"]
        if state == "BLOCKED":
            return self.quarantine_entry(entry, view)
        if state == "ALLOWED":
            if self.expiring(view):
                return self.retry(entry, "EXPIRED_BEFORE_RELEASE")
            self.journal.append(entry["id"], "RELEASING")  # durable BEFORE the single-use call
            self.release_fresh.add(entry["id"])
            return
        if state == "SCANNING":
            raise Backoff(1.0, "SCANNING")
        self.retry(entry, "SERVER_STATE_" + state)

    def step_release(self, entry: dict) -> None:
        fresh = entry["id"] in self.release_fresh
        self.release_fresh.discard(entry["id"])
        if not fresh:  # resumed after a crash or backoff: the single use may already be consumed
            view = self.get_view(entry)
            if view is None:
                return
            if view["state"] != "ALLOWED" or self.expiring(view):
                return self.retry(entry, "RELEASE_NOT_AVAILABLE:" + view["state"])
        self.fp("before_release_call")
        try:
            data = self.api(lambda: self.client.release(entry["transfer"]), counted=True)
        except ApiError as error:
            self.environment_error(error)
            if error.code in AUDIT_CODES:
                self.audit_failures += 1
                if self.audit_failures >= 3:
                    raise Fatal("repeated audit/checkpoint failures at the gateway; releases stopped (fail closed)") from None
            return self.retry(entry, "RELEASE_DENIED:" + error.code)
        except ProtocolViolation:
            return self.retry(entry, "RELEASE_PROTOCOL_ERROR")
        self.fp("after_release_response")
        self.audit_failures = self.rl_hits = 0
        if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            return self.retry(entry, "RELEASE_BYTES_MISMATCH")
        name = f"{entry['id']}.{entry['attempt']}.part"
        path = self.cfg.tmp / name
        total = len(data)
        write_exclusive(path, data, on_chunk=lambda written: self.fp("mid_write", written=written, total=total))
        if sha256_file(path) != entry["sha256"]:
            path.unlink(missing_ok=True)
            return self.retry(entry, "STAGE_VERIFY_FAILED")
        self.journal.append(entry["id"], "STAGED", tmp=name)
        self.fp("after_stage")

    def name_taken(self, lowered: str) -> bool:
        return lowered in self.journal.reserved_names() or lowered in {n.lower() for n in os.listdir(self.cfg.outbound)}

    def step_place(self, entry: dict) -> None:
        source = self.cfg.tmp / entry["tmp"]
        final = entry["out"]
        if not source.exists():
            # Crash after the atomic replace but before PLACED was journaled.
            if sha256_file(self.cfg.outbound / final) == entry["sha256"]:
                self.journal.append(entry["id"], "PLACED", out=final)
                return
            return self.retry(entry, "STAGED_FILE_MISSING")
        if sha256_file(source) != entry["sha256"]:
            return self.retry(entry, "STAGED_FILE_INVALID")
        destination = self.cfg.outbound / final
        if os.path.lexists(destination) and sha256_file(destination) != entry["sha256"]:
            final = outbound_name(entry["label"], entry["id"], self.name_taken)
            destination = self.cfg.outbound / final
        os.replace(source, destination)
        fsync_dir(self.cfg.outbound)
        self.fp("after_replace")
        self.journal.append(entry["id"], "PLACED", out=final)

    def step_finish(self, entry: dict) -> None:
        if sha256_file(self.cfg.outbound / entry["out"]) != entry["sha256"]:
            return self.retry(entry, "OUTBOUND_MISSING_AFTER_PLACE")
        note = None
        try:
            current = self.staging.lstat(entry["orig"])
        except FileNotFoundError:
            current = None
        if current is not None:
            if classify(current) is None and observation_of(current) == Observation(*entry["src"]):
                self.fp("before_source_remove")
                try:
                    self.staging.unlink(entry["orig"])
                except FileNotFoundError:
                    pass
                except OSError:
                    return self.local_failure(entry, "SOURCE_REMOVAL_FAILED")
            else:
                note = "SOURCE_CHANGED_NOT_REMOVED"
        self.journal.append(entry["id"], "DELIVERED", **({"reason": note} if note else {}))
        LOG.info("delivered %s (%s, %d bytes)", self.short(entry), entry["label"], entry["size"])
        self.drop_caches(entry["id"])

    def quarantine_entry(self, entry: dict, view: dict) -> None:
        held, report = f"{entry['id']}.held", f"{entry['id']}.report.json"
        try:
            current = self.staging.lstat(entry["orig"])
        except FileNotFoundError:
            current = None
        if current is not None and classify(current) is None and observation_of(current) == Observation(*entry["src"]):
            if not self.quarantine.exists(held):
                rename_between(self.staging, entry["orig"], self.quarantine, held)
        if not self.quarantine.exists(report):
            write_exclusive(self.cfg.quarantine / report, build_report(entry, view, held_file=self.quarantine.exists(held)))
        self.journal.append(entry["id"], "QUARANTINED", report=report, tstate="BLOCKED",
                            reason=(view.get("scan") or {}).get("decision", {}).get("reason"))
        LOG.warning("quarantined %s (%s): blocked by the gateway, nothing delivered", self.short(entry), entry["label"])
        self.drop_caches(entry["id"])

    def step_new_attempt(self, entry: dict) -> None:
        if self.get_data(entry) is None:
            return
        self.journal.append(entry["id"], "PREPARED", key=str(uuid4()), attempt=entry["attempt"] + 1,
                            transfer=None, tstate=None, expires=None, incident=None, tmp=None, reason=None)

    def drive(self, entry: dict) -> None:
        while entry["state"] not in TERMINAL:
            progress = self.journal.seq
            state = entry["state"]
            if state == "PREPARED":
                self.step_submit(entry)
            elif state == "SUBMITTED":
                self.step_after_submit(entry)
            elif state == "RELEASING":
                self.step_release(entry)
            elif state == "STAGED":
                self.step_place(entry)
            elif state == "PLACED":
                self.step_finish(entry)
            elif state == "RETRY":
                if time.time() < entry.get("not_before", 0):
                    return
                self.step_new_attempt(entry)
            else:  # pragma: no cover
                raise AssertionError(state)
            if self.journal.seq == progress:  # a step that journals nothing made no progress
                return

    # --------------------------------------------------------------------- main loop
    def start_entry(self, name: str, observation: Observation) -> None:
        try:
            data = read_verified(self.staging, name, observation)
        except (FileNotFoundError, Unstable, PermissionError):
            self.tracker.forget(name)  # changed, vanished or locked: look again next poll
            return
        label = sanitize_label(strip_ready(name))
        entry_id = str(uuid4())
        out = outbound_name(label, entry_id, self.name_taken)
        entry = self.journal.append(entry_id, "PREPARED", key=str(uuid4()), label=label, out=out, orig=name,
                                    src=list(observation), sha256=hashlib.sha256(data).hexdigest(),
                                    size=len(data), attempt=1)
        self.data[entry_id] = data
        self.fp("after_prepared")
        self.guarded(entry)

    def guarded(self, entry: dict) -> None:
        try:
            self.drive(entry)
        except OSError:
            self.local_failure(entry, "LOCAL_IO_ERROR")

    def report_rejections(self, scan) -> None:
        for name, (reason, st) in scan.rejections.items():
            if self.cfg.require_ready and not name.lower().endswith(".ready"):
                continue
            key = rejection_key(reason, st)
            if key in self.journal.rejected:
                continue
            self.journal.append(str(uuid4()), "REJECTED", reason=reason, rk=key, label=sanitize_label(strip_ready(name)),
                                orig=name, src=[st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns])
            LOG.warning("rejected %s: %s (left in staging, never delivered)", sanitize_label(strip_ready(name)), reason)

    def startup(self) -> None:
        referenced = {e["tmp"] for e in self.journal.entries.values() if e["state"] == "STAGED" and e.get("tmp")}
        for leftover in os.listdir(self.cfg.tmp):
            if leftover not in referenced:
                (self.cfg.tmp / leftover).unlink(missing_ok=True)

    def cycle(self) -> bool:
        """One poll. Returns True while anything may still need attention.

        A cycle that journaled anything always asks for another scan, because the staging
        directory may have changed while entries were being processed.
        """
        started = self.journal.seq
        scan = scan_directory(self.staging)
        self.report_rejections(scan)
        ready, waiting = self.tracker.step(scan.observations)
        for entry in self.journal.active():
            self.guarded(entry)
        for name in ready:
            observation = scan.observations[name]
            if not self.journal.known_source(observation):
                self.start_entry(name, observation)
        return self.journal.seq != started or bool(waiting) or bool(self.journal.active())

    def run(self, once: bool = False, max_wait: float = 300.0) -> int:
        deadline = time.monotonic() + max_wait
        self.startup()
        try:
            # Fail fast on a bad credential, wrong role or refused origin, even if staging is idle.
            # A gateway that is merely down is not an error here; it is retried when work arrives.
            try:
                self.ensure_session()
            except Backoff:
                pass
            while True:
                try:
                    pending = self.cycle()
                    if once and not pending:
                        return 0
                except Backoff as pause:
                    LOG.info("pausing %.1fs (%s)", pause.seconds * self.cfg.wait_scale, pause.reason)
                    self.sleep(pause.seconds * self.cfg.wait_scale)
                if once and time.monotonic() > deadline:
                    LOG.error("gave up waiting; %d entries still pending", len(self.journal.active()))
                    return 3
                self.sleep(self.cfg.poll_interval)
        finally:
            try:
                if self.client.authenticated:
                    self.client.logout()
            except Exception:
                pass
