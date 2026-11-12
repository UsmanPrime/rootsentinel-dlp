"""Visitor mode: short sandboxed sessions with no password, an explicit route allowlist and hard caps.

Every rule here is enforced on the server; the interface only hides what a visitor may not use. Nothing in this
module runs on a timer: cleanup is lazy (visitor entry and password sign-in) and bounded, so an idle process
makes no database call.

Rejected visitor requests (403 denials, 429 cap hits, 404 when the mode is off) are written to the application log
only. They never write to the audit chain. Audited visitor events are the lifecycle (VISITOR_ENTERED,
VISITOR_ENDED, VISITOR_EXPIRED) and the same scan, decision and release events every account produces.
"""
from collections import OrderedDict
from datetime import timedelta
import logging
from threading import Lock
import time
from uuid import uuid4

from sqlalchemy import delete, func, select, update

from .auth import Principal, csrf_for, digest
from .config import (VISITOR_ABSOLUTE_SECONDS, VISITOR_CLEANUP_BATCH, VISITOR_IDLE_SECONDS,
                     VISITOR_SEEN_THROTTLE_SECONDS)
from .db import now
from .errors import DomainError
from .gateway_models import AuditHead
from .models import SessionRecord, User, VisitorSession
from .registry import lock_state
from .schemas import AuthView, UserView, VisitorInfo

import secrets

LOG = logging.getLogger("rootsentinel.visitor")
# The password hash of a visitor row. It is not an Argon2 hash, so no password can ever verify against it and
# nothing here spends Argon2 work.
NO_PASSWORD = "!visitor-no-password"

# The complete list of routes a visitor may call, as (method, route template). Everything else is a 403.
# A new route is therefore denied to visitors until it is added here on purpose.
VISITOR_ROUTES = frozenset({
    ("GET", "/api/v1/auth/session"), ("GET", "/api/v1/auth/me"), ("POST", "/api/v1/auth/logout"),
    ("GET", "/api/v1/detection/profiles"), ("GET", "/api/v1/policies/active"), ("GET", "/api/v1/overview"),
    ("POST", "/api/v1/scans"), ("GET", "/api/v1/scans"), ("GET", "/api/v1/scans/{scan_id}"),
    ("POST", "/api/v1/transfers"), ("POST", "/api/v1/transfers/fixtures"), ("GET", "/api/v1/transfers"),
    ("GET", "/api/v1/transfers/{identifier}"), ("POST", "/api/v1/transfers/{identifier}/release"),
    ("GET", "/api/v1/visitor/audit/events"), ("GET", "/api/v1/visitor/transparency/key"),
    ("GET", "/api/v1/visitor/transparency/sth"), ("GET", "/api/v1/visitor/transparency/proof/inclusion"),
})


def visitor_user_ids():
    """A subquery of every visitor account id, used to keep visitor rows out of real users' default views."""
    return select(User.id).where(User.role == "VISITOR")


class EntryLimiter:
    """Per client address entries per hour, bounded memory. Single application worker; a restart resets it
    (the database caps for concurrent and daily sessions do not reset)."""

    def __init__(self, per_hour, clock=time.monotonic):
        self.per_hour, self.clock, self.lock, self.buckets = per_hour, clock, Lock(), OrderedDict()

    def check(self, peer):
        key = digest(peer)
        with self.lock:
            current = self.clock()
            start, count = self.buckets.get(key, (current, 0))
            if current - start >= 3600:
                start, count = current, 0
            if count >= self.per_hour:
                raise DomainError("VISITOR_RATE_LIMIT", 429)
            self.buckets[key] = (start, count + 1)
            self.buckets.move_to_end(key)
            while len(self.buckets) > 2048:
                self.buckets.popitem(last=False)


class VisitorService:
    def __init__(self, database, settings, audit):
        self.db, self.settings, self.audit = database, settings, audit
        self.limiter = EntryLimiter(settings.visitor_entries_per_ip_hour)

    # ---- entry -------------------------------------------------------------------------------------------
    def enter(self, peer):
        """Create a sandbox: a visitor account, a session and its counters, and one audit event, atomically."""
        try:
            self.limiter.check(peer)
            self.cleanup()
            with self.db.transaction() as s:
                lock_state(s)
                t = now()
                if s.get(AuditHead, 1).sequence >= self.settings.visitor_audit_ceiling:
                    raise DomainError("VISITOR_AUDIT_BUDGET", 429)
                if self._concurrent(s, t) >= self.settings.visitor_max_concurrent:
                    raise DomainError("VISITOR_CAPACITY", 429)
                day = t.replace(hour=0, minute=0, second=0, microsecond=0)
                if s.scalar(select(func.count()).select_from(VisitorSession).where(VisitorSession.created_at >= day)) \
                        >= self.settings.visitor_sessions_per_day:
                    raise DomainError("VISITOR_DAILY_CAP", 429)
                user = User(username="visitor-" + uuid4().hex[:16], password_hash=NO_PASSWORD, role="VISITOR", enabled=True)
                s.add(user)
                s.flush()
                token = secrets.token_urlsafe(32)
                csrf = csrf_for(token)
                expires = t + timedelta(seconds=VISITOR_ABSOLUTE_SECONDS)
                session = SessionRecord(user_id=user.id, token_digest=digest(token), csrf_digest=digest(csrf),
                                        expires_at=expires, last_seen_at=t)
                s.add(session)
                s.flush()
                s.add(VisitorSession(session_id=session.id, user_id=user.id, expires_at=expires))
                self.audit.append(s, "VISITOR_ENTERED", user.id, user.id)
                view = AuthView(user=UserView(id=user.id, username=user.username, role="VISITOR"), csrf_token=csrf,
                                visitor=self._info(expires, 0))
        except DomainError as error:
            LOG.warning("visitor entry refused ip=%s code=%s status=%d", peer, error.code, error.status)
            raise
        LOG.info("visitor entry ip=%s", peer)
        return token, view

    def _concurrent(self, s, t):
        return s.scalar(select(func.count()).select_from(VisitorSession)
                        .join(SessionRecord, SessionRecord.id == VisitorSession.session_id)
                        .where(VisitorSession.ended_at.is_(None), SessionRecord.revoked_at.is_(None),
                               SessionRecord.expires_at > t,
                               func.coalesce(SessionRecord.last_seen_at, SessionRecord.created_at)
                               > t - timedelta(seconds=VISITOR_IDLE_SECONDS)))

    def _info(self, expires, used):
        total = self.settings.visitor_scans_per_session
        return VisitorInfo(expires_at=expires, idle_seconds=VISITOR_IDLE_SECONDS,
                           submissions_remaining=max(total - used, 0), submissions_total=total)

    # ---- every authenticated visitor request ----------------------------------------------------------------
    def check_session(self, s, session, user):
        """Called inside authentication. Raises VISITOR_SESSION_ENDED when the sandbox is over; otherwise records
        the request time, at most once per VISITOR_SEEN_THROTTLE_SECONDS.

        The stored time lags the true last request by less than the throttle, so a visitor is ended after between
        IDLE minus THROTTLE and IDLE seconds without a request (540 to 600 s with the shipped constants)."""
        t = now()
        if not self.settings.visitor_mode_enabled:
            raise DomainError("AUTHENTICATION_REQUIRED", 401)
        seen = session.last_seen_at or session.created_at
        if session.expires_at <= t or t - seen > timedelta(seconds=VISITOR_IDLE_SECONDS):
            raise DomainError("VISITOR_SESSION_ENDED", 401)
        if t - seen >= timedelta(seconds=VISITOR_SEEN_THROTTLE_SECONDS):
            session.last_seen_at = t

    def info(self, principal):
        with self.db.transaction() as s:
            row = s.get(VisitorSession, principal.session_id)
            if row is None:
                raise DomainError("AUTHENTICATION_REQUIRED", 401)
            return self._info(row.expires_at, row.submissions_used)

    def guard(self, principal, method, route, peer):
        """Default deny: a visitor reaches only the routes in VISITOR_ROUTES."""
        if (method, route) not in VISITOR_ROUTES:
            LOG.warning("visitor request denied ip=%s method=%s route=%s", peer, method, route)
            raise DomainError("FORBIDDEN", 403)

    # ---- caps ---------------------------------------------------------------------------------------------
    def _ceiling(self, s):
        if s.get(AuditHead, 1).sequence >= self.settings.visitor_audit_ceiling:
            raise DomainError("VISITOR_AUDIT_BUDGET", 429)

    def consume_submission(self, s, principal, audited=True):
        """Count one scan or transfer submission against the session cap. Atomic; nothing is audited on refusal."""
        if audited:
            self._ceiling(s)
        result = s.execute(update(VisitorSession).where(
            VisitorSession.session_id == principal.session_id,
            VisitorSession.submissions_used < self.settings.visitor_scans_per_session
        ).values(submissions_used=VisitorSession.submissions_used + 1))
        if result.rowcount != 1:
            raise DomainError("VISITOR_SCAN_CAP", 429)

    def consume_release_attempt(self, principal):
        """A release attempt (allowed or denied) writes audit events, so attempts are capped like submissions."""
        with self.db.transaction() as s:
            self._ceiling(s)
            result = s.execute(update(VisitorSession).where(
                VisitorSession.session_id == principal.session_id,
                VisitorSession.release_attempts_used < self.settings.visitor_scans_per_session
            ).values(release_attempts_used=VisitorSession.release_attempts_used + 1))
            if result.rowcount != 1:
                raise DomainError("VISITOR_RELEASE_CAP", 429)

    # ---- end of a session ------------------------------------------------------------------------------------
    def end(self, principal):
        """Sign out: revoke the session and audit VISITOR_ENDED in one transaction (fails closed with the audit)."""
        with self.db.transaction() as s:
            lock_state(s)
            s.execute(update(SessionRecord).where(SessionRecord.id == principal.session_id).values(revoked_at=now()))
            if s.execute(update(VisitorSession).where(VisitorSession.session_id == principal.session_id,
                                                      VisitorSession.ended_at.is_(None)).values(ended_at=now())).rowcount:
                self.audit.append(s, "VISITOR_ENDED", principal.id, principal.id)

    def cleanup(self):
        """Lazy and bounded: audit VISITOR_EXPIRED for up to VISITOR_CLEANUP_BATCH finished sandboxes and delete
        their session rows (the token digests). Visitor accounts, counters and every append-only row stay.
        Never raises: a failure is logged and the next entry or sign-in tries again."""
        try:
            with self.db.transaction() as s:
                t = now()
                due = s.execute(select(VisitorSession.session_id, VisitorSession.user_id, SessionRecord.id)
                                .join(SessionRecord, SessionRecord.id == VisitorSession.session_id)
                                .where(VisitorSession.ended_at.is_(None),
                                       (SessionRecord.revoked_at.is_not(None)) | (SessionRecord.expires_at <= t)
                                       | (func.coalesce(SessionRecord.last_seen_at, SessionRecord.created_at)
                                          <= t - timedelta(seconds=VISITOR_IDLE_SECONDS)))
                                .order_by(SessionRecord.expires_at).limit(VISITOR_CLEANUP_BATCH)).all()
                if not due:
                    return 0
                lock_state(s)
                done = 0
                for session_id, user_id, _ in due:
                    if s.execute(update(VisitorSession).where(VisitorSession.session_id == session_id,
                                                              VisitorSession.ended_at.is_(None)).values(ended_at=t)).rowcount:
                        self.audit.append(s, "VISITOR_EXPIRED", user_id, user_id)
                        s.execute(delete(SessionRecord).where(SessionRecord.id == session_id))
                        done += 1
            if done:
                LOG.info("visitor sessions expired count=%d", done)
            return done
        except Exception:
            LOG.warning("visitor cleanup failed; it will be retried on the next entry or sign-in")
            return 0
