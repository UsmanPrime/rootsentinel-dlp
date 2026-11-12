"""Opaque sessions, Argon2id, and bounded single-worker login throttling."""
from collections import OrderedDict
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from hmac import compare_digest
import secrets
from threading import BoundedSemaphore, Lock
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from sqlalchemy import select, update

from .db import now
from .errors import DomainError
from .models import SessionRecord, User
from .schemas import AuthView, UserView

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def digest(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def csrf_for(token: str) -> str:
    return digest("rootsentinel-csrf-v1:" + token)


@dataclass(frozen=True)
class Principal:
    id: str
    username: str
    role: str
    session_id: str

    @property
    def own_only(self) -> bool:
        """EMPLOYEE and VISITOR see only their own scans and transfers."""
        return self.role in ("EMPLOYEE", "VISITOR")

    def require(self, *roles):
        if self.role not in roles:
            raise DomainError("FORBIDDEN", 403)


class LoginLimiter:
    """All attempts count. Bounded memory; global limit defeats key churn.

    Single application worker only. Restarts reset buckets; public mode is closed.
    Client IP must be the real peer (do not trust forwarded headers locally).
    """
    def __init__(self, clock=time.monotonic):
        self.clock, self.lock, self.buckets = clock, Lock(), OrderedDict()

    # Each bucket has its own stable 429 code (all start with LOGIN_RATE_LIMIT), so a probe can tell a
    # per-client limit from the global one. The codes reveal nothing about whether an account exists.
    CODES = {"global": "LOGIN_RATE_LIMIT_GLOBAL", "ip": "LOGIN_RATE_LIMIT_CLIENT", "user": "LOGIN_RATE_LIMIT_ACCOUNT"}

    def check(self, peer: str, username: str):
        keys = [("global", 30), ("ip:" + digest(peer), 15), ("user:" + digest(username), 5)]
        with self.lock:
            current = self.clock()
            for key, limit in keys:
                start, count = self.buckets.get(key, (current, 0))
                if current - start >= 60:
                    start, count = current, 0
                if count >= limit:
                    raise DomainError(self.CODES[key.split(":", 1)[0]], 429)
                self.buckets[key] = (start, count + 1)
                self.buckets.move_to_end(key)
            while len(self.buckets) > 2048:
                self.buckets.popitem(last=False)


class AuthService:
    def __init__(self, database, settings):
        self.db, self.settings = database, settings
        self.limiter = LoginLimiter()
        self.hash_slots = BoundedSemaphore(2)
        self.dummy_hash = HASHER.hash(secrets.token_urlsafe(32))
        # Set by create_app once the audit service exists. Visitor sessions are refused while it is None.
        self.visitors = None

    def login(self, username: str, password: str, peer: str, previous: str | None):
        self.limiter.check(peer, username)
        if not self.hash_slots.acquire(blocking=False):
            raise DomainError("LOGIN_CAPACITY", 503)
        try:
            result = self._login(username, password, previous)
        finally:
            self.hash_slots.release()
        if self.visitors is not None:
            self.visitors.cleanup()  # lazy and bounded; never raises, never delays or fails a sign-in
        return result

    def _login(self, username, password, previous):
        with self.db.transaction() as s:
            user = s.scalar(select(User).where(User.username == username))
            try:
                valid = HASHER.verify(user.password_hash if user else self.dummy_hash, password)
            except (VerificationError, InvalidHashError):
                valid = False
            if not valid or user is None or not user.enabled or user.role == "VISITOR":
                raise DomainError("INVALID_CREDENTIALS", 401)
            if HASHER.check_needs_rehash(user.password_hash):
                user.password_hash = HASHER.hash(password)
            if previous:
                s.execute(update(SessionRecord).where(SessionRecord.token_digest == digest(previous)).values(revoked_at=now()))
            token = secrets.token_urlsafe(32)
            csrf = csrf_for(token)
            s.add(SessionRecord(user_id=user.id, token_digest=digest(token), csrf_digest=digest(csrf),
                                expires_at=now() + timedelta(seconds=self.settings.session_seconds)))
            return token, AuthView(user=UserView(id=user.id, username=user.username, role=user.role), csrf_token=csrf)

    def authenticate(self, token: str | None, csrf: str | None = None, mutation=False) -> Principal:
        if not token or len(token) != 43:
            raise DomainError("AUTHENTICATION_REQUIRED", 401)
        with self.db.transaction() as s:
            row = s.execute(select(SessionRecord, User).join(User).where(SessionRecord.token_digest == digest(token))).first()
            if row is None:
                raise DomainError("AUTHENTICATION_REQUIRED", 401)
            session, user = row
            if user.role == "VISITOR" and not session.revoked_at and user.enabled:
                if self.visitors is None:
                    raise DomainError("AUTHENTICATION_REQUIRED", 401)
                self.visitors.check_session(s, session, user)  # ends the sandbox on absolute or idle expiry
            if session.revoked_at or session.expires_at <= now() or not user.enabled:
                raise DomainError("AUTHENTICATION_REQUIRED", 401)
            if mutation and (not csrf or len(csrf) != 64 or not compare_digest(session.csrf_digest, digest(csrf))):
                raise DomainError("CSRF_REJECTED", 403)
            return Principal(user.id, user.username, user.role, session.id)

    def logout(self, principal: Principal):
        if principal.role == "VISITOR" and self.visitors is not None:
            return self.visitors.end(principal)
        with self.db.transaction() as s:
            s.execute(update(SessionRecord).where(SessionRecord.id == principal.session_id).values(revoked_at=now()))
