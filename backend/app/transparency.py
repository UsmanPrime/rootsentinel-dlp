"""The audit transparency log: an RFC 9162 Merkle tree over the audit events, with Ed25519 signed tree heads.

The tree in memory is a cache of the stored events. It is brought up to date under the audit head lock, so it
always equals what the database holds for the transaction that is using it. Stored heads are append-only.
The cryptography is in ``crypto/transparency.py``; this module adds the key file, persistence and the checks.
"""
import base64
from dataclasses import dataclass, field
import hmac
import json
import logging
from pathlib import Path
from threading import RLock

from sqlalchemy import event, select

from .crypto.transparency import MerkleLog, event_leaf, key_id_for, leaf_hash, public_key_of, sign_head, verify_head
from .db import now
from .errors import DomainError
from .gateway_models import AuditEvent, TransparencyHead
from .private_files import read_private

LOG = logging.getLogger("rootsentinel.transparency")
STH_INTERVAL = 64      # a head is signed at every 64th event, at every release, at startup and on request
MAX_KEYS = 32


@dataclass(frozen=True)
class SigningKeys:
    """Ed25519 signing keys by key id. Only the active key signs; retired keys still verify older heads."""
    active_id: str
    seeds: dict[str, bytes] = field(repr=False)
    public: dict[str, bytes] = field(default_factory=dict)

    @property
    def available(self) -> bool:
        return self.active_id in self.seeds

    def seed(self) -> bytes:
        if not self.available:
            raise DomainError("TRANSPARENCY_KEY_UNAVAILABLE", 503)
        return self.seeds[self.active_id]

    def public_key(self, key_id: str) -> bytes:
        key = self.public.get(key_id)
        if key is None:
            raise DomainError("TRANSPARENCY_KEY_UNAVAILABLE", 503)
        return key

    @classmethod
    def from_seeds(cls, active_id, seeds):
        public = {key_id: public_key_of(seed) for key_id, seed in seeds.items()}
        if any(key_id_for(key) != key_id for key_id, key in public.items()) or active_id not in seeds:
            raise ValueError("Key ids must be the SHA-256 of their public keys")
        return cls(active_id, dict(seeds), public)

    @classmethod
    def load(cls, path: Path | None):
        """Read the private key file with the same checks as the audit keyring. None means "not configured"."""
        if path is None:
            return cls("missing", {}, {})
        try:
            value = json.loads(read_private(path, 16384))
            if set(value) != {"version", "algorithm", "active_id", "keys"} or value["version"] != 1 or value["algorithm"] != "Ed25519":
                raise ValueError()
            if not 1 <= len(value["keys"]) <= MAX_KEYS:
                raise ValueError()
            seeds = {key_id: base64.b64decode(seed, validate=True) for key_id, seed in value["keys"].items()}
            if any(len(seed) != 32 for seed in seeds.values()):
                raise ValueError()
            return cls.from_seeds(value["active_id"], seeds)
        except Exception:
            raise DomainError("TRANSPARENCY_KEY_UNAVAILABLE", 503) from None


def head_fields(row) -> dict:
    return {"log_id": row.log_id, "tree_size": row.tree_size, "root_hash": row.root_hash,
            "timestamp": row.timestamp, "key_id": row.key_id}


def head_view(row) -> dict:
    return {**head_fields(row), "signature": row.signature}


class TransparencyLog:
    def __init__(self, signing: SigningKeys | None = None):
        self.signing = signing or SigningKeys("missing", {}, {})
        self.lock = RLock()
        self.tree = MerkleLog()
        self.macs: list[str] = []
        self.committed = 0          # the largest tree size this process has seen committed
        self.loaded = False         # True after the first load has been checked against the latest stored head
        self.failure = None         # set once when the stored log contradicts itself; audited actions then stop
        self.owner = None           # the session whose uncommitted events are at the end of the tree
        self._mark = f"transparency-mark-{id(self)}"
        self._size = f"transparency-size-{id(self)}"

    # ------------------------------------------------------------------------------------------ memory and sessions
    def _truncate(self, size):
        self.tree.truncate(size)
        del self.macs[size:]

    def _fail(self, reason):
        self.failure = reason
        self._truncate(0)
        self.loaded = False
        LOG.error("audit transparency log check failed (%s). Every audited action and every release is refused "
                  "until the stored events and tree heads agree again. Compare the database with a tree head "
                  "kept outside it (docs/audit-spec.md), repair or restore the database, then restart.", reason)

    def _committed(self, session):
        with self.lock:
            self.committed = max(self.committed, session.info.get(self._size, 0))
            if self.owner is session:
                self.owner = None

    def _rolled_back(self, session):
        with self.lock:
            if self.owner is session:
                self._truncate(min(self.tree.size, session.info.get(self._mark, 0)))
                self.owner = None

    def sync(self, s, head, keys):
        """Make the tree equal to the stored events as this transaction sees them. Call with the audit head locked."""
        with self.lock:
            if self.failure:
                raise DomainError("AUDIT_LOG_INVALID", 503)
            first_touch = self._mark not in s.info
            if first_touch:
                # Nothing of this transaction is in the tree yet, so the head holds committed state only.
                if head.sequence < self.committed:
                    raise DomainError("AUDIT_LOG_ROLLBACK", 503)
                if self.tree.size > head.sequence:
                    self._truncate(head.sequence)     # another transaction's events that never committed
                    self.owner = None
            if self.tree.size < head.sequence or not self.loaded:
                self._load(s, head, keys)
            if self.tree.size != head.sequence or (head.sequence and not hmac.compare_digest(self.macs[-1], head.mac)):
                raise DomainError("AUDIT_LOG_INVALID", 503)
            if first_touch:
                self.committed = max(self.committed, head.sequence)
                s.info[self._mark] = s.info[self._size] = self.tree.size
                event.listen(s, "after_commit", self._committed)
                event.listen(s, "after_rollback", self._rolled_back)

    def _load(self, s, head, keys):
        from .audit import MAX_EVENTS, ZERO, check_event
        first = not self.loaded
        start = self.tree.size
        latest = s.scalar(select(TransparencyHead).order_by(TransparencyHead.tree_size.desc()).limit(1)) if first else None
        covered = latest.tree_size if latest is not None else 0
        try:
            rows = s.scalars(select(AuditEvent).where(AuditEvent.sequence > start).order_by(AuditEvent.sequence)
                             .limit(MAX_EVENTS + 1).execution_options(yield_per=500))
            for row in rows:
                expected = self.tree.size + 1
                if row.sequence != expected or row.stream_id != head.stream_id or expected > MAX_EVENTS:
                    raise ValueError("SEQUENCE_MISMATCH")
                if expected > covered:
                    # Events after the latest signed head are checked one by one; earlier ones by its root below.
                    check_event(row, keys, self.macs[-1] if self.macs else ZERO)
                self.tree.append(leaf_hash(event_leaf(row.canonical, row.mac)))
                self.macs.append(row.mac)
            if self.tree.size != head.sequence:
                raise ValueError("EVENTS_MISSING")
            if first and latest is not None:
                self._check_head(latest, head.stream_id)
        except DomainError as error:
            self._truncate(start)
            if first and error.code == "TREE_HEAD_INVALID":
                self._fail("the latest stored tree head does not match the stored events")
                raise DomainError("AUDIT_LOG_INVALID", 503) from None
            raise
        except ValueError as error:
            self._truncate(start)
            if first:
                self._fail("stored events are missing, reordered or altered: " + str(error))
            raise DomainError("AUDIT_LOG_INVALID", 503) from None
        self.loaded = True

    def _check_head(self, row, stream_id):
        """A stored head must carry a valid signature of a known key and the root of this tree at its size."""
        fields = head_fields(row)
        public = self.signing.public_key(row.key_id)
        try:
            signature = bytes.fromhex(row.signature)
            valid = (verify_head(public, fields, signature) and row.log_id == stream_id and 1 <= row.tree_size <= self.tree.size
                     and hmac.compare_digest(self.tree.root(row.tree_size).hex(), row.root_hash))
        except ValueError:
            valid = False
        if not valid:
            raise DomainError("TREE_HEAD_INVALID", 503)
        return fields

    def extend(self, s, row):
        """Add the event this transaction has just written. The session hooks undo it if the transaction fails."""
        with self.lock:
            self.tree.append(leaf_hash(event_leaf(row.canonical, row.mac)))
            self.macs.append(row.mac)
            self.owner = s
            s.info[self._size] = self.tree.size

    # ------------------------------------------------------------------------------------------ heads
    def latest(self, s):
        return s.scalar(select(TransparencyHead).order_by(TransparencyHead.tree_size.desc()).limit(1))

    def sign(self, s, stream_id) -> dict:
        """Return a stored, signed and re-verified head for the current tree, writing it when it does not exist."""
        with self.lock:
            size = self.tree.size
            if size == 0:
                raise DomainError("EMPTY_AUDIT_STREAM", 409)
            row = s.get(TransparencyHead, size)
            if row is None:
                seed = self.signing.seed()
                fields = {"log_id": stream_id, "tree_size": size, "root_hash": self.tree.root(size).hex(),
                          "timestamp": now().isoformat(timespec="microseconds").replace("+00:00", "Z"),
                          "key_id": self.signing.active_id}
                try:
                    signature = sign_head(seed, fields).hex()
                except Exception:
                    raise DomainError("TRANSPARENCY_SIGNING_FAILED", 503) from None
                row = TransparencyHead(**fields, signature=signature)
                s.add(row)
                s.flush()
            self._check_head(row, stream_id)
            return head_view(row)

    def check_tail(self, s, head, keys, checkpoint):
        """The release check: the latest stored head, then every stored event after it, against the tree.

        Events up to the latest head are covered by its signed root, which the tree in memory reproduces; they
        are not read again. Events after it are read, compared with the tree and checked like a full verify.
        """
        from .audit import MAX_EVENTS, ZERO, check_event
        with self.lock:
            latest = self.latest(s)
            covered = 0
            if latest is not None:
                self._check_head(latest, head.stream_id)
                covered = latest.tree_size
            rows = s.scalars(select(AuditEvent).where(AuditEvent.sequence > covered).order_by(AuditEvent.sequence).limit(MAX_EVENTS + 1)).all()
            try:
                if len(rows) != head.sequence - covered:
                    raise ValueError("EVENTS_MISSING")
                previous = self.macs[covered - 1] if covered else ZERO
                for offset, row in enumerate(rows):
                    sequence = covered + offset + 1
                    if row.sequence != sequence or row.stream_id != head.stream_id:
                        raise ValueError("SEQUENCE_MISMATCH")
                    if not hmac.compare_digest(leaf_hash(event_leaf(row.canonical, row.mac)), self.tree.leaf(sequence - 1)):
                        raise ValueError("LEAF_MISMATCH")
                    check_event(row, keys, previous)
                    previous = row.mac
                if checkpoint is not None:
                    if checkpoint["stream_id"] != head.stream_id or not 1 <= checkpoint["sequence"] <= head.sequence:
                        raise ValueError("CHECKPOINT_MISMATCH")
                    if not hmac.compare_digest(self.macs[checkpoint["sequence"] - 1], checkpoint["mac"]):
                        raise ValueError("CHECKPOINT_MISMATCH")
            except ValueError:
                raise DomainError("AUDIT_VERIFICATION_FAILED", 503) from None

    # ------------------------------------------------------------------------------------------ proofs
    def inclusion(self, leaf_index, tree_size) -> dict:
        with self.lock:
            if not 0 <= leaf_index < tree_size <= self.tree.size:
                raise DomainError("NOT_FOUND", 404)
            return {"leaf_index": leaf_index, "tree_size": tree_size, "leaf_hash": self.tree.leaf(leaf_index).hex(),
                    "path": [p.hex() for p in self.tree.inclusion_proof(leaf_index, tree_size)]}

    def consistency(self, first, second) -> dict:
        with self.lock:
            if not 1 <= first <= second <= self.tree.size:
                raise DomainError("NOT_FOUND", 404)
            return {"first": first, "second": second, "path": [p.hex() for p in self.tree.consistency_proof(first, second)]}

    def keys_view(self) -> dict:
        if not self.signing.available:
            raise DomainError("TRANSPARENCY_KEY_UNAVAILABLE", 503)
        return {"algorithm": "Ed25519", "active_key_id": self.signing.active_id,
                "keys": [{"key_id": key_id, "public_key": key.hex()} for key_id, key in sorted(self.signing.public.items())]}
