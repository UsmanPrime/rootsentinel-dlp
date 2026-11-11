"""Idempotent hosted bootstrap: managed accounts from a file of Argon2 hashes, plus synthetic protected assets.

Run once per container start, after migrations and before the server:

    python -m app.bootstrap [--accounts PATH]

* The accounts file holds usernames, roles and Argon2id password HASHES only (never a password).
  Produce it locally with ``scripts/make_account_hashes.py`` and upload it as a platform secret file.
  The file is the source of truth for the accounts it lists: a new name is created, a changed hash
  or role is applied and revokes that user's sessions, ``enabled: false`` disables the account.
  Accounts it does not list are never touched. Running it twice with the same file changes nothing.
* The synthetic protected sample is registered through the normal ``register`` function and the
  normal audit append, by a disabled internal ADMIN identity that cannot sign in.
* It prints counts only. It never prints usernames, hashes, paths of secrets or audit material.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import secrets
import sys
from typing import Annotated, Literal

from argon2 import extract_parameters
from argon2.exceptions import InvalidHashError
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, field_validator
from sqlalchemy import select, update

from .audit import AuditService, KeyRing
from .transparency import SigningKeys
from .auth import HASHER, Principal
from .db import Database, now
from .errors import DomainError
from . import profiles
from .models import Asset, AssetVersion, PolicyVersion, RegistryState, SessionRecord, User
from .policy import RULE_SET_V1, RULE_SET_V2, active_policy, new_policy
from .private_files import read_private
from .registry import add_missing_profiles, lock_state, register
from .settings import Settings
from .synthetic import protected_sample, source_sample

SYSTEM_USERNAME = "system-bootstrap"
# Synthetic only. The first seed's bytes are the server-side "protected" transfer fixture, so the hosted
# smoke test and the Transfers page produce a real BLOCK. The second is source-shaped text, the same bytes
# as the interface's "source" fixture, so shifted and inserted copies of it show the content-defined
# profile. Operators can register more as ADMIN.
SEEDS = {"synthetic-protected-sample": protected_sample(), "synthetic-source-sample": source_sample()}
MAX_ACCOUNTS = 50

Name = Annotated[str, StringConstraints(min_length=3, max_length=64, pattern=r"^[a-z0-9][a-z0-9_.-]*$")]


class Account(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    username: Name
    role: Literal["ADMIN", "ANALYST", "EMPLOYEE"]
    password_hash: str = Field(max_length=256)
    enabled: bool = True

    @field_validator("username")
    @classmethod
    def not_reserved(cls, value):
        if value == SYSTEM_USERNAME:
            raise ValueError("reserved")
        return value

    @field_validator("password_hash")
    @classmethod
    def argon2id_hash(cls, value):
        try:
            parameters = extract_parameters(value)
        except InvalidHashError:
            raise ValueError("not an Argon2 hash") from None
        if not value.startswith("$argon2id$") or parameters.memory_cost < 19456:
            raise ValueError("weak or wrong hash type")
        return value


class AccountsFile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: Literal[1]
    accounts: list[Account] = Field(max_length=MAX_ACCOUNTS)

    @field_validator("accounts")
    @classmethod
    def unique(cls, value):
        if len({a.username for a in value}) != len(value):
            raise ValueError("duplicate username")
        return value


def load_accounts(path: Path) -> AccountsFile:
    return AccountsFile.model_validate_json(read_private(path, 65536))


def apply_accounts(db: Database, accounts: AccountsFile) -> dict:
    counts = {"created": 0, "updated": 0, "unchanged": 0}
    with db.transaction() as s:
        for entry in accounts.accounts:
            user = s.scalar(select(User).where(User.username == entry.username))
            if user is None:
                s.add(User(username=entry.username, role=entry.role, password_hash=entry.password_hash, enabled=entry.enabled))
                counts["created"] += 1
                continue
            changed = (user.password_hash, user.role, user.enabled) != (entry.password_hash, entry.role, entry.enabled)
            if not changed:
                counts["unchanged"] += 1
                continue
            user.password_hash, user.role, user.enabled = entry.password_hash, entry.role, entry.enabled
            s.execute(update(SessionRecord).where(SessionRecord.user_id == user.id, SessionRecord.revoked_at.is_(None)).values(revoked_at=now()))
            counts["updated"] += 1
    return counts


def system_actor(db: Database) -> Principal:
    with db.transaction() as s:
        system = s.scalar(select(User).where(User.username == SYSTEM_USERNAME))
        if system is None:
            # Disabled and given a random hash nobody holds: this identity can never authenticate.
            system = User(username=SYSTEM_USERNAME, role="ADMIN", password_hash=HASHER.hash(secrets.token_urlsafe(32)), enabled=False)
            s.add(system)
            s.flush()
        return Principal(system.id, system.username, "ADMIN", "bootstrap")


def seed_assets(db: Database, audit: AuditService) -> dict:
    with db.transaction() as s:
        missing = [label for label in SEEDS if s.scalar(select(Asset.id).where(Asset.label == label)) is None]
    if not missing:
        return {"seeded": 0, "existing": len(SEEDS)}
    actor = system_actor(db)
    for label in missing:
        with db.transaction() as s:
            result = register(s, actor, label, SEEDS[label])
            audit.append(s, "ASSET_REGISTERED", actor.id, result.asset_id, registry_revision=result.registry_revision)
    return {"seeded": len(missing), "existing": len(SEEDS) - len(missing)}


def rebuild_seed_profiles(db: Database, audit: AuditService) -> int:
    """Give seed assets registered before a profile existed that profile's fingerprints.

    Possible only for seeds: their bytes are constants of this module, while the bytes of every other asset
    are gone after registration. A seed whose current version is no longer the seed bytes is left alone."""
    added = 0
    for label, data in SEEDS.items():
        with db.transaction() as s:
            asset = s.scalar(select(Asset).where(Asset.label == label))
            version = asset and s.scalar(select(AssetVersion).where(
                AssetVersion.asset_id == asset.id, AssetVersion.number == asset.current_version))
            stale = bool(version) and not asset.retired and version.file_sha256 == sha256(data).hexdigest() \
                and not all(p.fingerprinted for p in profiles.version_profiles(s, [version])[version.id])
            asset_id = asset.id if stale else None
        if asset_id is None:
            continue
        actor = system_actor(db)
        with db.transaction() as s:
            revision = add_missing_profiles(s, actor, asset_id, data)
            if revision is not None:
                audit.append(s, "ASSET_PROFILE_ADDED", actor.id, asset_id, registry_revision=revision)
                added += 1
    return added


def activate_rule_set(db: Database, audit: AuditService) -> bool:
    """Make rs-policy-v2 the active rule set, once: only while the migration's own policy 1 is still active.

    Any later policy was written by an administrator (or by an earlier run of this function) and is never
    overridden here, so an administrator's choice of rule set survives every restart."""
    with db.transaction() as s:
        state = s.get(RegistryState, 1)
        untouched = state is not None and (policy := s.get(PolicyVersion, state.policy_id)) is not None \
            and policy.number == 1 and policy.actor_id is None and policy.rule_set == RULE_SET_V1
    if not untouched:
        return False
    actor = system_actor(db)
    with db.transaction() as s:
        state = lock_state(s)
        previous = active_policy(s, state)
        if previous.number != 1 or previous.rule_set != RULE_SET_V1:
            return False
        new = new_policy(s, state, previous, actor.id, threshold=previous.threshold,
                         block_enabled=previous.block_enabled, rule_set=RULE_SET_V2)
        audit.append(s, "POLICY_CHANGED", actor.id, new.id, policy_id=new.id)
    return True


def anchor_checkpoint(db: Database, audit: AuditService):
    """Write a checkpoint for the current audit head. Checkpoints live on this container's disk only."""
    with db.transaction() as s:
        try:
            audit.retain_checkpoint(s)
        except DomainError as error:
            if error.code != "EMPTY_AUDIT_STREAM":
                raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--accounts", type=Path, help="private JSON file of account hashes (optional)")
    args = parser.parse_args(argv)
    settings = Settings.from_environment()
    if settings.audit_key_file is None or settings.checkpoint_root is None:
        print("Bootstrap needs the audit key file and checkpoint root to be configured.", file=sys.stderr)
        return 2
    settings.prepare_storage()
    db = Database(settings.database_url)
    try:
        audit = AuditService(KeyRing.load(settings.audit_key_file), settings.checkpoint_root,
                             SigningKeys.load(settings.transparency_key_file))
        if args.accounts is not None:
            counts = apply_accounts(db, load_accounts(args.accounts))
            print(f"accounts: created={counts['created']} updated={counts['updated']} unchanged={counts['unchanged']}")
        else:
            print("accounts: no accounts file given; none changed")
        seeds = seed_assets(db, audit)
        print(f"assets: seeded={seeds['seeded']} existing={seeds['existing']}")
        print(f"profiles: seed assets given missing fingerprints={rebuild_seed_profiles(db, audit)}")
        print(f"policy: rule set {RULE_SET_V2} {'activated' if activate_rule_set(db, audit) else 'not changed'}")
        anchor_checkpoint(db, audit)
        print("checkpoint: anchored for this container run (checkpoints are not durable across restarts)")
        return 0
    except ValidationError:
        print("The accounts file is not valid (schema, Argon2id hash or duplicate name).", file=sys.stderr)
        return 1
    except DomainError as error:
        print(f"Bootstrap stopped: {error.code}", file=sys.stderr)
        return 1
    except OSError:
        print("Bootstrap stopped: a required file could not be read.", file=sys.stderr)
        return 1
    finally:
        db.engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
