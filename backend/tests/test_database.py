from concurrent.futures import ThreadPoolExecutor

from alembic import command
import pytest
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import IntegrityError, DatabaseError

from app.models import Asset, AssetVersion, PolicyVersion, RegistryState
from app.registry import register
from app.errors import DomainError


def test_migration_indexes_constraints_and_repeatability(system):
    _, db, actors, cfg = system
    command.upgrade(cfg, "head")
    inspector = inspect(db.engine)
    assert set(inspector.get_table_names()) == {
        "alembic_version", "users", "sessions", "assets", "asset_versions", "asset_chunks",
        "registry_revisions", "registry_state", "policy_versions", "scan_evaluations",
        "matching_evidence", "policy_decisions",
        "transfers", "release_attempts", "incidents", "incident_history", "audit_heads", "audit_events",
        "transparency_heads",
    }
    assert "ix_exact_match" in {i["name"] for i in inspector.get_indexes("asset_versions")}
    assert "ix_block_match" in {i["name"] for i in inspector.get_indexes("asset_chunks")}
    assert inspector.get_foreign_keys("asset_versions")
    with db.transaction() as s:
        assert s.get(RegistryState, 1).revision == 0
        assert s.scalar(select(PolicyVersion)).threshold == 1024
    # Downgrade only this isolated disposable test database; never operator data.
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    assert "asset_versions" in inspect(db.engine).get_table_names()


def test_database_immutability_and_fk(system):
    _, db, actors, _ = system
    with db.transaction() as s:
        version = register(s, actors["admin"], "Immutable", b"abc")
    for sql in ("UPDATE asset_versions SET file_sha256 = 'changed'", "DELETE FROM asset_versions",
                "UPDATE asset_chunks SET sha256 = 'changed'", "DELETE FROM policy_versions"):
        with pytest.raises(DatabaseError), db.transaction() as s:
            s.execute(text(sql))
    with pytest.raises(IntegrityError), db.transaction() as s:
        s.add(AssetVersion(asset_id="missing", number=1, registry_revision=1, actor_id=actors["admin"].id,
                           profile_id="rs-fixed-sha256-v1", file_size=1, file_sha256="0"*64, merkle_root="0"*64, chunk_count=1))


def test_transaction_rollback(system):
    _, db, actors, _ = system
    with pytest.raises(RuntimeError), db.transaction() as s:
        register(s, actors["admin"], "Rollback", b"bytes")
        raise RuntimeError("simulated downstream failure")
    with db.transaction() as s:
        assert s.get(RegistryState, 1).revision == 0
        assert not s.scalars(select(Asset)).all()


def test_concurrent_registration_conflict(system):
    _, db, actors, _ = system
    def attempt(_):
        try:
            with db.transaction() as s:
                register(s, actors["admin"], "Same label", b"bytes")
            return "created"
        except DomainError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, range(2)))
    assert sorted(results) == ["DUPLICATE_ASSET_LABEL", "created"]
    with db.transaction() as s:
        assert s.get(RegistryState, 1).revision == 1
