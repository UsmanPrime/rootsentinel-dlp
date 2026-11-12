"""Visitor sandbox: VISITOR role, visitor session counters, synthetic asset flag, audit actor column

Revision ID: 0006
Revises: 0005

Forward only in operation (the downgrade exists for disposable test databases). On SQLite the users table is rebuilt (a CHECK constraint cannot be altered): the stored table, index and
trigger definitions are copied from sqlite_master, so nothing else about the table changes. Foreign keys are switched
off for the swap (migrations run one transaction each, see env.py) and checked afterwards. No audit or other
append-only row is rewritten; audit_events only gains a nullable column.
"""
from alembic import op
import sqlalchemy as sa

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None

OLD_CHECK = "role IN ('ADMIN','ANALYST','EMPLOYEE')"
NEW_CHECK = "role IN ('ADMIN','ANALYST','EMPLOYEE','VISITOR')"
SEED_LABELS = ("synthetic-protected-sample", "synthetic-source-sample")


def _rebuild_users_sqlite(bind, old_check, new_check):
    bind.exec_driver_sql("PRAGMA foreign_keys=OFF")
    rows = bind.exec_driver_sql("SELECT type, name, sql FROM sqlite_master WHERE tbl_name='users'").all()
    table_sql = next(sql for kind, name, sql in rows if kind == "table")
    if old_check not in table_sql:
        raise RuntimeError("users table definition not recognised")
    dependents = [sql for kind, name, sql in rows if kind in ("index", "trigger") and sql]
    new_sql = table_sql.replace(old_check, new_check).replace('CREATE TABLE users', 'CREATE TABLE users_rebuild', 1)
    if 'users_rebuild' not in new_sql:
        new_sql = table_sql.replace(old_check, new_check).replace('CREATE TABLE "users"', 'CREATE TABLE users_rebuild', 1)
    bind.exec_driver_sql(new_sql)
    bind.exec_driver_sql("INSERT INTO users_rebuild SELECT * FROM users")
    bind.exec_driver_sql("DROP TABLE users")
    bind.exec_driver_sql("ALTER TABLE users_rebuild RENAME TO users")
    for sql in dependents:
        bind.exec_driver_sql(sql)
    if bind.exec_driver_sql("PRAGMA foreign_key_check").all():
        raise RuntimeError("foreign key check failed after rebuilding users")


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        _rebuild_users_sqlite(bind, OLD_CHECK, NEW_CHECK)
    else:
        op.execute("ALTER TABLE users DROP CONSTRAINT ck_user_role")
        op.execute(f"ALTER TABLE users ADD CONSTRAINT ck_user_role CHECK ({NEW_CHECK})")
    op.add_column('sessions', sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True))
    op.create_table('visitor_sessions',
    sa.Column('session_id', sa.String(length=36), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('submissions_used', sa.Integer(), nullable=False),
    sa.Column('release_attempts_used', sa.Integer(), nullable=False),
    sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('session_id'),
    sa.UniqueConstraint('user_id')
    )
    op.create_index(op.f('ix_visitor_sessions_created_at'), 'visitor_sessions', ['created_at'], unique=False)
    op.add_column('assets', sa.Column('synthetic', sa.Boolean(), server_default=sa.false(), nullable=False))
    op.execute(sa.text("UPDATE assets SET synthetic = :yes WHERE label IN (:first, :second)").bindparams(
        yes=True, first=SEED_LABELS[0], second=SEED_LABELS[1]))
    op.add_column('audit_events', sa.Column('actor_id', sa.String(length=36), nullable=True))
    op.create_index(op.f('ix_audit_events_actor_id'), 'audit_events', ['actor_id'], unique=False)


def downgrade():
    """For disposable test databases only. Operations are forward only; this refuses to run when a visitor exists."""
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT COUNT(*) FROM users WHERE role = 'VISITOR'")).scalar():
        raise RuntimeError("Visitor accounts exist; this migration is not reversible on real data")
    op.drop_index(op.f('ix_audit_events_actor_id'), table_name='audit_events')
    op.drop_column('audit_events', 'actor_id')
    op.drop_column('assets', 'synthetic')
    op.drop_index(op.f('ix_visitor_sessions_created_at'), table_name='visitor_sessions')
    op.drop_table('visitor_sessions')
    op.drop_column('sessions', 'last_seen_at')
    if bind.dialect.name == "sqlite":
        _rebuild_users_sqlite(bind, NEW_CHECK, OLD_CHECK)
    else:
        op.execute("ALTER TABLE users DROP CONSTRAINT ck_user_role")
        op.execute(f"ALTER TABLE users ADD CONSTRAINT ck_user_role CHECK ({OLD_CHECK})")
