"""Signed tree heads over the audit chain

Revision ID: 0004
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa

revision = '0004'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('transparency_heads',
    sa.Column('tree_size', sa.Integer(), autoincrement=False, nullable=False),
    sa.Column('log_id', sa.String(length=36), nullable=False),
    sa.Column('root_hash', sa.String(length=64), nullable=False),
    sa.Column('timestamp', sa.String(length=27), nullable=False),
    sa.Column('key_id', sa.String(length=64), nullable=False),
    sa.Column('signature', sa.String(length=128), nullable=False),
    sa.CheckConstraint('tree_size >= 1', name='ck_transparency_head_size'),
    sa.ForeignKeyConstraint(['log_id'], ['audit_heads.stream_id'], ),
    sa.PrimaryKeyConstraint('tree_size')
    )
    # Append-only: a stored head is never changed or removed by the application. The triggers stop an accidental
    # edit; a database owner can drop them, and a deleted head is detected only by a party that kept a copy.
    if op.get_bind().dialect.name == "sqlite":
        for action in ("UPDATE", "DELETE"):
            op.execute(f"CREATE TRIGGER immutable_transparency_heads_{action.lower()} BEFORE {action} ON transparency_heads BEGIN SELECT RAISE(ABORT, 'immutable history'); END")
    else:
        op.execute("CREATE FUNCTION immutable_transparency_heads() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable history'; END; $$")
        op.execute("CREATE TRIGGER immutable_transparency_heads BEFORE UPDATE OR DELETE ON transparency_heads FOR EACH ROW EXECUTE FUNCTION immutable_transparency_heads()")


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TRIGGER immutable_transparency_heads ON transparency_heads")
        op.execute("DROP FUNCTION immutable_transparency_heads()")
    op.drop_table('transparency_heads')
