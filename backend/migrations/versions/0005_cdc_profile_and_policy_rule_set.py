"""Content-defined chunk rows, policy rule set and per-profile scan evidence

Revision ID: 0005
Revises: 0004
"""
from alembic import op
import sqlalchemy as sa

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('asset_cdc_chunks',
    sa.Column('version_id', sa.String(length=36), nullable=False),
    sa.Column('offset', sa.Integer(), autoincrement=False, nullable=False),
    sa.Column('length', sa.Integer(), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.CheckConstraint('"offset" >= 0 AND "offset" < 10485760 AND length BETWEEN 1 AND 8192', name='ck_cdc_chunk_bounds'),
    sa.ForeignKeyConstraint(['version_id'], ['asset_versions.id'], ),
    sa.PrimaryKeyConstraint('version_id', 'offset')
    )
    op.create_index('ix_cdc_match', 'asset_cdc_chunks', ['sha256'], unique=False)
    # Existing policies keep the rule set they were written for. No stored row of an earlier table changes.
    op.add_column('policy_versions', sa.Column('rule_set', sa.String(length=16), server_default='rs-policy-v1', nullable=False))
    op.add_column('policy_versions', sa.Column('cdc_threshold', sa.Integer(), nullable=True))
    op.add_column('scan_evaluations', sa.Column('profiles', sa.JSON(), nullable=True))
    # Rows are only ever inserted, like asset_chunks.
    if op.get_bind().dialect.name == "sqlite":
        for action in ("UPDATE", "DELETE"):
            op.execute(f"CREATE TRIGGER immutable_asset_cdc_chunks_{action.lower()} BEFORE {action} ON asset_cdc_chunks BEGIN SELECT RAISE(ABORT, 'immutable history'); END")
    else:
        op.execute("CREATE TRIGGER immutable_asset_cdc_chunks BEFORE UPDATE OR DELETE ON asset_cdc_chunks FOR EACH ROW EXECUTE FUNCTION rs_immutable_history()")


def downgrade():
    op.drop_column('scan_evaluations', 'profiles')
    op.drop_column('policy_versions', 'cdc_threshold')
    op.drop_column('policy_versions', 'rule_set')
    op.drop_index('ix_cdc_match', table_name='asset_cdc_chunks')
    op.drop_table('asset_cdc_chunks')
