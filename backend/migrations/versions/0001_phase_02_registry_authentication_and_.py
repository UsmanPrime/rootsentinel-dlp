"""Phase 02 registry authentication and evaluation

Revision ID: 0001
Revises: none
"""
from alembic import op
import sqlalchemy as sa

revision = '0001'
down_revision = None
branch_labels = None
depends_on = None

IMMUTABLE = ('policy_versions', 'registry_revisions', 'asset_versions', 'asset_chunks',
             'scan_evaluations', 'matching_evidence', 'policy_decisions')


def upgrade():
    op.create_table('assets',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('label', sa.String(length=120), nullable=False),
    sa.Column('current_version', sa.Integer(), nullable=False),
    sa.Column('retired', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('label')
    )
    op.create_index(op.f('ix_assets_retired'), 'assets', ['retired'], unique=False)
    op.create_table('users',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('password_hash', sa.String(length=256), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("role IN ('ADMIN','ANALYST','EMPLOYEE')", name='ck_user_role'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('policy_versions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('number', sa.Integer(), nullable=False),
    sa.Column('threshold', sa.Integer(), nullable=False),
    sa.Column('block_enabled', sa.Boolean(), nullable=False),
    sa.Column('actor_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint('threshold BETWEEN 1 AND 10485760', name='ck_policy_threshold'),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('number')
    )
    op.create_table('registry_revisions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('number', sa.Integer(), nullable=False),
    sa.Column('asset_id', sa.String(length=36), nullable=False),
    sa.Column('actor_id', sa.String(length=36), nullable=False),
    sa.Column('action', sa.String(length=16), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('number')
    )
    op.create_table('sessions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=False),
    sa.Column('token_digest', sa.String(length=64), nullable=False),
    sa.Column('csrf_digest', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token_digest')
    )
    op.create_index(op.f('ix_sessions_expires_at'), 'sessions', ['expires_at'], unique=False)
    op.create_index(op.f('ix_sessions_user_id'), 'sessions', ['user_id'], unique=False)
    op.create_table('asset_versions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('asset_id', sa.String(length=36), nullable=False),
    sa.Column('number', sa.Integer(), nullable=False),
    sa.Column('registry_revision', sa.Integer(), nullable=False),
    sa.Column('actor_id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('profile_id', sa.String(length=32), nullable=False),
    sa.Column('file_size', sa.Integer(), nullable=False),
    sa.Column('file_sha256', sa.String(length=64), nullable=False),
    sa.Column('merkle_root', sa.String(length=64), nullable=False),
    sa.Column('chunk_count', sa.Integer(), nullable=False),
    sa.CheckConstraint("profile_id = 'rs-fixed-sha256-v1'", name='ck_asset_profile'),
    sa.CheckConstraint('file_size BETWEEN 1 AND 10485760', name='ck_asset_size'),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
    sa.ForeignKeyConstraint(['registry_revision'], ['registry_revisions.number'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('asset_id', 'file_size', 'file_sha256', name='uq_asset_content'),
    sa.UniqueConstraint('asset_id', 'number', name='uq_asset_version')
    )
    op.create_index(op.f('ix_asset_versions_asset_id'), 'asset_versions', ['asset_id'], unique=False)
    op.create_index('ix_exact_match', 'asset_versions', ['profile_id', 'file_size', 'file_sha256'], unique=False)
    op.create_table('registry_state',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('revision', sa.Integer(), nullable=False),
    sa.Column('policy_id', sa.String(length=36), nullable=False),
    sa.CheckConstraint('id = 1 AND revision >= 0', name='ck_single_state'),
    sa.ForeignKeyConstraint(['policy_id'], ['policy_versions.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('scan_evaluations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('actor_id', sa.String(length=36), nullable=False),
    sa.Column('filename', sa.String(length=120), nullable=False),
    sa.Column('snapshot_id', sa.String(length=36), nullable=False),
    sa.Column('manifest', sa.JSON(), nullable=False),
    sa.Column('registry_revision', sa.Integer(), nullable=False),
    sa.Column('policy_id', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['policy_id'], ['policy_versions.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_evaluations_actor_id'), 'scan_evaluations', ['actor_id'], unique=False)
    op.create_index(op.f('ix_scan_evaluations_created_at'), 'scan_evaluations', ['created_at'], unique=False)
    op.create_table('asset_chunks',
    sa.Column('version_id', sa.String(length=36), nullable=False),
    sa.Column('index', sa.Integer(), nullable=False),
    sa.Column('length', sa.Integer(), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.CheckConstraint('"index" >= 0 AND "index" < 10240 AND length BETWEEN 1 AND 1024', name='ck_chunk_bounds'),
    sa.ForeignKeyConstraint(['version_id'], ['asset_versions.id'], ),
    sa.PrimaryKeyConstraint('version_id', 'index')
    )
    op.create_index('ix_block_match', 'asset_chunks', ['sha256', 'length'], unique=False)
    op.create_table('matching_evidence',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('scan_id', sa.String(length=36), nullable=False),
    sa.Column('version_id', sa.String(length=36), nullable=False),
    sa.Column('asset_id', sa.String(length=36), nullable=False),
    sa.Column('exact', sa.Boolean(), nullable=False),
    sa.Column('matched_bytes', sa.Integer(), nullable=False),
    sa.Column('coverage', sa.JSON(), nullable=False),
    sa.Column('intervals', sa.JSON(), nullable=False),
    sa.Column('blocks', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ),
    sa.ForeignKeyConstraint(['scan_id'], ['scan_evaluations.id'], ),
    sa.ForeignKeyConstraint(['version_id'], ['asset_versions.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('scan_id', 'version_id', name='uq_scan_match')
    )
    op.create_index(op.f('ix_matching_evidence_scan_id'), 'matching_evidence', ['scan_id'], unique=False)
    op.create_table('policy_decisions',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('scan_id', sa.String(length=36), nullable=False),
    sa.Column('outcome', sa.String(length=16), nullable=False),
    sa.Column('reason', sa.String(length=40), nullable=False),
    sa.Column('qualifying_versions', sa.JSON(), nullable=False),
    sa.CheckConstraint("outcome IN ('ALLOW','BLOCK','INDETERMINATE')", name='ck_outcome'),
    sa.ForeignKeyConstraint(['scan_id'], ['scan_evaluations.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('scan_id')
    )
    # Bootstrap policy contains no credentials and is immutable like later policies.
    op.execute("INSERT INTO policy_versions (id, number, threshold, block_enabled, actor_id, created_at) "
               "VALUES ('00000000-0000-4000-8000-000000000001', 1, 1024, true, NULL, CURRENT_TIMESTAMP)")
    op.execute("INSERT INTO registry_state (id, revision, policy_id) "
               "VALUES (1, 0, '00000000-0000-4000-8000-000000000001')")
    if op.get_bind().dialect.name == 'sqlite':
        for table in IMMUTABLE:
            for action in ('UPDATE', 'DELETE'):
                op.execute(f"CREATE TRIGGER immutable_{table}_{action.lower()} BEFORE {action} ON {table} "
                           "BEGIN SELECT RAISE(ABORT, 'immutable history'); END")
    elif op.get_bind().dialect.name == 'postgresql':
        op.execute("CREATE FUNCTION rs_immutable_history() RETURNS trigger LANGUAGE plpgsql AS $$ "
                   "BEGIN RAISE EXCEPTION 'immutable history'; END; $$")
        for table in IMMUTABLE:
            op.execute(f"CREATE TRIGGER immutable_{table} BEFORE UPDATE OR DELETE ON {table} "
                       "FOR EACH ROW EXECUTE FUNCTION rs_immutable_history()")


def downgrade():
    op.drop_table('policy_decisions')
    op.drop_index(op.f('ix_matching_evidence_scan_id'), table_name='matching_evidence')
    op.drop_table('matching_evidence')
    op.drop_index('ix_block_match', table_name='asset_chunks')
    op.drop_table('asset_chunks')
    op.drop_index(op.f('ix_scan_evaluations_created_at'), table_name='scan_evaluations')
    op.drop_index(op.f('ix_scan_evaluations_actor_id'), table_name='scan_evaluations')
    op.drop_table('scan_evaluations')
    op.drop_table('registry_state')
    op.drop_index('ix_exact_match', table_name='asset_versions')
    op.drop_index(op.f('ix_asset_versions_asset_id'), table_name='asset_versions')
    op.drop_table('asset_versions')
    op.drop_index(op.f('ix_sessions_user_id'), table_name='sessions')
    op.drop_index(op.f('ix_sessions_expires_at'), table_name='sessions')
    op.drop_table('sessions')
    op.drop_table('registry_revisions')
    op.drop_table('policy_versions')
    op.drop_table('users')
    op.drop_index(op.f('ix_assets_retired'), table_name='assets')
    op.drop_table('assets')
    if op.get_bind().dialect.name == 'postgresql':
        op.execute('DROP FUNCTION rs_immutable_history()')
