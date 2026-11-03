"""Controlled transfers incidents and audit chain

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa
from uuid import uuid4

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('audit_heads',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('stream_id', sa.String(length=36), nullable=False),
    sa.Column('sequence', sa.Integer(), nullable=False),
    sa.Column('mac', sa.String(length=64), nullable=False),
    sa.CheckConstraint('id = 1 AND sequence >= 0', name='ck_audit_head'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('stream_id')
    )
    op.create_table('audit_events',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('stream_id', sa.String(length=36), nullable=False),
    sa.Column('sequence', sa.Integer(), nullable=False),
    sa.Column('resource_id', sa.String(length=36), nullable=True),
    sa.Column('canonical', sa.Text(), nullable=False),
    sa.Column('mac', sa.String(length=64), nullable=False),
    sa.ForeignKeyConstraint(['stream_id'], ['audit_heads.stream_id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('sequence')
    )
    op.create_index(op.f('ix_audit_events_resource_id'), 'audit_events', ['resource_id'], unique=False)
    op.create_table('transfers',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('actor_id', sa.String(length=36), nullable=False),
    sa.Column('idempotency_key', sa.String(length=36), nullable=False),
    sa.Column('filename', sa.String(length=120), nullable=False),
    sa.Column('snapshot_id', sa.String(length=36), nullable=False),
    sa.Column('file_sha256', sa.String(length=64), nullable=False),
    sa.Column('file_size', sa.Integer(), nullable=False),
    sa.Column('state', sa.String(length=24), nullable=False),
    sa.Column('reason', sa.String(length=64), nullable=False),
    sa.Column('scan_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("state IN ('SCANNING','ALLOWED','BLOCKED','ERROR','STALE','EXPIRED','RELEASE_STARTED','STREAM_FINISHED','DELIVERY_UNKNOWN')", name='ck_transfer_state'),
    sa.CheckConstraint('file_size BETWEEN 0 AND 10485760', name='ck_transfer_size'),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['scan_id'], ['scan_evaluations.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('actor_id', 'idempotency_key', name='uq_transfer_retry'),
    sa.UniqueConstraint('scan_id'),
    sa.UniqueConstraint('snapshot_id')
    )
    op.create_index(op.f('ix_transfers_actor_id'), 'transfers', ['actor_id'], unique=False)
    op.create_index(op.f('ix_transfers_expires_at'), 'transfers', ['expires_at'], unique=False)
    op.create_index(op.f('ix_transfers_state'), 'transfers', ['state'], unique=False)
    op.create_table('incidents',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('transfer_id', sa.String(length=36), nullable=False),
    sa.Column('scan_id', sa.String(length=36), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('revision', sa.Integer(), nullable=False),
    sa.Column('reviewer_id', sa.String(length=36), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("severity IN ('HIGH','MEDIUM')", name='ck_incident_severity'),
    sa.CheckConstraint("status IN ('OPEN','INVESTIGATING','RESOLVED')", name='ck_incident_status'),
    sa.ForeignKeyConstraint(['reviewer_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['scan_id'], ['scan_evaluations.id'], ),
    sa.ForeignKeyConstraint(['transfer_id'], ['transfers.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('transfer_id')
    )
    op.create_index(op.f('ix_incidents_status'), 'incidents', ['status'], unique=False)
    op.create_table('release_attempts',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('transfer_id', sa.String(length=36), nullable=False),
    sa.Column('actor_id', sa.String(length=36), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('outcome', sa.String(length=24), nullable=False),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['transfer_id'], ['transfers.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('transfer_id')
    )
    op.create_table('incident_history',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('incident_id', sa.String(length=36), nullable=False),
    sa.Column('revision', sa.Integer(), nullable=False),
    sa.Column('actor_id', sa.String(length=36), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('note', sa.String(length=1000), nullable=False),
    sa.Column('resolution', sa.String(length=500), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('incident_id', 'revision', name='uq_incident_revision')
    )
    op.create_index(op.f('ix_incident_history_incident_id'), 'incident_history', ['incident_id'], unique=False)
    op.execute(sa.text("INSERT INTO audit_heads (id, stream_id, sequence, mac) VALUES (1, :stream, 0, :mac)").bindparams(stream=str(uuid4()), mac="0" * 64))
    for table in ("audit_events", "incident_history"):
        if op.get_bind().dialect.name == "sqlite":
            for action in ("UPDATE", "DELETE"):
                op.execute(f"CREATE TRIGGER immutable_{table}_{action.lower()} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT, 'immutable history'); END")
        else:
            op.execute(f"CREATE FUNCTION immutable_{table}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable history'; END; $$")
            op.execute(f"CREATE TRIGGER immutable_{table} BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION immutable_{table}()")


def downgrade():
    if op.get_bind().dialect.name == "postgresql":
        for table in ("audit_events", "incident_history"):
            op.execute(f"DROP TRIGGER immutable_{table} ON {table}")
            op.execute(f"DROP FUNCTION immutable_{table}()")
    op.drop_index(op.f('ix_incident_history_incident_id'), table_name='incident_history')
    op.drop_table('incident_history')
    op.drop_table('release_attempts')
    op.drop_index(op.f('ix_incidents_status'), table_name='incidents')
    op.drop_table('incidents')
    op.drop_index(op.f('ix_transfers_state'), table_name='transfers')
    op.drop_index(op.f('ix_transfers_expires_at'), table_name='transfers')
    op.drop_index(op.f('ix_transfers_actor_id'), table_name='transfers')
    op.drop_table('transfers')
    op.drop_index(op.f('ix_audit_events_resource_id'), table_name='audit_events')
    op.drop_table('audit_events')
    op.drop_table('audit_heads')
