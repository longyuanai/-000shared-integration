"""Add M3 identity bridge clients and short-lived user sessions.

Revision ID: 20260809_0002
Revises: 20260805_0001
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0002"
down_revision: str | None = "20260805_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
JSON_DOCUMENT = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("memberships") as batch_op:
        batch_op.add_column(
            sa.Column(
                "status",
                sa.String(length=32),
                server_default="active",
                nullable=False,
            )
        )

    op.create_table(
        "identity_clients",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("key_prefix", sa.String(length=32), nullable=False),
        sa.Column("secret_hash", sa.String(length=255), nullable=False),
        sa.Column("allowed_issuers", JSON_DOCUMENT, nullable=False),
        sa.Column("active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("rotated_from_id", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["rotated_from_id"],
            ["identity_clients.id"],
            name="fk_identity_clients_rotated_from_id_identity_clients",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_identity_clients"),
        sa.UniqueConstraint("key_prefix", name="uq_identity_clients_key_prefix"),
    )
    op.create_index(
        "ix_identity_clients_active_created",
        "identity_clients",
        ["active", "created_at"],
    )

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("identity_client_id", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["identity_client_id"],
            ["identity_clients.id"],
            name="fk_user_sessions_identity_client_id_identity_clients",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_user_sessions_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_sessions_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_sessions"),
        sa.UniqueConstraint("token_hash", name="uq_user_sessions_token_hash"),
    )
    op.create_index(
        "ix_user_sessions_expires_revoked",
        "user_sessions",
        ["expires_at", "revoked_at"],
    )
    op.create_index(
        "ix_user_sessions_tenant_user",
        "user_sessions",
        ["tenant_id", "user_id"],
    )


def downgrade() -> None:
    op.drop_table("user_sessions")
    op.drop_table("identity_clients")
    with op.batch_alter_table("memberships") as batch_op:
        batch_op.drop_column("status")
