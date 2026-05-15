"""provider driver tables

Revision ID: 0011_provider_driver_tables
Revises: 0010_events_node_created_index
Create Date: 2026-05-15 09:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0011_provider_driver_tables"
down_revision = "0010_events_node_created_index"
branch_labels = None
depends_on = None


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _indexes(table_name: str) -> set[str]:
    if table_name not in _tables():
        return set()
    return {item["name"] for item in sa.inspect(op.get_bind()).get_indexes(table_name)}


def upgrade() -> None:
    tables = _tables()
    if "provider_accounts" not in tables:
        op.create_table(
            "provider_accounts",
            sa.Column("id", sa.String(length=64), nullable=False),
            sa.Column("provider", sa.String(length=64), nullable=False),
            sa.Column("display_name", sa.String(length=128), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False),
            sa.Column("config", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
    if "provider_resources" not in tables:
        op.create_table(
            "provider_resources",
            sa.Column("id", sa.String(length=64), nullable=False),
            sa.Column("account_id", sa.String(length=64), nullable=False),
            sa.Column("provider", sa.String(length=64), nullable=False),
            sa.Column("resource_kind", sa.String(length=64), nullable=False),
            sa.Column("external_id", sa.String(length=256), nullable=True),
            sa.Column("desired", sa.JSON(), nullable=False),
            sa.Column("observed", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["account_id"], ["provider_accounts.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
    if "provider_actions" not in tables:
        op.create_table(
            "provider_actions",
            sa.Column("id", sa.String(length=64), nullable=False),
            sa.Column("account_id", sa.String(length=64), nullable=False),
            sa.Column("resource_id", sa.String(length=64), nullable=True),
            sa.Column("action", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("plan", sa.JSON(), nullable=False),
            sa.Column("result", sa.JSON(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.ForeignKeyConstraint(["account_id"], ["provider_accounts.id"]),
            sa.ForeignKeyConstraint(["resource_id"], ["provider_resources.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    wanted = {
        "provider_accounts": [
            ("ix_provider_accounts_provider", ["provider"]),
            ("ix_provider_accounts_enabled", ["enabled"]),
        ],
        "provider_resources": [
            ("ix_provider_resources_account_id", ["account_id"]),
            ("ix_provider_resources_provider_kind", ["provider", "resource_kind"]),
        ],
        "provider_actions": [
            ("ix_provider_actions_account_id", ["account_id"]),
            ("ix_provider_actions_resource_id", ["resource_id"]),
            ("ix_provider_actions_status", ["status"]),
        ],
    }
    for table_name, indexes in wanted.items():
        existing = _indexes(table_name)
        for index_name, columns in indexes:
            if index_name not in existing:
                op.create_index(index_name, table_name, columns, unique=False)


def downgrade() -> None:
    for table_name in ("provider_actions", "provider_resources", "provider_accounts"):
        if table_name in _tables():
            op.drop_table(table_name)
