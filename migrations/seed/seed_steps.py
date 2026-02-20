from __future__ import annotations

from sqlalchemy import Connection, text


def seed_cluster_settings(connection: Connection) -> None:
    statements = [
        ("mesh_domain", "mesh.local", True),
        ("mesh_cidr", "10.42.0.0/16", True),
        ("etcd_status", "ok", False),
        ("etcd_last_sync_at", "", True),
        ("auth_username", "", False),
        ("auth_password_hash", "", False),
        ("auth_password_updated_at", "", False),
        ("cluster_bootstrapped", "false", False),
        ("cluster_bootstrapped_at", "", False),
    ]
    for key, value, overwrite_existing in statements:
        if overwrite_existing:
            statement = text(
                """
                INSERT INTO cluster_settings (key, value)
                VALUES (:key, :value)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """
            )
        else:
            statement = text(
                """
                INSERT INTO cluster_settings (key, value)
                VALUES (:key, :value)
                ON CONFLICT(key) DO NOTHING
                """
            )
        connection.execute(statement, {"key": key, "value": value})


SEED_STEPS = [seed_cluster_settings]
