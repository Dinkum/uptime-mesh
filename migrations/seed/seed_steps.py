from __future__ import annotations

from sqlalchemy import Connection, text


def seed_cluster_settings(connection: Connection) -> None:
    # Repeatable seeds should create missing settings only. Runtime loops and
    # operators own updates after bootstrap, so migrations must not reset them.
    statements = [
        ("mesh_domain", "mesh.local"),
        ("mesh_cidr", "10.42.0.0/16"),
        ("etcd_status", "ok"),
        ("etcd_last_sync_at", ""),
        ("auth_username", ""),
        ("auth_password_hash", ""),
        ("auth_password_updated_at", ""),
        ("cluster_bootstrapped", "false"),
        ("cluster_bootstrapped_at", ""),
    ]
    statement = text(
        """
        INSERT INTO cluster_settings (key, value)
        VALUES (:key, :value)
        ON CONFLICT(key) DO NOTHING
        """
    )
    for key, value in statements:
        connection.execute(statement, {"key": key, "value": value})


SEED_STEPS = [seed_cluster_settings]
