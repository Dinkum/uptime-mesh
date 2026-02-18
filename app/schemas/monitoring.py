from __future__ import annotations

from pydantic import BaseModel


class MonitoringStatusOut(BaseModel):
    enabled: bool
    config_path: str
    candidate_path: str
    backup_path: str
    config_exists: bool
    config_sha256: str
    api_targets: list[str]
    node_exporter_targets: list[str]
    alertmanager_targets: list[str]
    api_target_count: int
    node_exporter_target_count: int
    alertmanager_target_count: int
    last_sync_at: str
    last_apply_status: str
    last_apply_error: str
