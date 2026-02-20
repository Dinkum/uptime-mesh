from __future__ import annotations

from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.versioning import get_version_info

DEFAULT_AUTH_SECRET_KEY = "change-me-uptimemesh-auth-secret"
DEFAULT_CLUSTER_SIGNING_KEY = "change-me-uptimemesh-cluster-signing-key"
_PROD_ENV_NAMES = {"prod", "production"}


class Settings(BaseSettings):
    app_name: str = Field(default="UptimeMesh")
    app_env: str = Field(default="dev")

    database_url: str = Field(default="")

    log_level: str = Field(default="INFO")
    log_file: str = Field(default="data/logs/app.log")
    managed_config_path: str = Field(default="config.yaml")
    log_db_queries: bool = Field(default=True)
    log_db_query_params: bool = Field(default=False)
    log_sql_max_length: int = Field(default=400)

    server_host: str = Field(default="0.0.0.0")
    server_port: int = Field(default=8000)
    auth_secret_key: str = Field(default=DEFAULT_AUTH_SECRET_KEY)
    auth_cookie_secure: bool = Field(default=False)
    auth_session_ttl_seconds: int = Field(default=43200)
    cluster_signing_key: str = Field(default=DEFAULT_CLUSTER_SIGNING_KEY)
    cluster_pki_dir: str = Field(default="data/pki")
    node_cert_validity_days: int = Field(default=30)
    cluster_lease_token_ttl_seconds: int = Field(default=86400)
    heartbeat_signature_max_skew_seconds: int = Field(default=30)
    metrics_enabled: bool = Field(default=True)
    etcd_enabled: bool = Field(default=False)
    etcd_endpoints: str = Field(default="")
    etcdctl_command: str = Field(default="etcdctl")
    etcd_prefix: str = Field(default="/uptimemesh")
    etcd_dial_timeout_seconds: int = Field(default=5, ge=1, le=60)
    etcd_command_timeout_seconds: int = Field(default=10, ge=1, le=120)
    etcd_snapshot_dir: str = Field(default="data/etcd-snapshots")
    etcd_snapshot_retention: int = Field(default=30, ge=1, le=365)
    etcd_snapshot_schedule_enabled: bool = Field(default=True)
    etcd_snapshot_interval_seconds: int = Field(default=86400, ge=60, le=604800)
    etcd_snapshot_schedule_requested_by: str = Field(default="runtime.snapshot_scheduler")
    events_retention_days: int = Field(default=30, ge=1, le=3650)
    runtime_events_prune_enable: bool = Field(default=True)
    runtime_events_prune_interval_seconds: int = Field(default=3600, ge=60, le=86400)
    runtime_events_prune_batch_size: int = Field(default=5000, ge=100, le=100000)
    support_bundle_dir: str = Field(default="data/support-bundles")
    lxd_enabled: bool = Field(default=True)
    lxd_command: str = Field(default="lxc")
    lxd_project: str = Field(default="default")
    lxd_default_image: str = Field(default="images:ubuntu/22.04")
    lxd_default_profile: str = Field(default="default")
    lxd_health_timeout_seconds: int = Field(default=60, ge=5, le=600)
    lxd_health_poll_seconds: int = Field(default=2, ge=1, le=30)

    runtime_enable: bool = Field(default=False)
    runtime_node_id: str = Field(default="")
    runtime_node_name: str = Field(default="")
    runtime_node_role: str = Field(default="worker")
    runtime_api_base_url: str = Field(default="http://127.0.0.1:8000")
    runtime_identity_dir: str = Field(default="data/identities")
    runtime_heartbeat_interval_seconds: int = Field(default=15, ge=5, le=300)
    runtime_heartbeat_ttl_seconds: int = Field(default=45, ge=10, le=300)
    runtime_mesh_cidr: str = Field(default="10.42.0.0/16")
    runtime_wg_primary_iface: str = Field(default="wg-mesh0")
    runtime_wg_secondary_iface: str = Field(default="wg-mesh1")
    runtime_wg_configure: bool = Field(default=True)
    runtime_wg_key_dir: str = Field(default="data/wireguard")
    runtime_wg_local_address: str = Field(default="")
    runtime_wg_primary_listen_port: int = Field(default=51820, ge=1, le=65535)
    runtime_wg_secondary_listen_port: int = Field(default=51821, ge=1, le=65535)
    runtime_wg_peer_port: int = Field(default=51820, ge=1, le=65535)
    runtime_wg_peer_allowed_ips: str = Field(default="")
    runtime_wg_persistent_keepalive_seconds: int = Field(default=25, ge=0, le=300)
    runtime_wg_primary_peer_public_key: str = Field(default="")
    runtime_wg_secondary_peer_public_key: str = Field(default="")
    runtime_wg_primary_peer_endpoint: str = Field(default="")
    runtime_wg_secondary_peer_endpoint: str = Field(default="")
    runtime_wg_primary_router_ip: str = Field(default="")
    runtime_wg_secondary_router_ip: str = Field(default="")
    runtime_failover_threshold: int = Field(default=3, ge=1, le=20)
    runtime_failback_stable_count: int = Field(default=6, ge=1, le=50)
    runtime_failback_enabled: bool = Field(default=False)
    runtime_route_primary_metric: int = Field(default=100, ge=1, le=10000)
    runtime_route_secondary_metric: int = Field(default=200, ge=1, le=10000)
    runtime_etcd_endpoints: str = Field(default="")
    runtime_etcd_probe_interval_seconds: int = Field(default=10, ge=3, le=300)
    runtime_discovery_enable: bool = Field(default=False)
    runtime_discovery_domain: str = Field(default="mesh.local")
    runtime_discovery_ttl_seconds: int = Field(default=30, ge=1, le=3600)
    runtime_discovery_zone_path: str = Field(default="data/coredns/db.mesh.local")
    runtime_discovery_corefile_path: str = Field(default="data/coredns/Corefile")
    runtime_discovery_listen: str = Field(default=".:53")
    runtime_discovery_forwarders: str = Field(default="/etc/resolv.conf")
    runtime_discovery_interval_seconds: int = Field(default=10, ge=3, le=300)
    runtime_discovery_reload_command: str = Field(default="")
    runtime_gateway_enable: bool = Field(default=False)
    runtime_gateway_config_path: str = Field(default="data/nginx/nginx.conf")
    runtime_gateway_candidate_path: str = Field(default="data/nginx/nginx.candidate.conf")
    runtime_gateway_backup_path: str = Field(default="data/nginx/nginx.prev.conf")
    runtime_gateway_listen: str = Field(default="0.0.0.0:80")
    runtime_gateway_server_name: str = Field(default="_")
    runtime_gateway_interval_seconds: int = Field(default=10, ge=3, le=300)
    runtime_gateway_validate_command: str = Field(default="nginx -t -c {config_path}")
    runtime_gateway_reload_command: str = Field(default="systemctl reload nginx")
    runtime_gateway_healthcheck_urls: str = Field(default="")
    runtime_gateway_healthcheck_timeout_seconds: int = Field(default=3, ge=1, le=60)
    runtime_gateway_healthcheck_expected_status: int = Field(default=200, ge=100, le=599)
    runtime_monitoring_enable: bool = Field(default=False)
    runtime_monitoring_interval_seconds: int = Field(default=15, ge=3, le=300)
    runtime_monitoring_prometheus_config_path: str = Field(default="data/monitoring/prometheus.yml")
    runtime_monitoring_prometheus_candidate_path: str = Field(
        default="data/monitoring/prometheus.candidate.yml"
    )
    runtime_monitoring_prometheus_backup_path: str = Field(default="data/monitoring/prometheus.prev.yml")
    runtime_monitoring_rules_path: str = Field(default="/etc/uptime-mesh/monitoring/alert_rules.yml")
    runtime_monitoring_alertmanager_targets: str = Field(default="127.0.0.1:9093")
    runtime_monitoring_scrape_interval_seconds: int = Field(default=15, ge=5, le=300)
    runtime_monitoring_evaluation_interval_seconds: int = Field(default=15, ge=5, le=300)
    runtime_monitoring_node_exporter_port: int = Field(default=9100, ge=1, le=65535)
    runtime_monitoring_include_localhost_targets: bool = Field(default=True)
    runtime_monitoring_validate_command: str = Field(
        default="promtool check config {candidate_path}"
    )
    runtime_monitoring_reload_command: str = Field(
        default="systemctl reload prometheus || systemctl restart prometheus"
    )
    runtime_scheduler_plan_cache_enable: bool = Field(default=True)
    runtime_scheduler_plan_cache_interval_seconds: int = Field(default=30, ge=5, le=3600)
    runtime_scheduler_plan_cache_service_limit: int = Field(default=200, ge=1, le=5000)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @property
    def app_version(self) -> str:
        return get_version_info().app_version

    @property
    def app_manifest_version(self) -> str:
        return get_version_info().manifest_version

    @property
    def app_release_channel(self) -> str:
        return get_version_info().channel

    @property
    def app_agent_version(self) -> str:
        return get_version_info().agent_version

    @property
    def app_version_source_path(self) -> str:
        return get_version_info().source_path

    @model_validator(mode="after")
    def validate_database_url(self) -> "Settings":
        if not self.database_url:
            raise ValueError("DATABASE_URL must be set in .env or environment variables.")
        _ = get_version_info()
        if self.app_env.strip().lower() in _PROD_ENV_NAMES:
            issues: list[str] = []
            if self.auth_secret_key == DEFAULT_AUTH_SECRET_KEY:
                issues.append("AUTH_SECRET_KEY must not use the default placeholder in production.")
            if self.cluster_signing_key == DEFAULT_CLUSTER_SIGNING_KEY:
                issues.append("CLUSTER_SIGNING_KEY must not use the default placeholder in production.")
            if len(self.auth_secret_key) < 32:
                issues.append("AUTH_SECRET_KEY must be at least 32 characters in production.")
            if len(self.cluster_signing_key) < 32:
                issues.append("CLUSTER_SIGNING_KEY must be at least 32 characters in production.")
            if not self.auth_cookie_secure:
                issues.append("AUTH_COOKIE_SECURE must be true in production.")
            if issues:
                raise ValueError(" ".join(issues))
        if self.runtime_enable and not self.runtime_node_id:
            raise ValueError("RUNTIME_NODE_ID is required when RUNTIME_ENABLE=true.")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
