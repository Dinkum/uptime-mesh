from __future__ import annotations

from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_AUTH_SECRET_KEY = "change-me-uptimemesh-auth-secret"
DEFAULT_CLUSTER_SIGNING_KEY = "change-me-uptimemesh-cluster-signing-key"
_PROD_ENV_NAMES = {"prod", "production"}


class Settings(BaseSettings):
    app_name: str = Field(default="UptimeMesh")
    app_env: str = Field(default="dev")
    app_version: str = Field(default="0.1.0")

    database_url: str = Field(default="")

    log_level: str = Field(default="INFO")
    log_file: str = Field(default="data/app.log")
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

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    @model_validator(mode="after")
    def validate_database_url(self) -> "Settings":
        if not self.database_url:
            raise ValueError("DATABASE_URL must be set in .env or environment variables.")
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
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
