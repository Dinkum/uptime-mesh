from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.logger import get_logger
from app.models.cluster_setting import ClusterSetting

try:
    import yaml
except Exception:  # noqa: BLE001
    yaml = None

_logger = get_logger("services.config_yaml")


@dataclass(frozen=True)
class _ConfigField:
    section: str
    key: str
    default: str
    description: str
    possible_values: str
    import_from_yaml: bool = False


_FIELDS: tuple[_ConfigField, ...] = (
    _ConfigField(
        section="APP",
        key="github_repo_url",
        default="https://github.com/Dinkum/uptime-mesh",
        description="GitHub repository URL used by install/update scripts.",
        possible_values="Any HTTPS GitHub repository URL.",
        import_from_yaml=True,
    ),
    _ConfigField(
        section="APP",
        key="release_channel",
        default="stable",
        description="Release channel used for rollout policy.",
        possible_values="stable | candidate | dev",
        import_from_yaml=True,
    ),
    _ConfigField(
        section="CLUSTER",
        key="cluster_bootstrapped",
        default="false",
        description="Bootstrap marker for cluster initialization.",
        possible_values="true | false",
    ),
    _ConfigField(
        section="CLUSTER",
        key="cluster_bootstrapped_at",
        default="",
        description="UTC timestamp when bootstrap was completed.",
        possible_values="ISO-8601 UTC timestamp or empty string.",
    ),
    _ConfigField(
        section="CLUSTER",
        key="etcd_status",
        default="unknown",
        description="Current etcd control-plane health status.",
        possible_values="ok | down | stale | unavailable | unknown",
    ),
    _ConfigField(
        section="CLUSTER",
        key="etcd_last_sync_at",
        default="",
        description="UTC timestamp of the latest successful etcd sync.",
        possible_values="ISO-8601 UTC timestamp or empty string.",
    ),
    _ConfigField(
        section="CLUSTER",
        key="swim_membership_json",
        default="{}",
        description="Latest SWIM membership snapshot reported by agents.",
        possible_values="JSON object map keyed by node_id.",
    ),
    _ConfigField(
        section="ROLES",
        key="role_specs_json",
        default='{"backend_server":{"kind":"replicated","min_replicas":1,"max_replicas":0,"ratio":0.5,"priority":100,"strict_separation_with":["reverse_proxy"],"cooldown_seconds":30,"slot_count":0,"runtime_template":"nginx_backend"},"reverse_proxy":{"kind":"replicated","min_replicas":1,"max_replicas":0,"ratio":0.5,"priority":80,"strict_separation_with":["backend_server"],"cooldown_seconds":30,"slot_count":0,"runtime_template":"caddy_reverse_proxy"}}',
        description="Role specification registry for deterministic placement.",
        possible_values="JSON object map keyed by role name.",
    ),
    _ConfigField(
        section="ROLES",
        key="role_placement_json",
        default="{}",
        description="Latest computed role placement snapshot.",
        possible_values="JSON object containing role holder assignments.",
    ),
    _ConfigField(
        section="CONTENT",
        key="internal_cdn_active_version",
        default="bootstrap-v1",
        description="Active internal CDN content bundle version.",
        possible_values="Any non-empty semantic or release-like version string.",
    ),
    _ConfigField(
        section="CONTENT",
        key="internal_cdn_active_hash_sha256",
        default="",
        description="SHA256 hash for the active content bundle.",
        possible_values="Lowercase 64-char SHA256 hex string.",
    ),
    _ConfigField(
        section="CONTENT",
        key="internal_cdn_active_size_bytes",
        default="0",
        description="Size in bytes of the active content payload.",
        possible_values="Integer >= 0.",
    ),
    _ConfigField(
        section="CONTENT",
        key="internal_cdn_active_body_base64",
        default="",
        description="Base64-encoded active content payload served to agents.",
        possible_values="Base64 text.",
    ),
    _ConfigField(
        section="CONTENT",
        key="internal_cdn_seeded_at",
        default="",
        description="UTC timestamp when default content bundle was seeded.",
        possible_values="ISO-8601 UTC timestamp or empty string.",
    ),
    _ConfigField(
        section="RUNTIME",
        key="runtime_heartbeat_interval_seconds",
        default="15",
        description="Heartbeat/SWIM interval used by node runtime loop.",
        possible_values="Integer seconds between 5 and 300.",
        import_from_yaml=True,
    ),
    _ConfigField(
        section="AUTH",
        key="auth_username",
        default="admin",
        description="Administrative username for UI and CLI authentication.",
        possible_values="Any non-empty username string (default: admin).",
        import_from_yaml=True,
    ),
    _ConfigField(
        section="AUTH",
        key="auth_password_updated_at",
        default="",
        description="UTC timestamp of the latest password update.",
        possible_values="ISO-8601 UTC timestamp or empty string.",
    ),
)

_FIELD_KEYS = {item.key for item in _FIELDS}
_SENSITIVE_KEYS = {"auth_secret_key", "cluster_signing_key"}


def _config_path() -> Path:
    settings = get_settings()
    path = Path(settings.managed_config_path).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def _coerce_string(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _load_yaml_map(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    raw = path.read_text(encoding="utf-8")
    if yaml is not None:
        try:
            parsed = yaml.safe_load(raw)
        except Exception:  # noqa: BLE001
            parsed = {}
    else:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}

    if parsed:
        out: dict[str, str] = {}
        for key, value in parsed.items():
            if isinstance(key, str) and key.strip():
                out[key.strip()] = _coerce_string(value)
        return out

    # Fallback parser keeps behavior predictable when yaml parser is unavailable.
    out: dict[str, str] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        clean_key = key.strip()
        clean_value = value.strip().strip('"').strip("'")
        if clean_key:
            out[clean_key] = clean_value
    return out


def _escape_yaml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return escaped.replace("\n", "\\n")


def _iter_sections() -> Iterable[str]:
    seen: set[str] = set()
    for item in _FIELDS:
        if item.section not in seen:
            seen.add(item.section)
            yield item.section


def _render_yaml(values: dict[str, str], extra_values: dict[str, str]) -> str:
    lines: list[str] = [
        "# UptimeMesh managed configuration file.",
        "# Auto-generated and auto-healed on startup.",
        "# Missing values are rebuilt with defaults in stable order.",
        "",
    ]
    for section in _iter_sections():
        lines.append("# ============================================================")
        lines.append(f"# [{section}]")
        lines.append("# ============================================================")
        for item in _FIELDS:
            if item.section != section:
                continue
            value = values.get(item.key, item.default)
            lines.append(f"# {item.description}")
            lines.append(f"# Possible values: {item.possible_values}")
            lines.append(f'{item.key}: "{_escape_yaml_string(value)}"')
            lines.append("")

    if extra_values:
        lines.append("# ============================================================")
        lines.append("# [EXTRA]")
        lines.append("# ============================================================")
        for key in sorted(extra_values):
            value = extra_values[key]
            lines.append("# Additional runtime setting persisted from cluster settings.")
            lines.append("# Possible values: free-form string.")
            lines.append(f'{key}: "{_escape_yaml_string(value)}"')
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


async def _db_settings_map(session: AsyncSession) -> dict[str, str]:
    result = await session.execute(select(ClusterSetting))
    rows = list(result.scalars().all())
    return {row.key: row.value for row in rows}


async def reconcile_with_db(session: AsyncSession) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    async with _logger.operation(
        "config_yaml.reconcile",
        "Reconciling config.yaml with cluster settings",
        path=str(path),
    ) as op:
        yaml_map = _load_yaml_map(path)
        db_map = await _db_settings_map(session)

        changed_db = False
        existing_rows = await session.execute(select(ClusterSetting))
        row_map = {row.key: row for row in existing_rows.scalars().all()}
        for field in _FIELDS:
            yaml_value = yaml_map.get(field.key, "").strip()
            desired = yaml_value if yaml_value else field.default
            row = row_map.get(field.key)
            if row is None:
                session.add(ClusterSetting(key=field.key, value=desired))
                changed_db = True
            elif field.import_from_yaml and yaml_value and row.value != desired:
                row.value = desired
                changed_db = True

        if changed_db:
            await session.commit()
            db_map = await _db_settings_map(session)
            op.step("db.upsert", "Applied config defaults/overrides to DB", count=len(_FIELDS))
        else:
            op.step("db.upsert", "No DB config changes required")

        managed_values: dict[str, str] = {}
        for field in _FIELDS:
            value = db_map.get(field.key, "").strip()
            managed_values[field.key] = value if value else field.default
        extra_values = {
            k: v for k, v in db_map.items() if k not in _FIELD_KEYS and k not in _SENSITIVE_KEYS
        }
        rendered = _render_yaml(managed_values, extra_values)
        path.write_text(rendered, encoding="utf-8")
        op.step(
            "file.write",
            "Wrote managed config.yaml",
            managed_keys=len(managed_values),
            extra_keys=len(extra_values),
        )


async def sync_from_db(session: AsyncSession) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    async with _logger.operation(
        "config_yaml.sync",
        "Syncing config.yaml from DB",
        path=str(path),
    ) as op:
        db_map = await _db_settings_map(session)
        existing = _load_yaml_map(path)
        managed_values: dict[str, str] = {}
        for field in _FIELDS:
            db_value = db_map.get(field.key, "").strip()
            if db_value:
                managed_values[field.key] = db_value
            else:
                fallback = existing.get(field.key, "").strip()
                managed_values[field.key] = fallback if fallback else field.default
        extra_values = {
            k: v for k, v in db_map.items() if k not in _FIELD_KEYS and k not in _SENSITIVE_KEYS
        }
        path.write_text(_render_yaml(managed_values, extra_values), encoding="utf-8")
        op.step(
            "file.write",
            "Synchronized managed config.yaml",
            managed_keys=len(managed_values),
            extra_keys=len(extra_values),
        )
