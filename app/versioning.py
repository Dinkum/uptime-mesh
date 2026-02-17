from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict

_VERSION_FILE_ENV = "UPTIMEMESH_VERSION_FILE"
_DEFAULT_CHANNEL = "stable"


@dataclass(frozen=True)
class VersionInfo:
    manifest_version: str
    app_version: str
    channel: str
    channel_version: str
    agent_version: str
    source_path: str


def _as_non_empty_str(value: object) -> str:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            return stripped
    return ""


def _candidate_paths() -> list[Path]:
    candidates: list[Path] = []
    env_path = os.getenv(_VERSION_FILE_ENV, "").strip()
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path.cwd() / "version.json")
    candidates.append(Path(__file__).resolve().parent.parent / "version.json")
    return candidates


def _resolve_version_file() -> Path:
    for candidate in _candidate_paths():
        if candidate.exists() and candidate.is_file():
            return candidate
    raise FileNotFoundError(
        f"Unable to locate version.json. Set {_VERSION_FILE_ENV} to an explicit path."
    )


def load_version_info(channel: str = _DEFAULT_CHANNEL) -> VersionInfo:
    version_file = _resolve_version_file()
    try:
        raw = json.loads(version_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {version_file}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError(f"Invalid version manifest in {version_file}: expected an object.")

    manifest_version = _as_non_empty_str(raw.get("version"))
    channels = raw.get("channels")
    channel_data: Dict[str, Any] = {}
    if isinstance(channels, dict):
        selected = channels.get(channel)
        if isinstance(selected, dict):
            channel_data = selected

    channel_version = _as_non_empty_str(channel_data.get("version"))
    agent_version = ""
    agent_data = channel_data.get("agent")
    if isinstance(agent_data, dict):
        agent_version = _as_non_empty_str(agent_data.get("version"))

    app_version = channel_version or manifest_version
    if not app_version:
        raise ValueError(f"Missing version in {version_file}. Expected top-level or channel version.")

    return VersionInfo(
        manifest_version=manifest_version or app_version,
        app_version=app_version,
        channel=channel,
        channel_version=channel_version or app_version,
        agent_version=agent_version,
        source_path=str(version_file),
    )


@lru_cache
def get_version_info() -> VersionInfo:
    return load_version_info()


try:
    __version__ = get_version_info().app_version
except Exception:
    __version__ = "0.0.0"
