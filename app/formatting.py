from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:  # noqa: BLE001
        return default


def safe_float(value: Any, default: float | None = None) -> float | None:
    try:
        return float(value)
    except Exception:  # noqa: BLE001
        return default


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return as_utc(value)
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        return as_utc(datetime.fromisoformat(raw.replace("Z", "+00:00")))
    except Exception:  # noqa: BLE001
        return None


def as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        raw = value.strip().lower()
        if raw in {"1", "true", "yes", "on"}:
            return True
        if raw in {"0", "false", "no", "off"}:
            return False
    return None


def form_bool(value: Any) -> bool:
    parsed = as_bool(value)
    return bool(parsed) if parsed is not None else False


def format_timestamp(value: datetime | None) -> str:
    timestamp = as_utc(value)
    if timestamp is None:
        return "-"
    return timestamp.strftime("%Y-%m-%d %H:%M:%SZ")


def format_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    minutes, rem_seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {rem_seconds}s"
    hours, rem_minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {rem_minutes}m"
    days, rem_hours = divmod(hours, 24)
    return f"{days}d {rem_hours}h"


def format_age(now: datetime, value: datetime | None) -> str:
    timestamp = as_utc(value)
    if timestamp is None:
        return "-"
    seconds = max(int((now - timestamp).total_seconds()), 0)
    return f"{format_duration(seconds)} ago"


def format_bytes(value: int | None) -> str:
    if value is None:
        return "-"
    size = float(max(int(value), 0))
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    return f"{size:.1f} {units[unit_index]}"


def format_remaining(now: datetime, value: datetime | None) -> str:
    timestamp = as_utc(value)
    if timestamp is None:
        return "-"
    seconds = int((timestamp - now).total_seconds())
    if seconds <= 0:
        return "expired"
    return f"in {format_duration(seconds)}"


def format_value(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)
