from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from app.config import get_settings
from app.logger import get_logger
from app.metrics import record_etcd_operation

_logger = get_logger("services.etcd")
_LEADING_DECIMAL_RE = re.compile(r"^\d+$")


class EtcdError(RuntimeError):
    def __init__(self, action: str, detail: str) -> None:
        super().__init__(f"{action}: {detail}")
        self.action = action
        self.detail = detail


class EtcdUnavailableError(EtcdError):
    pass


@dataclass(frozen=True)
class EtcdMember:
    member_id: str
    name: str
    peer_urls: list[str]
    client_urls: list[str]
    is_learner: bool


@dataclass(frozen=True)
class EtcdHealth:
    endpoint: str
    healthy: bool
    error: str = ""
    took_seconds: float = 0.0


@dataclass(frozen=True)
class EtcdMemberAddResult:
    member_id: str
    peer_urls: list[str]


@dataclass(frozen=True)
class _LeaseCacheEntry:
    lease_id: str
    ttl_seconds: int


_LEASE_CACHE: dict[str, _LeaseCacheEntry] = {}
_LEASE_CACHE_LOCK = asyncio.Lock()


def _parse_endpoints(raw: str) -> list[str]:
    parts = [item.strip().rstrip("/") for item in raw.split(",") if item.strip()]
    return parts


def _prefix_key(key: str) -> str:
    settings = get_settings()
    base = settings.etcd_prefix.strip() or "/uptimemesh"
    clean_base = base.rstrip("/")
    clean_key = key.strip().lstrip("/")
    return f"{clean_base}/{clean_key}"


def _decode_b64(value: object) -> str:
    if not isinstance(value, str) or not value:
        return ""
    try:
        return base64.b64decode(value).decode("utf-8")
    except Exception:  # noqa: BLE001
        return ""


def _run_etcdctl(
    *,
    args: Iterable[str],
    timeout_seconds: int,
) -> tuple[int, str, str]:
    settings = get_settings()
    endpoints = _parse_endpoints(settings.etcd_endpoints)
    if not settings.etcd_enabled:
        raise EtcdUnavailableError("etcd.disabled", "ETCD_ENABLED is false")
    if not endpoints:
        raise EtcdUnavailableError("etcd.endpoints", "ETCD_ENDPOINTS is empty")

    cmd = [
        settings.etcdctl_command,
        f"--endpoints={','.join(endpoints)}",
        f"--dial-timeout={settings.etcd_dial_timeout_seconds}s",
        f"--command-timeout={settings.etcd_command_timeout_seconds}s",
        *args,
    ]
    env = dict(os.environ)
    env["ETCDCTL_API"] = "3"
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            env=env,
        )
    except FileNotFoundError as exc:
        raise EtcdUnavailableError("etcd.command", str(exc)) from exc
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


async def _run_checked(
    *,
    args: Iterable[str],
    action: str,
    timeout_seconds: int = 20,
) -> str:
    arg_list = list(args)
    code, out, err = await asyncio.to_thread(
        _run_etcdctl,
        args=tuple(arg_list),
        timeout_seconds=timeout_seconds,
    )
    if code != 0:
        record_etcd_operation(action=action, ok=False)
        _logger.warning(
            "etcd.command.fail",
            "etcdctl command failed",
            action=action,
            args=" ".join(arg_list),
            exit_code=code,
            stderr=err,
            stdout=out,
        )
        raise EtcdError(action, err or out or f"exit_{code}")
    record_etcd_operation(action=action, ok=True)
    _logger.debug(
        "etcd.command.ok",
        "etcdctl command succeeded",
        action=action,
        args=" ".join(arg_list),
    )
    return out


def _parse_json_payload(payload: str) -> object:
    if not payload:
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {}


async def endpoint_health() -> list[EtcdHealth]:
    out = await _run_checked(
        args=("endpoint", "health", "-w", "json"),
        action="endpoint.health",
        timeout_seconds=15,
    )
    parsed = _parse_json_payload(out)
    rows: list[EtcdHealth] = []
    if isinstance(parsed, list):
        for item in parsed:
            if not isinstance(item, dict):
                continue
            endpoint = str(item.get("Endpoint", ""))
            healthy = bool(item.get("Health", False))
            error = str(item.get("Error", "")) if item.get("Error") else ""
            took_value = item.get("Took")
            took = 0.0
            if isinstance(took_value, (int, float)):
                took = float(took_value)
            rows.append(
                EtcdHealth(
                    endpoint=endpoint,
                    healthy=healthy,
                    error=error,
                    took_seconds=took,
                )
            )
    return rows


async def member_list() -> list[EtcdMember]:
    out = await _run_checked(
        args=("member", "list", "-w", "json"),
        action="member.list",
        timeout_seconds=15,
    )
    parsed = _parse_json_payload(out)
    members: list[EtcdMember] = []
    if isinstance(parsed, dict):
        raw_members = parsed.get("members")
        if isinstance(raw_members, list):
            for item in raw_members:
                if not isinstance(item, dict):
                    continue
                member_id = str(item.get("ID") or "")
                if isinstance(item.get("ID"), int):
                    member_id = str(item.get("ID"))
                name = str(item.get("name") or "")
                peer_urls = [str(url) for url in item.get("peerURLs", []) if isinstance(url, str)]
                client_urls = [
                    str(url) for url in item.get("clientURLs", []) if isinstance(url, str)
                ]
                members.append(
                    EtcdMember(
                        member_id=member_id,
                        name=name,
                        peer_urls=peer_urls,
                        client_urls=client_urls,
                        is_learner=bool(item.get("isLearner", False)),
                    )
                )
    return members


def _parse_member_id(raw: object) -> str:
    if isinstance(raw, int):
        return str(raw)
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return ""


async def member_add(*, name: str, peer_urls: list[str], is_learner: bool = False) -> EtcdMemberAddResult:
    clean_name = name.strip()
    clean_urls = [item.strip() for item in peer_urls if item and item.strip()]
    if not clean_name:
        raise EtcdError("member.add", "member name is required")
    if not clean_urls:
        raise EtcdError("member.add", "peer_urls is required")

    args: list[str] = [
        "member",
        "add",
        clean_name,
        f"--peer-urls={','.join(clean_urls)}",
        "-w",
        "json",
    ]
    if is_learner:
        args.append("--learner")

    out = await _run_checked(
        args=tuple(args),
        action="member.add",
        timeout_seconds=20,
    )
    parsed = _parse_json_payload(out)
    if isinstance(parsed, dict):
        member = parsed.get("member")
        if isinstance(member, dict):
            member_id = _parse_member_id(member.get("ID"))
            urls = [str(url) for url in member.get("peerURLs", []) if isinstance(url, str)]
            if member_id:
                return EtcdMemberAddResult(member_id=member_id, peer_urls=urls or clean_urls)

    members = await member_list()
    for member in members:
        if member.name == clean_name:
            return EtcdMemberAddResult(member_id=member.member_id, peer_urls=member.peer_urls)
    raise EtcdError("member.add", "unable to resolve member id after add")


async def member_remove(*, member_id: str) -> None:
    clean_id = member_id.strip()
    if not clean_id:
        raise EtcdError("member.remove", "member_id is required")
    await _run_checked(
        args=("member", "remove", clean_id),
        action="member.remove",
        timeout_seconds=20,
    )


async def put_value(*, key: str, value: str, lease_id: str = "") -> None:
    args = ["put", _prefix_key(key), value]
    if lease_id:
        args.extend(["--lease", lease_id])
    await _run_checked(args=tuple(args), action="kv.put", timeout_seconds=15)


async def get_value(*, key: str) -> str:
    out = await _run_checked(
        args=("get", _prefix_key(key), "-w", "json"),
        action="kv.get",
        timeout_seconds=15,
    )
    parsed = _parse_json_payload(out)
    if not isinstance(parsed, dict):
        return ""
    kvs = parsed.get("kvs")
    if not isinstance(kvs, list) or not kvs:
        return ""
    first = kvs[0]
    if not isinstance(first, dict):
        return ""
    return _decode_b64(first.get("value"))


async def get_prefix(*, key_prefix: str) -> dict[str, str]:
    out = await _run_checked(
        args=("get", _prefix_key(key_prefix), "--prefix", "-w", "json"),
        action="kv.get_prefix",
        timeout_seconds=20,
    )
    parsed = _parse_json_payload(out)
    results: dict[str, str] = {}
    if not isinstance(parsed, dict):
        return results
    kvs = parsed.get("kvs")
    if not isinstance(kvs, list):
        return results
    for item in kvs:
        if not isinstance(item, dict):
            continue
        key = _decode_b64(item.get("key"))
        value = _decode_b64(item.get("value"))
        if not key:
            continue
        results[key] = value
    return results


async def grant_lease(*, ttl_seconds: int) -> str:
    out = await _run_checked(
        args=("lease", "grant", str(ttl_seconds), "-w", "json"),
        action="lease.grant",
        timeout_seconds=15,
    )
    parsed = _parse_json_payload(out)
    if isinstance(parsed, dict):
        lease_id = parsed.get("ID")
        if isinstance(lease_id, int):
            return str(lease_id)
        if isinstance(lease_id, str) and lease_id:
            return lease_id
    # etcdctl versions may output text; fallback parse first integer token.
    for token in out.replace("=", " ").split():
        if _LEADING_DECIMAL_RE.match(token):
            return token
    raise EtcdError("lease.grant", f"unable to parse lease id from output: {out}")


async def keepalive_lease(*, lease_id: str) -> None:
    clean_lease_id = lease_id.strip()
    if not clean_lease_id:
        raise EtcdError("lease.keepalive", "lease_id is required")
    await _run_checked(
        args=("lease", "keep-alive", clean_lease_id, "--once", "-w", "json"),
        action="lease.keepalive",
        timeout_seconds=15,
    )


async def put_json_with_lease(*, key: str, payload: dict[str, object], ttl_seconds: int) -> str:
    cache_key = _prefix_key(key)
    payload_json = json.dumps(payload, separators=(",", ":"))
    cached_entry: _LeaseCacheEntry | None

    async with _LEASE_CACHE_LOCK:
        cached_entry = _LEASE_CACHE.get(cache_key)

    if cached_entry is not None and cached_entry.ttl_seconds == ttl_seconds:
        try:
            await keepalive_lease(lease_id=cached_entry.lease_id)
            await put_value(key=key, value=payload_json, lease_id=cached_entry.lease_id)
            return cached_entry.lease_id
        except EtcdError as exc:
            _logger.warning(
                "lease.reuse_failed",
                "Cached lease reuse failed; issuing new lease",
                key=cache_key,
                lease_id=cached_entry.lease_id,
                ttl_seconds=ttl_seconds,
                error=str(exc),
            )
            async with _LEASE_CACHE_LOCK:
                _LEASE_CACHE.pop(cache_key, None)

    lease_id = await grant_lease(ttl_seconds=ttl_seconds)
    await put_value(key=key, value=payload_json, lease_id=lease_id)
    async with _LEASE_CACHE_LOCK:
        _LEASE_CACHE[cache_key] = _LeaseCacheEntry(lease_id=lease_id, ttl_seconds=ttl_seconds)
    return lease_id


async def snapshot_save(*, path: str) -> None:
    snapshot_path = Path(path)
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    await _run_checked(
        args=("snapshot", "save", str(snapshot_path)),
        action="snapshot.save",
        timeout_seconds=120,
    )


async def restore_snapshot(*, path: str, output_dir: str) -> None:
    snapshot_path = Path(path)
    if not snapshot_path.exists():
        raise EtcdError("snapshot.restore", f"snapshot file does not exist: {path}")
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    await _run_checked(
        args=("snapshot", "restore", str(snapshot_path), "--data-dir", str(output_path)),
        action="snapshot.restore",
        timeout_seconds=180,
    )


def prune_old_snapshots(*, directory: str, keep: int) -> None:
    dir_path = Path(directory)
    if not dir_path.exists():
        return
    files = [item for item in dir_path.glob("*.db") if item.is_file()]
    files.sort(key=lambda item: item.stat().st_mtime, reverse=True)
    for stale in files[keep:]:
        try:
            stale.unlink()
        except OSError:
            continue
