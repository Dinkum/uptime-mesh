from __future__ import annotations

import hashlib
import base64
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.identity import (
    create_lease_token,
    decode_lease_token,
    ensure_cluster_ca,
    heartbeat_signing_message,
    sign_node_csr,
    verify_heartbeat_signature,
)
from app.logger import get_logger
from app.models.join_token import JoinToken
from app.models.node import Node
from app.models.router_assignment import RouterAssignment
from app.schemas.cluster import (
    ClusterBootstrapRequest,
    HeartbeatOut,
    JoinTokenOut,
    NodeJoinRequest,
    NodeJoinOut,
    NodeLeaseOut,
)
from app.services import cluster_settings
from app.services import etcd as etcd_service
from app.services.events import record_event

_logger = get_logger("services.cluster")
settings = get_settings()

BOOTSTRAPPED_KEY = "cluster_bootstrapped"
BOOTSTRAP_AT_KEY = "cluster_bootstrapped_at"
AUTH_SECRET_KEY_SETTING = "auth_secret_key"
CLUSTER_SIGNING_KEY_SETTING = "cluster_signing_key"
SWIM_MEMBERSHIP_KEY = "swim_membership_json"
CONTENT_VERSION_KEY = "internal_cdn_active_version"
CONTENT_HASH_KEY = "internal_cdn_active_hash_sha256"
CONTENT_SIZE_KEY = "internal_cdn_active_size_bytes"
CONTENT_BODY_KEY = "internal_cdn_active_body_base64"
CONTENT_SEEDED_AT_KEY = "internal_cdn_seeded_at"

_ROLE_ALIASES = {
    "worker": "general",
    "gateway": "general",
    "node": "general",
    "general": "general",
    "backend_server": "backend_server",
    "reverse_proxy": "reverse_proxy",
}

_DEFAULT_CONTENT_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Hello World</title>
    <style>
      :root {
        color-scheme: dark;
      }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background: radial-gradient(circle at 12% 12%, rgba(56, 189, 248, 0.35), transparent 40%),
          radial-gradient(circle at 88% 16%, rgba(74, 222, 128, 0.28), transparent 34%),
          linear-gradient(165deg, #020617 0%, #0b1220 48%, #111827 100%);
        font-family: "Space Grotesk", system-ui, sans-serif;
      }
      h1 {
        margin: 0;
        padding: 1.5rem 2.2rem;
        border: 1px solid rgba(148, 163, 184, 0.35);
        border-radius: 1rem;
        background: rgba(15, 23, 42, 0.78);
        color: #f8fafc;
        font-size: clamp(2.2rem, 8vw, 4rem);
        letter-spacing: 0.06em;
        text-transform: uppercase;
        box-shadow: 0 0 0 1px rgba(56, 189, 248, 0.18), 0 0 36px rgba(56, 189, 248, 0.22);
      }
    </style>
  </head>
  <body>
    <h1>Hello World</h1>
  </body>
</html>
"""


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _content_sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_role(value: str) -> str:
    clean = str(value).strip().lower()
    if clean in _ROLE_ALIASES:
        return _ROLE_ALIASES[clean]
    return "general"


def _parse_json_map(value: str) -> dict[str, object]:
    raw = value.strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _lease_state(expires_at: Optional[datetime], *, now: Optional[datetime] = None) -> str:
    normalized_expires = _normalize_utc(expires_at)
    if normalized_expires is None:
        return "unknown"
    current = now or _utcnow()
    if normalized_expires >= current:
        return "alive"
    if normalized_expires + timedelta(seconds=60) >= current:
        return "stale"
    return "dead"


def _etcd_configured() -> bool:
    return settings.etcd_enabled and bool(settings.etcd_endpoints.strip())


def _resolve_etcd_peer_url(payload: NodeJoinRequest) -> str:
    if payload.etcd_peer_url and payload.etcd_peer_url.strip():
        return payload.etcd_peer_url.strip()
    from_label = payload.labels.get("etcd_peer_url", "")
    if isinstance(from_label, str) and from_label.strip():
        return from_label.strip()
    if payload.mesh_ip and payload.mesh_ip.strip():
        return f"http://{payload.mesh_ip.strip()}:2380"
    if payload.api_endpoint and payload.api_endpoint.strip():
        parsed = urlparse(payload.api_endpoint.strip())
        host = parsed.hostname or ""
        if host:
            return f"http://{host}:2380"
    return ""


def _is_worker_node(node: Node) -> bool:
    roles = node.roles if isinstance(node.roles, list) else []
    normalized = {str(role).strip().lower() for role in roles if str(role).strip()}
    if not normalized:
        return False
    if normalized == {"gateway"}:
        return False
    return bool(normalized & {"worker", "general", "backend_server", "reverse_proxy"})


def _desired_router_pair(node_id: str, worker_ids: list[str]) -> tuple[str, str]:
    others = [item for item in worker_ids if item != node_id]
    if len(others) >= 2:
        return others[0], others[1]
    if len(others) == 1:
        return others[0], others[0]
    return node_id, node_id


async def _reconcile_router_assignments(
    session: AsyncSession,
    *,
    changed_node_id: str,
) -> tuple[int, int]:
    async with _logger.operation(
        "router_assignment.reconcile",
        "Reconciling router assignments for eligible nodes",
        changed_node_id=changed_node_id,
    ) as op:
        node_rows = await session.execute(select(Node))
        nodes = list(node_rows.scalars().all())
        worker_ids = sorted(node.id for node in nodes if _is_worker_node(node))
        if not worker_ids:
            op.step("nodes.none", "No eligible nodes found; skipping router assignment reconcile")
            return 0, 0

        assignment_rows = await session.execute(select(RouterAssignment))
        assignments = list(assignment_rows.scalars().all())
        by_node_id = {item.node_id: item for item in assignments}

        created_count = 0
        updated_count = 0
        for node_id in worker_ids:
            primary_router_id, secondary_router_id = _desired_router_pair(node_id, worker_ids)
            current = by_node_id.get(node_id)
            if current is None:
                current = RouterAssignment(
                    id=f"ra-{uuid4().hex[:16]}",
                    node_id=node_id,
                    primary_router_id=primary_router_id,
                    secondary_router_id=secondary_router_id,
                )
                session.add(current)
                created_count += 1
                await record_event(
                    session,
                    event_id=str(uuid4()),
                    category="router_assignments",
                    name="router_assignment.create.auto",
                    level="INFO",
                    fields={
                        "node_id": node_id,
                        "primary_router_id": primary_router_id,
                        "secondary_router_id": secondary_router_id,
                    },
                )
                op.child(
                    "assignment",
                    node_id,
                    "Created router assignment",
                    primary_router_id=primary_router_id,
                    secondary_router_id=secondary_router_id,
                )
                by_node_id[node_id] = current
                continue

            if (
                current.primary_router_id != primary_router_id
                or current.secondary_router_id != secondary_router_id
            ):
                current.primary_router_id = primary_router_id
                current.secondary_router_id = secondary_router_id
                updated_count += 1
                await record_event(
                    session,
                    event_id=str(uuid4()),
                    category="router_assignments",
                    name="router_assignment.update.auto",
                    level="INFO",
                    fields={
                        "node_id": node_id,
                        "primary_router_id": primary_router_id,
                        "secondary_router_id": secondary_router_id,
                    },
                )
                op.child(
                    "assignment",
                    node_id,
                    "Updated router assignment",
                    primary_router_id=primary_router_id,
                    secondary_router_id=secondary_router_id,
                )

        if created_count or updated_count:
            await session.commit()
            op.step(
                "db.commit",
                "Committed router assignment reconcile",
                created=created_count,
                updated=updated_count,
            )

            if _etcd_configured():
                for node_id in worker_ids:
                    assignment = by_node_id.get(node_id)
                    if assignment is None:
                        continue
                    try:
                        await etcd_service.put_value(
                            key=f"router_assignments/{node_id}",
                            value=json.dumps(
                                {
                                    "node_id": node_id,
                                    "primary_router_id": assignment.primary_router_id,
                                    "secondary_router_id": assignment.secondary_router_id,
                                    "updated_at": _utcnow().isoformat(),
                                },
                                separators=(",", ":"),
                            ),
                        )
                    except Exception as exc:  # noqa: BLE001
                        op.step_warning(
                            "etcd.assignment_upsert",
                            "Failed to upsert router assignment to etcd",
                            node_id=node_id,
                            error_type=type(exc).__name__,
                            error=str(exc),
                        )
                op.step("etcd.assignment_upsert", "Upserted router assignments to etcd")
            return created_count, updated_count

        op.step("change.none", "Router assignments already in desired state")
        return 0, 0


async def _resolve_cluster_secrets(
    session: AsyncSession,
    *,
    persist_if_missing: bool,
) -> tuple[str, str, bool]:
    settings_map = await cluster_settings.get_settings_map(session)
    auth_secret_key = settings_map.get(AUTH_SECRET_KEY_SETTING, "").strip()
    cluster_signing_key = settings_map.get(CLUSTER_SIGNING_KEY_SETTING, "").strip()
    updates: dict[str, str] = {}

    if not auth_secret_key:
        auth_secret_key = settings.auth_secret_key
        updates[AUTH_SECRET_KEY_SETTING] = auth_secret_key
    elif auth_secret_key != settings.auth_secret_key:
        _logger.warning(
            "cluster.secrets.mismatch",
            "Database auth secret differs from local process setting",
            key=AUTH_SECRET_KEY_SETTING,
        )
    if not cluster_signing_key:
        cluster_signing_key = settings.cluster_signing_key
        updates[CLUSTER_SIGNING_KEY_SETTING] = cluster_signing_key
    elif cluster_signing_key != settings.cluster_signing_key:
        _logger.warning(
            "cluster.secrets.mismatch",
            "Database cluster signing key differs from local process setting",
            key=CLUSTER_SIGNING_KEY_SETTING,
        )

    if updates and persist_if_missing:
        await cluster_settings.upsert_settings(session, updates, sync_file=False)

    return auth_secret_key, cluster_signing_key, bool(updates)


async def _ensure_default_content_registry(session: AsyncSession) -> None:
    settings_map = await cluster_settings.get_settings_map(session)
    has_existing = bool(settings_map.get(CONTENT_HASH_KEY, "").strip()) and bool(
        settings_map.get(CONTENT_BODY_KEY, "").strip()
    )
    if has_existing:
        return

    content_root = Path("data/content/default")
    content_root.mkdir(parents=True, exist_ok=True)
    index_path = content_root / "index.html"
    if not index_path.exists():
        index_path.write_text(_DEFAULT_CONTENT_HTML, encoding="utf-8")
    raw = index_path.read_bytes()
    payload = {
        CONTENT_VERSION_KEY: "bootstrap-v1",
        CONTENT_HASH_KEY: _content_sha256(raw),
        CONTENT_SIZE_KEY: str(len(raw)),
        CONTENT_BODY_KEY: base64.b64encode(raw).decode("ascii"),
        CONTENT_SEEDED_AT_KEY: _utcnow().isoformat(),
    }
    await cluster_settings.upsert_settings(session, payload, sync_file=False)
    _logger.info(
        "content.seed",
        "Seeded default internal CDN content",
        version=payload[CONTENT_VERSION_KEY],
        size_bytes=payload[CONTENT_SIZE_KEY],
    )


async def create_join_token(
    session: AsyncSession,
    *,
    role: str,
    ttl_seconds: int,
    issued_by: Optional[str],
) -> JoinTokenOut:
    canonical_role = _canonical_role(role)
    async with _logger.operation(
        "join_token.create",
        "Creating cluster join token",
        role=canonical_role,
        ttl_seconds=ttl_seconds,
        issued_by=issued_by or "unknown",
    ) as op:
        raw_token = secrets.token_urlsafe(32)
        expires_at = _utcnow() + timedelta(seconds=ttl_seconds)
        token = JoinToken(
            id=f"jt-{uuid4().hex[:16]}",
            token_hash=_hash_secret(raw_token),
            role=canonical_role,
            issued_by=issued_by,
            expires_at=expires_at,
        )
        op.step("token.prepare", "Prepared join token row", token_id=token.id)
        session.add(token)
        await record_event(
            session,
            event_id=str(uuid4()),
            category="cluster",
            name="join_token.create",
            level="INFO",
            fields={"role": canonical_role, "token_id": token.id, "expires_at": expires_at.isoformat()},
        )
        op.step("event.record", "Recorded join token event", token_id=token.id)
        await session.commit()
        op.step("db.commit", "Committed join token transaction", token_id=token.id)
        return JoinTokenOut(id=token.id, role=canonical_role, token=raw_token, expires_at=expires_at)


async def bootstrap_cluster(
    session: AsyncSession,
    *,
    payload: ClusterBootstrapRequest,
    requested_by: Optional[str],
) -> Tuple[bool, JoinTokenOut]:
    async with _logger.operation(
        "cluster.bootstrap",
        "Handling bootstrap request",
        requested_by=requested_by or "unknown",
    ) as op:
        ensure_cluster_ca(settings.cluster_pki_dir)
        op.step("pki.ensure_ca", "Ensured cluster CA exists", pki_dir=settings.cluster_pki_dir)
        _, _, secrets_persisted = await _resolve_cluster_secrets(
            session,
            persist_if_missing=True,
        )
        op.step(
            "secrets.resolve",
            "Resolved cluster-internal signing secrets",
            persisted_missing_keys=secrets_persisted,
        )
        await _ensure_default_content_registry(session)
        op.step("content.seed", "Ensured default internal CDN content registry")
        try:
            from app.services import roles as role_service

            await role_service.get_role_specs(session)
            op.step("roles.seed", "Ensured default role specs")
        except Exception as exc:  # noqa: BLE001
            op.step_warning(
                "roles.seed",
                "Failed to ensure default role specs",
                error_type=type(exc).__name__,
                error=str(exc),
            )

        is_bootstrapped_setting = await cluster_settings.get_setting(session, BOOTSTRAPPED_KEY)
        already_bootstrapped = (
            is_bootstrapped_setting is not None and is_bootstrapped_setting.value == "true"
        )
        op.step(
            "state.check",
            "Checked bootstrap marker",
            already_bootstrapped=already_bootstrapped,
        )

        worker = await create_join_token(
            session,
            role="general",
            ttl_seconds=payload.worker_token_ttl_seconds,
            issued_by=requested_by,
        )
        op.step(
            "token.issue",
            "Issued bootstrap join token",
            worker_token_id=worker.id,
        )

        if not already_bootstrapped:
            await cluster_settings.set_setting(session, BOOTSTRAPPED_KEY, "true")
            await cluster_settings.set_setting(session, BOOTSTRAP_AT_KEY, _utcnow().isoformat())
            _logger.info(
                "cluster.state.update",
                "Marked cluster as bootstrapped",
                requested_by=requested_by or "unknown",
            )
        return True, worker


async def _get_join_token_for_use(
    session: AsyncSession,
    token: str,
) -> Optional[JoinToken]:
    token_hash = _hash_secret(token)
    result = await session.execute(select(JoinToken).where(JoinToken.token_hash == token_hash))
    join_token = result.scalar_one_or_none()
    if join_token is None:
        return None
    now = _utcnow()
    if join_token.used_at is not None:
        return None
    expires_at = _normalize_utc(join_token.expires_at)
    if expires_at is None or expires_at < now:
        return None

    return join_token


async def join_node(session: AsyncSession, payload: NodeJoinRequest) -> Optional[NodeJoinOut]:
    canonical_role = _canonical_role(payload.role)
    async with _logger.operation(
        "node.join",
        "Processing node join request",
        node_id=payload.node_id,
        role=canonical_role,
        node_name=payload.name,
    ) as op:
        auth_secret_key, cluster_signing_key, secrets_persisted = await _resolve_cluster_secrets(
            session,
            persist_if_missing=True,
        )
        op.step(
            "secrets.resolve",
            "Resolved cluster-internal signing secrets",
            persisted_missing_keys=secrets_persisted,
        )
        join_token = await _get_join_token_for_use(
            session,
            payload.token,
        )
        if join_token is None:
            _logger.warning(
                "node.join.reject",
                "Rejected node join with invalid token",
                node_id=payload.node_id,
                role=canonical_role,
            )
            return None
        op.step("token.validate", "Validated join token", token_id=join_token.id)

        try:
            node_cert_pem, ca_cert_pem, identity_fingerprint, identity_expires_at = sign_node_csr(
                pki_dir=settings.cluster_pki_dir,
                csr_pem=payload.csr_pem,
                node_id=payload.node_id,
                validity_days=settings.node_cert_validity_days,
            )
        except ValueError:
            _logger.warning(
                "node.join.reject",
                "Rejected node join due to invalid CSR",
                node_id=payload.node_id,
                role=canonical_role,
            )
            return None
        op.step(
            "identity.sign",
            "Signed node identity certificate",
            fingerprint=identity_fingerprint,
            cert_validity_days=settings.node_cert_validity_days,
        )

        join_token.used_at = _utcnow()
        node = await session.get(Node, payload.node_id)
        now = _utcnow()
        lease_expires_at = now + timedelta(seconds=payload.lease_ttl_seconds)
        lease_token = create_lease_token(
            node_id=payload.node_id,
            identity_fingerprint=identity_fingerprint,
            secret_key=cluster_signing_key,
            ttl_seconds=settings.cluster_lease_token_ttl_seconds,
        )
        op.step(
            "lease.issue",
            "Issued signed node lease token",
            lease_ttl_seconds=settings.cluster_lease_token_ttl_seconds,
        )

        status = dict(payload.status)
        status["enrolled_at"] = now.isoformat()
        status["node_role"] = canonical_role

        if node is None:
            node = Node(
                id=payload.node_id,
                name=payload.name,
                roles=[canonical_role],
                labels=payload.labels,
                mesh_ip=payload.mesh_ip,
                status=status,
                api_endpoint=payload.api_endpoint,
                heartbeat_at=now,
                lease_expires_at=lease_expires_at,
                lease_token_hash=None,
                identity_fingerprint=identity_fingerprint,
                identity_cert_pem=node_cert_pem,
                identity_expires_at=identity_expires_at,
            )
            session.add(node)
            event_name = "node.join"
        else:
            node.name = payload.name
            node.roles = [canonical_role]
            node.labels = payload.labels
            node.mesh_ip = payload.mesh_ip
            node.api_endpoint = payload.api_endpoint
            node.status = {**(node.status or {}), **status}
            node.heartbeat_at = now
            node.lease_expires_at = lease_expires_at
            node.lease_token_hash = None
            node.identity_fingerprint = identity_fingerprint
            node.identity_cert_pem = node_cert_pem
            node.identity_expires_at = identity_expires_at
            event_name = "node.rejoin"
        op.step("node.upsert", "Applied node state", cluster_event=event_name)

        await record_event(
            session,
            event_id=str(uuid4()),
            category="cluster",
            name=event_name,
            level="INFO",
            fields={
                "node_id": payload.node_id,
                "name": payload.name,
                "role": canonical_role,
                "token_id": join_token.id,
            },
        )
        op.step("event.record", "Recorded node join event", cluster_event=event_name)
        await session.commit()
        op.step("db.commit", "Committed node join transaction")
        if _etcd_configured():
            try:
                await etcd_service.put_value(
                    key=f"nodes/{payload.node_id}",
                    value=json.dumps(
                        {
                            "node_id": payload.node_id,
                            "name": payload.name,
                            "role": canonical_role,
                            "roles": [canonical_role],
                            "labels": payload.labels,
                            "mesh_ip": payload.mesh_ip,
                            "api_endpoint": payload.api_endpoint,
                            "identity_fingerprint": identity_fingerprint,
                            "lease_expires_at": lease_expires_at.isoformat(),
                            "updated_at": now.isoformat(),
                        },
                        separators=(",", ":"),
                    ),
                )
                op.step("etcd.node_upsert", "Upserted node record to etcd")
            except Exception as exc:  # noqa: BLE001
                op.step_warning(
                    "etcd.node_upsert",
                    "Failed to upsert node record to etcd",
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
        if canonical_role in {"general", "backend_server", "reverse_proxy"} and _etcd_configured():
            peer_url = _resolve_etcd_peer_url(payload)
            if peer_url:
                try:
                    members = await etcd_service.member_list()
                    member_id = ""
                    for member in members:
                        if member.name == payload.node_id:
                            member_id = member.member_id
                            break
                    if not member_id:
                        added = await etcd_service.member_add(
                            name=payload.node_id,
                            peer_urls=[peer_url],
                            is_learner=False,
                        )
                        member_id = added.member_id
                        op.step(
                            "etcd.member_add",
                            "Added worker node as etcd member",
                            member_id=member_id,
                            peer_url=peer_url,
                        )
                    else:
                        op.step(
                            "etcd.member_exists",
                            "Worker node already exists in etcd membership",
                            member_id=member_id,
                            peer_url=peer_url,
                        )
                    node.status = {
                        **(node.status or {}),
                        "etcd_member_id": member_id,
                        "etcd_peer_url": peer_url,
                    }
                    await session.commit()
                except Exception as exc:  # noqa: BLE001
                    op.step_warning(
                        "etcd.member_add",
                        "Failed to ensure worker node etcd member",
                        error_type=type(exc).__name__,
                        error=str(exc),
                        peer_url=peer_url,
                    )
            else:
                op.step_warning(
                    "etcd.member_add",
                    "Skipped etcd member add due to missing peer URL",
                    node_id=payload.node_id,
                )
        if canonical_role in {"general", "backend_server", "reverse_proxy"}:
            created_assignments, updated_assignments = await _reconcile_router_assignments(
                session,
                changed_node_id=payload.node_id,
            )
            op.step(
                "router_assignment.reconcile",
                "Reconciled router assignments after node join",
                created=created_assignments,
                updated=updated_assignments,
            )
        return NodeJoinOut(
            node_id=payload.node_id,
            lease_token=lease_token,
            lease_expires_at=lease_expires_at,
            identity_fingerprint=identity_fingerprint,
            node_cert_pem=node_cert_pem,
            ca_cert_pem=ca_cert_pem,
            auth_secret_key=auth_secret_key,
            cluster_signing_key=cluster_signing_key,
        )


async def apply_heartbeat(
    session: AsyncSession,
    *,
    node_id: str,
    lease_token: str,
    ttl_seconds: int,
    status_patch: dict[str, object],
    signed_at: int,
    signature: str,
) -> Optional[HeartbeatOut]:
    async with _logger.operation(
        "node.heartbeat",
        "Processing node heartbeat",
        node_id=node_id,
        ttl_seconds=ttl_seconds,
    ) as op:
        _, cluster_signing_key, _ = await _resolve_cluster_secrets(
            session,
            persist_if_missing=False,
        )
        op.step("secrets.resolve", "Resolved cluster signing key for heartbeat validation")
        lease_claims = decode_lease_token(lease_token, cluster_signing_key)
        if lease_claims is None:
            _logger.warning(
                "heartbeat.reject",
                "Rejected heartbeat with invalid lease token",
                node_id=node_id,
            )
            return None
        if lease_claims.get("n") != node_id:
            _logger.warning(
                "heartbeat.reject",
                "Rejected heartbeat due to node ID mismatch",
                node_id=node_id,
                lease_node_id=lease_claims.get("n"),
            )
            return None
        op.step("lease.validate", "Validated signed lease token")

        node = await session.get(Node, node_id)
        if node is None or not node.identity_cert_pem or not node.identity_fingerprint:
            _logger.warning(
                "heartbeat.reject",
                "Rejected heartbeat for unknown or unprovisioned node",
                node_id=node_id,
            )
            return None
        if lease_claims.get("fp") != node.identity_fingerprint:
            _logger.warning(
                "heartbeat.reject",
                "Rejected heartbeat due to fingerprint mismatch",
                node_id=node_id,
            )
            return None
        op.step("identity.match", "Validated node identity fingerprint")

        now_epoch = int(time.time())
        if abs(now_epoch - signed_at) > settings.heartbeat_signature_max_skew_seconds:
            _logger.warning(
                "heartbeat.reject",
                "Rejected heartbeat outside allowed clock skew",
                node_id=node_id,
                signed_at=signed_at,
                now_epoch=now_epoch,
                max_skew_seconds=settings.heartbeat_signature_max_skew_seconds,
            )
            return None

        last_signed_at = 0
        if isinstance(node.status, dict):
            last_signed_at = int(node.status.get("last_heartbeat_signed_at", 0) or 0)
        if signed_at <= last_signed_at:
            _logger.warning(
                "heartbeat.reject",
                "Rejected replayed or stale heartbeat signature",
                node_id=node_id,
                signed_at=signed_at,
                last_signed_at=last_signed_at,
            )
            return None
        op.step("signature.sequence", "Validated heartbeat signature monotonicity")

        message = heartbeat_signing_message(
            node_id=node_id,
            lease_token=lease_token,
            signed_at=signed_at,
            ttl_seconds=ttl_seconds,
            status_patch=status_patch,
        )
        if not verify_heartbeat_signature(
            cert_pem=node.identity_cert_pem,
            message=message,
            signature_b64=signature,
        ):
            _logger.warning(
                "heartbeat.reject",
                "Rejected heartbeat due to signature verification failure",
                node_id=node_id,
            )
            return None
        op.step("signature.verify", "Verified heartbeat signature")

        now = _utcnow()
        lease_expires_at = now + timedelta(seconds=ttl_seconds)
        node.heartbeat_at = now
        node.lease_expires_at = lease_expires_at
        if status_patch:
            merged = dict(node.status or {})
            merged.update(status_patch)
            node.status = merged
        status = dict(node.status or {})
        status["last_heartbeat_signed_at"] = signed_at
        node.status = status
        op.step(
            "status.apply",
            "Applied heartbeat status update",
            status_fields=len(status_patch),
        )

        await session.commit()
        op.step("db.commit", "Committed heartbeat update")
        if _etcd_configured():
            try:
                lease_payload = {
                    "node_id": node_id,
                    "name": node.name,
                    "roles": node.roles,
                    "heartbeat_at": now.isoformat(),
                    "lease_expires_at": lease_expires_at.isoformat(),
                    "lease_state": _lease_state(lease_expires_at, now=now),
                }
                await etcd_service.put_json_with_lease(
                    key=f"leases/{node_id}",
                    payload=lease_payload,
                    ttl_seconds=ttl_seconds,
                )
                op.step("etcd.lease_upsert", "Upserted node lease to etcd", ttl_seconds=ttl_seconds)
            except Exception as exc:  # noqa: BLE001
                op.step_warning(
                    "etcd.lease_upsert",
                    "Failed to upsert node lease to etcd",
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
        return HeartbeatOut(
            node_id=node_id,
            heartbeat_at=now,
            lease_expires_at=lease_expires_at,
            lease_state=_lease_state(lease_expires_at, now=now),
        )


async def list_node_leases(session: AsyncSession, *, limit: int = 500) -> List[NodeLeaseOut]:
    if _etcd_configured():
        try:
            rows = await etcd_service.get_prefix(key_prefix="leases/")
            leases: list[NodeLeaseOut] = []
            for raw in rows.values():
                if not raw:
                    continue
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    continue
                heartbeat_at = payload.get("heartbeat_at")
                lease_expires_at = payload.get("lease_expires_at")
                heartbeat_dt = (
                    datetime.fromisoformat(heartbeat_at)
                    if isinstance(heartbeat_at, str) and heartbeat_at
                    else None
                )
                lease_dt = (
                    datetime.fromisoformat(lease_expires_at)
                    if isinstance(lease_expires_at, str) and lease_expires_at
                    else None
                )
                roles = payload.get("roles")
                lease = NodeLeaseOut(
                    node_id=str(payload.get("node_id") or ""),
                    name=str(payload.get("name") or payload.get("node_id") or ""),
                    roles=[str(item) for item in roles] if isinstance(roles, list) else [],
                    heartbeat_at=heartbeat_dt,
                    lease_expires_at=lease_dt,
                    lease_state=str(payload.get("lease_state") or _lease_state(lease_dt)),
                )
                if lease.node_id:
                    leases.append(lease)
            if leases:
                order = {"alive": 0, "stale": 1, "dead": 2, "unknown": 3}
                leases.sort(key=lambda item: (order.get(item.lease_state, 9), item.name))
                _logger.info("lease.list.etcd", "Listed node leases from etcd", count=len(leases))
                return leases[:limit]
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "lease.list.etcd_error",
                "Failed to list leases from etcd, falling back to DB",
                error_type=type(exc).__name__,
                error=str(exc),
            )

    result = await session.execute(select(Node).limit(limit))
    nodes = list(result.scalars().all())
    now = _utcnow()
    rows = [
        NodeLeaseOut(
            node_id=node.id,
            name=node.name,
            roles=node.roles,
            heartbeat_at=node.heartbeat_at,
            lease_expires_at=node.lease_expires_at,
            lease_state=_lease_state(node.lease_expires_at, now=now),
        )
        for node in nodes
    ]
    order = {"alive": 0, "stale": 1, "dead": 2, "unknown": 3}
    rows.sort(key=lambda item: (order.get(item.lease_state, 9), item.name))
    _logger.debug("lease.list", "Listed node leases", limit=limit, count=len(rows))
    return rows


async def validate_node_lease_token(
    session: AsyncSession,
    *,
    node_id: str,
    lease_token: str,
) -> bool:
    if not node_id or not lease_token:
        return False
    _, cluster_signing_key, _ = await _resolve_cluster_secrets(session, persist_if_missing=False)
    claims = decode_lease_token(lease_token, cluster_signing_key)
    if claims is None:
        return False
    if claims.get("n") != node_id:
        return False
    node = await session.get(Node, node_id)
    if node is None or not node.identity_fingerprint:
        return False
    return claims.get("fp") == node.identity_fingerprint


async def list_cluster_peers(
    session: AsyncSession,
    *,
    node_id: str,
    lease_token: str,
) -> list[dict[str, str]]:
    if not await validate_node_lease_token(session, node_id=node_id, lease_token=lease_token):
        return []
    rows = await session.execute(select(Node))
    nodes = list(rows.scalars().all())
    peers: list[dict[str, str]] = []
    for node in nodes:
        mesh_ip = str(node.mesh_ip or "").strip()
        if not mesh_ip:
            continue
        peers.append(
            {
                "node_id": node.id,
                "name": node.name,
                "mesh_ip": mesh_ip,
                "api_endpoint": str(node.api_endpoint or "").strip(),
            }
        )
    peers.sort(key=lambda item: item["node_id"])
    _logger.debug("peer.list", "Listed cluster peers for node", node_id=node_id, peers=len(peers))
    return peers


async def record_swim_report(
    session: AsyncSession,
    *,
    node_id: str,
    lease_token: str,
    incarnation: int,
    state: str,
    flags: dict[str, object],
    peers: dict[str, dict[str, object]],
) -> tuple[bool, str]:
    if not await validate_node_lease_token(session, node_id=node_id, lease_token=lease_token):
        return False, ""

    now = _utcnow().isoformat()
    settings_map = await cluster_settings.get_settings_map(session)
    membership_map = _parse_json_map(settings_map.get(SWIM_MEMBERSHIP_KEY, ""))
    if not isinstance(membership_map, dict):
        membership_map = {}
    membership_map[node_id] = {
        "node_id": node_id,
        "state": str(state or "healthy").strip().lower(),
        "incarnation": int(incarnation),
        "updated_at": now,
        "flags": flags or {},
        "peers": peers or {},
    }
    await cluster_settings.upsert_settings(
        session,
        {SWIM_MEMBERSHIP_KEY: json.dumps(membership_map, separators=(",", ":"))},
        sync_file=False,
    )

    node = await session.get(Node, node_id)
    if node is not None:
        status = dict(node.status or {})
        status["swim_state"] = str(state or "healthy").strip().lower()
        status["swim_incarnation"] = int(incarnation)
        status["swim_updated_at"] = now
        status["swim_peers_observed"] = len(peers or {})
        node.status = status
        await session.commit()

    if _etcd_configured():
        try:
            await etcd_service.put_value(
                key=f"swim/{node_id}",
                value=json.dumps(membership_map[node_id], separators=(",", ":")),
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "swim.etcd_upsert",
                "Failed to upsert SWIM member state into etcd",
                node_id=node_id,
                error_type=type(exc).__name__,
                error=str(exc),
            )

    _logger.info(
        "swim.report",
        "Recorded SWIM report",
        node_id=node_id,
        state=str(state or "healthy").strip().lower(),
        peers=len(peers or {}),
    )
    try:
        from app.services import roles as role_service

        await role_service.reconcile_placement(session, persist=True)
    except Exception as exc:  # noqa: BLE001
        _logger.warning(
            "swim.placement_reconcile",
            "Failed to reconcile role placement after SWIM report",
            node_id=node_id,
            error_type=type(exc).__name__,
            error=str(exc),
        )
    return True, now


async def list_swim_members(session: AsyncSession) -> dict[str, dict[str, object]]:
    settings_map = await cluster_settings.get_settings_map(session)
    membership_map = _parse_json_map(settings_map.get(SWIM_MEMBERSHIP_KEY, ""))
    out: dict[str, dict[str, object]] = {}
    for key, raw in membership_map.items():
        if not isinstance(key, str) or not isinstance(raw, dict):
            continue
        out[key] = {
            "node_id": key,
            "state": str(raw.get("state") or "unknown"),
            "incarnation": int(raw.get("incarnation") or 0),
            "updated_at": str(raw.get("updated_at") or ""),
            "flags": raw.get("flags") if isinstance(raw.get("flags"), dict) else {},
            "peers": raw.get("peers") if isinstance(raw.get("peers"), dict) else {},
        }
    return out


async def get_active_content(session: AsyncSession) -> dict[str, object]:
    await _ensure_default_content_registry(session)
    settings_map = await cluster_settings.get_settings_map(session)
    version = settings_map.get(CONTENT_VERSION_KEY, "bootstrap-v1")
    hash_sha = settings_map.get(CONTENT_HASH_KEY, "")
    size_raw = settings_map.get(CONTENT_SIZE_KEY, "0")
    body_base64 = settings_map.get(CONTENT_BODY_KEY, "")
    try:
        size_bytes = int(size_raw)
    except ValueError:
        size_bytes = 0
    return {
        "version": version,
        "hash_sha256": hash_sha,
        "size_bytes": max(size_bytes, 0),
        "body_base64": body_base64,
    }
