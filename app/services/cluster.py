from __future__ import annotations

import hashlib
import json
import secrets
import time
from datetime import datetime, timedelta, timezone
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


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


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


async def create_join_token(
    session: AsyncSession,
    *,
    role: str,
    ttl_seconds: int,
    issued_by: Optional[str],
) -> JoinTokenOut:
    async with _logger.operation(
        "join_token.create",
        "Creating cluster join token",
        role=role,
        ttl_seconds=ttl_seconds,
        issued_by=issued_by or "unknown",
    ) as op:
        raw_token = secrets.token_urlsafe(32)
        expires_at = _utcnow() + timedelta(seconds=ttl_seconds)
        token = JoinToken(
            id=f"jt-{uuid4().hex[:16]}",
            token_hash=_hash_secret(raw_token),
            role=role,
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
            fields={"role": role, "token_id": token.id, "expires_at": expires_at.isoformat()},
        )
        op.step("event.record", "Recorded join token event", token_id=token.id)
        await session.commit()
        op.step("db.commit", "Committed join token transaction", token_id=token.id)
        return JoinTokenOut(id=token.id, role=role, token=raw_token, expires_at=expires_at)


async def bootstrap_cluster(
    session: AsyncSession,
    *,
    payload: ClusterBootstrapRequest,
    requested_by: Optional[str],
) -> Tuple[bool, JoinTokenOut, JoinTokenOut]:
    async with _logger.operation(
        "cluster.bootstrap",
        "Handling bootstrap request",
        requested_by=requested_by or "unknown",
    ) as op:
        ensure_cluster_ca(settings.cluster_pki_dir)
        op.step("pki.ensure_ca", "Ensured cluster CA exists", pki_dir=settings.cluster_pki_dir)

        is_bootstrapped_setting = await cluster_settings.get_setting(session, BOOTSTRAPPED_KEY)
        already_bootstrapped = (
            is_bootstrapped_setting is not None and is_bootstrapped_setting.value == "true"
        )
        op.step(
            "state.check",
            "Checked bootstrap marker",
            already_bootstrapped=already_bootstrapped,
        )

        core = await create_join_token(
            session,
            role="core",
            ttl_seconds=payload.core_token_ttl_seconds,
            issued_by=requested_by,
        )
        worker = await create_join_token(
            session,
            role="worker",
            ttl_seconds=payload.worker_token_ttl_seconds,
            issued_by=requested_by,
        )
        op.step(
            "token.issue",
            "Issued bootstrap join tokens",
            core_token_id=core.id,
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
        return True, core, worker


async def _get_join_token_for_use(
    session: AsyncSession, token: str, *, expected_role: str
) -> Optional[JoinToken]:
    token_hash = _hash_secret(token)
    result = await session.execute(select(JoinToken).where(JoinToken.token_hash == token_hash))
    join_token = result.scalar_one_or_none()
    if join_token is None:
        return None
    if join_token.role != expected_role:
        return None
    now = _utcnow()
    if join_token.used_at is not None:
        return None
    expires_at = _normalize_utc(join_token.expires_at)
    if expires_at is None or expires_at < now:
        return None

    return join_token


async def join_node(session: AsyncSession, payload: NodeJoinRequest) -> Optional[NodeJoinOut]:
    async with _logger.operation(
        "node.join",
        "Processing node join request",
        node_id=payload.node_id,
        role=payload.role,
        node_name=payload.name,
    ) as op:
        join_token = await _get_join_token_for_use(
            session,
            payload.token,
            expected_role=payload.role,
        )
        if join_token is None:
            _logger.warning(
                "node.join.reject",
                "Rejected node join with invalid token",
                node_id=payload.node_id,
                role=payload.role,
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
                role=payload.role,
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
            secret_key=settings.cluster_signing_key,
            ttl_seconds=settings.cluster_lease_token_ttl_seconds,
        )
        op.step(
            "lease.issue",
            "Issued signed node lease token",
            lease_ttl_seconds=settings.cluster_lease_token_ttl_seconds,
        )

        status = dict(payload.status)
        status["enrolled_at"] = now.isoformat()
        status["node_role"] = payload.role

        if node is None:
            node = Node(
                id=payload.node_id,
                name=payload.name,
                roles=[payload.role],
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
            node.roles = [payload.role]
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
                "role": payload.role,
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
                            "role": payload.role,
                            "roles": [payload.role],
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
        if payload.role == "core" and _etcd_configured():
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
                            "Added core node as etcd member",
                            member_id=member_id,
                            peer_url=peer_url,
                        )
                    else:
                        op.step(
                            "etcd.member_exists",
                            "Core node already exists in etcd membership",
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
                        "Failed to ensure core node etcd member",
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
        return NodeJoinOut(
            node_id=payload.node_id,
            lease_token=lease_token,
            lease_expires_at=lease_expires_at,
            identity_fingerprint=identity_fingerprint,
            node_cert_pem=node_cert_pem,
            ca_cert_pem=ca_cert_pem,
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
        lease_claims = decode_lease_token(lease_token, settings.cluster_signing_key)
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
