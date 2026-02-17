from __future__ import annotations

from typing import List
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logger import get_logger
from app.models.support_bundle import SupportBundle
from app.schemas.support_bundles import SupportBundleCreate
from app.services.events import record_event

_logger = get_logger("services.support_bundles")


async def list_support_bundles(session: AsyncSession, limit: int = 50) -> List[SupportBundle]:
    result = await session.execute(
        select(SupportBundle).order_by(SupportBundle.created_at.desc()).limit(limit)
    )
    return list(result.scalars().all())


async def get_support_bundle(session: AsyncSession, bundle_id: str) -> SupportBundle | None:
    result = await session.execute(select(SupportBundle).where(SupportBundle.id == bundle_id))
    return result.scalar_one_or_none()


async def create_support_bundle(
    session: AsyncSession, payload: SupportBundleCreate
) -> SupportBundle:
    bundle_id = payload.id or str(uuid4())
    bundle = SupportBundle(
        id=bundle_id,
        status="pending",
        requested_by=payload.requested_by,
    )
    session.add(bundle)
    await record_event(
        session,
        event_id=str(uuid4()),
        category="support",
        name="support_bundle.requested",
        level="INFO",
        fields={"bundle_id": bundle.id, "requested_by": payload.requested_by},
    )
    await session.commit()
    await session.refresh(bundle)
    _logger.info("support_bundles.create", "Requested support bundle", bundle_id=bundle.id)
    return bundle
