from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db_session, get_writable_db_session
from app.schemas.roles import (
    RolePlacementOut,
    RoleSpecOut,
    RoleSpecUpsert,
)
from app.services import cluster as cluster_service
from app.services import roles as role_service

router = APIRouter(prefix="/roles", tags=["roles"])


@router.get("/specs", response_model=List[RoleSpecOut])
async def list_role_specs(
    session: AsyncSession = Depends(get_db_session),
) -> List[RoleSpecOut]:
    specs = await role_service.get_role_specs(session)
    rows: list[RoleSpecOut] = []
    for name, payload in sorted(specs.items()):
        row = {"name": name, **payload}
        rows.append(RoleSpecOut.model_validate(row))
    return rows


@router.put("/specs/{role_name}", response_model=RoleSpecOut)
async def put_role_spec(
    role_name: str,
    payload: RoleSpecUpsert,
    session: AsyncSession = Depends(get_writable_db_session),
) -> RoleSpecOut:
    spec = await role_service.set_role_spec(
        session,
        name=role_name,
        payload=payload.model_dump(),
    )
    return RoleSpecOut.model_validate({"name": role_name, **spec})


@router.get("/placement", response_model=RolePlacementOut)
async def get_role_placement(
    request: Request,
    node_id: str = "",
    lease_token: str = "",
    recompute: bool = False,
    session: AsyncSession = Depends(get_db_session),
) -> RolePlacementOut:
    auth_user = getattr(request.state, "auth_user", "")
    if not auth_user:
        valid = await cluster_service.validate_node_lease_token(
            session,
            node_id=node_id,
            lease_token=lease_token,
        )
        if not valid:
            raise HTTPException(status_code=401, detail="Authentication required")
    if recompute:
        payload = await role_service.reconcile_placement(session, persist=False)
    else:
        payload = await role_service.get_latest_placement(session)
    return RolePlacementOut.model_validate(payload)


@router.post("/placement/reconcile", response_model=RolePlacementOut)
async def reconcile_role_placement(
    persist: bool = True,
    session: AsyncSession = Depends(get_writable_db_session),
) -> RolePlacementOut:
    payload = await role_service.reconcile_placement(session, persist=persist)
    return RolePlacementOut.model_validate(payload)
