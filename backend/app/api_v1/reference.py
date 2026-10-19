from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api_v1.auth import Principal, read_access
from app.api_v1.schemas import ERRORS, MetaOut, WorkspaceOut
from app.db import get_db
from app.models import Workspace
from app.routers.settings import meta as meta_payload
from app.routers.workspaces import _link_counts
from app.serializers import workspace_out

router = APIRouter(tags=["Reference"], responses=ERRORS)


@router.get("/workspaces", response_model=list[WorkspaceOut], summary="List connected workspaces")
def list_workspaces(db: Session = Depends(get_db), _: Principal = Depends(read_access)):
    """Workspace ids are used by rules and filters. Credentials are never returned."""
    counts = _link_counts(db)
    return [workspace_out(ws, counts.get(ws.id)) for ws in db.query(Workspace).order_by(Workspace.priority, Workspace.name)]


@router.get("/meta", response_model=MetaOut, summary="List enum values")
def meta(_: Principal = Depends(read_access)):
    """Valid observable types, sub types and reputation scores."""
    return meta_payload()
