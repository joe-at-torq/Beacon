from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import history
from app.audit import log_event
from app.db import get_db
from app.models import ObservableLink, Rule, User, Workspace
from app.security import decrypt, encrypt, get_active_user, require_admin, require_analyst
from app.serializers import api_call_out, workspace_out
from app.services import source_cleanup
from app.sync.engine import SyncAlreadyRunning, recompute_case_counts, start_background_sync
from app.torq.client import TorqClient, TorqError

router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])

Region = Literal["us", "eu", "jp"]


class WorkspaceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    region: Region = "us"
    client_id: str = Field(min_length=1, max_length=256)
    client_secret: str = Field(min_length=1, max_length=1024)
    enabled: bool = True
    priority: int = 100


class WorkspaceUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    region: Region | None = None
    client_id: str | None = Field(default=None, min_length=1, max_length=256)
    client_secret: str | None = Field(default=None, max_length=1024)
    enabled: bool | None = None
    priority: int | None = None


class ConnectionTest(BaseModel):
    workspace_id: int | None = None
    region: Region | None = None  # defaults to the saved workspace's region, else "us"
    client_id: str = ""
    client_secret: str = ""


def _link_counts(db: Session) -> dict[int, dict[str, int]]:
    counts: dict[int, dict[str, int]] = {}
    rows = (
        db.query(ObservableLink.workspace_id, ObservableLink.relation, func.count())
        .group_by(ObservableLink.workspace_id, ObservableLink.relation)
        .all()
    )
    for ws_id, relation, n in rows:
        counts.setdefault(ws_id, {})[relation] = n
    return counts


def _get(db: Session, ws_id: int) -> Workspace:
    ws = db.get(Workspace, ws_id)
    if not ws:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
    return ws


@router.get("")
def list_workspaces(db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    counts = _link_counts(db)
    rows = db.query(Workspace).order_by(Workspace.priority, Workspace.name).all()
    return [workspace_out(ws, counts.get(ws.id)) for ws in rows]


@router.post("", status_code=201)
def create_workspace(body: WorkspaceCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    if db.query(Workspace).filter(Workspace.name == body.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "A workspace with that name already exists")
    ws = Workspace(
        name=body.name,
        region=body.region,
        client_id=body.client_id.strip(),
        client_secret_enc=encrypt(body.client_secret.strip()),
        enabled=body.enabled,
        priority=body.priority,
    )
    db.add(ws)
    log_event(db, admin.username, "create_workspace", "workspace", body.name)
    db.commit()
    return workspace_out(ws)


@router.patch("/{ws_id}")
def update_workspace(
    ws_id: int, body: WorkspaceUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)
):
    ws = _get(db, ws_id)
    if body.name and body.name != ws.name:
        if db.query(Workspace).filter(Workspace.name == body.name).first():
            raise HTTPException(status.HTTP_409_CONFLICT, "A workspace with that name already exists")
        ws.name = body.name
    if body.region:
        ws.region = body.region
    if body.client_id:
        ws.client_id = body.client_id.strip()
    if body.client_secret:
        ws.client_secret_enc = encrypt(body.client_secret.strip())
    if body.enabled is not None:
        ws.enabled = body.enabled
    if body.priority is not None:
        ws.priority = body.priority
    log_event(db, admin.username, "update_workspace", "workspace", ws.name)
    db.commit()
    return workspace_out(ws, _link_counts(db).get(ws.id))


@router.get("/{ws_id}/delete-impact")
def delete_impact(ws_id: int, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    """How many observables came only from this workspace (what "also remove its observables" would delete)."""
    _get(db, ws_id)
    return source_cleanup.impact(db, str(ws_id))


@router.delete("/{ws_id}", status_code=204)
def delete_workspace(ws_id: int, remove_observables: bool = False, db: Session = Depends(get_db),
                     admin: User = Depends(require_admin)):
    _get(db, ws_id)
    removed = source_cleanup.remove_exclusive(db, str(ws_id), admin.username) if remove_observables else None
    ws = _get(db, ws_id)
    # Strip the workspace from rules. A rule whose list becomes empty would silently widen to "any",
    # so such rules are disabled instead.
    for rule in db.query(Rule).all():
        for attr in ("source_workspace_ids", "target_workspace_ids"):
            ids = list(getattr(rule, attr) or [])
            if ws_id in ids:
                ids = [i for i in ids if i != ws_id]
                setattr(rule, attr, ids)
                if not ids:
                    rule.enabled = False
    for link in ws.links:
        history.record(link.observable, history.REMOVED_FROM_WORKSPACE, actor=admin.username,
                       workspace_id=ws.id, workspace_name=ws.name, relation=link.relation,
                       remote_id=link.remote_id, reason="workspace disconnected from Beacon")
    db.delete(ws)
    log_event(db, admin.username, "delete_workspace", "workspace",
              ws.name + (f" ({removed['deleted']} observables removed, {removed['tombstoned']} tombstoned)" if removed else ""))
    db.flush()
    recompute_case_counts(db)
    db.commit()


@router.post("/test")
async def test_connection(body: ConnectionTest, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    region, client_id, secret = body.region or "us", body.client_id.strip(), body.client_secret.strip()
    if body.workspace_id is not None:
        ws = _get(db, body.workspace_id)
        region = body.region or ws.region
        client_id = client_id or ws.client_id
        secret = secret or decrypt(ws.client_secret_enc)
    if not client_id or not secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Client ID and secret are required")
    calls: list[dict] = []
    async with TorqClient(region, client_id, secret, timeout=15, recorder=calls.append) as client:
        try:
            await client.get_token()
            await client.test_connection()
        except TorqError as e:
            message = str(e)
            if e.status == 403:
                message += " " + await client.diagnose_forbidden()
            return {"ok": False, "message": message, "calls": [api_call_out(c) for c in calls]}
    return {"ok": True, "message": "Connected successfully", "calls": [api_call_out(c) for c in calls]}


@router.post("/{ws_id}/sync", status_code=202)
async def sync_workspace(  # async: must run on the event loop to spawn the sync task
    ws_id: int, db: Session = Depends(get_db), user: User = Depends(require_analyst)
):
    ws = _get(db, ws_id)
    if not ws.enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Workspace is disabled")
    try:
        start_background_sync("manual", user.username, ws_id)
    except SyncAlreadyRunning:
        raise HTTPException(status.HTTP_409_CONFLICT, "A sync is already running") from None
    return {"started": True}
