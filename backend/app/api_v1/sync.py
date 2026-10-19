from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app import scheduler
from app.api_v1.auth import Principal, read_access, write_access
from app.api_v1.schemas import ERRORS, NOT_FOUND, SyncRequest, SyncRunOut, SyncStarted, SyncStatusOut
from app.audit import log_event
from app.db import get_db
from app.models import SyncRun, Workspace
from app.serializers import run_out
from app.sync.engine import SyncAlreadyRunning, start_background_sync, state

router = APIRouter(tags=["Sync"], responses=ERRORS)


@router.post("/sync", response_model=SyncStarted, status_code=202, summary="Sync observables",
             responses={409: {"description": "A sync is already running"}, **NOT_FOUND})
async def start_sync(  # async: the run is started as a task on the event loop
    body: SyncRequest | None = Body(None),
    db: Session = Depends(get_db),
    p: Principal = Depends(write_access),
):
    """Start a sync now: pull from workspaces, merge into the central database and push per the rules.

    Returns immediately with the run id; poll `GET /sync/status` or `GET /sync/runs/{run_id}` for the result.
    """
    workspace_id = body.workspace_id if body else None
    if workspace_id is not None:
        ws = db.get(Workspace, workspace_id)
        if not ws:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
        if not ws.enabled:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Workspace is disabled")
    try:
        run_id = start_background_sync("api", p.actor, workspace_id)
    except SyncAlreadyRunning:
        raise HTTPException(status.HTTP_409_CONFLICT, "A sync is already running") from None
    log_event(db, p.actor, "start_sync", "sync", f"run {run_id}" + (f" (workspace {workspace_id})" if workspace_id else ""))
    db.commit()
    return {"run_id": run_id, "status_url": "/api/v1/sync/status", "run_url": f"/api/v1/sync/runs/{run_id}"}


@router.get("/sync/status", response_model=SyncStatusOut, summary="Get sync status")
def sync_status(db: Session = Depends(get_db), _: Principal = Depends(read_access)):
    """Whether a sync is running (with live progress), when the next scheduled sync is, and the last finished run."""
    last = db.query(SyncRun).filter(SyncRun.status != "running").order_by(SyncRun.id.desc()).first()
    return {
        "running": state.running,
        "run_id": state.run_id if state.running else None,
        "phase": state.phase,
        "detail": state.detail,
        "started_at": state.started_at if state.running else None,
        "next_run_at": scheduler.next_run_iso(),
        "last_run": run_out(last) if last else None,
        "live": state.live if state.running and state.live else None,
    }


@router.get("/sync/runs", response_model=list[SyncRunOut], summary="List sync runs")
def list_runs(db: Session = Depends(get_db), _: Principal = Depends(read_access), limit: int = Query(25, ge=1, le=200)):
    return [run_out(r) for r in db.query(SyncRun).order_by(SyncRun.id.desc()).limit(limit).all()]


@router.get("/sync/runs/{run_id}", response_model=SyncRunOut, summary="Get a sync run", responses=NOT_FOUND)
def get_run(run_id: int, db: Session = Depends(get_db), _: Principal = Depends(read_access)):
    run = db.get(SyncRun, run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sync run not found")
    return run_out(run)
