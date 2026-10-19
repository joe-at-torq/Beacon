from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app import scheduler
from app.db import get_db
from app.models import SyncApiCall, SyncRun, User
from app.security import get_active_user, require_analyst
from app.serializers import api_call_out, run_out
from app.sync.engine import SyncAlreadyRunning, start_background_sync, state

router = APIRouter(prefix="/api/sync", tags=["sync"])


@router.post("/run", status_code=202)
async def run_now(user: User = Depends(require_analyst)):  # async: spawns a task on the event loop
    try:
        start_background_sync("manual", user.username)
    except SyncAlreadyRunning:
        raise HTTPException(status.HTTP_409_CONFLICT, "A sync is already running") from None
    return {"started": True}


@router.get("/status")
def sync_status(db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    last = db.query(SyncRun).filter(SyncRun.status != "running").order_by(SyncRun.id.desc()).first()
    return {
        "running": state.running,
        "run_id": state.run_id if state.running else None,
        "phase": state.phase,
        "detail": state.detail,
        "started_at": state.started_at if state.running else None,
        "next_run_at": scheduler.next_run_iso(),
        "live": {
            "workspaces": [{"workspace_id": int(k), **v} for k, v in state.live.get("workspaces", {}).items()],
            "edges": list(state.live.get("edges", {}).values()),
        }
        if state.running and state.live
        else None,
        "last_run": run_out(last) if last else None,
    }


@router.get("/runs")
def list_runs(
    db: Session = Depends(get_db), _: User = Depends(get_active_user), limit: int = Query(25, ge=1, le=200)
):
    return [run_out(r) for r in db.query(SyncRun).order_by(SyncRun.id.desc()).limit(limit).all()]


@router.get("/runs/{run_id}/calls")
def list_run_calls(
    run_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_active_user),
    failed_only: bool = False,
    workspace_id: int | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    """Every HTTP attempt made against the Torq API during a run, with redacted request/response details."""
    if not db.get(SyncRun, run_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sync run not found")
    q = db.query(SyncApiCall).filter(SyncApiCall.run_id == run_id)
    if failed_only:
        q = q.filter(or_(SyncApiCall.error.is_not(None), SyncApiCall.status_code >= 400))
    if workspace_id is not None:
        q = q.filter(SyncApiCall.workspace_id == workspace_id)
    total = q.count()
    items = q.order_by(SyncApiCall.id).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [api_call_out(c) for c in items], "total": total, "page": page, "page_size": page_size}
