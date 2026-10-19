from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import scheduler
from app.audit import log_event
from app.db import get_db
from app.models import Observable, User, Workspace
from app.sync.engine import merge_observable
from app.security import get_active_user, require_admin
from app.settings_store import get_all_settings, set_setting
from app.torq.mapping import REPUTATIONS, SUB_TYPES, TYPES

router = APIRouter(prefix="/api", tags=["settings"])


class SettingsIn(BaseModel):
    collision_strategy: Literal["highest_severity", "most_recent", "workspace_priority"] | None = None
    description_merge: Literal["winner", "concat"] | None = None
    sync_enabled: bool | None = None
    sync_interval_minutes: int | None = Field(default=None, ge=1, le=1440)


@router.get("/settings")
def get_settings(db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    return get_all_settings(db)


@router.put("/settings")
def put_settings(body: SettingsIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    changes = body.model_dump(exclude_none=True)
    for key, value in changes.items():
        set_setting(db, key, value)
    if changes:
        log_event(db, admin.username, "update_settings", "settings",
                  ", ".join(f"{k}={v}" for k, v in changes.items()))
    db.commit()
    if {"collision_strategy", "description_merge"} & changes.keys():
        _remerge_all(db, admin.username)
    if "sync_interval_minutes" in changes and scheduler.scheduler.running:
        scheduler.reschedule()
    return get_all_settings(db)


def _remerge_all(db: Session, username: str) -> int:
    """Re-resolve every observable's central value from its workspace copies under the new strategy."""
    settings = get_all_settings(db)
    workspaces = db.query(Workspace).all()
    priorities = {ws.id: ws.priority for ws in workspaces}
    names = {ws.id: ws.name for ws in workspaces}
    changed = 0
    for obs in db.query(Observable).filter(Observable.pinned.is_(False)):
        did, _ = merge_observable(obs, priorities, settings["collision_strategy"], settings["description_merge"],
                                  ws_names=names, actor=username, cause="strategy_change")
        changed += int(did)
    db.commit()
    return changed


@router.get("/meta")
def meta():
    """Static enum metadata used by the UI (no auth needed; contains no data)."""
    return {
        "types": [{"id": k, "label": v[0]} for k, v in TYPES.items()],
        "sub_types": [{"id": k, "label": v[0], "type": v[1]} for k, v in SUB_TYPES.items()],
        "reputations": [{"id": k, "label": v[0], "severity": v[1]} for k, v in REPUTATIONS.items()],
    }
