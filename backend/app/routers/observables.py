from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import log_event
from app.db import get_db
from app.intel import service as intel_service
from app.services import observables as svc
from app.models import Observable, ObservableEvent, User
from app.security import get_active_user, require_analyst
from app.serializers import event_out, observable_out
from app.torq.mapping import REPUTATIONS

router = APIRouter(prefix="/api/observables", tags=["observables"])

MAX_BULK_ENRICH = 50

class BulkAction(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=5000)
    action: Literal["delete", "set_reputation", "unpin"]
    reputation: str | None = None


class EnrichIn(BaseModel):
    providers: list[str] | None = None  # default: every enabled integration that supports the type


class BulkEnrichIn(EnrichIn):
    ids: list[int] = Field(min_length=1, max_length=MAX_BULK_ENRICH)


# Shared logic lives in app.services.observables (also used by the public v1 API).
_ws_names = svc.ws_names
_get = svc.get_or_404
_delete = svc.delete_with_tombstone
_unpin = svc.unpin
_manual_edit = svc.manual_edit


@router.get("")
def list_observables(
    db: Session = Depends(get_db),
    _: User = Depends(get_active_user),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    search: str = "",
    type: list[str] = Query(default=[]),
    sub_type: list[str] = Query(default=[]),
    reputation: list[str] = Query(default=[]),
    workspace_id: list[int] = Query(default=[]),
    source: list[str] = Query(default=[], description='Where it came from: workspace ids, "central", "feed:<id>"'),
    pinned: bool | None = None,
    origin: str | None = None,
    has_enrichment: bool | None = None,
    sort: str = "updated_at",
    order: Literal["asc", "desc"] = "desc",
):
    filters = svc.ObservableFilters(search=search, types=type, sub_types=sub_type, reputations=reputation,
                                    workspace_ids=workspace_id, sources=source, pinned=pinned, origin=origin,
                                    has_enrichment=has_enrichment)
    items, total = svc.page_of(svc.filtered_query(db, filters), sort, order, page, page_size)
    names = _ws_names(db)
    return {"items": [observable_out(o, names) for o in items], "total": total, "page": page,
            "page_size": page_size}


@router.get("/{obs_id}/history")
def observable_history(
    obs_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_active_user),
    kind: list[str] = Query(default=[]),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Change timeline for one observable, newest first."""
    _get(db, obs_id)
    q = db.query(ObservableEvent).filter(ObservableEvent.observable_id == obs_id)
    if kind:
        q = q.filter(ObservableEvent.kind.in_(kind))
    total = q.count()
    items = q.order_by(ObservableEvent.ts.desc(), ObservableEvent.id.desc()).offset(offset).limit(limit).all()
    return {"items": [event_out(e) for e in items], "total": total}


@router.get("/{obs_id}")
def get_observable(obs_id: int, db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    return svc.detail_out(db, _get(db, obs_id))


@router.post("", status_code=201)
def create_observable(body: svc.ObservableCreate, db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    obs = svc.create(db, body, user.username)
    log_event(db, user.username, "create_observable", "observable", obs.value)
    db.commit()
    return svc.detail_out(db, obs)


@router.patch("/{obs_id}")
def update_observable(
    obs_id: int, body: svc.ObservableUpdate, db: Session = Depends(get_db), user: User = Depends(require_analyst)
):
    obs = _get(db, obs_id)
    changes = _manual_edit(obs, user.username, body.reputation, body.description)
    if changes:
        log_event(db, user.username, "update_observable", "observable", f"{obs.value}: {', '.join(changes)}")
        db.commit()
    return svc.detail_out(db, obs)


@router.post("/{obs_id}/normalize")
def normalize_observable(obs_id: int, db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    """Apply the threat-intel normalized reputation to this observable (explicit, so it may also lower it)."""
    from app.intel import normalize

    obs = _get(db, obs_id)
    cfg = normalize.load_config(db)
    result = normalize.evaluate(cfg, obs)
    if not result:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No normalization rule produces a reputation for this observable")
    if normalize.should_apply(cfg, obs, result, force=True):
        normalize.apply(obs, result, user.username)
        log_event(db, user.username, "apply_normalization", "observable", f"{obs.value}: {result['label']}")
        db.commit()
    return svc.detail_out(db, obs)


@router.post("/{obs_id}/unpin")
def unpin_observable(obs_id: int, db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    obs = _get(db, obs_id)
    if obs.origin == "manual":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Manually created observables are always authoritative")
    _unpin(db, obs, user.username)
    log_event(db, user.username, "unpin_observable", "observable", obs.value)
    db.commit()
    return svc.detail_out(db, obs)


@router.delete("/{obs_id}", status_code=204)
def delete_observable(obs_id: int, db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    obs = _get(db, obs_id)
    _delete(db, obs, user.username)
    log_event(db, user.username, "delete_observable", "observable", obs.value)
    db.commit()


@router.post("/{obs_id}/enrich")
async def enrich_observable(
    obs_id: int, body: EnrichIn | None = None, db: Session = Depends(get_db), user: User = Depends(require_analyst)
):
    """Enrich one observable via the enabled threat-intel integrations; stores summaries + raw responses."""
    obs = _get(db, obs_id)
    caps = intel_service.capabilities(db).get(obs.type, [])
    providers = [p for p in (body.providers if body and body.providers else caps) if p in caps]
    if not providers:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No active integration can enrich this observable type")
    rows = await intel_service.enrich(db, [obs], user.username, providers)
    log_event(db, user.username, "enrich_observable", "observable",
              f"{obs.value} via {', '.join(r.provider for r in rows)}")
    db.commit()
    return svc.detail_out(db, obs)


@router.post("/bulk-enrich")
async def bulk_enrich(body: BulkEnrichIn, db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    items = db.query(Observable).filter(Observable.id.in_(body.ids)).all()
    caps = intel_service.capabilities(db)
    eligible = [o for o in items if caps.get(o.type)]
    if not eligible:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "None of the selected observables can be enriched")
    rows = await intel_service.enrich(db, eligible, user.username, body.providers)
    log_event(db, user.username, "bulk_enrich", "observable", f"{len(eligible)} observable(s)")
    db.commit()
    return {
        "enriched": len(eligible),
        "skipped": len(items) - len(eligible),
        "ok": sum(1 for r in rows if r.status == "ok"),
        "not_found": sum(1 for r in rows if r.status == "not_found"),
        "errors": sum(1 for r in rows if r.status == "error"),
        "first_error": next((r.error for r in rows if r.status == "error"), None),
    }


@router.post("/bulk")
def bulk_action(body: BulkAction, db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    if body.action == "set_reputation" and body.reputation not in REPUTATIONS:
        raise HTTPException(422, "A valid reputation is required")
    items = db.query(Observable).filter(Observable.id.in_(body.ids)).all()
    affected = 0
    for obs in items:
        if body.action == "delete":
            _delete(db, obs, user.username)
        elif body.action == "set_reputation":
            _manual_edit(obs, user.username, body.reputation, None)
        elif body.action == "unpin":
            if obs.origin == "manual":
                continue
            _unpin(db, obs, user.username)
        affected += 1
    log_event(db, user.username, f"bulk_{body.action}", "observable", f"{affected} observable(s)")
    db.commit()
    return {"affected": affected}
