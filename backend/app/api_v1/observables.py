from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api_v1.auth import Principal, read_access, write_access
from app.api_v1.schemas import ERRORS, NOT_FOUND, HistoryPage, ObservableOut, ObservablePage, ObservableQuery, SortKey
from app.audit import log_event
from app.db import get_db
from app.models import ObservableEvent
from app.serializers import event_out, observable_out
from app.services import observables as svc
from app.torq.mapping import TYPES

router = APIRouter(responses=ERRORS)
OBS = ["Observables"]


def _page(db: Session, filters: svc.ObservableFilters, sort: str, order: str, page: int, page_size: int) -> dict:
    items, total = svc.page_of(svc.filtered_query(db, filters), sort, order, page, page_size)
    names = svc.ws_names(db)
    return {"items": [observable_out(o, names) for o in items], "total": total, "page": page, "page_size": page_size}


@router.get("/observables", response_model=ObservablePage, tags=OBS, summary="List observables")
def list_observables(
    db: Session = Depends(get_db),
    _: Principal = Depends(read_access),
    search: str = Query("", description="Substring match on value or description"),
    type: list[str] = Query(default=[], description="Filter by type (repeatable)"),
    reputation: list[str] = Query(default=[], description="Filter by reputation score (repeatable)"),
    workspace_id: list[int] = Query(default=[], description="Present in workspace (repeatable)"),
    sort: SortKey = "updated_at",
    order: Literal["asc", "desc"] = "desc",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    """Simple listing with common filters. Use `POST /observables/query` for the full query language."""
    f = svc.ObservableFilters(search=search, types=type, reputations=reputation, workspace_ids=workspace_id)
    return _page(db, f, sort, order, page, page_size)


@router.post("/observables/query", response_model=ObservablePage, summary="Query the database", tags=["Database query"])
def query_observables(body: ObservableQuery, db: Session = Depends(get_db), _: Principal = Depends(read_access)):
    """Query the central observable database with combinable filters, sorting and pagination."""
    f = svc.ObservableFilters(
        search=body.search, types=body.types, sub_types=body.sub_types, reputations=body.reputations,
        min_severity=body.min_severity, workspace_ids=body.workspace_ids, sources=[str(x) for x in body.sources],
        pinned=body.pinned, origin=body.origin,
        has_enrichment=body.has_enrichment,
        first_observed_from=body.first_observed.from_ if body.first_observed else None,
        first_observed_to=body.first_observed.to if body.first_observed else None,
        last_observed_from=body.last_observed.from_ if body.last_observed else None,
        last_observed_to=body.last_observed.to if body.last_observed else None,
        min_cases=body.min_cases,
    )
    return _page(db, f, body.sort, body.order, body.page, body.page_size)


@router.get("/observables/lookup", response_model=ObservableOut, summary="Look up an observable by value",
            tags=["Database query"], responses=NOT_FOUND)
def lookup_observable(
    type: str = Query(..., description="Observable type, e.g. TYPE_ID_IP_ADDRESS"),
    value: str = Query(..., description="Value; normalized like Beacon does (case, IPv6 compression, ...)"),
    db: Session = Depends(get_db),
    _: Principal = Depends(read_access),
):
    if type not in TYPES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown observable type")
    obs = svc.find_by_value(db, type, value)
    if not obs:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Observable not found")
    return svc.detail_out(db, obs)


@router.get("/observables/{obs_id}", response_model=ObservableOut, tags=OBS, summary="Get an observable", responses=NOT_FOUND)
def get_observable(obs_id: int, db: Session = Depends(get_db), _: Principal = Depends(read_access)):
    """Full detail including workspace copies, threat-intel summaries and raw enrichment responses."""
    return svc.detail_out(db, svc.get_or_404(db, obs_id))


@router.get("/observables/{obs_id}/history", response_model=HistoryPage, tags=OBS, summary="Get an observable's change history",
            responses=NOT_FOUND)
def observable_history(
    obs_id: int,
    db: Session = Depends(get_db),
    _: Principal = Depends(read_access),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    svc.get_or_404(db, obs_id)
    q = db.query(ObservableEvent).filter(ObservableEvent.observable_id == obs_id)
    total = q.count()
    items = q.order_by(ObservableEvent.ts.desc(), ObservableEvent.id.desc()).offset(offset).limit(limit).all()
    return {"items": [event_out(e) for e in items], "total": total}


@router.post("/observables", response_model=ObservableOut, status_code=201, tags=OBS, summary="Create an observable",
             responses={409: {"description": "The observable already exists"}})
def create_observable(body: svc.ObservableCreate, db: Session = Depends(get_db), p: Principal = Depends(write_access)):
    """Create an observable centrally. It is authoritative and syncs via rules whose source includes `central`."""
    obs = svc.create(db, body, p.actor)
    log_event(db, p.actor, "create_observable", "observable", obs.value)
    db.commit()
    return svc.detail_out(db, obs)


@router.patch("/observables/{obs_id}", response_model=ObservableOut, tags=OBS, summary="Update an observable", responses=NOT_FOUND)
def update_observable(obs_id: int, body: svc.ObservableUpdate, db: Session = Depends(get_db),
                      p: Principal = Depends(write_access)):
    """Change reputation and/or description. The observable becomes centrally authoritative (pinned)."""
    obs = svc.get_or_404(db, obs_id)
    changes = svc.manual_edit(obs, p.actor, body.reputation, body.description)
    if changes:
        log_event(db, p.actor, "update_observable", "observable", f"{obs.value}: {', '.join(changes)}")
        db.commit()
    return svc.detail_out(db, obs)


@router.post("/observables/{obs_id}/revert", response_model=ObservableOut, tags=OBS, summary="Revert central edits",
             responses=NOT_FOUND)
def revert_observable(obs_id: int, db: Session = Depends(get_db), p: Principal = Depends(write_access)):
    """Unpin: return control to the workspace values (collision strategy)."""
    obs = svc.get_or_404(db, obs_id)
    if obs.origin == "manual":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Manually created observables are always authoritative")
    svc.unpin(db, obs, p.actor)
    log_event(db, p.actor, "unpin_observable", "observable", obs.value)
    db.commit()
    return svc.detail_out(db, obs)


@router.delete("/observables/{obs_id}", status_code=204, response_class=Response, tags=OBS, summary="Delete an observable",
               responses=NOT_FOUND)
def delete_observable(obs_id: int, db: Session = Depends(get_db), p: Principal = Depends(write_access)):
    """Remove it centrally and block re-import. Torq workspaces keep their copies."""
    obs = svc.get_or_404(db, obs_id)
    svc.delete_with_tombstone(db, obs, p.actor)
    log_event(db, p.actor, "delete_observable", "observable", obs.value)
    db.commit()
    return Response(status_code=204)
