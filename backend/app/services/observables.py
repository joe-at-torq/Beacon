"""Observable operations shared by the internal UI API and the public v1 API."""

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, event, exists, false, func, or_
from sqlalchemy.orm import Query, Session

from app import history
from app.intel.enrichment_rules import enqueue as enqueue_enrichment
from app.intel.queue import wake as wake_enrichment_queue
from app.models import FeedLink, IntelEnrichment, Observable, ObservableLink, Tombstone, Workspace, utcnow
from app.settings_store import get_setting
from app.sync.engine import merge_observable
from app.torq.mapping import REPUTATIONS, SUB_TYPES, TYPES, infer_sub_type, normalize_value

SORTABLE = {
    "value": Observable.value_norm,
    "type": Observable.type,
    "created_at": Observable.created_at,
    "updated_at": Observable.updated_at,
    "last_observed_at": Observable.last_observed_at,
    "first_observed_at": Observable.first_observed_at,
    "associated_cases_count": Observable.associated_cases_count,
}
severity_expr = case({k: v[1] for k, v in REPUTATIONS.items()}, value=Observable.reputation, else_=0)
SORT_KEYS = [*SORTABLE, "reputation"]


class ObservableCreate(BaseModel):
    type: str = Field(description="Observable type, e.g. TYPE_ID_IP_ADDRESS (see GET /meta)")
    sub_type: str = Field("SUB_TYPE_ID_UNKNOWN", description="Optional sub type; inferred when unknown (e.g. IPv4/IPv6)")
    value: str = Field(min_length=1, max_length=4096)
    reputation: str = Field("SCORE_UNKNOWN", description="Reputation score id, e.g. SCORE_MALICIOUS")
    description: str = Field(default="", max_length=10000)

    model_config = {"json_schema_extra": {"examples": [
        {"type": "TYPE_ID_IP_ADDRESS", "value": "203.0.113.7", "reputation": "SCORE_MALICIOUS",
         "description": "C2 server seen in incident IR-1042"}]}}

    @field_validator("type")
    @classmethod
    def _type(cls, v):
        if v not in TYPES:
            raise ValueError("Unknown observable type")
        return v

    @field_validator("sub_type")
    @classmethod
    def _sub(cls, v):
        if v not in SUB_TYPES:
            raise ValueError("Unknown sub type")
        return v

    @field_validator("reputation")
    @classmethod
    def _rep(cls, v):
        if v not in REPUTATIONS:
            raise ValueError("Unknown reputation")
        return v


class ObservableUpdate(BaseModel):
    reputation: str | None = Field(None, description="New reputation score id")
    description: str | None = Field(default=None, max_length=10000)

    model_config = {"json_schema_extra": {"examples": [{"reputation": "SCORE_SUSPICIOUS_OR_RISKY",
                                                         "description": "Downgraded after triage"}]}}

    @field_validator("reputation")
    @classmethod
    def _rep(cls, v):
        if v is not None and v not in REPUTATIONS:
            raise ValueError("Unknown reputation")
        return v


@dataclass
class ObservableFilters:
    search: str = ""
    types: list[str] | None = None
    sub_types: list[str] | None = None
    reputations: list[str] | None = None
    min_severity: int | None = None
    workspace_ids: list[int] | None = None
    sources: list[str] | None = None  # where it came from: workspace ids, "central", "feed:<id>"
    pinned: bool | None = None
    origin: str | None = None
    has_enrichment: bool | None = None
    first_observed_from: datetime | None = None
    first_observed_to: datetime | None = None
    last_observed_from: datetime | None = None
    last_observed_to: datetime | None = None
    min_cases: int | None = None


def detail_out(db: Session, obs: Observable) -> dict:
    """Observable detail incl. the threat-intel normalized reputation (if any rule/verdict applies)."""
    from app.intel import normalize
    from app.serializers import observable_out

    from app.models import Feed, FeedLink
    from app.serializers import iso

    out = observable_out(obs, ws_names(db), detail=True)
    cfg = normalize.load_config(db)
    out["normalized"] = normalize.evaluate(cfg, obs) if obs.intel else None
    if out["normalized"]:
        # In automatic mode a differing verdict was held back on purpose; say why instead of asking to apply it.
        blocked = None
        if cfg.mode == "auto" and out["normalized"]["differs"] and not normalize.should_apply(cfg, obs, out["normalized"]):
            blocked = "lower"  # "only raise severity" is on
        out["normalized"] |= {"mode": cfg.mode, "blocked": blocked}
    out["feeds"] = [
        {"feed_id": link.feed_id, "feed_name": name, "stix_id": link.stix_id, "reputation": link.reputation,
         "valid_until": iso(link.valid_until), "active": link.active, "first_seen_at": iso(link.first_seen_at),
         "last_seen_at": iso(link.last_seen_at)}
        for link, name in db.query(FeedLink, Feed.name).join(Feed, Feed.id == FeedLink.feed_id)
        .filter(FeedLink.observable_id == obs.id).order_by(FeedLink.active.desc(), FeedLink.last_seen_at.desc())
    ]
    return out


def ws_names(db: Session) -> dict[int, str]:
    return {ws.id: ws.name for ws in db.query(Workspace).all()}


def get_or_404(db: Session, obs_id: int) -> Observable:
    obs = db.get(Observable, obs_id)
    if not obs:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Observable not found")
    return obs


def _naive(ts: datetime | None) -> datetime | None:
    """Timestamps are stored as naive UTC; convert aware inputs."""
    return ts.astimezone(UTC).replace(tzinfo=None) if ts and ts.tzinfo else ts


def source_clause(sources: list, feeds_ever: bool = True):
    """SQL for "the observable came from one of these sources".

    A workspace id: first seen natively there (or its current central value came from there). "central":
    created or edited in Beacon. "feed:<id>": listed by that feed: ever (feeds_ever) or currently.
    """
    clauses = []
    for raw in sources:
        s = str(raw)
        if s == "central":
            clauses.append(or_(Observable.origin == "manual", Observable.pinned.is_(True)))
        elif s.startswith("feed:") and s[5:].isdigit():
            cond = [FeedLink.observable_id == Observable.id, FeedLink.feed_id == int(s[5:])]
            if not feeds_ever:
                cond.append(FeedLink.active.is_(True))
            clauses.append(exists().where(*cond))
        elif s.isdigit():
            clauses.append(or_(Observable.value_source == s, exists().where(
                ObservableLink.observable_id == Observable.id, ObservableLink.workspace_id == int(s),
                ObservableLink.relation == "origin")))
    return or_(*clauses) if clauses else false()


def filtered_query(db: Session, f: ObservableFilters) -> Query:
    q = db.query(Observable)
    if f.search:
        term = f"%{f.search.strip().lower()}%"
        q = q.filter(or_(Observable.value_norm.like(term), func.lower(Observable.value).like(term),
                         func.lower(Observable.description).like(term)))
    if f.types:
        q = q.filter(Observable.type.in_(f.types))
    if f.sub_types:
        q = q.filter(Observable.sub_type.in_(f.sub_types))
    if f.reputations:
        q = q.filter(Observable.reputation.in_(f.reputations))
    if f.min_severity is not None:
        q = q.filter(severity_expr >= f.min_severity)
    if f.workspace_ids:
        q = q.filter(Observable.links.any(ObservableLink.workspace_id.in_(f.workspace_ids)))
    if f.sources:
        q = q.filter(source_clause(f.sources))
    if f.pinned is not None:
        q = q.filter(Observable.pinned == f.pinned)
    if f.origin:
        q = q.filter(Observable.origin == f.origin)
    if f.has_enrichment is not None:
        enriched = or_(
            Observable.links.any(ObservableLink.has_enrichment.is_(True)),
            Observable.intel.any(IntelEnrichment.status == "ok"),
        )
        q = q.filter(enriched if f.has_enrichment else ~enriched)
    for col, lo, hi in (
        (Observable.first_observed_at, f.first_observed_from, f.first_observed_to),
        (Observable.last_observed_at, f.last_observed_from, f.last_observed_to),
    ):
        if lo:
            q = q.filter(col >= _naive(lo))
        if hi:
            q = q.filter(col <= _naive(hi))
    if f.min_cases is not None:
        q = q.filter(Observable.associated_cases_count >= f.min_cases)
    return q


def page_of(q: Query, sort: str, order: str, page: int, page_size: int) -> tuple[list[Observable], int]:
    total = q.count()
    col = severity_expr if sort == "reputation" else SORTABLE.get(sort, Observable.updated_at)
    q = q.order_by(col.asc() if order == "asc" else col.desc(), Observable.id.desc())
    return q.offset((page - 1) * page_size).limit(page_size).all(), total


def find_by_value(db: Session, type_id: str, value: str) -> Observable | None:
    return db.query(Observable).filter_by(type=type_id, value_norm=normalize_value(type_id, value)).first()


def create(db: Session, body: ObservableCreate, username: str) -> Observable:
    value = body.value.strip()
    if body.type == "TYPE_ID_IP_ADDRESS":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise HTTPException(422, "Invalid IP address") from None
    if body.type == "TYPE_ID_EMAIL_ADDRESS" and "@" not in value:
        raise HTTPException(422, "Invalid email address")
    norm = normalize_value(body.type, value)
    if db.query(Observable).filter_by(type=body.type, value_norm=norm).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "This observable already exists")
    # Explicitly re-adding a deleted observable lifts its tombstone.
    db.query(Tombstone).filter_by(type=body.type, value_norm=norm).delete()
    now = utcnow()
    obs = Observable(
        type=body.type,
        sub_type=infer_sub_type(body.type, value, body.sub_type),
        value=value,
        value_norm=norm,
        reputation=body.reputation,
        description=body.description,
        first_observed_at=now,
        last_observed_at=now,
        origin="manual",
        pinned=True,
        value_source="central",
    )
    db.add(obs)
    history.record(obs, history.CREATED, actor=username, new=body.reputation, origin="manual", db=db)
    db.flush()
    if enqueue_enrichment(db, [obs], "new"):
        # Start the lookups once the caller's transaction is committed.
        event.listen(db, "after_commit", lambda _s: wake_enrichment_queue(), once=True)
    return obs


def delete_with_tombstone(db: Session, obs: Observable, username: str) -> None:
    if not db.query(Tombstone).filter_by(type=obs.type, value_norm=obs.value_norm).first():
        db.add(Tombstone(type=obs.type, value_norm=obs.value_norm, value=obs.value, deleted_by=username))
    db.delete(obs)


def unpin(db: Session, obs: Observable, username: str) -> None:
    obs.pinned = False
    history.record(obs, history.UNPINNED, actor=username)
    workspaces = db.query(Workspace).all()
    merge_observable(
        obs,
        {ws.id: ws.priority for ws in workspaces},
        get_setting(db, "collision_strategy"),
        get_setting(db, "description_merge"),
        ws_names={ws.id: ws.name for ws in workspaces},
        actor=username,
        cause="revert",
    )


def manual_edit(obs: Observable, username: str, reputation: str | None, description: str | None) -> list[str]:
    """Apply a user edit (which makes the observable centrally authoritative) and record it. Returns changes."""
    old_rep, old_desc = obs.reputation, obs.description or ""
    changes = []
    if reputation is not None and reputation != obs.reputation:
        changes.append(f"reputation {REPUTATIONS[obs.reputation][0]} → {REPUTATIONS[reputation][0]}")
        obs.reputation = reputation
    if description is not None and description != old_desc:
        changes.append("description")
        obs.description = description
    if changes:
        obs.value_source = "central"
        history.record_value_changes(obs, old_rep, old_desc, actor=username, cause="manual")
        if not obs.pinned:
            obs.pinned = True
            history.record(obs, history.PINNED, actor=username)
        obs.updated_at = utcnow()
    return changes
