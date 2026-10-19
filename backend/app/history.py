"""Observable change history ("timeline")."""

from sqlalchemy import exists, select
from sqlalchemy.orm import Session, object_session

from app.models import Observable, ObservableEvent, utcnow

MAX_VALUE_CHARS = 4000

# Event kinds
CREATED = "created"
SEEN_IN_WORKSPACE = "seen_in_workspace"
PUSHED_TO_WORKSPACE = "pushed_to_workspace"
UPDATED_IN_WORKSPACE = "updated_in_workspace"
REMOVED_FROM_WORKSPACE = "removed_from_workspace"
WORKSPACE_REPUTATION_CHANGED = "workspace_reputation_changed"
REPUTATION_CHANGED = "reputation_changed"
DESCRIPTION_CHANGED = "description_changed"
PINNED = "pinned"
UNPINNED = "unpinned"
ENRICHMENT_ADDED = "enrichment_added"
ENRICHMENT_UPDATED = "enrichment_updated"
ENRICHMENT_REMOVED = "enrichment_removed"
SEEN_IN_FEED = "seen_in_feed"
REMOVED_FROM_FEED = "removed_from_feed"


def _clip(value) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= MAX_VALUE_CHARS else text[:MAX_VALUE_CHARS] + "…"


def record(
    obs: Observable,
    kind: str,
    *,
    actor: str = "sync",
    workspace_id: int | None = None,
    workspace_name: str = "",
    run_id: int | None = None,
    field: str | None = None,
    old=None,
    new=None,
    db: Session | None = None,
    **detail,
) -> None:
    session = db or object_session(obs)
    if session is None:
        raise RuntimeError("Observable is not attached to a session")
    session.add(
        ObservableEvent(
            observable=obs,
            ts=utcnow(),
            kind=kind,
            actor=actor,
            workspace_id=workspace_id,
            workspace_name=workspace_name,
            run_id=run_id,
            field=field,
            old_value=_clip(old),
            new_value=_clip(new),
            detail=detail,
        )
    )


def record_value_changes(obs: Observable, old_rep: str, old_desc: str, **kw) -> None:
    """Record reputation/description changes on obs relative to the given previous values."""
    if obs.reputation != old_rep:
        record(obs, REPUTATION_CHANGED, field="reputation", old=old_rep, new=obs.reputation, **kw)
    if (obs.description or "") != (old_desc or ""):
        record(obs, DESCRIPTION_CHANGED, field="description", old=old_desc or "", new=obs.description or "", **kw)


def backfill(db: Session) -> int:
    """Give observables that predate history tracking a baseline timeline. Returns how many were filled."""
    missing = (
        db.execute(
            select(Observable).where(~exists().where(ObservableEvent.observable_id == Observable.id))
        )
        .scalars()
        .all()
    )
    for obs in missing:
        first = next((link for link in obs.links if link.relation == "origin"), None)
        ws_name = first.workspace.name if first is not None else ""
        events = [
            ObservableEvent(
                observable=obs,
                ts=obs.created_at,
                kind=CREATED,
                actor="sync" if obs.origin == "workspace" else "unknown",
                workspace_id=first.workspace_id if first is not None else None,
                workspace_name=ws_name,
                new_value=obs.reputation,
                detail={"backfilled": True, "origin": obs.origin, "reputation": obs.reputation},
            )
        ]
        for link in obs.links:
            if link is first:
                continue
            events.append(
                ObservableEvent(
                    observable=obs,
                    ts=obs.created_at,
                    kind=SEEN_IN_WORKSPACE if link.relation == "origin" else PUSHED_TO_WORKSPACE,
                    workspace_id=link.workspace_id,
                    workspace_name=link.workspace.name,
                    detail={"backfilled": True, "remote_id": link.remote_id},
                )
            )
        db.add_all(events)
    return len(missing)
