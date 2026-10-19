"""Optionally remove a source's observables when the source (a workspace or a feed) is deleted.

Only observables that came *solely* from that source are removed: anything also seen natively in another
workspace, listed by another feed, or created/edited in Beacon still has a source and is kept. Removed observables
are tombstoned only when Beacon pushed copies of them to other workspaces (Torq's API can't delete those copies,
and the next sync would otherwise re-import them); the rest are deleted cleanly, so re-adding the source later
brings them back.
"""

from sqlalchemy import and_, exists, not_, or_
from sqlalchemy.orm import Session

from app.models import FeedLink, IntelEnrichment, Observable, ObservableLink, Tombstone

CHUNK = 800


def _not_central():
    return not_(or_(Observable.origin == "manual", Observable.pinned.is_(True)))


def _native_in(*conds):
    return exists().where(ObservableLink.observable_id == Observable.id, ObservableLink.relation == "origin", *conds)


def _listed_by(*conds):
    return exists().where(FeedLink.observable_id == Observable.id, *conds)


def exclusive_filter(source: str):
    """SQL for observables whose only source is `source` ("<workspace id>" or "feed:<id>")."""
    if source.startswith("feed:"):
        fid = int(source[5:])
        return and_(_listed_by(FeedLink.feed_id == fid), not_(_listed_by(FeedLink.feed_id != fid)),
                    not_(_native_in()), _not_central())
    wid = int(source)
    return and_(_native_in(ObservableLink.workspace_id == wid), not_(_native_in(ObservableLink.workspace_id != wid)),
                not_(_listed_by()), _not_central())


def _copies_elsewhere(source: str):
    """Pushed copies in workspaces other than the one being removed."""
    conds = [ObservableLink.observable_id == Observable.id, ObservableLink.relation == "pushed"]
    if not source.startswith("feed:"):
        conds.append(ObservableLink.workspace_id != int(source))
    return exists().where(*conds)


def impact(db: Session, source: str) -> dict:
    q = db.query(Observable.id).filter(exclusive_filter(source))
    return {"observables": q.count(), "with_copies": q.filter(_copies_elsewhere(source)).count()}


def remove_exclusive(db: Session, source: str, username: str) -> dict:
    """Delete observables that came only from `source`. Call before deleting the source. The caller commits."""
    rows = db.query(Observable.id, Observable.type, Observable.value_norm, Observable.value).filter(exclusive_filter(source)).all()
    if not rows:
        return {"deleted": 0, "tombstoned": 0}
    ids = [r.id for r in rows]
    with_copies: set[int] = set()
    for i in range(0, len(ids), CHUNK):
        chunk = ids[i : i + CHUNK]
        with_copies.update(oid for (oid,) in db.query(Observable.id).filter(Observable.id.in_(chunk), _copies_elsewhere(source)))
    tombstoned = 0
    for r in rows:
        if r.id in with_copies and not db.query(Tombstone.id).filter_by(type=r.type, value_norm=r.value_norm).first():
            db.add(Tombstone(type=r.type, value_norm=r.value_norm, value=r.value, deleted_by=username))
            tombstoned += 1
    db.flush()
    # Bulk delete; links, history, enrichment, feed listings and queued jobs go with it (ON DELETE CASCADE).
    for i in range(0, len(ids), CHUNK):
        db.query(Observable).filter(Observable.id.in_(ids[i : i + CHUNK])).delete(synchronize_session=False)
    db.expire_all()
    return {"deleted": len(ids), "tombstoned": tombstoned}


def enrichment_count(db: Session, provider: str) -> int:
    return db.query(IntelEnrichment).filter_by(provider=provider).count()


def remove_enrichment(db: Session, provider: str) -> int:
    n = db.query(IntelEnrichment).filter_by(provider=provider).delete(synchronize_session=False)
    db.expire_all()
    return n
