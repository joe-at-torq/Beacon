"""Upsert parsed feed indicators (STIX/TAXII or plain-text lists) into the central database.

Feeds never pin an observable (pinning would make it a "central" source and block workspace merges), and pinned
(centrally edited) observables are never changed by a feed. A new value becomes an observable with origin "feed".
For existing observables there are two modes, both applied only when something changed (a new listing, or the
feed's own verdict changed), so an analyst's later change isn't fought on every poll:
  * escalate (STIX/TAXII): the feed only raises the reputation;
  * match (plain-text lists): the observable takes the feed's reputation, up or down. What the feed set and what it
    replaced are kept on the listing, so when the value drops off the list the previous reputation is restored,
    provided nobody changed it since. History is written only on state changes.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import and_, or_, tuple_
from sqlalchemy.orm import Session

from app import history
from app.models import Feed, FeedLink, Observable, Tombstone, utcnow
from app.stix.parser import Parsed
from app.torq.mapping import severity

CHUNK = 500


@dataclass
class IngestStats:
    indicators: int = 0
    created: int = 0
    linked: int = 0
    escalated: int = 0
    deactivated: int = 0
    reverted: int = 0
    skipped_tombstoned: int = 0
    new_observable_ids: list[int] = field(default_factory=list)
    seen_link_ids: set[int] = field(default_factory=set)

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("indicators", "created", "linked", "escalated", "deactivated", "reverted",
                                              "skipped_tombstoned")}


def actor_for(feed: Feed) -> str:
    return f"feed:{feed.name}"[:64]


def _source(feed: Feed) -> str:
    return f"feed:{feed.id}"


def _escalate(obs: Observable, feed: Feed, reputation: str, stats: IngestStats) -> None:
    if obs.pinned or severity(reputation) <= severity(obs.reputation):
        return
    old = obs.reputation
    obs.reputation = reputation
    obs.value_source = _source(feed)
    history.record(obs, history.REPUTATION_CHANGED, actor=actor_for(feed), field="reputation", old=old, new=reputation,
                   cause="feed", feed_id=feed.id, feed_name=feed.name)
    stats.escalated += 1


def _match(obs: Observable, feed: Feed, link: FeedLink, reputation: str, stats: IngestStats) -> None:
    """Set the observable to the feed's reputation (unless centrally edited), remembering what it replaced."""
    if obs.pinned:
        return
    if obs.reputation == reputation:
        if link.applied_reputation is not None:
            link.applied_reputation = reputation
        return
    if link.applied_reputation is None:  # first change by this listing: remember what to restore
        link.prev_reputation, link.prev_value_source = obs.reputation, obs.value_source
    old = obs.reputation
    obs.reputation = reputation
    obs.value_source = _source(feed)
    link.applied_reputation = reputation
    history.record(obs, history.REPUTATION_CHANGED, actor=actor_for(feed), field="reputation", old=old, new=reputation,
                   cause="feed", feed_id=feed.id, feed_name=feed.name)
    stats.escalated += 1


def _apply(obs: Observable, feed: Feed, link: FeedLink, reputation: str, stats: IngestStats, mode: str) -> None:
    if mode == "match":
        _match(obs, feed, link, reputation, stats)
    else:
        _escalate(obs, feed, reputation, stats)


def _revert(db: Session, feed: Feed, link: FeedLink, stats: IngestStats) -> None:
    """The feed no longer lists the observable: restore what it replaced, if nobody changed it since."""
    applied, prev, prev_source = link.applied_reputation, link.prev_reputation, link.prev_value_source
    link.applied_reputation = link.prev_reputation = link.prev_value_source = None
    obs = db.get(Observable, link.observable_id)
    if obs is None or applied is None or obs.pinned or obs.reputation != applied:
        return
    # Another feed still lists it at this reputation: hand the restore point over instead of reverting now.
    other = (
        db.query(FeedLink)
        .filter(FeedLink.observable_id == obs.id, FeedLink.feed_id != feed.id, FeedLink.active == True)  # noqa: E712
        .order_by(FeedLink.id)
        .first()
    )
    if other is not None:
        if other.applied_reputation is None:
            other.applied_reputation, other.prev_reputation, other.prev_value_source = applied, prev, prev_source
        return
    restore = prev or "SCORE_UNKNOWN"
    obs.reputation = restore
    if obs.value_source == _source(feed):
        obs.value_source = prev_source
    history.record(obs, history.REPUTATION_CHANGED, actor=actor_for(feed), field="reputation", old=applied, new=restore,
                   cause="feed_removed", feed_id=feed.id, feed_name=feed.name)
    stats.reverted += 1


def _still_listed(db: Session, feed_id: int, obs_id: int) -> bool:
    return db.query(FeedLink.id).filter_by(feed_id=feed_id, observable_id=obs_id, active=True).first() is not None


def _removed(db: Session, feed: Feed, link: FeedLink, reason: str, stats: IngestStats) -> None:
    link.active = False
    stats.deactivated += 1
    db.flush()
    if not _still_listed(db, feed.id, link.observable_id):
        obs = db.get(Observable, link.observable_id)
        if obs is not None:
            history.record(obs, history.REMOVED_FROM_FEED, actor=actor_for(feed), feed_id=feed.id, feed_name=feed.name,
                           reason=reason, stix_id=link.stix_id)


def upsert(db: Session, feed: Feed, items: list[Parsed], stats: IngestStats | None = None, now: datetime | None = None,
           mode: str = "escalate") -> IngestStats:
    """Apply parsed indicators (any size; processed in chunks). mode: "escalate" or "match". The caller commits."""
    stats = stats or IngestStats()
    now = now or utcnow()
    # Last occurrence wins when the same indicator/value appears twice.
    unique = list({(p.stix_id, p.type, p.value_norm): p for p in items}.values())
    stats.indicators += len({p.stix_id for p in unique})
    for i in range(0, len(unique), CHUNK):
        _upsert_chunk(db, feed, unique[i : i + CHUNK], stats, now, mode)
    return stats


def _upsert_chunk(db: Session, feed: Feed, items: list[Parsed], stats: IngestStats, now: datetime, mode: str) -> None:
    keys = list({(p.type, p.value_norm) for p in items})
    tombstoned = {
        (t, v) for t, v in db.query(Tombstone.type, Tombstone.value_norm).filter(tuple_(Tombstone.type, Tombstone.value_norm).in_(keys))
    }
    existing = {
        (o.type, o.value_norm): o
        for o in db.query(Observable).filter(tuple_(Observable.type, Observable.value_norm).in_(keys))
    }
    obs_ids = [o.id for o in existing.values()]
    links = {
        (lk.stix_id, lk.observable_id): lk
        for lk in (db.query(FeedLink).filter(FeedLink.feed_id == feed.id, FeedLink.observable_id.in_(obs_ids)) if obs_ids else [])
    }
    listed = {lk.observable_id for lk in links.values() if lk.active}  # listed by this feed before this chunk
    # New values first, flushed once per chunk (ids are needed for links and history).
    created: list[tuple[Observable, Parsed]] = []
    for p in items:
        key = (p.type, p.value_norm)
        if key in tombstoned or key in existing or not p.active:
            continue
        obs = Observable(
            type=p.type, sub_type=p.sub_type, value=p.value, value_norm=p.value_norm, reputation=p.reputation,
            description=p.description, first_observed_at=p.valid_from or now, last_observed_at=now,
            origin="feed", value_source=_source(feed), links=[],
        )
        db.add(obs)
        existing[key] = obs
        created.append((obs, p))
    if created:
        db.flush()
        new_links = []
        for obs, p in created:
            history.record(obs, history.CREATED, actor=actor_for(feed), new=p.reputation, origin="feed",
                           feed_id=feed.id, feed_name=feed.name, stix_id=p.stix_id)
            link = FeedLink(feed_id=feed.id, observable_id=obs.id, stix_id=p.stix_id, reputation=p.reputation,
                            valid_until=p.valid_until, active=True, first_seen_at=now, last_seen_at=now)
            if mode == "match":  # created by this list: removal sends it back to Unknown
                link.applied_reputation, link.prev_reputation = p.reputation, "SCORE_UNKNOWN"
            db.add(link)
            new_links.append(link)
            links[(p.stix_id, obs.id)] = link
            listed.add(obs.id)
            stats.created += 1
            stats.new_observable_ids.append(obs.id)
        db.flush()
        stats.seen_link_ids.update(lk.id for lk in new_links)
    fresh = {id(obs) for obs, _ in created}
    for p in items:
        key = (p.type, p.value_norm)
        if key in tombstoned:
            stats.skipped_tombstoned += 1
            continue
        obs = existing.get(key)
        if obs is None:
            continue  # revoked/expired indicators never create observables
        if id(obs) in fresh and (p.stix_id, obs.id) in links:
            continue  # created above in this chunk

        link = links.get((p.stix_id, obs.id))
        if link is None:
            if not p.active:
                continue
            link = FeedLink(feed_id=feed.id, observable_id=obs.id, stix_id=p.stix_id, reputation=p.reputation,
                            valid_until=p.valid_until, active=True, first_seen_at=now, last_seen_at=now)
            db.add(link)
            db.flush()
            links[(p.stix_id, obs.id)] = link
            stats.linked += 1
            if obs.id not in listed:
                history.record(obs, history.SEEN_IN_FEED, actor=actor_for(feed), new=p.reputation, feed_id=feed.id,
                               feed_name=feed.name, stix_id=p.stix_id, pinned=obs.pinned)
                listed.add(obs.id)
            _apply(obs, feed, link, p.reputation, stats, mode)
            stats.seen_link_ids.add(link.id)
            continue

        stats.seen_link_ids.add(link.id)
        link.last_seen_at, link.valid_until = now, p.valid_until
        if not p.active:
            if link.active:
                _removed(db, feed, link, "revoked or expired", stats)
                if not _still_listed(db, feed.id, obs.id):
                    listed.discard(obs.id)
            continue
        changed = (not link.active) or link.reputation != p.reputation
        if not link.active:
            link.active = True
            if obs.id not in listed:
                history.record(obs, history.SEEN_IN_FEED, actor=actor_for(feed), new=p.reputation, feed_id=feed.id,
                               feed_name=feed.name, stix_id=p.stix_id, pinned=obs.pinned)
                listed.add(obs.id)
        link.reputation = p.reputation
        if changed:
            _apply(obs, feed, link, p.reputation, stats, mode)
    db.flush()


def finish_snapshot(db: Session, feed: Feed, stats: IngestStats, revert: bool = False) -> None:
    """A STIX bundle URL or text list is a full snapshot: listings missing from it are no longer active.
    With revert (text lists), reputations the feed set are restored once it no longer lists the observable."""
    gone = db.query(FeedLink).filter(FeedLink.feed_id == feed.id, FeedLink.active == True)  # noqa: E712
    for link in gone.all():
        if link.id not in stats.seen_link_ids:
            _removed(db, feed, link, "no longer in the feed", stats)
            if revert and not _still_listed(db, feed.id, link.observable_id):
                _revert(db, feed, link, stats)


def expire(db: Session, now: datetime | None = None) -> int:
    """Deactivate listings past their valid_until, or older than their feed's max age. The caller commits."""
    now = now or utcnow()
    stats = IngestStats()
    feeds = {f.id: f for f in db.query(Feed).all()}
    aged = [and_(FeedLink.feed_id == f.id, FeedLink.last_seen_at < now - timedelta(days=f.max_age_days))
            for f in feeds.values() if f.max_age_days > 0]
    q = db.query(FeedLink).filter(
        FeedLink.active == True,  # noqa: E712
        or_(and_(FeedLink.valid_until.is_not(None), FeedLink.valid_until <= now), *aged),
    )
    for link in q.all():
        feed = feeds.get(link.feed_id)
        if feed:
            reason = "expired" if link.valid_until and link.valid_until <= now else "not seen recently"
            _removed(db, feed, link, reason, stats)
    return stats.deactivated
