"""Poll STIX/TAXII feeds on their schedule and ingest new indicators.

Like the enrichment queue it never holds a database write across an HTTP call: fetch and parse with no session
open, wait while a sync is running (the sync works on in-memory observables), then write each page in a short
session. The TAXII cursor is advanced after each committed page, so an interrupted poll resumes where it stopped.
"""

import asyncio
import logging
from datetime import timedelta

from sqlalchemy.exc import IntegrityError

from app.db import SessionLocal
from app.feeds import client, ingest, textlist
from app.models import Feed, FeedLink, Observable, utcnow
from app.security import decrypt
from app.stix.parser import parse_objects

log = logging.getLogger("beacon.feeds")

JOB_ID = "feed-poller"
TICK_SECONDS = 60
CURSOR_OVERLAP = timedelta(minutes=5)
_polling: set[int] = set()


def credentials(feed: Feed) -> client.Credentials:
    return client.Credentials(auth=feed.auth, username=feed.username or "",
                              secret=decrypt(feed.secret_enc) if feed.secret_enc else "", header_name=feed.header_name or "")


async def _wait_for_sync(max_wait: float = 900) -> None:
    from app.sync import engine

    waited = 0.0
    while engine._lock.locked() and waited < max_wait:
        await asyncio.sleep(1)
        waited += 1


def _iso(dt) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _write(feed_id: int, apply) -> bool:
    """Run apply(db, feed) and commit; on a unique-value race (the same observable was just created elsewhere)
    roll back and retry once, so the page links to the existing observable instead of failing. False if the feed
    was deleted meanwhile."""
    for attempt in range(2):
        with SessionLocal() as db:
            feed = db.get(Feed, feed_id)
            if feed is None:
                return False
            try:
                apply(db, feed)
                db.commit()
                return True
            except IntegrityError:
                db.rollback()
                if attempt:
                    raise
                log.info("Feed %s: value created concurrently; retrying the page", feed_id)
    return True


def _enqueue_new(db, feed: Feed, ids: list[int]) -> None:
    if not (feed.enrich_new and ids):
        return
    from app.intel.enrichment_rules import enqueue
    from app.intel.queue import wake

    if enqueue(db, db.query(Observable).filter(Observable.id.in_(ids)).all(), "new"):
        wake()


async def poll_feed(feed_id: int) -> dict:
    """Poll one feed now. Returns ingest stats; failures are recorded on the feed."""
    if feed_id in _polling:
        return {"skipped": "already polling"}
    _polling.add(feed_id)
    started = utcnow()
    stats = ingest.IngestStats()
    error: str | None = None
    try:
        with SessionLocal() as db:
            feed = db.get(Feed, feed_id)
            if feed is None:
                return {"skipped": "feed deleted"}
            cfg = {k: getattr(feed, k) for k in ("kind", "url", "collection_id", "cursor", "etag", "last_modified",
                                                 "default_reputation", "min_confidence", "initial_lookback_days",
                                                 "list_type")}
            creds = credentials(feed)
        if cfg["kind"] == "text_list":
            body, etag, last_modified = await client.text(cfg["url"], creds, cfg["etag"], cfg["last_modified"])
            if body is not None:
                listed = textlist.parse(body, cfg["list_type"], cfg["default_reputation"])
                await _wait_for_sync()

                def apply_list(db, feed):
                    nonlocal stats
                    stats = ingest.IngestStats()  # fresh on retry
                    # Only the delta changes anything: already-listed values are untouched, new ones are set to the
                    # feed's reputation, values gone from the list are restored.
                    ingest.upsert(db, feed, listed.items, stats, mode="match")
                    ingest.finish_snapshot(db, feed, stats, revert=True)
                    feed.etag, feed.last_modified = etag, last_modified
                    _enqueue_new(db, feed, stats.new_observable_ids)

                if not _write(feed_id, apply_list):
                    return {"skipped": "feed deleted"}
        elif cfg["kind"] == "stix_url":
            objects, etag, last_modified = await client.bundle(cfg["url"], creds, cfg["etag"], cfg["last_modified"])
            if objects is not None:
                parsed = parse_objects(objects, cfg["default_reputation"], cfg["min_confidence"])
                await _wait_for_sync()

                def apply_bundle(db, feed):
                    nonlocal stats
                    stats = ingest.IngestStats()  # fresh on retry
                    ingest.upsert(db, feed, parsed, stats)
                    ingest.finish_snapshot(db, feed, stats)
                    feed.etag, feed.last_modified = etag, last_modified
                    _enqueue_new(db, feed, stats.new_observable_ids)

                if not _write(feed_id, apply_bundle):
                    return {"skipped": "feed deleted"}
        else:
            added_after = cfg["cursor"] or _iso(started - timedelta(days=max(0, cfg["initial_lookback_days"])))
            async for page in client.taxii_pages(cfg["url"], cfg["collection_id"], creds, added_after):
                parsed = parse_objects(page.objects, cfg["default_reputation"], cfg["min_confidence"])
                await _wait_for_sync()

                holder: dict = {}

                def apply_page(db, feed, page=page, parsed=parsed, holder=holder):
                    page_stats = holder["stats"] = ingest.IngestStats()  # fresh on retry
                    ingest.upsert(db, feed, parsed, page_stats)
                    # Resume point: the server's last date_added on this page, else the poll start (with overlap).
                    feed.cursor = page.date_added_last or _iso(started - CURSOR_OVERLAP)
                    _enqueue_new(db, feed, page_stats.new_observable_ids)

                if not _write(feed_id, apply_page):
                    return {"skipped": "feed deleted"}
                _merge_stats(stats, holder["stats"])
    except client.FeedError as e:
        error = str(e)
    except Exception as e:  # noqa: BLE001 - recorded on the feed, never raised into the scheduler
        log.exception("Feed %s poll failed", feed_id)
        error = repr(e)
    finally:
        _polling.discard(feed_id)
        with SessionLocal() as db:
            feed = db.get(Feed, feed_id)
            if feed is not None:
                feed.last_poll_at = started
                feed.last_status = "error" if error else "ok"
                feed.last_error = error
                feed.stats = {**stats.as_dict(), "duration_seconds": round((utcnow() - started).total_seconds(), 1)}
                db.commit()
    result = stats.as_dict()
    if error:
        result["error"] = error
    log.info("Feed %s polled: %s", feed_id, result)
    return result


def _merge_stats(total: ingest.IngestStats, page: ingest.IngestStats) -> None:
    for k in ("indicators", "created", "linked", "escalated", "deactivated", "skipped_tombstoned"):
        setattr(total, k, getattr(total, k) + getattr(page, k))
    total.new_observable_ids += page.new_observable_ids


def due(feed: Feed, now) -> bool:
    return feed.enabled and (feed.last_poll_at is None or feed.last_poll_at + timedelta(minutes=max(1, feed.poll_minutes)) <= now)


async def tick() -> None:
    """Scheduler job: expire stale listings, then poll every feed that's due (one at a time)."""
    now = utcnow()
    with SessionLocal() as db:
        if ingest.expire(db, now):
            db.commit()
        due_ids = [f.id for f in db.query(Feed).filter_by(enabled=True).all() if due(f, now)]
    for feed_id in due_ids:
        await poll_feed(feed_id)


def listed_counts(db) -> dict[int, int]:
    from sqlalchemy import func

    return dict(
        db.query(FeedLink.feed_id, func.count(func.distinct(FeedLink.observable_id)))
        .filter(FeedLink.active == True)  # noqa: E712
        .group_by(FeedLink.feed_id)
        .all()
    )
