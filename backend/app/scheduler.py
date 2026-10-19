import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.db import session_scope
from app.models import Workspace
from app.settings_store import get_setting
from app.sync.engine import SyncAlreadyRunning, start_background_sync

log = logging.getLogger("tim.scheduler")

JOB_ID = "scheduled-sync"
scheduler = AsyncIOScheduler()


async def _scheduled_sync() -> None:
    with session_scope() as db:
        if not get_setting(db, "sync_enabled"):
            return
        if db.query(Workspace).filter_by(enabled=True).count() == 0:
            return
    try:
        start_background_sync("schedule", "scheduler")
    except SyncAlreadyRunning:
        log.info("Skipping scheduled sync; a sync is already running")


def reschedule() -> None:
    with session_scope() as db:
        minutes = max(1, int(get_setting(db, "sync_interval_minutes") or 15))
    scheduler.add_job(
        _scheduled_sync,
        IntervalTrigger(minutes=minutes),
        id=JOB_ID,
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    log.info("Scheduled sync every %d minute(s)", minutes)


def schedule_enrichment_queue() -> None:
    from app.intel.queue import JOB_ID as QUEUE_JOB_ID, TICK_SECONDS, process_queue

    scheduler.add_job(
        process_queue,
        IntervalTrigger(seconds=TICK_SECONDS),
        id=QUEUE_JOB_ID,
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )


def schedule_feed_poller() -> None:
    from app.feeds.poller import JOB_ID as FEED_JOB_ID, TICK_SECONDS as FEED_TICK, tick

    scheduler.add_job(tick, IntervalTrigger(seconds=FEED_TICK), id=FEED_JOB_ID, replace_existing=True,
                      max_instances=1, coalesce=True)


def next_run_iso() -> str | None:
    job = scheduler.get_job(JOB_ID) if scheduler.running else None
    if job and job.next_run_time:
        return job.next_run_time.isoformat()
    return None


def start() -> None:
    if not scheduler.running:
        scheduler.start()
    reschedule()
    schedule_enrichment_queue()
    schedule_feed_poller()


def shutdown() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
