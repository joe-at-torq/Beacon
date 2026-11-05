"""Priority sync: start a sync right away when Beacon gives an observable a priority reputation.

Sync rules can list reputations that shouldn't wait for the sync interval. When an observable is created or its
reputation changes outside a sync run (manual edit, API call, bulk edit, threat-intel normalization), a sync starts
within a few seconds instead. Bursts are coalesced into one run, priority runs are spaced at least MIN_GAP_SECONDS
apart, and a request that arrives while a sync is running starts another run right after it.

A full sync (pull, merge, push) is used rather than a targeted push: it refreshes each workspace first, which is
what prevents duplicates when an observable already exists in a target workspace.
"""

import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import event, inspect as sa_inspect
from sqlalchemy.orm import Session

from app.db import SessionLocal
from app.models import Observable, Rule, Workspace
from app.settings_store import get_setting
from app.torq.mapping import REPUTATIONS

log = logging.getLogger("beacon.priority")

JOB_ID = "priority-sync"
DEBOUNCE_SECONDS = 5
MIN_GAP_SECONDS = 30
SYNC_SESSION = "sync_run"  # Session.info flag set by the sync engine: its changes are pushed by that same run


@dataclass(frozen=True)
class Candidate:
    type: str
    sub_type: str
    reputation: str
    value: str


_last_started = 0.0  # monotonic time the last priority sync started
_pending: str | None = None  # label of a request that arrived while a sync was running
requests: list[str] = []  # labels requested since startup (diagnostics and tests)


def matching(candidates: list[Candidate], rules: list[Rule]) -> list[Candidate]:
    """Candidates with a priority reputation on an enabled rule whose type filters they match."""
    out = []
    for c in candidates:
        for r in rules:
            if not r.enabled or c.reputation not in (r.priority_reputations or []):
                continue
            if r.types and c.type not in r.types:
                continue
            if r.sub_types and c.sub_type not in r.sub_types:
                continue
            out.append(c)
            break
    return out


def label_for(hits: list[Candidate]) -> str:
    first = hits[0]
    text = f"{REPUTATIONS.get(first.reputation, (first.reputation,))[0]}: {first.value}"
    if len(hits) > 1:
        text += f" (+{len(hits) - 1})"
    return text[:64]


def check(candidates: list[Candidate]) -> bool:
    """Request a priority sync if any candidate matches a rule's priority reputations."""
    with SessionLocal() as db:
        rules = [r for r in db.query(Rule).filter_by(enabled=True).all() if r.priority_reputations]
        if not rules:
            return False
        hits = matching(candidates, rules)
    if hits:
        request(label_for(hits))
    return bool(hits)


def request(label: str) -> None:
    """Schedule a priority sync soon (thread-safe; coalesces with one that's already scheduled)."""
    from apscheduler.triggers.date import DateTrigger

    from app.scheduler import scheduler

    requests.append(label)
    if not scheduler.running:
        log.info("Priority sync requested (%s) but the scheduler isn't running", label)
        return
    if scheduler.get_job(JOB_ID):
        return  # one is already scheduled; it will pick up this change too
    wait = max(DEBOUNCE_SECONDS, MIN_GAP_SECONDS - (time.monotonic() - _last_started))
    scheduler.add_job(
        run, DateTrigger(run_date=datetime.now(UTC) + timedelta(seconds=wait)), args=[label], id=JOB_ID,
        replace_existing=False, misfire_grace_time=300, coalesce=True,
    )
    log.info("Priority sync scheduled in %ds (%s)", wait, label)


async def run(label: str) -> int | None:
    """Start the priority sync (or queue it behind the sync that's running). Returns the run id if started."""
    global _last_started, _pending
    from app.sync.engine import SyncAlreadyRunning, start_background_sync

    with SessionLocal() as db:
        if not get_setting(db, "sync_enabled"):
            log.info("Priority sync skipped: syncing is disabled")
            return None
        if db.query(Workspace).filter_by(enabled=True).count() == 0:
            return None
    try:
        run_id = start_background_sync("priority", label)
    except SyncAlreadyRunning:
        _pending = label
        return None
    _last_started = time.monotonic()
    _pending = None
    return run_id


def after_sync_run() -> None:
    """Called when any sync finishes: start the priority sync that had to wait for it."""
    global _pending
    if _pending:
        label, _pending = _pending, None
        request(label)


# ---- Change detection --------------------------------------------------------------------------------


@event.listens_for(Session, "after_flush")
def _collect(session: Session, _ctx) -> None:
    if session.info.get(SYNC_SESSION):
        return
    found = session.info.setdefault("priority_candidates", [])
    for obj in list(session.new) + list(session.dirty):
        if not isinstance(obj, Observable):
            continue
        if obj in session.new or sa_inspect(obj).attrs.reputation.history.has_changes():
            found.append(Candidate(obj.type, obj.sub_type or "", obj.reputation, obj.value))


@event.listens_for(Session, "after_commit")
def _committed(session: Session) -> None:
    candidates = session.info.pop("priority_candidates", None)
    if not candidates:
        return
    try:
        check(candidates)
    except Exception:  # noqa: BLE001 - never break the caller's request over this
        log.exception("Priority sync check failed")


@event.listens_for(Session, "after_rollback")
def _rolled_back(session: Session) -> None:
    session.info.pop("priority_candidates", None)
