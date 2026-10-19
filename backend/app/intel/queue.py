"""Rate-limited worker for rule-driven enrichment jobs.

Runs as a scheduler job every few seconds. Concurrency rules (SQLite, one event loop):
  * it does nothing while a sync is running;
  * it never holds a database write across an HTTP call: claim + commit, look up with no session open,
    then a fresh session reloads the observable and stores the result.
Pacing is per provider: a sliding one-minute window (in memory) and a daily budget counted from jobs
attempted since UTC midnight. A 429 or a rejected key puts the provider in a cooldown instead of
burning through the queue.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func

from app.db import SessionLocal
from app.intel.enrichment_rules import FRESH_STATUSES, is_fresh, limits
from app.intel.providers import PROVIDERS, IntelError
from app.intel.service import active_integrations, apply_result, lookup
from app.models import EnrichmentJob, Integration, Observable, utcnow
from app.security import decrypt
from app.serializers import iso
from app.settings_store import get_setting

log = logging.getLogger("tim.enrichment")

JOB_ID = "enrichment-queue"
TICK_SECONDS = 15
MAX_ATTEMPTS = 3
COOLDOWN_START, COOLDOWN_MAX = 60, 15 * 60
KEEP_FINISHED_DAYS = 7
CONCURRENCY = 6


@dataclass
class Cooldown:
    until: datetime
    reason: str
    backoff: int


_window: dict[str, deque[float]] = defaultdict(deque)  # monotonic times of lookups in the last minute
_cooldowns: dict[str, Cooldown] = {}
_tick = asyncio.Lock()


def reset_state() -> None:
    """Forget in-memory pacing (tests, restarts)."""
    _window.clear()
    _cooldowns.clear()


def actor_for(rule_name: str) -> str:
    return f"rule:{rule_name or 'deleted rule'}"[:64]


def _midnight(now: datetime) -> datetime:
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def used_last_minute(provider: str) -> int:
    w = _window[provider]
    cutoff = time.monotonic() - 60
    while w and w[0] < cutoff:
        w.popleft()
    return len(w)


def used_today(db, provider: str, now: datetime | None = None) -> int:
    now = now or utcnow()
    return (
        db.query(func.count(EnrichmentJob.id))
        .filter(EnrichmentJob.provider == provider, EnrichmentJob.last_attempt_at >= _midnight(now))
        .scalar()
        or 0
    )


def cooldown_of(provider: str, now: datetime | None = None) -> Cooldown | None:
    cd = _cooldowns.get(provider)
    if cd and cd.until > (now or utcnow()):
        return cd
    return None


def _start_cooldown(provider: str, reason: str, seconds: int | None = None) -> Cooldown:
    prev = _cooldowns.get(provider)
    backoff = seconds or min(COOLDOWN_MAX, (prev.backoff * 2) if prev else COOLDOWN_START)
    cd = Cooldown(until=utcnow() + timedelta(seconds=backoff), reason=reason, backoff=backoff)
    _cooldowns[provider] = cd
    return cd


def reset_running() -> int:
    """After a restart, jobs that were mid-lookup go back to the queue."""
    with SessionLocal() as db:
        n = db.query(EnrichmentJob).filter_by(status="running").update({"status": "queued"})
        db.commit()
        return n


def wake() -> None:
    """Run the worker as soon as possible (thread-safe; no-op when the scheduler isn't running)."""
    from app.scheduler import scheduler

    try:
        if scheduler.running and scheduler.get_job(JOB_ID):
            scheduler.modify_job(JOB_ID, next_run_time=datetime.now(UTC))
    except Exception:  # noqa: BLE001 - waking is best effort
        log.debug("Could not wake the enrichment queue", exc_info=True)


@dataclass
class Claim:
    job_id: int
    provider: str
    obs_id: int
    obs_type: str
    value: str
    api_key: str
    rule_id: int | None
    rule_name: str


def unavailable_reason(db, provider: str, active: set[str], lim: dict, now: datetime) -> str | None:
    """Why a provider can't take lookups for a while (per-minute pacing doesn't count: it clears in minutes)."""
    if provider not in active:
        return "integration unavailable"
    cd = cooldown_of(provider, now)
    if cd:
        return cd.reason.lower() if cd.reason else "cooling down"
    if used_today(db, provider, now) >= lim[provider]["per_day"]:
        return "daily limit reached"
    return None


def _skip_busy(db, now: datetime, active: set[str]) -> int:
    """Skip queued lookups whose rules opted out of waiting, for providers that are out of capacity."""
    lim = limits(db)
    skipped = 0
    providers = {p for (p,) in db.query(EnrichmentJob.provider).filter_by(status="queued", skip_when_busy=True).distinct()}
    for provider in providers:
        reason = unavailable_reason(db, provider, active, lim, now) if provider in PROVIDERS else "integration unavailable"
        if not reason:
            continue
        name = PROVIDERS[provider].name if provider in PROVIDERS else provider
        skipped += (
            db.query(EnrichmentJob)
            .filter_by(status="queued", provider=provider, skip_when_busy=True)
            .update({"status": "skipped", "finished_at": now, "error": f"Skipped: {name} {reason}"}, synchronize_session=False)
        )
    return skipped


def _claim(db, now: datetime) -> list[Claim]:
    keys = {i.provider: decrypt(i.api_key_enc) for i in active_integrations(db)}
    lim = limits(db)
    claims: list[Claim] = []
    for provider, key in keys.items():
        if cooldown_of(provider, now):
            continue
        budget = min(lim[provider]["per_minute"] - used_last_minute(provider), lim[provider]["per_day"] - used_today(db, provider, now))
        while budget > 0:
            jobs = (
                db.query(EnrichmentJob)
                .filter(EnrichmentJob.status == "queued", EnrichmentJob.provider == provider, EnrichmentJob.not_before <= now)
                .order_by(EnrichmentJob.created_at, EnrichmentJob.id)
                .limit(budget)
                .all()
            )
            if not jobs:
                break
            for job in jobs:
                obs = db.get(Observable, job.observable_id)
                row = next((e for e in obs.intel if e.provider == provider), None) if obs else None
                if obs is None or not PROVIDERS[provider].supports(obs.type, obs.sub_type):
                    job.status, job.finished_at = "skipped", now
                    job.error = "" if obs else "observable deleted"
                    continue
                if row and is_fresh(row.status, row.fetched_at, job.refresh_days, now):
                    job.status, job.finished_at = "skipped", now  # enriched since it was queued
                    continue
                job.status, job.last_attempt_at = "running", now
                _window[provider].append(time.monotonic())
                budget -= 1
                claims.append(Claim(job.id, provider, obs.id, obs.type, obs.value, key, job.rule_id, job.rule_name))
            db.flush()  # the session doesn't autoflush; the next batch must not see these jobs as queued
    return claims


def _store(db, claim: Claim, result, now: datetime) -> str:
    job = db.get(EnrichmentJob, claim.job_id)
    obs = db.get(Observable, claim.obs_id)
    if job is None or obs is None:
        return "dropped"  # deleted while the lookup was in flight
    status = getattr(result, "status", None) if isinstance(result, IntelError) else None
    if status in (429, 401, 403):
        if status == 429:
            cd, outcome = _start_cooldown(claim.provider, "Rate limit reached (429)"), "rate_limited"
        else:
            cd, outcome = _start_cooldown(claim.provider, "API key rejected", COOLDOWN_MAX), "key_rejected"
        if job.skip_when_busy:  # the rule would rather enrich with the other integrations than wait
            job.status, job.finished_at = "skipped", now
            job.error = f"Skipped: {PROVIDERS[claim.provider].name} {cd.reason.lower()}"
        else:
            job.status, job.not_before, job.error = "queued", cd.until, str(result)
        return outcome
    actor = actor_for(claim.rule_name)
    if isinstance(result, BaseException):
        job.attempts += 1
        job.error = str(result) if isinstance(result, IntelError) else repr(result)
        if job.attempts < MAX_ATTEMPTS:
            job.status, job.not_before = "queued", now + timedelta(minutes=2 ** job.attempts)
            return "retry"
        job.status, job.finished_at = "error", now
        row = next((e for e in obs.intel if e.provider == claim.provider), None)
        if not (row and row.status in FRESH_STATUSES):  # never replace a good result with an error
            apply_result(db, obs, claim.provider, result, actor)
        return "error"
    apply_result(db, obs, claim.provider, result, actor, rule_id=claim.rule_id, rule_name=claim.rule_name)
    job.status, job.finished_at, job.error = "done", now, ""
    _cooldowns.pop(claim.provider, None)
    return "done"


async def process_queue(max_wait_for_sync: float = 600) -> dict:
    """One worker tick. Returns counts by outcome (for tests and logs)."""
    from app.sync import engine

    if _tick.locked():
        return {"skipped": "busy"}
    async with _tick:
        if engine._lock.locked():
            return {"skipped": "sync running"}
        now = utcnow()
        with SessionLocal() as db:
            if get_setting(db, "enrichment_paused"):
                return {"skipped": "paused"}
            db.query(EnrichmentJob).filter(
                EnrichmentJob.status.in_(("done", "skipped", "error", "cancelled")),
                EnrichmentJob.created_at < now - timedelta(days=KEEP_FINISHED_DAYS),
            ).delete(synchronize_session=False)
            skipped = _skip_busy(db, now, {i.provider for i in active_integrations(db)})
            claims = _claim(db, now)
            db.commit()
        if skipped:
            log.info("Skipped %d lookup(s) for integrations out of capacity", skipped)
        if not claims:
            return {"skipped_busy": skipped} if skipped else {}

        sem = asyncio.Semaphore(CONCURRENCY)

        async def run(c: Claim):
            async with sem:
                return await lookup(c.api_key, c.provider, c.obs_type, c.value)

        results = await asyncio.gather(*(run(c) for c in claims))
        # Results are written only between syncs, so a running sync never works on stale observables.
        waited = 0.0
        while engine._lock.locked() and waited < max_wait_for_sync:
            await asyncio.sleep(1)
            waited += 1
        outcome: dict[str, int] = {"skipped_busy": skipped} if skipped else {}
        with SessionLocal() as db:
            now = utcnow()
            for c, r in zip(claims, results, strict=True):
                key = _store(db, c, r, now)
                outcome[key] = outcome.get(key, 0) + 1
            db.commit()
        log.info("Enrichment queue tick: %s", outcome)
        return outcome


def summary(db) -> dict:
    """Queue state for the UI: totals, per-provider usage and blockers, recent errors."""
    now = utcnow()
    midnight = _midnight(now)
    lim = limits(db)
    integrations = {i.provider: i for i in db.query(Integration).all()}
    by_status = dict(
        db.query(EnrichmentJob.status, func.count(EnrichmentJob.id)).group_by(EnrichmentJob.status).all()
    )
    queued_by_provider = dict(
        db.query(EnrichmentJob.provider, func.count(EnrichmentJob.id))
        .filter(EnrichmentJob.status.in_(("queued", "running")))
        .group_by(EnrichmentJob.provider)
        .all()
    )
    finished_today = {
        (p, s): n
        for p, s, n in db.query(EnrichmentJob.provider, EnrichmentJob.status, func.count(EnrichmentJob.id))
        .filter(EnrichmentJob.finished_at >= midnight)
        .group_by(EnrichmentJob.provider, EnrichmentJob.status)
        .all()
    }
    providers = []
    for p, prov in PROVIDERS.items():
        integ = integrations.get(p)
        cd = cooldown_of(p, now)
        blocked = None if integ and integ.enabled else ("Integration disabled" if integ else "Not connected")
        providers.append({
            "provider": p, "name": prov.name, "queued": queued_by_provider.get(p, 0),
            "used_today": used_today(db, p, now), "used_last_minute": used_last_minute(p),
            "done_today": finished_today.get((p, "done"), 0), "errors_today": finished_today.get((p, "error"), 0),
            "per_minute": lim[p]["per_minute"], "per_day": lim[p]["per_day"],
            "blocked": blocked, "cooldown_until": iso(cd.until) if cd else None,
            "cooldown_reason": cd.reason if cd else None,
        })
    errors = (
        db.query(EnrichmentJob, Observable.value)
        .join(Observable, Observable.id == EnrichmentJob.observable_id)
        .filter(EnrichmentJob.status == "error")
        .order_by(EnrichmentJob.finished_at.desc())
        .limit(20)
        .all()
    )
    return {
        "paused": bool(get_setting(db, "enrichment_paused")),
        "queued": by_status.get("queued", 0),
        "running": by_status.get("running", 0),
        "done_today": sum(n for (p, s), n in finished_today.items() if s == "done"),
        "errors_today": sum(n for (p, s), n in finished_today.items() if s == "error"),
        "skipped_today": sum(n for (p, s), n in finished_today.items() if s == "skipped"),
        "providers": providers,
        "recent_errors": [
            {"id": j.id, "provider": j.provider, "observable_id": j.observable_id, "value": value, "rule_name": j.rule_name,
             "error": j.error, "finished_at": iso(j.finished_at)}
            for j, value in errors
        ],
    }
