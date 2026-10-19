"""Rule-driven enrichment: match observables to enrichment rules and queue provider lookups.

Rules fire for observables that are new to the central database; "Run on existing matches" queues the
current matches on demand. Lookups are worked off by the rate-limited queue in app.intel.queue.
"""

import math
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.intel.providers import PROVIDERS
from app.intel.service import active_integrations
from app.models import EnrichmentJob, EnrichmentRule, IntelEnrichment, Observable, utcnow
from app.settings_store import DEFAULTS, get_setting

PENDING = ("queued", "running")
FRESH_STATUSES = ("ok", "not_found")
CHUNK = 800  # stay well under SQLite's bound-parameter limit


def limits(db: Session) -> dict[str, dict[str, int]]:
    """Per-provider pacing: stored overrides on top of the defaults."""
    stored = get_setting(db, "enrichment_limits") or {}
    out: dict[str, dict[str, int]] = {}
    for p in PROVIDERS:
        lim = dict(DEFAULTS["enrichment_limits"].get(p, {"per_minute": 10, "per_day": 1000}))
        for k, v in (stored.get(p) or {}).items():
            if k in ("per_minute", "per_day"):
                lim[k] = max(1, int(v))
        out[p] = lim
    return out


def rule_matches(rule, obs) -> bool:
    if obs.type != rule.type:
        return False
    if rule.sub_types and obs.sub_type not in rule.sub_types:
        return False
    if rule.reputations and obs.reputation not in rule.reputations:
        return False
    return True


def _window_rank(days: int) -> float:
    """Order refresh windows from shortest (0 = always) to longest (-1 = never re-enrich)."""
    return math.inf if days < 0 else days


def providers_for(rules: Iterable, obs, active: set[str]) -> dict[str, tuple[int, object, bool]]:
    """Provider -> (refresh window, rule, skip when busy) across all matching rules.

    The shortest window wins; a busy provider is only skipped when every rule asking for it allows that.
    """
    out: dict[str, tuple[int, object, bool]] = {}
    for rule in rules:
        if not rule.enabled or not rule_matches(rule, obs):
            continue
        skip = bool(getattr(rule, "skip_when_busy", False))
        for p in rule.providers:
            if p not in active or p not in PROVIDERS or not PROVIDERS[p].supports(obs.type, obs.sub_type):
                continue
            if p not in out:
                out[p] = (rule.refresh_days, rule, skip)
                continue
            days, best, skip_all = out[p]
            if _window_rank(rule.refresh_days) < _window_rank(days):
                days, best = rule.refresh_days, rule
            out[p] = (days, best, skip_all and skip)
    return out


def is_fresh(status: str | None, fetched_at: datetime | None, refresh_days: int, now: datetime | None = None) -> bool:
    """Whether an existing result makes a new lookup unnecessary. Error rows never count."""
    if status not in FRESH_STATUSES or fetched_at is None:
        return False
    if refresh_days < 0:
        return True
    if refresh_days == 0:
        return False
    return fetched_at >= (now or utcnow()) - timedelta(days=refresh_days)


def _chunks(ids: list[int]):
    for i in range(0, len(ids), CHUNK):
        yield ids[i : i + CHUNK]


def _existing_results(db: Session, obs_ids: list[int]) -> dict[tuple[int, str], tuple[str, datetime]]:
    out = {}
    for chunk in _chunks(obs_ids):
        rows = db.execute(
            select(IntelEnrichment.observable_id, IntelEnrichment.provider, IntelEnrichment.status, IntelEnrichment.fetched_at)
            .where(IntelEnrichment.observable_id.in_(chunk))
        )
        for oid, p, status, fetched in rows:
            out[(oid, p)] = (status, fetched)
    return out


def _pending_pairs(db: Session, obs_ids: list[int]) -> set[tuple[int, str]]:
    out = set()
    for chunk in _chunks(obs_ids):
        rows = db.execute(
            select(EnrichmentJob.observable_id, EnrichmentJob.provider)
            .where(EnrichmentJob.observable_id.in_(chunk), EnrichmentJob.status.in_(PENDING))
        )
        out.update((oid, p) for oid, p in rows)
    return out


def plan_jobs(db: Session, observables: list[Observable], rules: list | None = None) -> list[dict]:
    """The lookups rules would queue for these observables (skipping fresh results and pending jobs)."""
    if rules is None:
        rules = db.query(EnrichmentRule).filter_by(enabled=True).all()
    rules = [r for r in rules if r.enabled]
    if not rules or not observables:
        return []
    active = {i.provider for i in active_integrations(db)}
    wanted = []
    for obs in observables:
        for p, (days, rule, skip) in providers_for(rules, obs, active).items():
            wanted.append((obs, p, days, rule, skip))
    if not wanted:
        return []
    ids = sorted({o.id for o, *_ in wanted})
    existing = _existing_results(db, ids)
    pending = _pending_pairs(db, ids)
    now = utcnow()
    jobs = []
    for obs, p, days, rule, skip in wanted:
        if (obs.id, p) in pending:
            continue
        status, fetched = existing.get((obs.id, p), (None, None))
        if is_fresh(status, fetched, days, now):
            continue
        jobs.append({"obs": obs, "provider": p, "refresh_days": days, "rule": rule, "skip_when_busy": skip})
    return jobs


def enqueue(db: Session, observables: list[Observable], reason: str, rules: list | None = None, cap: int = 10_000) -> dict[str, int]:
    """Queue lookups for matching observables. Returns jobs queued per provider. The caller commits."""
    counts: dict[str, int] = {}
    for job in plan_jobs(db, observables, rules)[:cap]:
        rule = job["rule"]
        db.add(EnrichmentJob(
            observable_id=job["obs"].id, provider=job["provider"], rule_id=getattr(rule, "id", None),
            rule_name=(rule.name or "")[:64], refresh_days=job["refresh_days"], skip_when_busy=job["skip_when_busy"],
            reason=reason,
        ))
        counts[job["provider"]] = counts.get(job["provider"], 0) + 1
    return counts


def matching_observables(db: Session, rule) -> list[Observable]:
    q = db.query(Observable).filter(Observable.type == rule.type)
    if rule.sub_types:
        q = q.filter(Observable.sub_type.in_(rule.sub_types))
    if rule.reputations:
        q = q.filter(Observable.reputation.in_(rule.reputations))
    return q.all()


def eta_seconds(jobs: int, per_minute: int, per_day: int) -> int:
    """Rough time to work off this many lookups at the provider's pace."""
    if jobs <= 0:
        return 0
    if jobs <= per_day:
        return int(jobs / per_minute * 60)
    full_days = jobs // per_day
    rest = jobs - full_days * per_day
    return int(full_days * 86400 + rest / per_minute * 60)


def preview(db: Session, rule, cap: int = 10_000) -> dict:
    """What a (draft) rule matches today and what "Run on existing matches" would queue."""
    draft = SimpleNamespace(
        id=getattr(rule, "id", None), name=rule.name, enabled=True, type=rule.type, sub_types=list(rule.sub_types or []),
        reputations=list(rule.reputations or []), providers=list(rule.providers or []), refresh_days=rule.refresh_days,
        skip_when_busy=bool(getattr(rule, "skip_when_busy", False)),
    )
    matches = matching_observables(db, draft)
    jobs = plan_jobs(db, matches, [draft])
    lim = limits(db)
    per_provider: dict[str, int] = {}
    for j in jobs[:cap]:
        per_provider[j["provider"]] = per_provider.get(j["provider"], 0) + 1
    return {
        "matching": len(matches),
        "jobs": sum(per_provider.values()),
        "capped": len(jobs) > cap,
        "providers": [
            {"provider": p, "jobs": n, "eta_seconds": eta_seconds(n, lim[p]["per_minute"], lim[p]["per_day"])}
            for p, n in sorted(per_provider.items(), key=lambda kv: -kv[1])
        ],
    }
