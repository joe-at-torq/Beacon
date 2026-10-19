from collections import Counter
from datetime import date, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session, aliased

from app.db import get_db
from app.intel.providers import PROVIDERS
from app.intel.service import INTEL_ENRICHED
from app.models import (AuditEvent, Feed, FeedLink, IntelEnrichment, Observable, ObservableEvent, ObservableLink, Rule, SyncRun, User,
                        Workspace, utcnow)
from app.security import get_active_user
from app.serializers import audit_out, iso, run_out
from app.sync.engine import origin_set, plan_push
from app.sync.rules import CENTRAL, node_id as _node_id, rule_edge_pairs as rule_edges
from app.torq.mapping import REPUTATIONS, TYPES

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

GROWTH_DAYS = 30


@router.get("")
def dashboard(db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    total = db.query(Observable).count()
    by_type = dict(db.query(Observable.type, func.count()).group_by(Observable.type).all())
    by_rep = dict(db.query(Observable.reputation, func.count()).group_by(Observable.reputation).all())
    malicious = sum(n for rep, n in by_rep.items() if REPUTATIONS.get(rep, ("", 0))[1] >= 8)
    suspicious = sum(n for rep, n in by_rep.items() if 5 <= REPUTATIONS.get(rep, ("", 0))[1] < 8)

    link_counts: dict[int, dict[str, int]] = {}
    for ws_id, relation, n in (
        db.query(ObservableLink.workspace_id, ObservableLink.relation, func.count())
        .group_by(ObservableLink.workspace_id, ObservableLink.relation)
        .all()
    ):
        link_counts.setdefault(ws_id, {})[relation] = n

    workspaces = db.query(Workspace).order_by(Workspace.priority, Workspace.name).all()

    # Daily new observables over the window plus a running total.
    start = (utcnow() - timedelta(days=GROWTH_DAYS - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    day_col = func.date(Observable.created_at)
    daily = dict(
        db.query(day_col, func.count()).filter(Observable.created_at >= start).group_by(day_col).all()
    )
    running = db.query(Observable).filter(Observable.created_at < start).count()
    growth = []
    for i in range(GROWTH_DAYS):
        day = (start + timedelta(days=i)).date().isoformat()
        added = daily.get(day, 0)
        running += added
        growth.append({"date": day, "added": added, "total": running})

    return {
        "totals": {
            "observables": total,
            "malicious": malicious,
            "suspicious": suspicious,
            "pinned": db.query(Observable).filter(Observable.pinned.is_(True)).count(),
            "workspaces": len(workspaces),
            "workspaces_healthy": sum(1 for ws in workspaces if ws.enabled and ws.last_sync_status == "ok"),
            "rules_active": db.query(Rule).filter(Rule.enabled.is_(True)).count(),
        },
        "by_type": [{"id": t, "label": TYPES[t][0], "count": by_type[t]} for t in TYPES if by_type.get(t)],
        "by_reputation": [
            {"id": r, "label": label, "severity": sev, "count": by_rep.get(r, 0)}
            for r, (label, sev) in REPUTATIONS.items()
            if r != "SCORE_OTHER" or by_rep.get(r)
        ],
        "workspaces": [
            {
                "id": ws.id,
                "name": ws.name,
                "region": ws.region,
                "enabled": ws.enabled,
                "status": ws.last_sync_status,
                "last_sync_at": iso(ws.last_sync_at),
                "last_error": ws.last_error,
                "origin_count": link_counts.get(ws.id, {}).get("origin", 0),
                "pushed_count": link_counts.get(ws.id, {}).get("pushed", 0),
            }
            for ws in workspaces
        ],
        "growth": growth,
        "recent_runs": [run_out(r) for r in db.query(SyncRun).order_by(SyncRun.id.desc()).limit(8).all()],
        "recent_activity": [
            audit_out(e)
            for e in db.query(AuditEvent).filter(AuditEvent.action != "login").order_by(AuditEvent.id.desc()).limit(12)
        ],
    }


# range -> (days back, bucket size); "all" picks its bucket from the data's span.
OBSERVED_RANGES: dict[str, tuple[int | None, str | None]] = {
    "7d": (7, "day"),
    "14d": (14, "day"),
    "30d": (30, "day"),
    "3m": (91, "day"),
    "6m": (182, "week"),
    "9m": (273, "week"),
    "12m": (365, "week"),
    "all": (None, None),
}
Bucket = Literal["day", "week", "month"]


def _floor(d: date, bucket: Bucket) -> date:
    if bucket == "week":
        return d - timedelta(days=d.weekday())  # Monday
    if bucket == "month":
        return d.replace(day=1)
    return d


def _next(d: date, bucket: Bucket) -> date:
    if bucket == "week":
        return d + timedelta(days=7)
    if bucket == "month":
        return date(d.year + (d.month == 12), d.month % 12 + 1, 1)
    return d + timedelta(days=1)


def _window(range: str, earliest, today: date) -> tuple[date, Bucket]:
    """Start (floored to the bucket) and bucket size for a range; "all" sizes the bucket to the data's span."""
    days, bucket = OBSERVED_RANGES[range]
    if days is None:
        first = earliest()
        start = first.date() if first else today
        span = (today - start).days
        bucket = "day" if span <= 120 else "week" if span <= 730 else "month"
    else:
        start = today - timedelta(days=days - 1)
    return _floor(start, bucket), bucket


def _periods(start: date, today: date, bucket: Bucket):
    d = start
    while d <= today:
        nxt = _next(d, bucket)
        yield d, (min(nxt, today + timedelta(days=1)) - timedelta(days=1))
        d = nxt


@router.get("/observed")
def observed_over_time(
    db: Session = Depends(get_db),
    _: User = Depends(get_active_user),
    range: Literal["7d", "14d", "30d", "3m", "6m", "9m", "12m", "all"] = Query("30d"),
):
    """Observables per period by when Torq first observed them, and by when they were last observed."""
    today = utcnow().date()
    start, bucket = _window(range, lambda: db.query(func.min(Observable.first_observed_at)).scalar(), today)
    since = datetime.combine(start, datetime.min.time())

    def counts(column) -> Counter:
        rows = db.query(column).filter(column.is_not(None), column >= since).all()
        return Counter(_floor(ts.date(), bucket) for (ts,) in rows)

    first, last = counts(Observable.first_observed_at), counts(Observable.last_observed_at)
    points = [
        {"start": d.isoformat(), "end": end.isoformat(), "first_observed": first.get(d, 0), "last_observed": last.get(d, 0)}
        for d, end in _periods(start, today, bucket)
    ]
    return {
        "range": range,
        "bucket": bucket,
        "start": start.isoformat(),
        "end": today.isoformat(),
        "points": points,
        "totals": {"first_observed": sum(first.values()), "last_observed": sum(last.values())},
        # Observables first observed before the range starts (baseline for a cumulative view).
        "first_observed_before": db.query(Observable)
        .filter(Observable.first_observed_at.is_not(None), Observable.first_observed_at < since)
        .count(),
        "undated": db.query(Observable).filter(Observable.first_observed_at.is_(None)).count(),
    }


@router.get("/flows")
def observable_flows(
    db: Session = Depends(get_db),
    _: User = Depends(get_active_user),
    type: list[str] = Query(default=[]),
):
    """Graph of how observables move between workspaces through Beacon, and which rules allow each direction."""
    workspaces = db.query(Workspace).order_by(Workspace.priority, Workspace.name).all()
    ws_ids = [ws.id for ws in workspaces]
    rules = db.query(Rule).order_by(Rule.order, Rule.id).all()

    def typed(q):
        return q.join(Observable, Observable.id == ObservableLink.observable_id).filter(Observable.type.in_(type)) if type else q

    # Native / synced-in counts per workspace.
    link_counts: dict[int, dict[str, int]] = {}
    for ws_id, relation, n in typed(
        db.query(ObservableLink.workspace_id, ObservableLink.relation, func.count(ObservableLink.id))
    ).group_by(ObservableLink.workspace_id, ObservableLink.relation):
        link_counts.setdefault(ws_id, {})[relation] = n

    edges: dict[tuple[str, str], dict] = {}

    def edge(src: str, tgt: str) -> dict:
        return edges.setdefault((src, tgt), {"source": src, "target": tgt, "count": 0, "pending_create": 0,
                                             "pending_update": 0, "rules": [], "allowed": False})

    # Traffic: observables native to S that Beacon synced into T.
    origin, pushed = aliased(ObservableLink), aliased(ObservableLink)
    q = (
        db.query(origin.workspace_id, pushed.workspace_id, func.count(func.distinct(pushed.observable_id)))
        .join(pushed, (pushed.observable_id == origin.observable_id) & (pushed.relation == "pushed"))
        .filter(origin.relation == "origin", origin.workspace_id != pushed.workspace_id)
    )
    if type:
        q = q.join(Observable, Observable.id == origin.observable_id).filter(Observable.type.in_(type))
    for src, tgt, n in q.group_by(origin.workspace_id, pushed.workspace_id):
        edge(f"ws:{src}", f"ws:{tgt}")["count"] = n
    # Manually created observables flow from central.
    mq = db.query(ObservableLink.workspace_id, func.count(ObservableLink.id)).join(
        Observable, Observable.id == ObservableLink.observable_id
    ).filter(Observable.origin == "manual", ObservableLink.relation == "pushed")
    if type:
        mq = mq.filter(Observable.type.in_(type))
    for tgt, n in mq.group_by(ObservableLink.workspace_id):
        edge(CENTRAL, f"ws:{tgt}")["count"] = n
    # Feeds: observables a feed brought into Beacon that were pushed to a workspace. Values that already
    # existed (and were synced by other rules) don't count as feed traffic, like central counts only manual ones.
    feeds = db.query(Feed).order_by(Feed.name).all()
    fq = (
        db.query(FeedLink.feed_id, ObservableLink.workspace_id, func.count(func.distinct(ObservableLink.observable_id)))
        .join(ObservableLink, (ObservableLink.observable_id == FeedLink.observable_id) & (ObservableLink.relation == "pushed"))
        .join(Observable, Observable.id == FeedLink.observable_id)
        .filter(FeedLink.active == True, Observable.origin == "feed")  # noqa: E712
    )
    if type:
        fq = fq.filter(Observable.type.in_(type))
    for feed_id, tgt, n in fq.group_by(FeedLink.feed_id, ObservableLink.workspace_id):
        edge(f"feed:{feed_id}", f"ws:{tgt}")["count"] = n
    lq = db.query(FeedLink.feed_id, func.count(func.distinct(FeedLink.observable_id))).filter(FeedLink.active == True)  # noqa: E712
    if type:
        lq = lq.join(Observable, Observable.id == FeedLink.observable_id).filter(Observable.type.in_(type))
    feed_listed = dict(lq.group_by(FeedLink.feed_id).all())

    # Rules: which directions each permits.
    rules_out = []
    for rule in rules:
        pairs = rule_edges(rule, ws_ids)
        for pair in pairs:
            e = edge(*pair)
            if rule.enabled:
                e["rules"].append(rule.id)
                e["allowed"] = True
        rules_out.append({
            "id": rule.id,
            "name": rule.name,
            "enabled": rule.enabled,
            "sync_updates": rule.sync_updates,
            "types": rule.types or [],
            "sub_types": rule.sub_types or [],
            "min_reputation": rule.min_reputation,
            "sources": rule.source_workspace_ids or [],
            "targets": rule.target_workspace_ids or [],
            "edges": [list(pair) for pair in pairs],
        })

    # Pending: what the next sync would push, attributed to allowed source -> target directions.
    observables = db.query(Observable)
    if type:
        observables = observables.filter(Observable.type.in_(type))
    enabled_ws = [ws for ws in workspaces if ws.enabled]
    for op in plan_push(observables.all(), rules, enabled_ws):
        tgt = f"ws:{op.workspace.id}"
        for src in origin_set(op.observable) - {str(op.workspace.id)}:
            key = (_node_id(src), tgt)
            if key in edges and edges[key]["allowed"]:
                edges[key]["pending_create" if op.kind == "create" else "pending_update"] += 1

    # Drop directions that neither carry traffic nor are permitted by any rule (enabled or not).
    edge_list = [e for e in edges.values() if e["count"] or e["allowed"] or any(
        [e["source"], e["target"]] in r["edges"] for r in rules_out)]

    nodes = []
    for ws in workspaces:
        nid = f"ws:{ws.id}"
        counts = link_counts.get(ws.id, {})
        nodes.append({
            "id": nid,
            "kind": "workspace",
            "workspace_id": ws.id,
            "name": ws.name,
            "region": ws.region,
            "enabled": ws.enabled,
            "status": ws.last_sync_status,
            "native": counts.get("origin", 0),
            "synced_in": counts.get("pushed", 0),
            "synced_out": sum(e["count"] for e in edge_list if e["source"] == nid),
            "pending_in": sum(e["pending_create"] + e["pending_update"] for e in edge_list if e["target"] == nid),
        })
    obs_q = db.query(Observable)
    if type:
        obs_q = obs_q.filter(Observable.type.in_(type))
    total = obs_q.count()
    manual = obs_q.filter(Observable.origin == "manual").count()
    nodes.append({"id": CENTRAL, "kind": "central", "name": "Beacon central", "total": total, "manual": manual,
                  "synced_out": sum(e["count"] for e in edge_list if e["source"] == CENTRAL)})
    for f in feeds:
        nid = f"feed:{f.id}"
        nodes.append({"id": nid, "kind": "feed", "feed_id": f.id, "feed_kind": f.kind, "list_type": f.list_type,
                      "name": f.name, "enabled": f.enabled,
                      "status": f.last_status, "listed": feed_listed.get(f.id, 0),
                      "synced_out": sum(e["count"] for e in edge_list if e["source"] == nid),
                      "pending_out": sum(e["pending_create"] + e["pending_update"] for e in edge_list if e["source"] == nid)})

    return {
        "nodes": nodes,
        "edges": edge_list,
        "spokes": [{"workspace_id": ws.id, "native": link_counts.get(ws.id, {}).get("origin", 0)} for ws in workspaces],
        "feed_spokes": [{"feed_id": f.id, "listed": feed_listed.get(f.id, 0)} for f in feeds],
        "rules": rules_out,
        "totals": {
            "observables": total,
            "synced": sum(e["count"] for e in edge_list),
            "pending": sum(e["pending_create"] + e["pending_update"] for e in edge_list),
        },
    }


@router.get("/enrichment")
def enrichment_over_time(
    db: Session = Depends(get_db),
    _: User = Depends(get_active_user),
    range: Literal["7d", "14d", "30d", "3m", "6m", "9m", "12m", "all"] = Query("30d"),
):
    """Threat-intel lookups done by the platform: per period and provider, automatic (rules) vs manual, coverage.

    Counts successful lookups (a result or "not found"), from each observable's history.
    """
    today = utcnow().date()
    start, bucket = _window(
        range,
        lambda: db.query(func.min(ObservableEvent.ts)).filter(ObservableEvent.kind == INTEL_ENRICHED).scalar(),
        today,
    )
    since = datetime.combine(start, datetime.min.time())
    rows = (
        db.query(ObservableEvent.ts, ObservableEvent.actor, ObservableEvent.observable_id, ObservableEvent.detail,
                 ObservableEvent.new_value)
        .filter(ObservableEvent.kind == INTEL_ENRICHED, ObservableEvent.ts >= since)
        .all()
    )
    per_period: dict[date, Counter] = {}
    providers, verdicts, observables = Counter(), Counter(), set()
    automatic = 0
    for ts, actor, obs_id, detail, verdict in rows:
        provider = (detail or {}).get("provider") or "unknown"
        period = per_period.setdefault(_floor(ts.date(), bucket), Counter())
        period[provider] += 1
        period["@automatic" if (actor or "").startswith("rule:") else "@manual"] += 1
        providers[provider] += 1
        verdicts["not_found" if (detail or {}).get("status") == "not_found" else (verdict or "unknown")] += 1
        observables.add(obs_id)
        automatic += (actor or "").startswith("rule:")
    enriched_total = (
        db.query(func.count(func.distinct(IntelEnrichment.observable_id)))
        .filter(IntelEnrichment.status.in_(("ok", "not_found")))
        .scalar()
        or 0
    )
    return {
        "range": range,
        "bucket": bucket,
        "start": start.isoformat(),
        "end": today.isoformat(),
        "points": [
            {"start": d.isoformat(), "end": end.isoformat(),
             "total": per_period.get(d, Counter())["@automatic"] + per_period.get(d, Counter())["@manual"],
             "automatic": per_period.get(d, Counter())["@automatic"], "manual": per_period.get(d, Counter())["@manual"],
             "providers": {p: n for p, n in per_period.get(d, Counter()).items() if not p.startswith("@")}}
            for d, end in _periods(start, today, bucket)
        ],
        "totals": {
            "lookups": len(rows),
            "automatic": automatic,
            "manual": len(rows) - automatic,
            "observables": len(observables),
        },
        "providers": [{"provider": p, "name": PROVIDERS[p].name if p in PROVIDERS else p, "lookups": n}
                      for p, n in providers.most_common()],
        "verdicts": dict(verdicts),
        "coverage": {"enriched": enriched_total, "observables": db.query(Observable).count()},
        "failing_now": db.query(IntelEnrichment).filter(IntelEnrichment.status == "error").count(),
    }
