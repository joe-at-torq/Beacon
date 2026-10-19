"""Pull → merge → push synchronisation pipeline."""

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from app import history
from app.db import SessionLocal
from app.intel.enrichment_rules import enqueue as enqueue_enrichment
from app.intel.queue import wake as wake_enrichment_queue
from sqlalchemy import delete, func, insert, select, update

from app.models import Observable, ObservableLink, Rule, SyncApiCall, SyncRun, Tombstone, Workspace, utcnow
from app.security import decrypt
from app.settings_store import get_setting
from app.sync.collision import Candidate, resolve
from app.sync.rules import CENTRAL, evaluate, node_id, rule_edge_pairs
from app.torq.client import Recorder, TorqClient, TorqError
from app.torq.mapping import RemoteObservable, build_payload, normalize_value, parse_remote


log = logging.getLogger("tim.sync")

PULL_CONCURRENCY = 4
PUSH_CONCURRENCY = 8
MAX_ERRORS_LOGGED = 50
# API call log: failed calls are always kept; successful ones up to this many per run.
MAX_STORED_SUCCESS_CALLS = 2000
# API call details are kept for this many most recent runs.
API_CALL_RETENTION_RUNS = 100

ClientFactory = Callable[[Workspace, Recorder | None], TorqClient]


def default_client_factory(ws: Workspace, recorder: Recorder | None = None) -> TorqClient:
    return TorqClient(ws.region, ws.client_id, decrypt(ws.client_secret_enc), recorder=recorder)


def is_failed_call(call: dict) -> bool:
    return bool(call.get("error")) or (call.get("status_code") or 0) >= 400


def _store_api_calls(db: Session, run: SyncRun, calls: list[dict], stats: "RunStats") -> None:
    run.api_calls = len(calls)
    run.api_errors = sum(1 for c in calls if is_failed_call(c))
    kept, dropped = [], 0
    successes = 0
    for c in calls:
        if not is_failed_call(c):
            successes += 1
            if successes > MAX_STORED_SUCCESS_CALLS:
                dropped += 1
                continue
        kept.append({**c, "run_id": run.id})
    if dropped:
        stats.error(f"API call log: {dropped} successful call(s) not stored (limit {MAX_STORED_SUCCESS_CALLS} per run)")
    if kept:
        db.execute(insert(SyncApiCall), kept)
    keep_ids = select(SyncRun.id).order_by(SyncRun.id.desc()).limit(API_CALL_RETENTION_RUNS)
    db.execute(delete(SyncApiCall).where(SyncApiCall.run_id.not_in(keep_ids)))


class SyncAlreadyRunning(Exception):
    pass


@dataclass
class SyncState:
    running: bool = False
    run_id: int | None = None
    phase: str = "idle"
    detail: str = ""
    started_at: str | None = None
    # Live progress for the UI while running:
    #   workspaces: {"<id>": {name, pull: pending|running|done|error, pulled, push_total, push_done, push_failed}}
    #   edges: {"<src>><tgt>": {source, target, total, done}}   (push phase, attributed like the flow graph)
    live: dict = field(default_factory=dict)


state = SyncState()
_lock = asyncio.Lock()


@dataclass
class PushOp:
    kind: str  # create | update
    observable: Observable
    workspace: Workspace
    link: ObservableLink | None = None
    reputation: str | None = None
    description: str | None = None


@dataclass
class RunStats:
    pulled: int = 0
    created_central: int = 0
    updated_central: int = 0
    conflicts: int = 0
    pushed_created: int = 0
    pushed_updated: int = 0
    errors: list[str] = field(default_factory=list)

    def error(self, msg: str) -> None:
        log.warning(msg)
        if len(self.errors) < MAX_ERRORS_LOGGED:
            self.errors.append(msg)


def origin_set(obs: Observable) -> set[str]:
    """Sources an observable's current value may flow from: the workspaces it was originally seen in, the
    workspace whose change produced the current central value, and "central" for manual/edited ones."""
    origins = {str(link.workspace_id) for link in obs.links if link.relation == "origin"}
    if obs.value_source and not obs.value_source.startswith("feed:"):
        origins.add(obs.value_source)
    if obs.origin == "manual" or obs.pinned:
        origins.add(CENTRAL)
    # Feeds count only while they still list the observable (expired/revoked/removed indicators don't).
    origins.update(f"feed:{link.feed_id}" for link in obs.feed_sources)
    return origins


@dataclass
class PullChanges:
    """What the pull phase saw, used to decide which observables need their central value revisited."""

    # observable id -> [(link, reputation_changed, description_changed)] for copies whose value changed
    changed: dict[int, list[tuple[ObservableLink, bool, bool]]] = field(default_factory=dict)
    # observables that appeared in a workspace for the first time (new central or newly seen copy)
    discovered: set[int] = field(default_factory=set)
    # observables that are new to the central database (drives enrichment rules)
    created: set[int] = field(default_factory=set)


def plan_push(
    observables: list[Observable], rules: list[Rule], targets: list[Workspace]
) -> list[PushOp]:
    """Compute the remote operations required to bring targets in line with the central database."""
    ops: list[PushOp] = []
    active_rules = [r for r in sorted(rules, key=lambda r: (r.order, r.id or 0)) if r.enabled]
    if not active_rules or not targets:
        return ops
    for obs in observables:
        origins = origin_set(obs)
        if not origins:
            continue
        links = {link.workspace_id: link for link in obs.links}
        for ws in targets:
            decision = evaluate(active_rules, origins, ws.id, obs)
            if decision is None:
                continue
            link = links.get(ws.id)
            if link is None:
                ops.append(PushOp("create", obs, ws))
            elif decision:
                rep = obs.reputation if link.remote_reputation != obs.reputation else None
                desc = obs.description if (link.remote_description or "") != (obs.description or "") else None
                if rep is not None or desc is not None:
                    ops.append(PushOp("update", obs, ws, link, rep, desc))
    return ops


def merge_observable(
    obs: Observable,
    priorities: dict[int, int],
    strategy: str,
    description_merge: str,
    *,
    ws_names: dict[int, str] | None = None,
    run_id: int | None = None,
    actor: str = "sync",
    cause: str = "merge",
    include_current: bool = False,
) -> tuple[bool, bool]:
    """Apply the collision strategy across the observable's original workspace copies (plus, with
    include_current, the current central value as prior knowledge). Records changes. Returns (changed, conflict)."""
    if obs.pinned:
        return False, False
    candidates = [
        Candidate(
            workspace_id=link.workspace_id,
            priority=priorities.get(link.workspace_id, 1000),
            reputation=link.remote_reputation,
            description=link.remote_description,
            updated_at=link.remote_updated_at,
        )
        for link in obs.links
        if link.relation == "origin"
    ]
    if include_current and candidates:
        source = int(obs.value_source) if (obs.value_source or "").isdigit() else 0
        candidates.append(
            Candidate(
                workspace_id=source,
                priority=priorities.get(source, 1000),
                reputation=obs.reputation,
                description=obs.description or "",
                updated_at=obs.updated_at,
            )
        )
    res = resolve(candidates, strategy, description_merge)
    if res is None:
        return False, False
    changed = obs.reputation != res.reputation or (obs.description or "") != res.description
    if changed:
        old_rep, old_desc = obs.reputation, obs.description or ""
        obs.reputation = res.reputation
        obs.description = res.description
        obs.updated_at = utcnow()
        winner = res.winner_workspace_id
        if winner:
            obs.value_source = str(winner)
        history.record_value_changes(
            obs, old_rep, old_desc, actor=actor, run_id=run_id,
            workspace_id=winner, workspace_name=(ws_names or {}).get(winner, "") if winner else "",
            cause=cause, strategy=strategy, sources=len(candidates),
        )
    return changed, res.conflict


def recompute_case_counts(db: Session) -> None:
    """Set each observable's associated_cases_count to the sum over its workspace copies."""
    db.execute(
        update(Observable).values(
            associated_cases_count=select(func.coalesce(func.sum(ObservableLink.remote_cases_count), 0))
            .where(ObservableLink.observable_id == Observable.id)
            .scalar_subquery()
        )
    )
    # Bulk UPDATE bypasses the identity map; refresh loaded objects lazily.
    db.expire_all()


def adopt_workspace_changes(
    obs: Observable,
    changes: list[tuple[ObservableLink, bool, bool]],
    priorities: dict[int, int],
    strategy: str,
    ws_names: dict[int, str],
    run_id: int | None = None,
) -> bool:
    """A value changed in a workspace is a new verdict: central adopts it (the collision strategy only
    breaks ties when several workspaces changed the same field in one sync). Returns whether central changed."""
    if obs.pinned:
        return False
    changed = False
    for field_name, picked in (("reputation", [c for c in changes if c[1]]), ("description", [c for c in changes if c[2]])):
        if not picked:
            continue
        cands = [
            Candidate(link.workspace_id, priorities.get(link.workspace_id, 1000), link.remote_reputation,
                      link.remote_description or "", link.remote_updated_at)
            for link, *_ in picked
        ]
        res = resolve(cands, strategy, "winner")
        new = res.reputation if field_name == "reputation" else res.description
        old = obs.reputation if field_name == "reputation" else (obs.description or "")
        if new == old:
            continue
        winner = res.winner_workspace_id
        setattr(obs, field_name, new)
        obs.value_source = str(winner)
        obs.updated_at = utcnow()
        changed = True
        history.record(
            obs, history.REPUTATION_CHANGED if field_name == "reputation" else history.DESCRIPTION_CHANGED,
            field=field_name, old=old, new=new, run_id=run_id, workspace_id=winner,
            workspace_name=ws_names.get(winner, ""), cause="workspace_change",
        )
    return changed


async def _fetch_all(client: TorqClient, on_progress: Callable[[int], None] | None = None) -> list[RemoteObservable]:
    out = []
    async for raw in client.iter_observables():
        parsed = parse_remote(raw)
        if parsed:
            out.append(parsed)
            if on_progress and len(out) % 100 == 0:
                on_progress(len(out))
    if on_progress:
        on_progress(len(out))
    return out


def _live_ws(ws_id: int) -> dict:
    return state.live.setdefault("workspaces", {}).setdefault(str(ws_id), {})


def _plan_live_push(ops: list["PushOp"], rules: list[Rule], ws_ids: list[int]) -> dict[int, list[str]]:
    """Seed push progress per target workspace and per direction; returns op index -> direction keys."""
    allowed = {pair for rule in rules if rule.enabled for pair in rule_edge_pairs(rule, ws_ids)}
    edges = state.live.setdefault("edges", {})
    keys_by_op: dict[int, list[str]] = {}
    for i, op in enumerate(ops):
        _live_ws(op.workspace.id)["push_total"] = _live_ws(op.workspace.id).get("push_total", 0) + 1
        target = f"ws:{op.workspace.id}"
        keys = []
        for src in origin_set(op.observable) - {str(op.workspace.id)}:
            pair = (node_id(src), target)
            if pair in allowed:
                key = f"{pair[0]}>{pair[1]}"
                edges.setdefault(key, {"source": pair[0], "target": pair[1], "total": 0, "done": 0})["total"] += 1
                keys.append(key)
        keys_by_op[i] = keys
    return keys_by_op


def _apply_pull(
    db: Session,
    ws: Workspace,
    remotes: list[RemoteObservable],
    index: dict[tuple[str, str], Observable],
    tombstones: set[tuple[str, str]],
    stats: RunStats,
    run_id: int | None = None,
    changes: PullChanges | None = None,
) -> None:
    changes = changes if changes is not None else PullChanges()
    now = utcnow()
    ev = {"workspace_id": ws.id, "workspace_name": ws.name, "run_id": run_id}
    existing = {link.remote_id: link for link in db.query(ObservableLink).filter_by(workspace_id=ws.id)}
    linked_obs_ids = {link.observable_id for link in existing.values()}
    seen: set[str] = set()

    for r in remotes:
        key = (r.type, normalize_value(r.type, r.value))
        if key in tombstones:
            continue
        stats.pulled += 1
        link = existing.get(r.remote_id)
        new_link = link is None
        if not new_link:
            obs = link.observable
        else:
            obs = index.get(key)
            if obs is None:
                obs = Observable(
                    type=r.type,
                    sub_type=r.sub_type,
                    value=r.value.strip(),
                    value_norm=key[1],
                    reputation=r.reputation,
                    description=r.description,
                    first_observed_at=r.first_observed_at,
                    last_observed_at=r.last_observed_at,
                    origin="workspace",
                    value_source=str(ws.id),
                    links=[],
                )
                db.add(obs)
                db.flush()
                index[key] = obs
                changes.created.add(obs.id)
                stats.created_central += 1
                history.record(obs, history.CREATED, new=r.reputation, origin="workspace",
                               remote_id=r.remote_id, **ev)
            elif obs.id in linked_obs_ids:
                # Duplicate of an observable already linked in this workspace.
                continue
            else:
                history.record(obs, history.SEEN_IN_WORKSPACE, new=r.reputation, remote_id=r.remote_id, **ev)
            link = ObservableLink(observable=obs, workspace_id=ws.id, remote_id=r.remote_id, relation="origin")
            db.add(link)
            existing[r.remote_id] = link
            linked_obs_ids.add(obs.id)
            changes.discovered.add(obs.id)
        if not new_link:
            rep_changed = link.remote_reputation != r.reputation
            desc_changed = (link.remote_description or "").strip() != (r.description or "").strip()
            if rep_changed:
                history.record(obs, history.WORKSPACE_REPUTATION_CHANGED, field="reputation",
                               old=link.remote_reputation, new=r.reputation, relation=link.relation,
                               pinned=obs.pinned, **ev)
            if rep_changed or desc_changed:
                changes.changed.setdefault(obs.id, []).append((link, rep_changed, desc_changed))

        had_enrichment, old_enriched_at = bool(link.has_enrichment), link.remote_enrichment_updated_at
        if r.enrichment is not None and not had_enrichment:
            history.record(obs, history.ENRICHMENT_ADDED, new=_iso(r.enrichment_updated_at), **ev)
        elif r.enrichment is None and had_enrichment:
            history.record(obs, history.ENRICHMENT_REMOVED, old=_iso(old_enriched_at), **ev)
        elif r.enrichment is not None and old_enriched_at != r.enrichment_updated_at:
            history.record(obs, history.ENRICHMENT_UPDATED, old=_iso(old_enriched_at),
                           new=_iso(r.enrichment_updated_at), **ev)

        link.remote_cases_count = r.cases_count
        link.remote_reputation = r.reputation
        link.remote_description = r.description
        link.remote_updated_at = r.updated_at
        link.last_synced_at = now
        if r.enrichment is not None or link.has_enrichment:
            link.remote_enrichment = r.enrichment
        link.has_enrichment = r.enrichment is not None
        link.remote_enrichment_updated_at = r.enrichment_updated_at
        seen.add(r.remote_id)

        if obs.sub_type == "SUB_TYPE_ID_UNKNOWN" and r.sub_type != "SUB_TYPE_ID_UNKNOWN":
            obs.sub_type = r.sub_type
        if r.first_observed_at and (obs.first_observed_at is None or r.first_observed_at < obs.first_observed_at):
            obs.first_observed_at = r.first_observed_at
        if r.last_observed_at and (obs.last_observed_at is None or r.last_observed_at > obs.last_observed_at):
            obs.last_observed_at = r.last_observed_at

    # Remote observables that disappeared from the workspace lose their link.
    # Removing from the parent collection (delete-orphan) keeps in-memory obs.links consistent.
    for remote_id, link in list(existing.items()):
        if remote_id not in seen:
            history.record(link.observable, history.REMOVED_FROM_WORKSPACE, relation=link.relation,
                           remote_id=remote_id, reason="no longer present in workspace", **ev)
            link.observable.links.remove(link)
    db.flush()


def _iso(ts) -> str | None:
    return ts.isoformat() + "Z" if ts else None


async def _execute_push(
    ops: list[PushOp],
    clients: dict[int, TorqClient],
    stats: RunStats,
    db: Session,
    run_id: int | None = None,
    on_done: Callable[[int, bool], None] | None = None,
) -> None:
    sem = asyncio.Semaphore(PUSH_CONCURRENCY)
    now = utcnow()

    async def run(i: int, op: PushOp):
        async with sem:
            client = clients[op.workspace.id]
            obs = op.observable
            try:
                if op.kind == "create":
                    payload = build_payload(obs.type, obs.sub_type, obs.value, obs.reputation, obs.description)
                    result = await client.create_observable(payload)
                else:
                    result = await client.update_observable(op.link.remote_id, op.reputation, op.description)
            except Exception:
                if on_done:
                    on_done(i, False)
                raise
            if on_done:
                on_done(i, True)
            return result

    results = await asyncio.gather(*(run(i, op) for i, op in enumerate(ops)), return_exceptions=True)
    for op, result in zip(ops, results, strict=True):
        label = f"{op.workspace.name}: {op.kind} {op.observable.value}"
        if isinstance(result, BaseException):
            stats.error(f"{label} failed: {result}")
            continue
        if op.kind == "create":
            remote_id = result.get("id") if isinstance(result, dict) else None
            if remote_id is None:
                stats.error(f"{label} returned no id")
                continue
            clash = db.query(ObservableLink).filter_by(workspace_id=op.workspace.id, remote_id=str(remote_id)).first()
            if clash is not None:
                # Torq returned an existing observable; keep the original link.
                continue
            db.add(
                ObservableLink(
                    observable=op.observable,
                    workspace_id=op.workspace.id,
                    remote_id=str(remote_id),
                    remote_reputation=op.observable.reputation,
                    remote_description=op.observable.description or "",
                    remote_updated_at=now,
                    relation="pushed",
                    last_synced_at=now,
                )
            )
            history.record(op.observable, history.PUSHED_TO_WORKSPACE, workspace_id=op.workspace.id,
                           workspace_name=op.workspace.name, run_id=run_id, new=op.observable.reputation,
                           remote_id=str(remote_id))
            stats.pushed_created += 1
        else:
            changes = {}
            if op.reputation is not None:
                changes["reputation"] = {"old": op.link.remote_reputation, "new": op.reputation}
            if op.description is not None:
                changes["description"] = {"old": op.link.remote_description or "", "new": op.description}
            history.record(op.observable, history.UPDATED_IN_WORKSPACE, workspace_id=op.workspace.id,
                           workspace_name=op.workspace.name, run_id=run_id,
                           field=",".join(changes), old=changes.get("reputation", {}).get("old"),
                           new=changes.get("reputation", {}).get("new"), changes=changes)
            if op.reputation is not None:
                op.link.remote_reputation = op.reputation
            if op.description is not None:
                op.link.remote_description = op.description
            op.link.remote_updated_at = now
            op.link.last_synced_at = now
            stats.pushed_updated += 1
    db.flush()


async def run_sync(
    trigger: str = "manual",
    triggered_by: str = "",
    workspace_id: int | None = None,
    client_factory: ClientFactory = default_client_factory,
    run_id: int | None = None,
) -> int:
    """Run a sync. With run_id, use that pre-created SyncRun row (so callers can return its id immediately)."""
    if _lock.locked():
        raise SyncAlreadyRunning()
    async with _lock:
        db = SessionLocal()
        db.info["sync_run"] = True  # this run pushes its own changes; they don't need a priority sync
        stats = RunStats()
        run = db.get(SyncRun, run_id) if run_id is not None else None
        if run is None:
            run = SyncRun(trigger=trigger, triggered_by=triggered_by, workspace_id=workspace_id)
            db.add(run)
            db.commit()
        state.running, state.run_id, state.started_at = True, run.id, run.started_at.isoformat() + "Z"
        clients: dict[int, TorqClient] = {}
        calls: list[dict] = []

        def recorder_for(ws: Workspace) -> Recorder:
            ws_id, ws_name = ws.id, ws.name
            return lambda call: calls.append({**call, "workspace_id": ws_id, "workspace_name": ws_name})

        try:
            query = db.query(Workspace).filter_by(enabled=True)
            if workspace_id is not None:
                query = query.filter(Workspace.id == workspace_id)
            workspaces = query.all()
            state.live = {"workspaces": {}, "edges": {}}
            for ws in workspaces:
                _live_ws(ws.id).update(name=ws.name, pull="pending", pulled=0, push_total=0, push_done=0, push_failed=0)
                try:
                    clients[ws.id] = client_factory(ws, recorder_for(ws))
                except Exception as e:  # e.g. undecryptable secret
                    stats.error(f"{ws.name}: cannot create client: {e}")
                    _live_ws(ws.id)["pull"] = "error"

            # ---- Pull ------------------------------------------------------------------------
            state.phase, state.detail = "pull", f"Pulling from {len(clients)} workspace(s)"
            sem = asyncio.Semaphore(PULL_CONCURRENCY)

            async def fetch(ws: Workspace):
                async with sem:
                    live = _live_ws(ws.id)
                    live["pull"] = "running"
                    try:
                        result = await _fetch_all(clients[ws.id], lambda n: live.__setitem__("pulled", n))
                    except Exception:
                        live["pull"] = "error"
                        raise
                    live["pull"] = "done"
                    return result

            pull_targets = [ws for ws in workspaces if ws.id in clients]
            fetched = await asyncio.gather(*(fetch(ws) for ws in pull_targets), return_exceptions=True)

            index = {(o.type, o.value_norm): o for o in db.query(Observable).all()}
            tombstones = {(t.type, t.value_norm) for t in db.query(Tombstone).all()}
            healthy: list[Workspace] = []
            pull_changes = PullChanges()
            now = utcnow()
            for ws, result in zip(pull_targets, fetched, strict=True):
                ws.last_sync_at = now
                if isinstance(result, BaseException):
                    msg = str(result) if isinstance(result, TorqError) else repr(result)
                    if isinstance(result, TorqError) and result.status == 403:
                        msg += " " + await clients[ws.id].diagnose_forbidden()
                    stats.error(f"{ws.name}: pull failed: {msg}")
                    ws.last_sync_status, ws.last_error = "error", msg[:1000]
                    continue
                _apply_pull(db, ws, result, index, tombstones, stats, run.id, pull_changes)
                ws.last_sync_status, ws.last_error = "ok", None
                healthy.append(ws)
            for ws in workspaces:
                if ws.id not in clients:
                    ws.last_sync_at, ws.last_sync_status, ws.last_error = now, "error", "Invalid credentials"
            db.flush()
            recompute_case_counts(db)
            db.commit()

            # ---- Merge -----------------------------------------------------------------------
            state.phase, state.detail = "merge", "Resolving collisions"
            strategy = get_setting(db, "collision_strategy")
            description_merge = get_setting(db, "description_merge")
            all_ws = db.query(Workspace).all()
            priorities = {ws.id: ws.priority for ws in all_ws}
            ws_names = {ws.id: ws.name for ws in all_ws}
            observables = db.query(Observable).all()
            for obs in observables:
                if obs.id in pull_changes.changed:
                    # Values edited in a workspace win: they are new verdicts, not a collision.
                    changed = adopt_workspace_changes(obs, pull_changes.changed[obs.id], priorities, strategy,
                                                      ws_names, run.id)
                    conflict = False
                elif obs.id in pull_changes.discovered:
                    # Newly seen copies may disagree with what we know: resolve with the collision strategy.
                    changed, conflict = merge_observable(obs, priorities, strategy, description_merge,
                                                         ws_names=ws_names, run_id=run.id, include_current=True)
                else:
                    continue
                stats.updated_central += int(changed)
                stats.conflicts += int(conflict)
            if pull_changes.created:
                # Enrichment rules match on the merged reputation; the jobs commit with the merge.
                try:
                    with db.begin_nested():
                        queued = enqueue_enrichment(db, [o for o in observables if o.id in pull_changes.created], "new")
                    if queued:
                        log.info("Queued %d enrichment lookup(s) for new observables", sum(queued.values()))
                except Exception:
                    log.exception("Enrichment rules failed; continuing the sync")
            db.commit()

            # ---- Push ------------------------------------------------------------------------
            # Only push to workspaces whose state we just refreshed, to avoid creating duplicates.
            rules = db.query(Rule).all()
            ops = plan_push(observables, rules, healthy)
            cap = int(get_setting(db, "max_pushes_per_run") or 0)
            if cap and len(ops) > cap:
                # Updates keep existing copies accurate, so they go first; remaining creates follow next run.
                ops = sorted(ops, key=lambda op: op.kind != "update")
                stats.error(f"Push capped at {cap:,} of {len(ops):,} change(s); the rest follow in the next sync")
                ops = ops[:cap]
            state.phase, state.detail = "push", f"Applying {len(ops)} change(s)"
            if ops:
                keys_by_op = _plan_live_push(ops, rules, [ws.id for ws in all_ws])

                def push_done(i: int, ok: bool) -> None:
                    live = _live_ws(ops[i].workspace.id)
                    live["push_done" if ok else "push_failed"] = live.get("push_done" if ok else "push_failed", 0) + 1
                    for key in keys_by_op.get(i, []):
                        state.live["edges"][key]["done"] += 1

                await _execute_push(ops, clients, stats, db, run.id, push_done)
            db.commit()

            run.status = "ok" if not stats.errors else ("partial" if healthy else "error")
        except Exception as e:
            log.exception("Sync run failed")
            db.rollback()
            stats.error(f"Sync failed: {e!r}")
            run.status = "error"
        finally:
            for client in clients.values():
                await client.close()
            try:
                _store_api_calls(db, run, calls, stats)
            except Exception:
                log.exception("Failed to store API call log")
                db.rollback()
            run.finished_at = utcnow()
            for name in ("pulled", "created_central", "updated_central", "conflicts", "pushed_created",
                         "pushed_updated"):
                setattr(run, name, getattr(stats, name))
            run.errors = stats.errors
            db.merge(run)
            db.commit()
            db.close()
            state.running, state.phase, state.detail, state.live = False, "idle", "", {}
            wake_enrichment_queue()
            from app.sync import priority

            priority.after_sync_run()
        return run.id


_background: set[asyncio.Task] = set()


def start_background_sync(trigger: str, triggered_by: str = "", workspace_id: int | None = None) -> int:
    """Start a sync in the background and return its run id right away."""
    if state.running or _lock.locked():
        raise SyncAlreadyRunning()
    state.running, state.phase = True, "starting"
    with SessionLocal() as db:
        run = SyncRun(trigger=trigger, triggered_by=triggered_by, workspace_id=workspace_id)
        db.add(run)
        db.commit()
        new_run_id = run.id

    async def runner():
        try:
            await run_sync(trigger, triggered_by, workspace_id, run_id=new_run_id)
        except SyncAlreadyRunning:
            with SessionLocal() as db:
                if (r := db.get(SyncRun, new_run_id)) is not None:
                    r.status, r.finished_at, r.errors = "error", utcnow(), ["Another sync was already running"]
                    db.commit()
        except Exception:
            log.exception("Background sync crashed")
            state.running, state.phase = False, "idle"

    task = asyncio.create_task(runner())
    _background.add(task)
    task.add_done_callback(_background.discard)
    return new_run_id
