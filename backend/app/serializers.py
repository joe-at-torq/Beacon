from datetime import datetime

from app.models import AuditEvent, Observable, ObservableEvent, Rule, SyncApiCall, SyncRun, User, Workspace


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def user_out(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "role": u.role,
        "must_change_password": u.must_change_password,
        "created_at": iso(u.created_at),
        "last_login": iso(u.last_login),
    }


def workspace_out(ws: Workspace, counts: dict | None = None) -> dict:
    counts = counts or {}
    return {
        "id": ws.id,
        "name": ws.name,
        "region": ws.region,
        "client_id": ws.client_id,
        "enabled": ws.enabled,
        "priority": ws.priority,
        "created_at": iso(ws.created_at),
        "last_sync_at": iso(ws.last_sync_at),
        "last_sync_status": ws.last_sync_status,
        "last_error": ws.last_error,
        "origin_count": counts.get("origin", 0),
        "pushed_count": counts.get("pushed", 0),
    }


def observable_out(o: Observable, ws_names: dict[int, str], detail: bool = False) -> dict:
    data = {
        "id": o.id,
        "type": o.type,
        "sub_type": o.sub_type,
        "value": o.value,
        "reputation": o.reputation,
        "description": o.description or "",
        "first_observed_at": iso(o.first_observed_at),
        "last_observed_at": iso(o.last_observed_at),
        "created_at": iso(o.created_at),
        "updated_at": iso(o.updated_at),
        "pinned": o.pinned,
        "origin": o.origin,
        "has_enrichment": any(link.has_enrichment for link in o.links) or any(e.status == "ok" for e in o.intel),
        "intel": [intel_out(e) for e in sorted(o.intel, key=lambda e: e.provider)],
        "associated_cases_count": o.associated_cases_count or 0,
        "links": [
            {
                "workspace_id": link.workspace_id,
                "workspace_name": ws_names.get(link.workspace_id, f"#{link.workspace_id}"),
                "relation": link.relation,
                "has_enrichment": bool(link.has_enrichment),
                "associated_cases_count": link.remote_cases_count or 0,
                **(
                    {
                        "remote_id": link.remote_id,
                        "remote_reputation": link.remote_reputation,
                        "remote_description": link.remote_description,
                        "remote_updated_at": iso(link.remote_updated_at),
                        "last_synced_at": iso(link.last_synced_at),
                        "enrichment": link.remote_enrichment if link.has_enrichment else None,
                        "enrichment_updated_at": iso(link.remote_enrichment_updated_at),
                    }
                    if detail
                    else {}
                ),
            }
            for link in sorted(o.links, key=lambda link: link.workspace_id)
        ],
    }
    if detail:
        # Raw threat-intel API responses, keyed by provider (only loaded for the detail view).
        data["enrichment"] = {e.provider: e.data for e in o.intel if e.data is not None}
    return data


def intel_out(e) -> dict:
    return {
        "provider": e.provider,
        "status": e.status,
        "summary": e.summary or {},
        "error": e.error,
        "fetched_at": iso(e.fetched_at),
        "fetched_by": e.fetched_by,
    }


def rule_out(r: Rule) -> dict:
    return {
        "id": r.id,
        "name": r.name,
        "description": r.description or "",
        "enabled": r.enabled,
        "order": r.order,
        "source_workspace_ids": r.source_workspace_ids or [],
        "target_workspace_ids": r.target_workspace_ids or [],
        "types": r.types or [],
        "sub_types": r.sub_types or [],
        "min_reputation": r.min_reputation,
        "sync_updates": r.sync_updates,
        "priority_reputations": r.priority_reputations or [],
        "created_at": iso(r.created_at),
        "updated_at": iso(r.updated_at),
    }


def run_out(r: SyncRun) -> dict:
    return {
        "id": r.id,
        "started_at": iso(r.started_at),
        "finished_at": iso(r.finished_at),
        "trigger": r.trigger,
        "triggered_by": r.triggered_by,
        "workspace_id": r.workspace_id,
        "status": r.status,
        "pulled": r.pulled,
        "created_central": r.created_central,
        "updated_central": r.updated_central,
        "conflicts": r.conflicts,
        "pushed_created": r.pushed_created,
        "pushed_updated": r.pushed_updated,
        "errors": r.errors or [],
        "api_calls": r.api_calls or 0,
        "api_errors": r.api_errors or 0,
    }


def api_call_out(c: SyncApiCall | dict) -> dict:
    get = (lambda k: c.get(k)) if isinstance(c, dict) else (lambda k: getattr(c, k))
    ts = get("ts")
    return {
        "id": get("id"),
        "ts": iso(ts) if hasattr(ts, "isoformat") else ts,
        "workspace_id": get("workspace_id"),
        "workspace_name": get("workspace_name") or "",
        "method": get("method"),
        "url": get("url"),
        "attempt": get("attempt") or 1,
        "status_code": get("status_code"),
        "duration_ms": get("duration_ms") or 0,
        "request_headers": get("request_headers") or {},
        "request_body": get("request_body") or "",
        "response_headers": get("response_headers") or {},
        "response_body": get("response_body") or "",
        "error": get("error"),
    }


def event_out(e: ObservableEvent) -> dict:
    return {
        "id": e.id,
        "ts": iso(e.ts),
        "kind": e.kind,
        "actor": e.actor,
        "workspace_id": e.workspace_id,
        "workspace_name": e.workspace_name,
        "run_id": e.run_id,
        "field": e.field,
        "old_value": e.old_value,
        "new_value": e.new_value,
        "detail": e.detail or {},
    }


def audit_out(e: AuditEvent) -> dict:
    return {
        "id": e.id,
        "ts": iso(e.ts),
        "username": e.username,
        "action": e.action,
        "entity": e.entity,
        "detail": e.detail,
    }
