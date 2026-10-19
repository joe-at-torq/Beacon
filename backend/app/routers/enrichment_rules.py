from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import log_event
from app.db import get_db
from app.intel import enrichment_rules as er
from app.intel import queue
from app.intel.providers import PROVIDERS
from app.models import EnrichmentJob, EnrichmentRule, User, utcnow
from app.security import get_active_user, require_admin, require_analyst
from app.services import enrichment_rules as svc
from app.settings_store import set_setting

router = APIRouter(prefix="/api/enrichment-rules", tags=["enrichment-rules"])


class LimitIn(BaseModel):
    per_minute: int = Field(ge=1, le=10_000)
    per_day: int = Field(ge=1, le=10_000_000)


class SettingsIn(BaseModel):
    paused: bool | None = None
    limits: dict[str, LimitIn] | None = None


def _config(db: Session) -> dict:
    stats = svc.rule_stats(db)
    rules = db.query(EnrichmentRule).order_by(EnrichmentRule.id).all()
    return {
        "rules": [svc.rule_out(r, stats.get(r.id)) for r in rules],
        "providers": [
            {"id": p.id, "name": p.name, "color": p.color, "monogram": p.monogram, "types": p.types, "sub_types": p.sub_types}
            for p in PROVIDERS.values()
        ],
        "limits": er.limits(db),
        "queue": queue.summary(db),
    }


@router.get("")
def get_config(db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    return _config(db)


@router.get("/queue")
def get_queue(db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    return queue.summary(db)


@router.post("", status_code=201)
def create_rule(body: svc.EnrichmentRuleIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rule = svc.create(db, body, admin.username)
    log_event(db, admin.username, "create_enrichment_rule", "enrichment_rule", rule.name)
    db.commit()
    return svc.rule_out(rule)


@router.put("/{rule_id:int}")
def update_rule(rule_id: int, body: svc.EnrichmentRuleIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rule = svc.get_or_404(db, rule_id)
    svc.apply(rule, body)
    if not rule.enabled:
        svc.cancel_queued(db, rule.id)
    log_event(db, admin.username, "update_enrichment_rule", "enrichment_rule", rule.name)
    db.commit()
    return svc.rule_out(rule, svc.rule_stats(db).get(rule.id))


@router.patch("/{rule_id:int}/enabled")
def set_enabled(rule_id: int, enabled: bool, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rule = svc.get_or_404(db, rule_id)
    rule.enabled, rule.updated_at = enabled, utcnow()
    cancelled = 0 if enabled else svc.cancel_queued(db, rule.id)
    log_event(db, admin.username, "enable_enrichment_rule" if enabled else "disable_enrichment_rule", "enrichment_rule",
              f"{rule.name}" + (f" ({cancelled} queued lookups cancelled)" if cancelled else ""))
    db.commit()
    return svc.rule_out(rule, svc.rule_stats(db).get(rule.id))


@router.delete("/{rule_id:int}", status_code=204)
def delete_rule(rule_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rule = svc.get_or_404(db, rule_id)
    svc.cancel_queued(db, rule.id)
    db.delete(rule)
    log_event(db, admin.username, "delete_enrichment_rule", "enrichment_rule", rule.name)
    db.commit()


@router.post("/preview")
def preview(body: svc.EnrichmentRuleIn, db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    return er.preview(db, body)


@router.post("/{rule_id:int}/run")
def run_rule(rule_id: int, db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    rule = svc.get_or_404(db, rule_id)
    counts = svc.run_existing(db, rule)
    log_event(db, user.username, "run_enrichment_rule", "enrichment_rule", f"{rule.name}: {sum(counts.values())} lookups queued")
    db.commit()
    queue.wake()
    return {"queued": sum(counts.values()), "providers": counts}


@router.put("/settings")
def update_settings(body: SettingsIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    if body.limits is not None:
        unknown = [p for p in body.limits if p not in PROVIDERS]
        if unknown:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown providers: {unknown}")
        current = er.limits(db)
        current.update({p: lim.model_dump() for p, lim in body.limits.items()})
        set_setting(db, "enrichment_limits", current)
    if body.paused is not None:
        set_setting(db, "enrichment_paused", body.paused)
    log_event(db, admin.username, "update_enrichment_settings", "settings", body.model_dump_json(exclude_none=True))
    db.commit()
    if body.paused is False:
        queue.wake()
    return _config(db)


@router.post("/queue/clear")
def clear_queue(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    n = (
        db.query(EnrichmentJob)
        .filter(EnrichmentJob.status == "queued")
        .update({"status": "cancelled", "finished_at": utcnow()}, synchronize_session=False)
    )
    log_event(db, admin.username, "clear_enrichment_queue", "enrichment_queue", f"{n} lookups cancelled")
    db.commit()
    return {"cancelled": n}
