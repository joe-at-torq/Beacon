from fastapi import APIRouter, Depends, Response
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api_v1.auth import Principal, admin_access, read_access, write_access
from app.api_v1.schemas import (
    ERRORS,
    NOT_FOUND,
    EnrichmentPreviewOut,
    EnrichmentRuleOut,
    EnrichmentRulePatch,
    EnrichmentRunOut,
)
from app.audit import log_event
from app.db import get_db
from app.intel import enrichment_rules as er
from app.intel import queue
from app.models import EnrichmentRule
from app.services import enrichment_rules as svc

router = APIRouter(tags=["Enrichment rules"], responses=ERRORS)


def _out(db: Session, rule: EnrichmentRule) -> dict:
    return svc.rule_out(rule, svc.rule_stats(db).get(rule.id))


@router.get("/enrichment-rules", response_model=list[EnrichmentRuleOut], summary="List enrichment rules")
def list_rules(db: Session = Depends(get_db), _: Principal = Depends(read_access)):
    """Rules that automatically enrich observables new to the central database with threat-intel integrations."""
    stats = svc.rule_stats(db)
    return [svc.rule_out(r, stats.get(r.id)) for r in db.query(EnrichmentRule).order_by(EnrichmentRule.id).all()]


@router.get("/enrichment-rules/queue", summary="Enrichment queue status")
def queue_status(db: Session = Depends(get_db), _: Principal = Depends(read_access)) -> dict:
    """Queued and running lookups, per-provider usage against the configured limits, cooldowns and recent errors."""
    return queue.summary(db)


@router.get("/enrichment-rules/{rule_id}", response_model=EnrichmentRuleOut, summary="Get an enrichment rule",
            responses=NOT_FOUND)
def get_rule(rule_id: int, db: Session = Depends(get_db), _: Principal = Depends(read_access)):
    return _out(db, svc.get_or_404(db, rule_id))


@router.post("/enrichment-rules", response_model=EnrichmentRuleOut, status_code=201, summary="Create an enrichment rule")
def create_rule(body: svc.EnrichmentRuleIn, db: Session = Depends(get_db), p: Principal = Depends(admin_access)):
    """Providers must support the rule's type and sub types (e.g. urlscan.io only looks up SHA-256 hashes)."""
    rule = svc.create(db, body, p.actor)
    log_event(db, p.actor, "create_enrichment_rule", "enrichment_rule", rule.name)
    db.commit()
    return _out(db, rule)


@router.put("/enrichment-rules/{rule_id}", response_model=EnrichmentRuleOut, summary="Replace an enrichment rule",
            responses=NOT_FOUND)
def replace_rule(rule_id: int, body: svc.EnrichmentRuleIn, db: Session = Depends(get_db), p: Principal = Depends(admin_access)):
    rule = svc.get_or_404(db, rule_id)
    svc.apply(rule, body)
    if not rule.enabled:
        svc.cancel_queued(db, rule.id)
    log_event(db, p.actor, "update_enrichment_rule", "enrichment_rule", rule.name)
    db.commit()
    return _out(db, rule)


@router.patch("/enrichment-rules/{rule_id}", response_model=EnrichmentRuleOut, summary="Update part of an enrichment rule",
              responses=NOT_FOUND)
def patch_rule(rule_id: int, body: EnrichmentRulePatch, db: Session = Depends(get_db), p: Principal = Depends(admin_access)):
    """Change only the provided fields, e.g. `{"enabled": false}`. Disabling cancels the rule's queued lookups."""
    rule = svc.get_or_404(db, rule_id)
    current = svc.rule_out(rule)
    try:
        merged = svc.EnrichmentRuleIn(**{k: current[k] for k in svc.EnrichmentRuleIn.model_fields} | body.model_dump(exclude_unset=True))
    except ValidationError as e:  # report like any other request validation error
        raise RequestValidationError(e.errors(include_url=False)) from None
    svc.apply(rule, merged)
    if not rule.enabled:
        svc.cancel_queued(db, rule.id)
    log_event(db, p.actor, "update_enrichment_rule", "enrichment_rule", rule.name)
    db.commit()
    return _out(db, rule)


@router.delete("/enrichment-rules/{rule_id}", status_code=204, response_class=Response, summary="Delete an enrichment rule",
               responses=NOT_FOUND)
def delete_rule(rule_id: int, db: Session = Depends(get_db), p: Principal = Depends(admin_access)):
    rule = svc.get_or_404(db, rule_id)
    svc.cancel_queued(db, rule.id)
    db.delete(rule)
    log_event(db, p.actor, "delete_enrichment_rule", "enrichment_rule", rule.name)
    db.commit()
    return Response(status_code=204)


@router.post("/enrichment-rules/preview", response_model=EnrichmentPreviewOut, summary="Preview an enrichment rule")
def preview_rule(body: svc.EnrichmentRuleIn, db: Session = Depends(get_db), _: Principal = Depends(read_access)):
    """What a rule matches today and how many lookups running it would queue, with a rough time to completion."""
    return er.preview(db, body)


@router.post("/enrichment-rules/{rule_id}/run", response_model=EnrichmentRunOut, summary="Run on existing matches",
             responses=NOT_FOUND)
def run_rule(rule_id: int, db: Session = Depends(get_db), p: Principal = Depends(write_access)):
    """Queue lookups for observables already in the database that match the rule (respecting its refresh window)."""
    rule = svc.get_or_404(db, rule_id)
    counts = svc.run_existing(db, rule)
    log_event(db, p.actor, "run_enrichment_rule", "enrichment_rule", f"{rule.name}: {sum(counts.values())} lookups queued")
    db.commit()
    queue.wake()
    return {"queued": sum(counts.values()), "providers": counts}
