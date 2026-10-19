from fastapi import APIRouter, Body, Depends, Response
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api_v1.auth import Principal, admin_access, read_access
from app.api_v1.schemas import ERRORS, NOT_FOUND, RuleOut, RulePatch, RulePreviewOut
from app.audit import log_event
from app.db import get_db
from app.models import Rule
from app.serializers import rule_out
from app.services import rules as svc

router = APIRouter(tags=["Rules"], responses=ERRORS)


@router.get("/rules", response_model=list[RuleOut], summary="List rules")
def list_rules(db: Session = Depends(get_db), _: Principal = Depends(read_access)):
    """All sync rules in display order. Rules are an allow-list: nothing is pushed without a matching rule."""
    return [rule_out(r) for r in db.query(Rule).order_by(Rule.order, Rule.id).all()]


@router.get("/rules/{rule_id}", response_model=RuleOut, summary="Get a rule", responses=NOT_FOUND)
def get_rule(rule_id: int, db: Session = Depends(get_db), _: Principal = Depends(read_access)):
    return rule_out(svc.get_or_404(db, rule_id))


@router.post("/rules", response_model=RuleOut, status_code=201, summary="Create a rule")
def create_rule(body: svc.RuleIn, db: Session = Depends(get_db), p: Principal = Depends(admin_access)):
    rule = svc.create(db, body)
    log_event(db, p.actor, "create_rule", "rule", body.name)
    db.commit()
    return rule_out(rule)


@router.put("/rules/{rule_id}", response_model=RuleOut, summary="Replace a rule", responses=NOT_FOUND)
def replace_rule(rule_id: int, body: svc.RuleIn, db: Session = Depends(get_db), p: Principal = Depends(admin_access)):
    rule = svc.get_or_404(db, rule_id)
    svc.validate_refs(db, body)
    svc.apply(rule, body)
    log_event(db, p.actor, "update_rule", "rule", body.name)
    db.commit()
    return rule_out(rule)


@router.patch("/rules/{rule_id}", response_model=RuleOut, summary="Update part of a rule", responses=NOT_FOUND)
def patch_rule(rule_id: int, body: RulePatch, db: Session = Depends(get_db), p: Principal = Depends(admin_access)):
    """Change only the provided fields, e.g. `{"enabled": false}` to pause a rule."""
    rule = svc.get_or_404(db, rule_id)
    current = rule_out(rule)
    try:
        merged = svc.RuleIn(**{k: current[k] for k in svc.RuleIn.model_fields} | body.model_dump(exclude_unset=True))
    except ValidationError as e:  # report like any other request validation error
        raise RequestValidationError(e.errors(include_url=False)) from None
    svc.validate_refs(db, merged)
    svc.apply(rule, merged)
    log_event(db, p.actor, "update_rule", "rule", merged.name)
    db.commit()
    return rule_out(rule)


@router.delete("/rules/{rule_id}", status_code=204, response_class=Response, summary="Delete a rule", responses=NOT_FOUND)
def delete_rule(rule_id: int, db: Session = Depends(get_db), p: Principal = Depends(admin_access)):
    rule = svc.get_or_404(db, rule_id)
    db.delete(rule)
    log_event(db, p.actor, "delete_rule", "rule", rule.name)
    db.commit()
    return Response(status_code=204)


@router.post("/rules/preview", response_model=RulePreviewOut, summary="Preview the effect of rules")
def preview_rules(
    body: svc.RuleIn | None = Body(None, description="A draft rule to evaluate alone; omit to preview all saved rules"),
    db: Session = Depends(get_db),
    _: Principal = Depends(read_access),
):
    """Dry run: how many observables the next sync would create/update in each workspace."""
    return svc.preview(db, body)
