from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.audit import log_event
from app.db import get_db
from app.models import Rule, User
from app.services import rules as rules_svc
from app.security import get_active_user, require_admin
from app.serializers import rule_out

router = APIRouter(prefix="/api/rules", tags=["rules"])


RuleIn = rules_svc.RuleIn


class ReorderIn(BaseModel):
    ids: list[int]


class PreviewIn(BaseModel):
    rule: RuleIn | None = None


_validate_refs = rules_svc.validate_refs
_apply = rules_svc.apply


@router.get("")
def list_rules(db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    return [rule_out(r) for r in db.query(Rule).order_by(Rule.order, Rule.id).all()]


@router.post("", status_code=201)
def create_rule(body: RuleIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    _validate_refs(db, body)
    max_order = max([r.order for r in db.query(Rule).all()] or [0])
    rule = Rule(order=max_order + 1)
    _apply(rule, body)
    db.add(rule)
    log_event(db, admin.username, "create_rule", "rule", body.name)
    db.commit()
    return rule_out(rule)


@router.put("/{rule_id}")
def update_rule(rule_id: int, body: RuleIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rule = db.get(Rule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    _validate_refs(db, body)
    _apply(rule, body)
    log_event(db, admin.username, "update_rule", "rule", body.name)
    db.commit()
    return rule_out(rule)


@router.patch("/{rule_id}/enabled")
def toggle_rule(rule_id: int, enabled: bool, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rule = db.get(Rule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    rule.enabled = enabled
    log_event(db, admin.username, "enable_rule" if enabled else "disable_rule", "rule", rule.name)
    db.commit()
    return rule_out(rule)


@router.delete("/{rule_id}", status_code=204)
def delete_rule(rule_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rule = db.get(Rule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    db.delete(rule)
    log_event(db, admin.username, "delete_rule", "rule", rule.name)
    db.commit()


@router.post("/reorder")
def reorder_rules(body: ReorderIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    rules = {r.id: r for r in db.query(Rule).all()}
    for idx, rid in enumerate(body.ids):
        if rid in rules:
            rules[rid].order = idx + 1
    log_event(db, admin.username, "reorder_rules", "rule", "")
    db.commit()
    return [rule_out(r) for r in sorted(rules.values(), key=lambda r: (r.order, r.id))]


@router.post("/preview")
def preview(body: PreviewIn, db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    """Dry-run: how many observables would be created/updated per target with the given (or saved) rules."""
    return rules_svc.preview(db, body.rule)
