import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import log_event
from app.db import get_db
from app.intel import normalize as norm
from app.intel.providers import PROVIDERS
from app.models import NormalizationRule, Observable, User
from app.security import get_active_user, require_admin, require_analyst
from app.settings_store import get_all_settings, set_setting
from app.torq.mapping import REPUTATIONS, severity

router = APIRouter(prefix="/api/normalization", tags=["normalization"])

SETTING_KEYS = ("normalization_mode", "normalization_strategy", "normalization_only_escalate",
                "normalization_fallback_verdicts", "normalization_provider_order")


class SettingsIn(BaseModel):
    mode: Literal["suggest", "auto"] | None = None
    strategy: Literal["highest_severity", "lowest_severity", "most_common", "priority"] | None = None
    only_escalate: bool | None = None
    fallback_verdicts: bool | None = None
    provider_order: list[str] | None = None


class RuleIn(BaseModel):
    metric: str
    operator: str
    value: Any = None
    reputation: str
    enabled: bool = True


class PreviewIn(BaseModel):
    settings: SettingsIn | None = None
    sample: int = Field(50, ge=1, le=500)


def _rule_out(r: NormalizationRule) -> dict:
    return {"id": r.id, "provider": r.provider, "metric": r.metric, "operator": r.operator, "value": r.value,
            "reputation": r.reputation, "enabled": r.enabled, "order": r.order}


def _settings(db: Session) -> dict:
    s = get_all_settings(db)
    return {"mode": s["normalization_mode"], "strategy": s["normalization_strategy"],
            "only_escalate": s["normalization_only_escalate"], "fallback_verdicts": s["normalization_fallback_verdicts"],
            "provider_order": s["normalization_provider_order"] or []}


def _config_out(db: Session) -> dict:
    rules = db.query(NormalizationRule).order_by(NormalizationRule.provider, NormalizationRule.order, NormalizationRule.id).all()
    return {
        "settings": _settings(db),
        "rules": [_rule_out(r) for r in rules],
        "providers": [{"id": p.id, "name": p.name, "color": p.color, "monogram": p.monogram, "types": p.types,
                       "metrics": [m.as_dict() for m in norm.metrics_for(p.id)]} for p in PROVIDERS.values()],
    }


@router.get("")
def get_config(db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    return _config_out(db)


@router.put("/settings")
def put_settings(body: SettingsIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    changes = body.model_dump(exclude_none=True)
    if "provider_order" in changes:
        unknown = [p for p in changes["provider_order"] if p not in PROVIDERS]
        if unknown:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown providers: {unknown}")
    for key, value in changes.items():
        set_setting(db, f"normalization_{key}", value)
    if changes:
        log_event(db, admin.username, "update_normalization", "settings", ", ".join(f"{k}={v}" for k, v in changes.items()))
    db.commit()
    return _config_out(db)


@router.put("/rules/{provider}")
def replace_rules(provider: str, body: list[RuleIn], db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Replace a provider's ordered rule list (the first matching enabled rule wins)."""
    if provider not in PROVIDERS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown provider")
    new_rules = []
    for i, r in enumerate(body):
        try:
            value = norm.validate_rule(provider, r.metric, r.operator, r.value, r.reputation)
        except ValueError as e:
            raise HTTPException(422, f"Rule {i + 1}: {e}") from None
        new_rules.append(NormalizationRule(provider=provider, metric=r.metric, operator=r.operator, value=value,
                                           reputation=r.reputation, enabled=r.enabled, order=i))
    db.query(NormalizationRule).filter_by(provider=provider).delete()
    db.add_all(new_rules)
    log_event(db, admin.username, "update_normalization_rules", "normalization", f"{PROVIDERS[provider].name}: {len(new_rules)} rule(s)")
    db.commit()
    return _config_out(db)


def _norm_value(v):
    """Compare rule values loosely: stored JSON may hold "true" / '"high"' strings from older saves."""
    if isinstance(v, str):
        try:
            v = json.loads(v)
        except ValueError:
            pass
    return str(v).lower()


@router.post("/recommended")
def load_recommended(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Add recommended rules: the full set for providers without rules; for providers that already have rules, the
    missing safe-side catch-alls (clean results, "not found"), appended after the existing rules. Escalating rules are
    never appended to an existing list: first match wins, so they'd land behind the user's own rules."""
    added = 0
    for provider, rules in norm.RECOMMENDED.items():
        current = db.query(NormalizationRule).filter_by(provider=provider).order_by(NormalizationRule.order).all()
        if current:
            rules = [r for r in rules if severity(r[3]) <= severity("SCORE_PROBABLY_SAFE")]
        have = {(r.metric, r.operator, _norm_value(r.value)) for r in current}
        order = max((r.order for r in current), default=-1)
        for metric_id, op, value, rep in rules:
            if (metric_id, op, _norm_value(value)) in have:
                continue
            order += 1
            db.add(NormalizationRule(provider=provider, metric=metric_id, operator=op, value=value, reputation=rep, order=order))
            added += 1
    log_event(db, admin.username, "load_recommended_normalization", "normalization", f"{added} rule(s)")
    db.commit()
    return {**_config_out(db), "added": added}


def _evaluate_all(db: Session, cfg: norm.Config):
    observables = db.query(Observable).filter(Observable.intel.any()).all()
    return [(o, norm.evaluate(cfg, o)) for o in observables]


@router.post("/preview")
def preview(body: PreviewIn, db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    """What normalization would do across all observables with threat-intel enrichment."""
    overrides = {f"normalization_{k}": v for k, v in (body.settings.model_dump(exclude_none=True) if body.settings else {}).items()}
    cfg = norm.load_config(db, overrides)
    results = _evaluate_all(db, cfg)
    distribution: dict[str, int] = {}
    changes, would_apply = [], 0
    for obs, n in results:
        key = n["reputation"] if n else "none"
        distribution[key] = distribution.get(key, 0) + 1
        if n and n["differs"]:
            applies = norm.should_apply(cfg, obs, n)
            would_apply += int(applies)
            if len(changes) < body.sample:
                changes.append({"id": obs.id, "type": obs.type, "value": obs.value, "current": obs.reputation,
                                "normalized": n["reputation"], "decided_by": n["decided_by"], "applies": applies,
                                "escalation": severity(n["reputation"]) > severity(obs.reputation),
                                "contributions": n["contributions"]})
    return {
        "enriched": len(results),
        "with_opinion": sum(1 for _, n in results if n),
        "differs": sum(1 for _, n in results if n and n["differs"]),
        "would_apply": would_apply,
        "distribution": [{"reputation": k, "label": REPUTATIONS.get(k, ("No opinion", 0))[0], "count": v}
                         for k, v in sorted(distribution.items(), key=lambda kv: -severity(kv[0]) if kv[0] in REPUTATIONS else 1)],
        "changes": changes,
    }


@router.post("/apply")
def apply_all(db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    """Apply the normalized reputation to every enriched observable where it differs (respects 'only raise')."""
    cfg = norm.load_config(db)
    changed = 0
    for obs, n in _evaluate_all(db, cfg):
        if norm.should_apply(cfg, obs, n):
            norm.apply(obs, n, user.username)
            changed += 1
    log_event(db, user.username, "apply_normalization", "normalization", f"{changed} observable(s)")
    db.commit()
    return {"changed": changed}
