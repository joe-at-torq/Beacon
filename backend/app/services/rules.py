"""Sync-rule operations shared by the internal UI API and the public v1 API."""

from fastapi import HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app.models import Feed, Observable, Rule, Workspace
from app.sync.engine import plan_push
from app.sync.rules import CENTRAL
from app.torq.mapping import REPUTATIONS, SUB_TYPES, TYPES


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = ""
    enabled: bool = True
    source_workspace_ids: list[int | str] = Field(
        default=[], description='Workspace ids observables may come from, "central" and/or "feed:<id>". Empty = any '
                            'workspace or central; feeds must be selected explicitly.')
    target_workspace_ids: list[int] = Field(default=[], description="Workspace ids to push to. Empty = all other workspaces.")
    types: list[str] = Field(default=[], description="Observable types the rule applies to. Empty = all types.")
    sub_types: list[str] = Field(default=[], description="Sub types (e.g. SUB_TYPE_ID_IP_ADDRESS_IPV4). Empty = all.")
    min_reputation: str | None = Field(None, description="Only sync observables at least this severe.")
    sync_updates: bool = Field(True, description="Also push reputation/description changes to existing copies.")
    priority_reputations: list[str] = Field(
        default=[], description="Sync immediately (instead of waiting for the sync interval) when Beacon gives a matching "
                                "observable one of these reputations, e.g. a manual edit, an API call or threat-intel "
                                "normalization.")

    model_config = {"json_schema_extra": {"examples": [{
        "name": "Prod IPv4 to Dev", "description": "Share IPv4 IOCs one way", "enabled": True,
        "source_workspace_ids": [1], "target_workspace_ids": [2], "types": ["TYPE_ID_IP_ADDRESS"],
        "sub_types": ["SUB_TYPE_ID_IP_ADDRESS_IPV4"], "min_reputation": None, "sync_updates": True,
        "priority_reputations": ["SCORE_MALICIOUS", "SCORE_PROBABLY_MALICIOUS"]}]}}

    @field_validator("source_workspace_ids")
    @classmethod
    def _sources(cls, v):
        out = []
        for item in v:
            if item == CENTRAL:
                out.append(CENTRAL)
            elif isinstance(item, str) and item.startswith("feed:") and item[5:].isdigit():
                out.append(item)
            else:
                try:
                    out.append(int(item))
                except (TypeError, ValueError):
                    raise ValueError(f"Invalid source {item!r}") from None
        return out

    @field_validator("types")
    @classmethod
    def _types(cls, v):
        bad = [t for t in v if t not in TYPES]
        if bad:
            raise ValueError(f"Unknown types: {bad}")
        return v

    @field_validator("sub_types")
    @classmethod
    def _sub_types(cls, v):
        bad = [t for t in v if t not in SUB_TYPES]
        if bad:
            raise ValueError(f"Unknown sub types: {bad}")
        return v

    @field_validator("priority_reputations")
    @classmethod
    def _priority(cls, v):
        bad = [r for r in v if r not in REPUTATIONS]
        if bad:
            raise ValueError(f"Unknown reputations: {bad}")
        return list(dict.fromkeys(v))

    @field_validator("min_reputation")
    @classmethod
    def _rep(cls, v):
        if v and v not in REPUTATIONS:
            raise ValueError("Unknown reputation")
        return v or None


def validate_refs(db: Session, body: RuleIn) -> None:
    ws_ids = {ws.id for ws in db.query(Workspace).all()}
    feed_ids = {f"feed:{f.id}" for f in db.query(Feed).all()}
    unknown = [i for i in body.source_workspace_ids if i != CENTRAL and i not in ws_ids and i not in feed_ids]
    unknown += [i for i in body.target_workspace_ids if i not in ws_ids]
    if unknown:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown workspace or feed ids: {unknown}")


def apply(rule: Rule, body: RuleIn) -> None:
    for k, v in body.model_dump().items():
        setattr(rule, k, v)


def get_or_404(db: Session, rule_id: int) -> Rule:
    rule = db.get(Rule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    return rule


def create(db: Session, body: RuleIn) -> Rule:
    validate_refs(db, body)
    max_order = max([r.order for r in db.query(Rule).all()] or [0])
    rule = Rule(order=max_order + 1)
    apply(rule, body)
    db.add(rule)
    return rule


def preview(db: Session, draft_in: RuleIn | None) -> dict:
    """Dry run: observables that would be created/updated per target with the given (or saved) rules."""
    if draft_in is not None:
        draft = Rule(id=0, order=0)
        apply(draft, draft_in)
        draft.enabled = True
        rules = [draft]
    else:
        rules = db.query(Rule).all()
    workspaces = db.query(Workspace).filter_by(enabled=True).all()
    ops = plan_push(db.query(Observable).all(), rules, workspaces)
    per_target = {ws.id: {"workspace_id": ws.id, "workspace_name": ws.name, "create": 0, "update": 0}
                  for ws in workspaces}
    for op in ops:
        per_target[op.workspace.id][op.kind] += 1
    return {
        "total_create": sum(1 for op in ops if op.kind == "create"),
        "total_update": sum(1 for op in ops if op.kind == "update"),
        "targets": list(per_target.values()),
    }
