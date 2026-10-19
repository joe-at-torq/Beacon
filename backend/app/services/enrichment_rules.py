"""Enrichment-rule operations shared by the internal UI API and the public v1 API."""

from fastapi import HTTPException, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session

from app.intel import enrichment_rules as er
from app.intel.providers import PROVIDERS
from app.models import EnrichmentJob, EnrichmentRule, utcnow
from app.serializers import iso
from app.torq.mapping import REPUTATIONS, SUB_TYPES, TYPES

REFRESH_CHOICES = (-1, 0, 1, 7, 30)
GENERIC_SUB_TYPES = ("SUB_TYPE_ID_UNKNOWN", "SUB_TYPE_ID_OTHER")


class EnrichmentRuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    enabled: bool = True
    type: str = Field(description="Observable type, e.g. TYPE_ID_IP_ADDRESS")
    sub_types: list[str] = Field(default=[], description="Sub types of that type. Empty = any sub type.")
    reputations: list[str] = Field(default=[], description="Only observables with one of these reputations. Empty = any.")
    providers: list[str] = Field(min_length=1, description="Integrations to enrich with, e.g. virustotal, abuseipdb.")
    refresh_days: int = Field(7, description="Skip a provider that enriched the observable within this many days. "
                                             "0 = always look up, -1 = never re-enrich.")
    skip_when_busy: bool = Field(False, description="When an integration is out of capacity (daily limit reached, "
                                                    "rate-limited or disabled), skip it and enrich with the others "
                                                    "instead of waiting for it.")

    model_config = {"json_schema_extra": {"examples": [{
        "name": "Enrich malicious IPv4", "enabled": True, "type": "TYPE_ID_IP_ADDRESS",
        "sub_types": ["SUB_TYPE_ID_IP_ADDRESS_IPV4"], "reputations": ["SCORE_MALICIOUS", "SCORE_PROBABLY_MALICIOUS"],
        "providers": ["virustotal", "abuseipdb"], "refresh_days": 7, "skip_when_busy": True}]}}

    @model_validator(mode="after")
    def _check(self):
        if self.type not in TYPES:
            raise ValueError(f"Unknown type {self.type!r}")
        # Generic sub types (Unknown / Other) apply to every type; the rest must belong to the rule's type.
        bad = [s for s in self.sub_types if s not in GENERIC_SUB_TYPES and SUB_TYPES.get(s, (None, None))[1] != self.type]
        if bad:
            raise ValueError(f"Sub types don't belong to {TYPES[self.type][0]}: {bad}")
        bad = [r for r in self.reputations if r not in REPUTATIONS]
        if bad:
            raise ValueError(f"Unknown reputations: {bad}")
        if self.refresh_days not in REFRESH_CHOICES:
            raise ValueError(f"refresh_days must be one of {list(REFRESH_CHOICES)}")
        unknown = [p for p in self.providers if p not in PROVIDERS]
        if unknown:
            raise ValueError(f"Unknown providers: {unknown}")
        for p in self.providers:
            prov = PROVIDERS[p]
            subs = self.sub_types or [None]
            if not any(prov.supports(self.type, s) for s in subs):
                what = ", ".join(SUB_TYPES[s][0] for s in self.sub_types) or TYPES[self.type][0]
                raise ValueError(f"{prov.name} can't enrich {what}")
        self.providers = list(dict.fromkeys(self.providers))
        return self


def rule_out(rule: EnrichmentRule, stats: dict | None = None) -> dict:
    return {
        "id": rule.id, "name": rule.name, "enabled": rule.enabled, "type": rule.type, "sub_types": rule.sub_types or [],
        "reputations": rule.reputations or [], "providers": rule.providers or [], "refresh_days": rule.refresh_days,
        "skip_when_busy": bool(rule.skip_when_busy),
        "created_by": rule.created_by, "created_at": iso(rule.created_at), "updated_at": iso(rule.updated_at),
        "stats": stats or {"queued": 0, "done": 0, "error": 0, "skipped": 0},
    }


def rule_stats(db: Session) -> dict[int, dict]:
    """Recent job counts per rule (finished jobs are kept for a week)."""
    from sqlalchemy import func

    out: dict[int, dict] = {}
    rows = (
        db.query(EnrichmentJob.rule_id, EnrichmentJob.status, func.count(EnrichmentJob.id))
        .filter(EnrichmentJob.rule_id.isnot(None))
        .group_by(EnrichmentJob.rule_id, EnrichmentJob.status)
        .all()
    )
    for rule_id, st, n in rows:
        s = out.setdefault(rule_id, {"queued": 0, "done": 0, "error": 0, "skipped": 0})
        key = "queued" if st in ("queued", "running") else st
        if key in s:
            s[key] += n
    return out


def get_or_404(db: Session, rule_id: int) -> EnrichmentRule:
    rule = db.get(EnrichmentRule, rule_id)
    if not rule:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Enrichment rule not found")
    return rule


def apply(rule: EnrichmentRule, body: EnrichmentRuleIn) -> None:
    for k, v in body.model_dump().items():
        setattr(rule, k, v)
    rule.updated_at = utcnow()


def create(db: Session, body: EnrichmentRuleIn, username: str) -> EnrichmentRule:
    rule = EnrichmentRule(created_by=username)
    apply(rule, body)
    db.add(rule)
    db.flush()
    return rule


def cancel_queued(db: Session, rule_id: int) -> int:
    """Cancel a rule's queued lookups (on delete/disable: the way to stop a large run)."""
    return (
        db.query(EnrichmentJob)
        .filter(EnrichmentJob.rule_id == rule_id, EnrichmentJob.status == "queued")
        .update({"status": "cancelled", "finished_at": utcnow()}, synchronize_session=False)
    )


def run_existing(db: Session, rule: EnrichmentRule) -> dict[str, int]:
    """Queue lookups for the observables the rule matches today."""
    if not rule.enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Enable the rule before running it")
    return er.enqueue(db, er.matching_observables(db, rule), "manual_run", rules=[rule])
