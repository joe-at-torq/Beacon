from typing import Any

from sqlalchemy.orm import Session

from app.models import Setting

COLLISION_STRATEGIES = ("highest_severity", "most_recent", "workspace_priority")
DESCRIPTION_MERGE_MODES = ("winner", "concat")

DEFAULTS: dict[str, Any] = {
    "collision_strategy": "highest_severity",
    "description_merge": "winner",
    "sync_enabled": True,
    "sync_interval_minutes": 15,
    # Threat-intel reputation normalization
    "normalization_mode": "suggest",  # suggest | auto
    "normalization_strategy": "highest_severity",  # highest_severity | lowest_severity | most_common | priority
    "normalization_only_escalate": True,  # auto mode never lowers a reputation
    "normalization_fallback_verdicts": False,  # use a provider's built-in verdict when none of its rules match
    "normalization_provider_order": [],  # for the priority strategy
    # Rule-driven enrichment queue: per-provider pacing (conservative free-tier guesses; adjust to your plan).
    "enrichment_limits": {
        "virustotal": {"per_minute": 4, "per_day": 500},
        "otx": {"per_minute": 30, "per_day": 10000},
        "abuseipdb": {"per_minute": 10, "per_day": 1000},
        "urlscan": {"per_minute": 10, "per_day": 1000},
        "recordedfuture": {"per_minute": 30, "per_day": 5000},
        "greynoise": {"per_minute": 5, "per_day": 50},
        "emailrep": {"per_minute": 5, "per_day": 250},
    },
    "enrichment_paused": False,
    # Beacon's own read-only TAXII 2.1 server (one collection).
    "taxii_enabled": False,
    "taxii_collection": {"min_reputation": "SCORE_SUSPICIOUS_OR_RISKY", "types": [], "sources": []},
    # Safety valve: most observables pushed in one sync run (0 = unlimited).
    "max_pushes_per_run": 5000,
}


def get_setting(db: Session, key: str) -> Any:
    row = db.get(Setting, key)
    return row.value if row is not None else DEFAULTS.get(key)


def get_all_settings(db: Session) -> dict[str, Any]:
    values = dict(DEFAULTS)
    for row in db.query(Setting).all():
        values[row.key] = row.value
    return values


def set_setting(db: Session, key: str, value: Any) -> None:
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value
