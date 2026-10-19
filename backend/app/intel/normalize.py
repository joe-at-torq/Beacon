"""Normalize threat-intel enrichment into a single Torq reputation.

Each provider exposes *signals* (metrics) extracted from its enrichment result. Admins define ordered rules per
provider, e.g. ``virustotal.malicious_engines >= 5 -> SCORE_MALICIOUS``; the first matching rule gives that
provider's opinion. Opinions from all providers are combined with a strategy (most severe, least severe, most
common or provider priority) into the normalized reputation, which is suggested or applied automatically.
"""

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app import history
from app.intel.providers import PROVIDERS, VERDICT_REPUTATION
from app.models import IntelEnrichment, NormalizationRule, Observable, utcnow
from app.settings_store import get_all_settings
from app.torq.mapping import REPUTATIONS, severity

STRATEGIES = ("highest_severity", "lowest_severity", "most_common", "priority")
NUMBER_OPS = (">=", ">", "<=", "<", "==", "!=")
EQUALITY_OPS = ("==", "!=")
VERDICTS = ["malicious", "suspicious", "harmless", "unknown"]
REASON = "normalization"


@dataclass
class Metric:
    id: str
    label: str
    kind: str  # number | enum | bool
    extract: Callable[[dict, dict, dict | None], Any] = field(repr=False)
    options: list[str] | None = None
    unit: str = ""
    help: str = ""

    def as_dict(self) -> dict:
        ops = NUMBER_OPS if self.kind == "number" else EQUALITY_OPS
        return {"id": self.id, "label": self.label, "kind": self.kind, "options": self.options, "unit": self.unit,
                "help": self.help, "operators": list(ops)}


def _stat(key: str):
    return lambda summary, stats, data: stats.get(key)


def _vt_ratio(summary, stats, data):
    total = stats.get("total") or 0
    return round(100 * (stats.get("malicious") or 0) / total, 1) if total else None


def _emailrep_flag(key: str):
    def get(summary, stats, data):
        if key in stats:
            return bool(stats[key])
        details = (data or {}).get("details") or {}
        return bool(details.get(key)) if details else None

    return get


VERDICT = Metric("verdict", "Beacon verdict", "enum", lambda s, st, d: s.get("verdict"), VERDICTS,
                 help="The verdict Beacon derived from this provider (malicious / suspicious / harmless / unknown)")
FOUND, NOT_FOUND = "Found", "Not found"
RESULT = Metric("result", "Lookup result", "enum", lambda s, st, d: s.get("_lookup"), [FOUND, NOT_FOUND],
                help="Whether the provider had any data for the observable (Not found = no reputation data returned)")

METRICS: dict[str, list[Metric]] = {
    "virustotal": [
        Metric("malicious_engines", "Malicious engines", "number", _stat("malicious"), help="Engines flagging it malicious"),
        Metric("suspicious_engines", "Suspicious engines", "number", _stat("suspicious")),
        Metric("malicious_ratio", "Malicious ratio", "number", _vt_ratio, unit="%", help="Malicious engines / all engines"),
        Metric("community_score", "Community score", "number", _stat("reputation"), help="VirusTotal reputation (negative = bad)"),
    ],
    "otx": [
        Metric("pulses", "Pulses", "number", _stat("pulses"), help="OTX pulses referencing the indicator"),
        Metric("malware_families", "Malware families", "number", lambda s, st, d: len(st.get("malware_families") or [])),
    ],
    "abuseipdb": [
        Metric("abuse_confidence", "Abuse confidence", "number", _stat("abuse_confidence"), unit="%"),
        Metric("reports", "Reports (90 days)", "number", _stat("reports")),
        Metric("distinct_users", "Distinct reporters", "number", _stat("distinct_users")),
    ],
    "urlscan": [
        Metric("malicious_scans", "Malicious scans", "number", _stat("malicious_scans")),
        Metric("scans", "Scans", "number", _stat("scans")),
    ],
    "recordedfuture": [
        Metric("risk_score", "Risk score", "number", _stat("risk_score"), unit="/99"),
        Metric("criticality", "Criticality", "enum", _stat("criticality"),
               ["None", "Unusual", "Suspicious", "Malicious", "Very Malicious"]),
        Metric("rules_triggered", "Risk rules triggered", "number", _stat("rules_triggered")),
    ],
    "greynoise": [
        Metric("classification", "Classification", "enum", _stat("classification"), ["malicious", "benign", "unknown"]),
        Metric("noise", "Internet scanner (noise)", "bool", _stat("noise")),
        Metric("riot", "Known benign service (RIOT)", "bool", _stat("riot")),
    ],
    "emailrep": [
        Metric("reputation", "Reputation", "enum", _stat("reputation"), ["high", "medium", "low", "none"]),
        Metric("suspicious", "Suspicious", "bool", _stat("suspicious")),
        Metric("malicious_activity", "Malicious activity", "bool", _emailrep_flag("malicious_activity")),
        Metric("blacklisted", "Blacklisted", "bool", _emailrep_flag("blacklisted")),
        Metric("credentials_leaked", "Credentials leaked", "bool", _emailrep_flag("credentials_leaked")),
        Metric("data_breach", "In a data breach", "bool", _emailrep_flag("data_breach")),
        Metric("spam", "Spam", "bool", _emailrep_flag("spam")),
        Metric("disposable", "Disposable address", "bool", _emailrep_flag("disposable")),
    ],
}


def metrics_for(provider: str) -> list[Metric]:
    return [*METRICS.get(provider, []), RESULT, VERDICT]


def metric(provider: str, metric_id: str) -> Metric | None:
    return next((m for m in metrics_for(provider) if m.id == metric_id), None)


# Order matters (first match wins): escalating signals first, then clean results and "no data returned" map to
# Probably safe so enriched observables don't stay Unknown. Strong benign evidence (GreyNoise RIOT, EmailRep high
# reputation) maps to Safe.
PS, NF = "SCORE_PROBABLY_SAFE", ("result", "==", NOT_FOUND, "SCORE_PROBABLY_SAFE")
RECOMMENDED: dict[str, list[tuple[str, str, Any, str]]] = {
    "virustotal": [("malicious_engines", ">=", 5, "SCORE_MALICIOUS"), ("malicious_engines", ">=", 2, "SCORE_PROBABLY_MALICIOUS"),
                   ("malicious_engines", ">=", 1, "SCORE_SUSPICIOUS_OR_RISKY"), ("malicious_engines", "==", 0, PS), NF],
    "otx": [("pulses", ">=", 10, "SCORE_PROBABLY_MALICIOUS"), ("pulses", ">=", 1, "SCORE_SUSPICIOUS_OR_RISKY"),
            ("pulses", "==", 0, PS), NF],
    "abuseipdb": [("abuse_confidence", ">=", 90, "SCORE_MALICIOUS"), ("abuse_confidence", ">=", 50, "SCORE_PROBABLY_MALICIOUS"),
                  ("abuse_confidence", ">=", 25, "SCORE_SUSPICIOUS_OR_RISKY"), ("abuse_confidence", "<", 25, PS), NF],
    "urlscan": [("malicious_scans", ">=", 2, "SCORE_MALICIOUS"), ("malicious_scans", ">=", 1, "SCORE_PROBABLY_MALICIOUS"),
                ("malicious_scans", "==", 0, PS), NF],
    "recordedfuture": [("risk_score", ">=", 90, "SCORE_MALICIOUS"), ("risk_score", ">=", 65, "SCORE_PROBABLY_MALICIOUS"),
                       ("risk_score", ">=", 25, "SCORE_SUSPICIOUS_OR_RISKY"), ("risk_score", "<", 25, PS), NF],
    "greynoise": [("riot", "==", True, "SCORE_SAFE"), ("classification", "==", "malicious", "SCORE_PROBABLY_MALICIOUS"),
                  ("classification", "==", "benign", PS), NF],
    "emailrep": [("malicious_activity", "==", True, "SCORE_MALICIOUS"), ("blacklisted", "==", True, "SCORE_PROBABLY_MALICIOUS"),
                 ("suspicious", "==", True, "SCORE_SUSPICIOUS_OR_RISKY"), ("reputation", "==", "high", "SCORE_SAFE"),
                 ("reputation", "==", "medium", PS), NF],
}


def validate_rule(provider: str, metric_id: str, operator: str, value: Any, reputation: str) -> Any:
    """Validate a rule definition; returns the value coerced to the metric's type."""
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider {provider!r}")
    m = metric(provider, metric_id)
    if m is None:
        raise ValueError(f"Unknown signal {metric_id!r} for {provider}")
    if reputation not in REPUTATIONS:
        raise ValueError(f"Unknown reputation {reputation!r}")
    allowed = NUMBER_OPS if m.kind == "number" else EQUALITY_OPS
    if operator not in allowed:
        raise ValueError(f"Operator {operator!r} is not valid for {m.label}")
    if m.kind == "number":
        try:
            return float(value) if not float(value).is_integer() else int(float(value))
        except (TypeError, ValueError):
            raise ValueError(f"{m.label} needs a number") from None
    if m.kind == "bool":
        if isinstance(value, str):
            value = value.lower() in ("true", "yes", "1")
        return bool(value)
    if m.options and value not in m.options:
        raise ValueError(f"{m.label} must be one of {m.options}")
    return value


def _compare(actual: Any, operator: str, expected: Any) -> bool:
    if actual is None:
        return False
    try:
        if operator == ">=":
            return actual >= expected
        if operator == ">":
            return actual > expected
        if operator == "<=":
            return actual <= expected
        if operator == "<":
            return actual < expected
        if operator == "==":
            return actual == expected
        if operator == "!=":
            return actual != expected
    except TypeError:
        return False
    return False


@dataclass
class Config:
    rules: dict[str, list[NormalizationRule]]
    strategy: str
    fallback_verdicts: bool
    provider_order: list[str]
    mode: str
    only_escalate: bool


def load_config(db: Session, overrides: dict | None = None) -> Config:
    settings = {**get_all_settings(db), **(overrides or {})}
    rules: dict[str, list[NormalizationRule]] = {}
    for r in db.query(NormalizationRule).filter_by(enabled=True).order_by(NormalizationRule.order, NormalizationRule.id):
        rules.setdefault(r.provider, []).append(r)
    return Config(
        rules=rules,
        strategy=settings["normalization_strategy"],
        fallback_verdicts=bool(settings["normalization_fallback_verdicts"]),
        provider_order=list(settings["normalization_provider_order"] or []),
        mode=settings["normalization_mode"],
        only_escalate=bool(settings["normalization_only_escalate"]),
    )


def provider_opinion(cfg: Config, enrichment: IntelEnrichment, data: dict | None = None) -> dict | None:
    """Reputation a single provider's result maps to (first matching rule), or None."""
    if enrichment.status not in ("ok", "not_found"):
        return None  # errors carry no information
    summary = {**(enrichment.summary or {}), "_lookup": NOT_FOUND if enrichment.status == "not_found" else FOUND}
    stats = summary.get("stats") or {}
    for rule in cfg.rules.get(enrichment.provider, []):
        m = metric(enrichment.provider, rule.metric)
        if m is None:
            continue
        actual = m.extract(summary, stats, data)
        if _compare(actual, rule.operator, rule.value):
            return {"provider": enrichment.provider, "reputation": rule.reputation, "rule_id": rule.id,
                    "metric": m.id, "metric_label": m.label, "operator": rule.operator, "threshold": rule.value,
                    "actual": actual, "unit": m.unit, "source": "rule"}
    if cfg.fallback_verdicts and (rep := VERDICT_REPUTATION.get(summary.get("verdict"))):
        return {"provider": enrichment.provider, "reputation": rep, "rule_id": None, "metric": "verdict",
                "metric_label": "Beacon verdict", "operator": "==", "threshold": summary.get("verdict"),
                "actual": summary.get("verdict"), "unit": "", "source": "verdict"}
    return None


def combine(cfg: Config, opinions: list[dict]) -> dict | None:
    if not opinions:
        return None
    if cfg.strategy == "lowest_severity":
        chosen = min(opinions, key=lambda o: severity(o["reputation"]))
    elif cfg.strategy == "most_common":
        counts = Counter(o["reputation"] for o in opinions)
        top = max(counts.values())
        chosen = max((o for o in opinions if counts[o["reputation"]] == top), key=lambda o: severity(o["reputation"]))
    elif cfg.strategy == "priority":
        order = {p: i for i, p in enumerate(cfg.provider_order)}
        chosen = min(opinions, key=lambda o: (order.get(o["provider"], len(order) + list(PROVIDERS).index(o["provider"]))))
    else:  # highest_severity
        chosen = max(opinions, key=lambda o: severity(o["reputation"]))
    return {"reputation": chosen["reputation"], "decided_by": chosen["provider"], "strategy": cfg.strategy}


def _needs_raw(cfg: Config, enrichment: IntelEnrichment) -> bool:
    return enrichment.provider == "emailrep" and any(
        r.metric in ("malicious_activity", "blacklisted", "credentials_leaked", "data_breach", "spam", "disposable")
        for r in cfg.rules.get("emailrep", []))


def evaluate(cfg: Config, obs: Observable) -> dict | None:
    """Normalized reputation for an observable from its threat-intel enrichment (None if no opinion)."""
    opinions = []
    for e in obs.intel:
        data = e.data if _needs_raw(cfg, e) else None
        if (o := provider_opinion(cfg, e, data)) is not None:
            opinions.append(o)
    result = combine(cfg, opinions)
    if result is None:
        return None
    return {**result, "label": REPUTATIONS[result["reputation"]][0], "current": obs.reputation,
            "differs": result["reputation"] != obs.reputation, "contributions": opinions}


def should_apply(cfg: Config, obs: Observable, normalized: dict | None, force: bool = False) -> bool:
    if not normalized or not normalized["differs"]:
        return False
    if cfg.only_escalate and not force and severity(normalized["reputation"]) <= severity(obs.reputation):
        return False
    return True


def apply(obs: Observable, normalized: dict, actor: str) -> None:
    """Set the observable's central reputation to the normalized value (authoritative; syncs via Central rules)."""
    old = obs.reputation
    obs.reputation = normalized["reputation"]
    obs.value_source = "central"
    obs.updated_at = utcnow()
    providers = sorted({c["provider"] for c in normalized["contributions"]})
    history.record(obs, history.REPUTATION_CHANGED, actor=actor, field="reputation", old=old, new=obs.reputation,
                   cause=REASON, strategy=normalized["strategy"], decided_by=normalized["decided_by"],
                   providers=[PROVIDERS[p].name for p in providers if p in PROVIDERS])
    if not obs.pinned:
        obs.pinned = True
        history.record(obs, history.PINNED, actor=actor, cause=REASON)


def auto_apply(db: Session, observables: list[Observable], actor: str) -> int:
    """After enrichment: apply normalization when the mode is automatic. Returns how many changed."""
    cfg = load_config(db)
    if cfg.mode != "auto":
        return 0
    changed = 0
    for obs in observables:
        normalized = evaluate(cfg, obs)
        if should_apply(cfg, obs, normalized):
            apply(obs, normalized, actor)
            changed += 1
    return changed
