"""Synchronisation rule evaluation.

Rules are an allow-list. An observable may be pushed to a target workspace when at least one enabled
rule matches: one of the observable's *origin* sources (workspaces where it was observed natively,
"central" for manually created/edited observables, or "feed:<id>" for STIX/TAXII feeds listing it,
excluding the target itself) is among the rule's sources, the target is among the rule's targets, and the
type/sub-type/reputation filters match. A rule with no sources matches any workspace or central, but never a
feed: feeds are only pushed by rules that name them.
"""

from collections.abc import Iterable
from typing import Protocol

from app.torq.mapping import severity

CENTRAL = "central"
FEED_PREFIX = "feed:"


def is_feed(source: str | int) -> bool:
    return str(source).startswith(FEED_PREFIX)


class RuleLike(Protocol):
    enabled: bool
    source_workspace_ids: list
    target_workspace_ids: list
    types: list
    sub_types: list
    min_reputation: str | None
    sync_updates: bool


class ObservableLike(Protocol):
    type: str
    sub_type: str
    reputation: str


def _ids(values: Iterable) -> set[str]:
    return {str(v) for v in values or []}


def rule_matches(rule: RuleLike, sources: set[str], target_id: int, obs: ObservableLike) -> bool:
    if not rule.enabled or not sources:
        return False
    rule_sources = _ids(rule.source_workspace_ids)
    if rule_sources:
        if not (rule_sources & sources):
            return False
    elif not any(not is_feed(s) for s in sources):
        return False  # "any source" excludes feeds
    rule_targets = _ids(rule.target_workspace_ids)
    if rule_targets and str(target_id) not in rule_targets:
        return False
    if rule.types and obs.type not in rule.types:
        return False
    if rule.sub_types and obs.sub_type not in rule.sub_types:
        return False
    if rule.min_reputation and severity(obs.reputation) < severity(rule.min_reputation):
        return False
    return True


def evaluate(rules: Iterable[RuleLike], origins: set[str], target_id: int, obs: ObservableLike) -> bool | None:
    """Return None if pushing to target is not allowed, otherwise whether updates should also be synced."""
    sources = origins - {str(target_id)}
    allowed: bool | None = None
    for rule in rules:
        if rule_matches(rule, sources, target_id, obs):
            if rule.sync_updates:
                return True
            allowed = False
    return allowed


def node_id(source: str | int) -> str:
    """Graph node id for a rule/origin source: "central", "feed:<id>" or "ws:<id>"."""
    s = str(source)
    return s if s == CENTRAL or is_feed(s) else f"ws:{s}"


def rule_edge_pairs(rule: RuleLike, ws_ids: list[int]) -> list[tuple[str, str]]:
    """Directed (source, target) node pairs a rule permits, ignoring its type/reputation filters."""
    sources = [str(s) for s in (rule.source_workspace_ids or [])] or [str(i) for i in ws_ids] + [CENTRAL]
    targets = [int(t) for t in (rule.target_workspace_ids or [])] or ws_ids
    return [(node_id(s), f"ws:{t}") for s in sources for t in targets if str(s) != str(t)]
