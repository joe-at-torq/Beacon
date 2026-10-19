"""Collision resolution: derive the central reputation/description from every origin workspace's copy."""

from dataclasses import dataclass
from datetime import datetime

from app.torq.mapping import severity

DESCRIPTION_SEPARATOR = "\n---\n"


@dataclass
class Candidate:
    workspace_id: int
    priority: int
    reputation: str
    description: str
    updated_at: datetime | None


@dataclass
class Resolution:
    reputation: str
    description: str
    conflict: bool
    winner_workspace_id: int | None = None


def _priority_key(c: Candidate) -> tuple[int, int]:
    return (c.priority, c.workspace_id)


def resolve(candidates: list[Candidate], strategy: str, description_merge: str = "winner") -> Resolution | None:
    if not candidates:
        return None
    by_priority = sorted(candidates, key=_priority_key)

    if strategy == "most_recent":
        # Newest first; ties broken by workspace priority.
        ordered = sorted(
            by_priority,
            key=lambda c: c.updated_at.timestamp() if c.updated_at else float("-inf"),
            reverse=True,
        )
    elif strategy == "workspace_priority":
        ordered = by_priority
    else:  # highest_severity
        ordered = sorted(by_priority, key=lambda c: severity(c.reputation), reverse=True)

    winner = ordered[0]
    reputation = winner.reputation
    # Prefer a real verdict over "unknown" when the winner has none (except strict priority mode).
    if severity(reputation) == 0 and strategy != "workspace_priority":
        for c in ordered:
            if severity(c.reputation) > 0:
                reputation = c.reputation
                break

    unique_descriptions: list[str] = []
    for c in ordered:
        d = (c.description or "").strip()
        if d and d not in unique_descriptions:
            unique_descriptions.append(d)

    if description_merge == "concat":
        description = DESCRIPTION_SEPARATOR.join(unique_descriptions)
    else:
        description = (winner.description or "").strip() or (unique_descriptions[0] if unique_descriptions else "")

    conflict = len({c.reputation for c in candidates}) > 1 or len(unique_descriptions) > 1
    return Resolution(reputation=reputation, description=description, conflict=conflict,
                      winner_workspace_id=winner.workspace_id)
