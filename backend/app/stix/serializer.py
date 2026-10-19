"""Serialize Beacon observables as STIX 2.1 indicators (for the TAXII server)."""

import uuid
from datetime import datetime

from app.torq.mapping import REPUTATIONS, severity

# Fixed namespace: the same observable always gets the same indicator id, across restarts and installs.
NAMESPACE = uuid.UUID("6f1f3b5e-2c8a-4d6e-9b1a-be7acb0e0001")
SPEC = "2.1"
HASH_BY_LENGTH = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def indicator_id(type_id: str, value_norm: str) -> str:
    return f"indicator--{uuid.uuid5(NAMESPACE, f'{type_id}|{value_norm}')}"


def _literal(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def pattern_for(type_id: str, value: str) -> str | None:
    v = value.strip()
    if type_id == "TYPE_ID_IP_ADDRESS":
        path = "ipv6-addr:value" if ":" in v else "ipv4-addr:value"
    elif type_id == "TYPE_ID_HOSTNAME":
        path = "domain-name:value"
    elif type_id == "TYPE_ID_URL":
        path = "url:value"
    elif type_id == "TYPE_ID_EMAIL_ADDRESS":
        path = "email-addr:value"
    elif type_id == "TYPE_ID_FILE_HASH":
        algo = HASH_BY_LENGTH.get(len(v))
        if not algo:
            return None
        path = f"file:hashes.'{algo}'"
    elif type_id == "TYPE_ID_MAC_ADDRESS":
        path = "mac-addr:value"
    elif type_id == "TYPE_ID_FILE_NAME":
        path = "file:name"
    elif type_id == "TYPE_ID_PROCESS_NAME":
        path = "process:name"
    elif type_id == "TYPE_ID_USER_NAME":
        path = "user-account:account_login"
    else:
        return None
    return f"[{path} = {_literal(v)}]"


def indicator_types(reputation: str) -> list[str]:
    sev = severity(reputation)
    if sev >= 9:
        return ["malicious-activity"]
    if sev >= 5:
        return ["anomalous-activity"]
    if sev >= 1:
        return ["benign"]
    return ["unknown"]


def confidence(reputation: str) -> int | None:
    """How sure the verdict is: strongest at either end of the reputation scale."""
    sev = severity(reputation)
    return None if sev == 0 else {10: 95, 9: 85, 8: 70, 7: 60, 6: 50, 5: 40, 4: 50, 3: 60, 2: 75, 1: 90}[sev]


def ts(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if dt else None


def indicator(obs, revoked: bool = False) -> dict | None:
    """A STIX 2.1 indicator for an observable (None if the type has no STIX pattern)."""
    pattern = pattern_for(obs.type, obs.value)
    if pattern is None:
        return None
    modified = obs.changed_at or obs.updated_at or obs.created_at
    created = min(obs.created_at or modified, modified)
    out = {
        "type": "indicator",
        "spec_version": SPEC,
        "id": obs.stix_id or indicator_id(obs.type, obs.value_norm),
        "created": ts(created),
        "modified": ts(modified),
        "name": obs.value[:256],
        "indicator_types": indicator_types(obs.reputation),
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ts(obs.first_observed_at or obs.created_at),
        "x_beacon_reputation": obs.reputation,
        "x_beacon_reputation_label": REPUTATIONS.get(obs.reputation, (obs.reputation,))[0],
    }
    if (c := confidence(obs.reputation)) is not None:
        out["confidence"] = c
    if obs.description:
        out["description"] = obs.description[:2000]
    if revoked:
        out["revoked"] = True
    return out


def revoked_tombstone(tomb) -> dict | None:
    """A revoked indicator for a deleted observable, so subscribers retire it."""
    pattern = pattern_for(tomb.type, tomb.value or tomb.value_norm)
    if pattern is None:
        return None
    when = ts(tomb.deleted_at)
    return {"type": "indicator", "spec_version": SPEC, "id": indicator_id(tomb.type, tomb.value_norm), "created": when,
            "modified": when, "name": (tomb.value or tomb.value_norm)[:256], "indicator_types": ["unknown"],
            "pattern": pattern, "pattern_type": "stix", "valid_from": when, "revoked": True}
