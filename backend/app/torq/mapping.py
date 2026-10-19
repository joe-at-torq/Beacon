"""Torq observable enums, value-field mapping and value normalisation."""

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime

# type id -> (label, value field in v1ObservableValue)
TYPES: dict[str, tuple[str, str]] = {
    "TYPE_ID_HOSTNAME": ("Hostname", "hostname"),
    "TYPE_ID_IP_ADDRESS": ("IP address", "ip"),
    "TYPE_ID_MAC_ADDRESS": ("MAC address", "mac_address"),
    "TYPE_ID_USER_NAME": ("Username", "username"),
    "TYPE_ID_EMAIL_ADDRESS": ("Email address", "email_address"),
    "TYPE_ID_URL": ("URL", "url"),
    "TYPE_ID_FILE_NAME": ("File name", "file_name"),
    "TYPE_ID_FILE_HASH": ("File hash", "file_hash"),
    "TYPE_ID_PROCESS_NAME": ("Process name", "process_name"),
    "TYPE_ID_RESOURCE_UID": ("Resource UID", "resource_uid"),
    "TYPE_ID_OTHER": ("Other", "other_type"),
    "TYPE_ID_UNKNOWN": ("Unknown", "unknown"),
}
VALUE_FIELD_TO_TYPE = {field: type_id for type_id, (_, field) in TYPES.items()}

# sub type id -> (label, parent type id or None for generic)
SUB_TYPES: dict[str, tuple[str, str | None]] = {
    "SUB_TYPE_ID_UNKNOWN": ("Unknown", None),
    "SUB_TYPE_ID_HOSTNAME_FQDN": ("FQDN", "TYPE_ID_HOSTNAME"),
    "SUB_TYPE_ID_HOSTNAME_NETBIOS": ("NetBIOS", "TYPE_ID_HOSTNAME"),
    "SUB_TYPE_ID_IP_ADDRESS_IPV4": ("IPv4", "TYPE_ID_IP_ADDRESS"),
    "SUB_TYPE_ID_IP_ADDRESS_IPV6": ("IPv6", "TYPE_ID_IP_ADDRESS"),
    "SUB_TYPE_ID_FILE_HASH_MD5": ("MD5", "TYPE_ID_FILE_HASH"),
    "SUB_TYPE_ID_FILE_HASH_SHA1": ("SHA-1", "TYPE_ID_FILE_HASH"),
    "SUB_TYPE_ID_FILE_HASH_SHA256": ("SHA-256", "TYPE_ID_FILE_HASH"),
    "SUB_TYPE_ID_USERNAME_UPN": ("UPN", "TYPE_ID_USER_NAME"),
    "SUB_TYPE_ID_USERNAME_DOMAIN": ("Domain user", "TYPE_ID_USER_NAME"),
    "SUB_TYPE_ID_OTHER": ("Other", None),
}

# reputation id -> (label, severity). Severity 0 = no verdict.
REPUTATIONS: dict[str, tuple[str, int]] = {
    "SCORE_UNKNOWN": ("Unknown", 0),
    "SCORE_OTHER": ("Other", 0),
    "SCORE_VERY_SAFE": ("Very safe", 1),
    "SCORE_SAFE": ("Safe", 2),
    "SCORE_PROBABLY_SAFE": ("Probably safe", 3),
    "SCORE_LEANS_SAFE": ("Leans safe", 4),
    "SCORE_MAY_NOT_BE_SAFE": ("May not be safe", 5),
    "SCORE_EXERCISE_CAUTION": ("Exercise caution", 6),
    "SCORE_SUSPICIOUS_OR_RISKY": ("Suspicious or risky", 7),
    "SCORE_POSSIBLY_MALICIOUS": ("Possibly malicious", 8),
    "SCORE_PROBABLY_MALICIOUS": ("Probably malicious", 9),
    "SCORE_MALICIOUS": ("Malicious", 10),
}


def severity(reputation: str | None) -> int:
    return REPUTATIONS.get(reputation or "", ("", 0))[1]


_HEX_RE = re.compile(r"^[0-9a-f]+$")


def normalize_value(type_id: str, value: str) -> str:
    v = (value or "").strip()
    if type_id == "TYPE_ID_IP_ADDRESS":
        try:
            return ipaddress.ip_address(v).compressed
        except ValueError:
            return v.lower()
    if type_id == "TYPE_ID_HOSTNAME":
        return v.lower().rstrip(".")
    if type_id in ("TYPE_ID_EMAIL_ADDRESS", "TYPE_ID_FILE_HASH"):
        return v.lower()
    if type_id == "TYPE_ID_MAC_ADDRESS":
        digits = re.sub(r"[^0-9a-fA-F]", "", v).lower()
        if len(digits) == 12:
            return ":".join(digits[i : i + 2] for i in range(0, 12, 2))
        return v.lower()
    return v


def infer_sub_type(type_id: str, value: str, current: str | None = None) -> str:
    if current and current != "SUB_TYPE_ID_UNKNOWN":
        return current
    v = (value or "").strip()
    if type_id == "TYPE_ID_IP_ADDRESS":
        try:
            ip = ipaddress.ip_address(v)
            return "SUB_TYPE_ID_IP_ADDRESS_IPV4" if ip.version == 4 else "SUB_TYPE_ID_IP_ADDRESS_IPV6"
        except ValueError:
            pass
    elif type_id == "TYPE_ID_FILE_HASH" and _HEX_RE.match(v.lower()):
        return {32: "SUB_TYPE_ID_FILE_HASH_MD5", 40: "SUB_TYPE_ID_FILE_HASH_SHA1",
                64: "SUB_TYPE_ID_FILE_HASH_SHA256"}.get(len(v), "SUB_TYPE_ID_UNKNOWN")
    elif type_id == "TYPE_ID_HOSTNAME" and "." in v:
        return "SUB_TYPE_ID_HOSTNAME_FQDN"
    return current or "SUB_TYPE_ID_UNKNOWN"


def parse_ts(value: str | None) -> datetime | None:
    """Parse an RFC 3339 timestamp (possibly with nanoseconds) to naive UTC."""
    if not value:
        return None
    s = value.strip().replace("Z", "+00:00")
    m = re.match(r"^(.*?\.\d{6})\d*(.*)$", s)
    if m:
        s = m.group(1) + m.group(2)
    try:
        ts = datetime.fromisoformat(s)
    except ValueError:
        return None
    if ts.tzinfo is not None:
        ts = ts.astimezone(UTC).replace(tzinfo=None)
    return ts


def _int(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _enum_id(obj, default: str) -> str:
    if isinstance(obj, dict):
        return obj.get("id") or default
    if isinstance(obj, str) and obj:
        return obj
    return default


@dataclass
class RemoteObservable:
    remote_id: str
    type: str
    sub_type: str
    value: str
    reputation: str
    description: str
    first_observed_at: datetime | None
    last_observed_at: datetime | None
    updated_at: datetime | None
    enrichment: dict | None = None
    enrichment_updated_at: datetime | None = None
    cases_count: int = 0


def parse_remote(raw: dict) -> RemoteObservable | None:
    """Convert a Torq API observable into a RemoteObservable; None if it has no usable value."""
    type_id = _enum_id(raw.get("type"), "TYPE_ID_UNKNOWN")
    value_obj = raw.get("value") or {}
    value = ""
    if isinstance(value_obj, dict):
        field = TYPES.get(type_id, ("", ""))[1]
        value = value_obj.get(field) or ""
        if not value:
            for f, v in value_obj.items():
                if v:
                    value = str(v)
                    if type_id == "TYPE_ID_UNKNOWN" and f in VALUE_FIELD_TO_TYPE:
                        type_id = VALUE_FIELD_TO_TYPE[f]
                    break
    elif isinstance(value_obj, str):
        value = value_obj
    if not value or raw.get("id") is None:
        return None
    sub_type = infer_sub_type(type_id, value, _enum_id(raw.get("sub_type"), "SUB_TYPE_ID_UNKNOWN"))
    return RemoteObservable(
        remote_id=str(raw["id"]),
        type=type_id,
        sub_type=sub_type,
        value=value,
        reputation=_enum_id(raw.get("reputation"), "SCORE_UNKNOWN"),
        description=raw.get("description") or "",
        first_observed_at=parse_ts(raw.get("first_observed_at")),
        last_observed_at=parse_ts(raw.get("last_observed_at")),
        updated_at=parse_ts(raw.get("updated_at")) or parse_ts(raw.get("last_observed_at")),
        enrichment=raw["enrichment"] if isinstance(raw.get("enrichment"), dict) and raw["enrichment"] else None,
        enrichment_updated_at=parse_ts(raw.get("enrichment_updated_at")),
        cases_count=_int(raw.get("associated_cases_count")),
    )


def build_payload(type_id: str, sub_type: str, value: str, reputation: str, description: str) -> dict:
    field = TYPES.get(type_id, ("", "unknown"))[1]
    obs: dict = {
        "type": {"id": type_id},
        "value": {field: value},
        "reputation": {"id": reputation or "SCORE_UNKNOWN"},
    }
    if sub_type and sub_type != "SUB_TYPE_ID_UNKNOWN":
        obs["sub_type"] = {"id": sub_type}
    if description:
        obs["description"] = description
    return obs
