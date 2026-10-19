"""Parse STIX 2.0 / 2.1 indicators into Beacon observables (no external dependencies).

Only indicators with a STIX pattern are used. Every equality comparison on a supported object path becomes an
observable (``[ipv4-addr:value = '1.2.3.4' OR domain-name:value = 'evil.com']`` yields two). Comparisons using
other operators (``!=``, ``LIKE``, ``MATCHES``, ``NOT =`` ...) are skipped: they don't name a concrete value.
"""

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from app.torq.mapping import REPUTATIONS, infer_sub_type, normalize_value, severity

# object path -> Beacon type (hash keys are handled separately)
PATHS = {
    "ipv4-addr:value": "TYPE_ID_IP_ADDRESS",
    "ipv6-addr:value": "TYPE_ID_IP_ADDRESS",
    "domain-name:value": "TYPE_ID_HOSTNAME",
    "url:value": "TYPE_ID_URL",
    "email-addr:value": "TYPE_ID_EMAIL_ADDRESS",
    "email-message:from_ref.value": "TYPE_ID_EMAIL_ADDRESS",
    "email-message:sender_ref.value": "TYPE_ID_EMAIL_ADDRESS",
}
HASH_KEYS = {"md5": "MD5", "sha-1": "SHA-1", "sha1": "SHA-1", "sha-256": "SHA-256", "sha256": "SHA-256"}
MALICIOUS_TYPES = {"malicious-activity", "compromised", "attribution"}

_COMPARISON = re.compile(
    r"(?P<path>[a-z0-9-]+:[A-Za-z0-9_.\-'\"]+(?:\[\*\]|\[\d+\])?(?:\.[A-Za-z0-9_\-'\"]+)*)"
    r"\s*(?P<op>!=|=|>=|<=|>|<|\bLIKE\b|\bMATCHES\b|\bIN\b|\bISSUBSET\b|\bISSUPERSET\b|\bNOT\b)\s*"
    r"(?P<val>'(?:[^'\\]|\\.)*')?"
)


@dataclass(frozen=True)
class Parsed:
    stix_id: str
    type: str
    value: str
    value_norm: str
    sub_type: str
    reputation: str
    description: str
    valid_from: datetime | None
    valid_until: datetime | None
    active: bool  # False for revoked / expired / below minimum confidence (deactivates existing links)


def parse_time(value) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else dt


def _unquote(literal: str) -> str:
    return re.sub(r"\\(.)", r"\1", literal[1:-1])


def refang(value: str) -> str:
    """Undo common defanging (evil[.]com, hxxp://, user[@]example.com) so values match existing observables."""
    v = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]", ".", value, flags=re.I)
    v = re.sub(r"\[\s*@\s*\]|\[at\]", "@", v, flags=re.I)
    v = re.sub(r"\[\s*:\s*\]", ":", v)
    return re.sub(r"^hxxp(s?)(\[?:\]?)//", r"http\1://", v, flags=re.I)


def _hash_path(path: str) -> bool:
    m = re.fullmatch(r"(?:artifact|file):hashes\.['\"]?([A-Za-z0-9-]+)['\"]?", path)
    return bool(m and m.group(1).lower() in HASH_KEYS)


def extract(pattern: str) -> list[tuple[str, str]]:
    """(Beacon type, raw value) for every equality comparison on a supported path."""
    out = []
    for m in _COMPARISON.finditer(pattern or ""):
        if m.group("op") != "=" or not m.group("val"):
            continue
        path, value = m.group("path"), refang(_unquote(m.group("val")).strip())
        if not value:
            continue
        if _hash_path(path):
            if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
                out.append(("TYPE_ID_FILE_HASH", value))
            continue
        type_id = PATHS.get(path)
        if not type_id:
            continue
        if type_id == "TYPE_ID_IP_ADDRESS":
            value = _single_ip(value)
            if not value:
                continue
        out.append((type_id, value))
    return out


def _single_ip(value: str) -> str | None:
    """An IP, or a CIDR block covering exactly one address; anything else is skipped."""
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            return str(net.network_address) if net.num_addresses == 1 else None
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def reputation_for(indicator: dict, default: str) -> str:
    """Feed default, refined by the indicator's STIX types (2.1 indicator_types, 2.0 labels)."""
    kinds = {str(k).lower() for k in (indicator.get("indicator_types") or indicator.get("labels") or [])}
    if kinds & MALICIOUS_TYPES:
        return default if severity(default) > severity("SCORE_MALICIOUS") else "SCORE_MALICIOUS"
    if "anomalous-activity" in kinds:
        return "SCORE_SUSPICIOUS_OR_RISKY"
    if "benign" in kinds:
        return "SCORE_PROBABLY_SAFE"
    return default if default in REPUTATIONS else "SCORE_UNKNOWN"


def parse_indicator(obj: dict, default_reputation: str, min_confidence: int = 0, now: datetime | None = None) -> list[Parsed]:
    if not isinstance(obj, dict) or obj.get("type") != "indicator":
        return []
    if obj.get("pattern_type", "stix") != "stix":
        return []  # e.g. snort, yara, sigma
    now = now or datetime.now(UTC).replace(tzinfo=None)
    valid_from = parse_time(obj.get("valid_from")) or parse_time(obj.get("created"))
    valid_until = parse_time(obj.get("valid_until"))
    confidence = obj.get("confidence")
    active = not obj.get("revoked") and not (valid_until and valid_until <= now)
    if isinstance(confidence, int | float) and confidence < min_confidence:
        active = False
    reputation = reputation_for(obj, default_reputation)
    description = str(obj.get("name") or obj.get("description") or "")[:500]
    out, seen = [], set()
    for type_id, value in extract(obj.get("pattern", "")):
        norm = normalize_value(type_id, value)
        if (type_id, norm) in seen:
            continue
        seen.add((type_id, norm))
        out.append(Parsed(
            stix_id=str(obj.get("id", ""))[:128], type=type_id, value=value, value_norm=norm,
            sub_type=infer_sub_type(type_id, value), reputation=reputation, description=description,
            valid_from=valid_from, valid_until=valid_until, active=active,
        ))
    return out


def parse_objects(objects, default_reputation: str, min_confidence: int = 0, now: datetime | None = None) -> list[Parsed]:
    """Observables from a list of STIX objects (a bundle's or a TAXII envelope's "objects")."""
    out: list[Parsed] = []
    for obj in objects or []:
        out.extend(parse_indicator(obj, default_reputation, min_confidence, now))
    return out
