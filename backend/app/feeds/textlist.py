"""Parse plain-text threat lists (one IP / URL / domain / hash per line) into feed observables.

Comment lines (#, ;, //) and blank lines are skipped. Only the first whitespace-separated token of a line is used,
which drops trailing comments and extra columns; IP and domain lists may also be comma separated. Values are
refanged (evil[.]com, hxxp://) and normalized like every other source, so they match existing observables.
"""

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field

from app.stix.parser import Parsed, refang
from app.torq.mapping import infer_sub_type, normalize_value

MAX_LINES = 500_000
LIST_TYPES = ("ip", "url", "domain", "auto")
TYPE_LABEL = {"TYPE_ID_IP_ADDRESS": "IP address", "TYPE_ID_URL": "URL", "TYPE_ID_HOSTNAME": "domain",
              "TYPE_ID_FILE_HASH": "file hash"}
_HOST = re.compile(r"(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}", re.I)
_HASH = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", re.I)
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)


@dataclass
class ListResult:
    items: list[Parsed]
    skipped: int = 0
    counts: dict[str, int] = field(default_factory=dict)
    samples: list[str] = field(default_factory=list)
    truncated: bool = False


def listing_id(type_id: str, value_norm: str) -> str:
    return "line:" + hashlib.sha1(f"{type_id}|{value_norm}".encode()).hexdigest()[:20]


def _ip(token: str) -> str | None:
    try:
        if "/" in token:
            net = ipaddress.ip_network(token, strict=False)
            return str(net.network_address) if net.num_addresses == 1 else None
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def _domain(token: str) -> str | None:
    t = token.strip().lower().rstrip(".")
    if t.startswith("*."):
        t = t[2:]
    return t if _HOST.fullmatch(t) and _ip(t) is None else None


_CIDR = re.compile(r"[0-9a-f.:]+/\d{1,3}", re.I)


def _url(token: str) -> str | None:
    if _SCHEME.match(token):
        return token
    if _CIDR.fullmatch(token):
        return None  # an address block, not a URL
    host = token.split("/", 1)[0]
    if "/" in token and (_domain(host.split(":", 1)[0]) or _ip(host.split(":", 1)[0])):
        return "http://" + token
    return None


def classify(token: str, list_type: str) -> tuple[str, str] | None:
    """(Beacon type, value) for a token, or None if it doesn't fit the list type."""
    if list_type == "ip":
        v = _ip(token)
        return ("TYPE_ID_IP_ADDRESS", v) if v else None
    if list_type == "url":
        v = _url(token)
        return ("TYPE_ID_URL", v) if v else None
    if list_type == "domain":
        v = _domain(token)
        return ("TYPE_ID_HOSTNAME", v) if v else None
    if v := _ip(token):
        return "TYPE_ID_IP_ADDRESS", v
    if _SCHEME.match(token):
        return "TYPE_ID_URL", token
    if _HASH.fullmatch(token):
        return "TYPE_ID_FILE_HASH", token.lower()
    if v := _domain(token):
        return "TYPE_ID_HOSTNAME", v
    if v := _url(token):
        return "TYPE_ID_URL", v
    return None


def parse(text: str, list_type: str, reputation: str) -> ListResult:
    result = ListResult(items=[])
    seen: set[tuple[str, str]] = set()
    for n, raw in enumerate(text.splitlines()):
        if n >= MAX_LINES:
            result.truncated = True
            break
        line = raw.strip().lstrip("﻿")
        if not line or line.startswith(("#", ";", "//")):
            continue
        token = line.split()[0]
        if list_type in ("ip", "domain"):
            token = token.split(",")[0]
        token = refang(token.strip().strip("\"'"))
        found = classify(token, list_type)
        if not found:
            result.skipped += 1
            continue
        type_id, value = found
        norm = normalize_value(type_id, value)
        if (type_id, norm) in seen:
            continue
        seen.add((type_id, norm))
        result.items.append(Parsed(
            stix_id=listing_id(type_id, norm), type=type_id, value=value, value_norm=norm,
            sub_type=infer_sub_type(type_id, value), reputation=reputation, description="",
            valid_from=None, valid_until=None, active=True,
        ))
        label = TYPE_LABEL.get(type_id, type_id)
        result.counts[label] = result.counts.get(label, 0) + 1
        if len(result.samples) < 5:
            result.samples.append(value)
    return result
