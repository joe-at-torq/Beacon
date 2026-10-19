"""Threat-intelligence provider clients used to enrich observables.

Each provider declares which observable types it supports, how to look one up, and how to summarize the
response into a common shape:

    {verdict, headline, stats, suggested_reputation, link, tags}

verdict is one of: malicious | suspicious | harmless | unknown
"""

import base64
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import quote

import httpx

TIMEOUT = 20.0
USER_AGENT = "Beacon-Threat-Intelligence-Manager/1.0"
VERDICT_REPUTATION = {
    "malicious": "SCORE_MALICIOUS",
    "suspicious": "SCORE_SUSPICIOUS_OR_RISKY",
    "harmless": "SCORE_PROBABLY_SAFE",
}


class IntelError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass
class LookupResult:
    status: str  # ok | not_found
    summary: dict
    data: dict | None = None


@dataclass
class Provider:
    id: str
    name: str
    description: str
    types: list[str]
    key_help: str
    docs_url: str
    color: str
    monogram: str = ""
    # Sub-type restrictions per type; a type that isn't listed accepts all of its sub-types.
    sub_types: dict[str, list[str]] = field(default_factory=dict)
    transport: httpx.AsyncBaseTransport | None = field(default=None, repr=False)

    def client(self, api_key: str) -> httpx.AsyncClient:
        raise NotImplementedError

    def supports(self, type_id: str, sub_type: str | None = None) -> bool:
        if type_id not in self.types:
            return False
        allowed = self.sub_types.get(type_id)
        # Unknown/unclassified sub-types are given the benefit of the doubt.
        return not allowed or sub_type in (None, "", "SUB_TYPE_ID_UNKNOWN", "SUB_TYPE_ID_OTHER") or sub_type in allowed

    async def test(self, api_key: str) -> str:
        raise NotImplementedError

    async def lookup(self, api_key: str, type_id: str, value: str) -> LookupResult:
        raise NotImplementedError


def _raise_for(resp: httpx.Response, provider: str) -> None:
    if resp.status_code in (401, 403):
        raise IntelError(f"{provider} rejected the API key ({resp.status_code})", resp.status_code)
    if resp.status_code == 429:
        raise IntelError(f"{provider} rate limit reached (429): try again shortly or upgrade the API quota", 429)
    if resp.status_code >= 400:
        raise IntelError(f"{provider} request failed ({resp.status_code}): {resp.text[:200]}", resp.status_code)


def _verdict_summary(
    verdict: str, headline: str, stats: dict, link: str, tags: list[str] | None = None,
    facts: list[tuple[str, object]] | None = None,
) -> dict:
    return {
        "verdict": verdict,
        "headline": headline,
        "stats": stats,
        "suggested_reputation": VERDICT_REPUTATION.get(verdict),
        "link": link,
        "tags": [t for t in (tags or []) if t][:12],
        # Provider-chosen key facts shown as a label/value grid in the UI.
        "facts": [{"label": label, "value": value} for label, value in (facts or []) if value not in (None, "", [])],
    }


def _json_client(base: str, headers: dict, transport) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=base, headers={"Accept": "application/json", "User-Agent": USER_AGENT, **headers},
                             timeout=TIMEOUT, transport=transport)


# ---- VirusTotal (API v3) --------------------------------------------------------------------------

class VirusTotal(Provider):
    BASE = "https://www.virustotal.com/api/v3"
    GUI = "https://www.virustotal.com/gui"

    def client(self, api_key: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=self.BASE, headers={"x-apikey": api_key, "Accept": "application/json"},
                                 timeout=TIMEOUT, transport=self.transport)

    @staticmethod
    def _path(type_id: str, value: str) -> tuple[str, str]:
        if type_id == "TYPE_ID_IP_ADDRESS":
            return f"/ip_addresses/{value}", f"ip-address/{value}"
        if type_id == "TYPE_ID_HOSTNAME":
            return f"/domains/{value}", f"domain/{value}"
        if type_id == "TYPE_ID_URL":
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            return f"/urls/{url_id}", f"url/{url_id}"
        if type_id == "TYPE_ID_FILE_HASH":
            return f"/files/{value}", f"file/{value}"
        raise IntelError(f"VirusTotal does not support {type_id}")

    async def test(self, api_key: str) -> str:
        async with self.client(api_key) as c:
            resp = await c.get("/ip_addresses/8.8.8.8")
        _raise_for(resp, self.name)
        return "Connected to VirusTotal"

    async def lookup(self, api_key: str, type_id: str, value: str) -> LookupResult:
        path, gui = self._path(type_id, value)
        async with self.client(api_key) as c:
            resp = await c.get(path)
        link = f"{self.GUI}/{gui}"
        if resp.status_code == 404:
            return LookupResult("not_found", _verdict_summary("unknown", "Not found in VirusTotal", {}, link))
        _raise_for(resp, self.name)
        data = resp.json()
        attrs = (data.get("data") or {}).get("attributes") or {}
        s = attrs.get("last_analysis_stats") or {}
        mal, sus = int(s.get("malicious", 0)), int(s.get("suspicious", 0))
        harmless, undetected = int(s.get("harmless", 0)), int(s.get("undetected", 0))
        total = sum(int(v) for v in s.values() if isinstance(v, int))
        verdict = "malicious" if mal >= 3 else "suspicious" if (mal or sus) else "harmless" if harmless else "unknown"
        stats = {"malicious": mal, "suspicious": sus, "harmless": harmless, "undetected": undetected,
                 "total": total, "reputation": attrs.get("reputation")}
        headline = f"{mal}/{total} engines flag as malicious" if total else "No analysis results"
        tags = list(attrs.get("tags") or [])
        return LookupResult("ok", _verdict_summary(verdict, headline, stats, link, tags), data)


# ---- AlienVault OTX --------------------------------------------------------------------------------

class AlienVaultOTX(Provider):
    BASE = "https://otx.alienvault.com/api/v1"
    GUI = "https://otx.alienvault.com/indicator"

    def client(self, api_key: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=self.BASE, headers={"X-OTX-API-KEY": api_key, "Accept": "application/json"},
                                 timeout=TIMEOUT, transport=self.transport)

    @staticmethod
    def _section(type_id: str, value: str) -> tuple[str, str]:
        if type_id == "TYPE_ID_IP_ADDRESS":
            kind = "IPv6" if ipaddress.ip_address(value).version == 6 else "IPv4"
            return kind, "ip"
        if type_id == "TYPE_ID_HOSTNAME":
            # OTX treats registrable domains and sub-domains separately.
            kind = "domain" if value.count(".") <= 1 else "hostname"
            return kind, kind
        if type_id == "TYPE_ID_URL":
            return "url", "url"
        if type_id == "TYPE_ID_FILE_HASH":
            return "file", "file"
        raise IntelError(f"AlienVault OTX does not support {type_id}")

    async def test(self, api_key: str) -> str:
        async with self.client(api_key) as c:
            resp = await c.get("/users/me")
        _raise_for(resp, self.name)
        user = resp.json()
        who = user.get("username") or user.get("user_id")
        return f"Connected to AlienVault OTX{f' as {who}' if who else ''}"

    async def lookup(self, api_key: str, type_id: str, value: str) -> LookupResult:
        kind, gui_kind = self._section(type_id, value)
        async with self.client(api_key) as c:
            resp = await c.get(f"/indicators/{kind}/{quote(value, safe='')}/general")
        link = f"{self.GUI}/{gui_kind}/{quote(value, safe='')}"
        if resp.status_code == 404:
            return LookupResult("not_found", _verdict_summary("unknown", "Not found in AlienVault OTX", {}, link))
        _raise_for(resp, self.name)
        data = resp.json()
        pulse_info = data.get("pulse_info") or {}
        pulses = int(pulse_info.get("count") or 0)
        names = [p.get("name") for p in (pulse_info.get("pulses") or [])[:5] if p.get("name")]
        tags = sorted({t for p in (pulse_info.get("pulses") or []) for t in (p.get("tags") or [])})
        malware = [f.get("display_name") for f in (pulse_info.get("related", {}).get("alienvault", {}).get("malware_families") or [])
                   if isinstance(f, dict)]
        verdict = "malicious" if pulses >= 5 else "suspicious" if pulses else "unknown"
        stats = {"pulses": pulses, "reputation": data.get("reputation"), "top_pulses": names,
                 "malware_families": [m for m in malware if m][:5]}
        headline = f"Referenced in {pulses} OTX pulse{'s' if pulses != 1 else ''}" if pulses else "Not referenced in any OTX pulse"
        return LookupResult("ok", _verdict_summary(verdict, headline, stats, link, tags), data)


# ---- AbuseIPDB (API v2) -----------------------------------------------------------------------------

class AbuseIPDB(Provider):
    BASE = "https://api.abuseipdb.com/api/v2"

    def client(self, api_key: str) -> httpx.AsyncClient:
        return _json_client(self.BASE, {"Key": api_key}, self.transport)

    async def test(self, api_key: str) -> str:
        async with self.client(api_key) as c:
            resp = await c.get("/check", params={"ipAddress": "8.8.8.8"})
        _raise_for(resp, self.name)
        return "Connected to AbuseIPDB"

    async def lookup(self, api_key: str, type_id: str, value: str) -> LookupResult:
        if type_id != "TYPE_ID_IP_ADDRESS":
            raise IntelError(f"AbuseIPDB does not support {type_id}")
        async with self.client(api_key) as c:
            resp = await c.get("/check", params={"ipAddress": value, "maxAgeInDays": 90})
        _raise_for(resp, self.name)
        data = resp.json()
        d = data.get("data") or {}
        score, reports = int(d.get("abuseConfidenceScore") or 0), int(d.get("totalReports") or 0)
        users = int(d.get("numDistinctUsers") or 0)
        if d.get("isWhitelisted"):
            verdict = "harmless"
        else:
            verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "unknown"
        headline = (f"Abuse confidence {score}% · {reports} report{'s' if reports != 1 else ''} from {users} user{'s' if users != 1 else ''}"
                    if reports else "No abuse reports in the last 90 days")
        stats = {"abuse_confidence": score, "reports": reports, "distinct_users": users}
        facts = [("Abuse confidence", f"{score}%"), ("Reports (90 days)", reports), ("Country", d.get("countryCode")),
                 ("ISP", d.get("isp")), ("Usage type", d.get("usageType")), ("Domain", d.get("domain")),
                 ("Tor exit node", "Yes" if d.get("isTor") else None), ("Whitelisted", "Yes" if d.get("isWhitelisted") else None),
                 ("Last reported", d.get("lastReportedAt"))]
        tags = [d.get("usageType"), "tor" if d.get("isTor") else None]
        return LookupResult("ok", _verdict_summary(verdict, headline, stats, f"https://www.abuseipdb.com/check/{value}",
                                                   tags, facts), data)


# ---- urlscan.io ------------------------------------------------------------------------------------

class URLScan(Provider):
    BASE = "https://urlscan.io"

    def client(self, api_key: str) -> httpx.AsyncClient:
        return _json_client(self.BASE, {"API-Key": api_key}, self.transport)

    @staticmethod
    def query(type_id: str, value: str) -> str:
        if type_id == "TYPE_ID_IP_ADDRESS":
            return f"ip:{value}"
        if type_id == "TYPE_ID_HOSTNAME":
            return f"domain:{value}"
        if type_id == "TYPE_ID_URL":
            return 'page.url:"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
        if type_id == "TYPE_ID_FILE_HASH":
            return f"hash:{value}"
        raise IntelError(f"urlscan.io does not support {type_id}")

    async def test(self, api_key: str) -> str:
        async with self.client(api_key) as c:
            resp = await c.get("/user/quotas/")
        _raise_for(resp, self.name)
        return "Connected to urlscan.io"

    async def lookup(self, api_key: str, type_id: str, value: str) -> LookupResult:
        q = self.query(type_id, value)
        async with self.client(api_key) as c:
            resp = await c.get("/api/v1/search/", params={"q": q, "size": 100})
        _raise_for(resp, self.name)
        data = resp.json()
        results = data.get("results") or []
        total = int(data.get("total") or len(results))
        search_link = f"https://urlscan.io/search/#{quote(q, safe='')}"
        if not total:
            return LookupResult("not_found", _verdict_summary("unknown", "Not seen in any urlscan.io scan", {}, search_link),
                                data)
        malicious = sum(1 for r in results if (r.get("verdicts") or {}).get("malicious"))
        latest = results[0] if results else {}
        verdict = "malicious" if malicious else "unknown"
        headline = f"Seen in {total} scan{'s' if total != 1 else ''}" + (f" · {malicious} flagged malicious" if malicious else "")
        page, task = latest.get("page") or {}, latest.get("task") or {}
        stats = {"scans": total, "malicious_scans": malicious}
        facts = [("Scans", total), ("Flagged malicious", malicious or None), ("Last scanned", task.get("time")),
                 ("Last URL", page.get("url")), ("Server IP", page.get("ip")), ("Country", page.get("country")),
                 ("Server", page.get("server")), ("TLS issuer", page.get("tlsIssuer"))]
        link = f"https://urlscan.io/result/{latest['_id']}/" if latest.get("_id") else search_link
        tags = sorted({t for r in results for t in ((r.get("task") or {}).get("tags") or [])})
        return LookupResult("ok", _verdict_summary(verdict, headline, stats, link, tags, facts), data)


# ---- Recorded Future (Connect API v2) ----------------------------------------------------------------

class RecordedFuture(Provider):
    BASE = "https://api.recordedfuture.com/v2"
    PATHS = {"TYPE_ID_IP_ADDRESS": "ip", "TYPE_ID_HOSTNAME": "domain", "TYPE_ID_URL": "url", "TYPE_ID_FILE_HASH": "hash"}

    def client(self, api_key: str) -> httpx.AsyncClient:
        return _json_client(self.BASE, {"X-RFToken": api_key}, self.transport)

    async def test(self, api_key: str) -> str:
        async with self.client(api_key) as c:
            resp = await c.get("/ip/8.8.8.8", params={"fields": "risk"})
        _raise_for(resp, self.name)
        return "Connected to Recorded Future"

    async def lookup(self, api_key: str, type_id: str, value: str) -> LookupResult:
        kind = self.PATHS.get(type_id)
        if not kind:
            raise IntelError(f"Recorded Future does not support {type_id}")
        async with self.client(api_key) as c:
            resp = await c.get(f"/{kind}/{quote(value, safe='')}", params={"fields": "entity,risk,intelCard"})
        if resp.status_code == 404:
            return LookupResult("not_found", _verdict_summary("unknown", "Not found in Recorded Future", {}, ""))
        _raise_for(resp, self.name)
        data = resp.json()
        d = data.get("data") or {}
        risk = d.get("risk") or {}
        score = int(risk.get("score") or 0)
        label = risk.get("criticalityLabel") or "None"
        verdict = "malicious" if score >= 65 else "suspicious" if score >= 25 else "unknown"
        rules = [e.get("rule") for e in sorted(risk.get("evidenceDetails") or [], key=lambda e: -(e.get("criticality") or 0))]
        headline = f"Risk score {score}/99 · {label}" + (f" · {risk['riskSummary']}" if risk.get("riskSummary") else "")
        stats = {"risk_score": score, "criticality": label, "rules_triggered": risk.get("rules")}
        facts = [("Risk score", f"{score}/99"), ("Criticality", label), ("Risk rules", risk.get("riskSummary")),
                 ("Top evidence", ", ".join(r for r in rules[:3] if r))]
        return LookupResult("ok", _verdict_summary(verdict, headline, stats, d.get("intelCard") or "", rules[:8], facts), data)


# ---- GreyNoise (Community API) ------------------------------------------------------------------------

class GreyNoise(Provider):
    BASE = "https://api.greynoise.io"

    def client(self, api_key: str) -> httpx.AsyncClient:
        return _json_client(self.BASE, {"key": api_key}, self.transport)

    async def test(self, api_key: str) -> str:
        async with self.client(api_key) as c:
            resp = await c.get("/v3/community/8.8.8.8")
        if resp.status_code != 404:  # 404 = "not observed", which still proves the key works
            _raise_for(resp, self.name)
        return "Connected to GreyNoise"

    async def lookup(self, api_key: str, type_id: str, value: str) -> LookupResult:
        if type_id != "TYPE_ID_IP_ADDRESS":
            raise IntelError(f"GreyNoise does not support {type_id}")
        async with self.client(api_key) as c:
            resp = await c.get(f"/v3/community/{value}")
        link = f"https://viz.greynoise.io/ip/{value}"
        if resp.status_code == 404:
            return LookupResult("not_found", _verdict_summary(
                "unknown", "Not observed scanning the internet and not a known benign service", {}, link), resp.json() if resp.content else None)
        _raise_for(resp, self.name)
        data = resp.json()
        cls, noise, riot = data.get("classification") or "unknown", bool(data.get("noise")), bool(data.get("riot"))
        if cls == "malicious":
            verdict = "malicious"
        elif cls == "benign" or riot:
            verdict = "harmless"
        else:
            verdict = "suspicious" if noise else "unknown"
        if riot:
            headline = f"Known benign service: {data.get('name') or 'RIOT dataset'}"
        elif noise:
            headline = f"Internet scanner · classified {cls}" + (f" ({data['name']})" if data.get("name") and data["name"] != "unknown" else "")
        else:
            headline = f"Classified {cls}"
        stats = {"classification": cls, "noise": noise, "riot": riot}
        facts = [("Classification", cls.capitalize()), ("Internet scanner (noise)", "Yes" if noise else "No"),
                 ("Benign service (RIOT)", "Yes" if riot else "No"), ("Actor / service", data.get("name")),
                 ("Last seen", data.get("last_seen"))]
        return LookupResult("ok", _verdict_summary(verdict, headline, stats, data.get("link") or link,
                                                   [cls, "noise" if noise else None, "riot" if riot else None], facts), data)


# ---- EmailRep.io -------------------------------------------------------------------------------------

class EmailRep(Provider):
    BASE = "https://emailrep.io"
    FLAGS = [("blacklisted", "Blacklisted"), ("malicious_activity", "Malicious activity"),
             ("malicious_activity_recent", "Recent malicious activity"), ("credentials_leaked", "Credentials leaked"),
             ("data_breach", "In a data breach"), ("spam", "Spam"), ("disposable", "Disposable"),
             ("suspicious_tld", "Suspicious TLD"), ("new_domain", "New domain"), ("spoofable", "Spoofable")]

    def client(self, api_key: str) -> httpx.AsyncClient:
        return _json_client(self.BASE, {"Key": api_key}, self.transport)

    async def test(self, api_key: str) -> str:
        async with self.client(api_key) as c:
            resp = await c.get("/bill@microsoft.com")
        _raise_for(resp, self.name)
        return "Connected to EmailRep.io"

    async def lookup(self, api_key: str, type_id: str, value: str) -> LookupResult:
        if type_id != "TYPE_ID_EMAIL_ADDRESS":
            raise IntelError(f"EmailRep.io does not support {type_id}")
        async with self.client(api_key) as c:
            resp = await c.get(f"/{quote(value, safe='@')}")
        _raise_for(resp, self.name)
        data = resp.json()
        details = data.get("details") or {}
        rep, suspicious = data.get("reputation") or "none", bool(data.get("suspicious"))
        if details.get("malicious_activity") or details.get("blacklisted"):
            verdict = "malicious"
        elif suspicious:
            verdict = "suspicious"
        elif rep in ("high", "medium"):
            verdict = "harmless"
        else:
            verdict = "unknown"
        refs = int(data.get("references") or 0)
        flags = [label for key, label in self.FLAGS if details.get(key)]
        headline = f"Reputation {rep}" + (" · suspicious" if suspicious else "") + f" · {refs} reference{'s' if refs != 1 else ''}"
        stats = {"reputation": rep, "suspicious": suspicious, "references": refs,
                 **{key: bool(details.get(key)) for key, _ in self.FLAGS}}
        facts = [("Reputation", rep.capitalize()), ("Suspicious", "Yes" if suspicious else "No"), ("References", refs),
                 ("Domain reputation", details.get("domain_reputation")), ("First seen", details.get("first_seen")),
                 ("Last seen", details.get("last_seen")), ("Deliverable", {True: "Yes", False: "No"}.get(details.get("deliverable"))),
                 ("Free provider", "Yes" if details.get("free_provider") else None), ("Profiles", ", ".join(details.get("profiles") or []))]
        return LookupResult("ok", _verdict_summary(verdict, headline, stats, "", flags, facts), data)


PROVIDERS: dict[str, Provider] = {
    "virustotal": VirusTotal(
        id="virustotal",
        name="VirusTotal",
        description="Multi-engine reputation for IPs, domains, URLs and file hashes.",
        types=["TYPE_ID_IP_ADDRESS", "TYPE_ID_HOSTNAME", "TYPE_ID_URL", "TYPE_ID_FILE_HASH"],
        key_help="VirusTotal → your profile menu → API key.",
        docs_url="https://docs.virustotal.com/reference/overview",
        color="#394EFF",
        monogram="VT",
        sub_types={"TYPE_ID_HOSTNAME": ["SUB_TYPE_ID_HOSTNAME_FQDN"]},
    ),
    "otx": AlienVaultOTX(
        id="otx",
        name="AlienVault OTX",
        description="Open Threat Exchange community pulses for IPs, domains, hostnames, URLs and file hashes.",
        types=["TYPE_ID_IP_ADDRESS", "TYPE_ID_HOSTNAME", "TYPE_ID_URL", "TYPE_ID_FILE_HASH"],
        key_help="OTX → Settings → OTX Key.",
        docs_url="https://otx.alienvault.com/api",
        color="#00A88E",
        monogram="OTX",
        sub_types={"TYPE_ID_HOSTNAME": ["SUB_TYPE_ID_HOSTNAME_FQDN"]},
    ),
    "abuseipdb": AbuseIPDB(
        id="abuseipdb",
        name="AbuseIPDB",
        description="Crowd-sourced abuse reports and confidence score for IP addresses.",
        types=["TYPE_ID_IP_ADDRESS"],
        key_help="AbuseIPDB → Account → API → Create Key.",
        docs_url="https://docs.abuseipdb.com/",
        color="#B91C1C",
        monogram="AI",
    ),
    "urlscan": URLScan(
        id="urlscan",
        name="urlscan.io",
        description="Website scan history and verdicts for URLs, domains, IPs and response hashes (SHA-256).",
        types=["TYPE_ID_URL", "TYPE_ID_HOSTNAME", "TYPE_ID_IP_ADDRESS", "TYPE_ID_FILE_HASH"],
        key_help="urlscan.io → Settings & API → API Keys.",
        docs_url="https://urlscan.io/docs/api/",
        color="#0F6AB4",
        monogram="US",
        sub_types={"TYPE_ID_HOSTNAME": ["SUB_TYPE_ID_HOSTNAME_FQDN"], "TYPE_ID_FILE_HASH": ["SUB_TYPE_ID_FILE_HASH_SHA256"]},
    ),
    "recordedfuture": RecordedFuture(
        id="recordedfuture",
        name="Recorded Future",
        description="Risk scores, criticality and evidence for IPs, domains, URLs and file hashes.",
        types=["TYPE_ID_IP_ADDRESS", "TYPE_ID_HOSTNAME", "TYPE_ID_URL", "TYPE_ID_FILE_HASH"],
        key_help="Recorded Future → User Settings → API Access (Connect API token).",
        docs_url="https://docs.recordedfuture.com/reference/get-started",
        color="#13294B",
        monogram="RF",
        sub_types={"TYPE_ID_HOSTNAME": ["SUB_TYPE_ID_HOSTNAME_FQDN"]},
    ),
    "greynoise": GreyNoise(
        id="greynoise",
        name="GreyNoise",
        description="Separates internet background noise and benign services from targeted activity for IPs.",
        types=["TYPE_ID_IP_ADDRESS"],
        key_help="GreyNoise → Account → API Key (Community API).",
        docs_url="https://docs.greynoise.io/docs/using-the-greynoise-community-api",
        color="#1F6F54",
        monogram="GN",
        sub_types={"TYPE_ID_IP_ADDRESS": ["SUB_TYPE_ID_IP_ADDRESS_IPV4"]},  # GreyNoise observes IPv4 only
    ),
    "emailrep": EmailRep(
        id="emailrep",
        name="EmailRep.io",
        description="Reputation, breach exposure and abuse signals for email addresses.",
        types=["TYPE_ID_EMAIL_ADDRESS"],
        key_help="Use an existing EmailRep.io API key (the service is not issuing new keys at the moment).",
        docs_url="https://docs.sublime.security/docs/emailrep-introduction",
        color="#6D28D9",
        monogram="ER",
    ),
}
