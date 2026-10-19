"""Threat-intel reputation normalization: rules per provider signal -> Torq reputation, combined across sources."""

import httpx
import respx

from app.intel import normalize as norm
from app.intel.providers import _verdict_summary
from app.models import IntelEnrichment, Observable

IP = "TYPE_ID_IP_ADDRESS"


def _obs(db, value, reputation="SCORE_UNKNOWN", **intel) -> Observable:
    o = Observable(type=IP, value=value, value_norm=value, reputation=reputation, origin="workspace", links=[])
    db.add(o)
    db.flush()
    for provider, (verdict, stats) in intel.items():
        o.intel.append(IntelEnrichment(provider=provider, status="ok", fetched_by="t",
                                       summary=_verdict_summary(verdict, "h", stats, "")))
    db.commit()
    return o


def _rules(client, provider, rules):
    r = client.put(f"/api/normalization/rules/{provider}", json=rules)
    assert r.status_code == 200, r.text
    return r.json()


def _settings(client, **kw):
    assert client.put("/api/normalization/settings", json=kw).status_code == 200


VT = [{"metric": "malicious_engines", "operator": ">=", "value": 5, "reputation": "SCORE_MALICIOUS"},
      {"metric": "malicious_engines", "operator": ">=", "value": 1, "reputation": "SCORE_SUSPICIOUS_OR_RISKY"}]
ABUSE = [{"metric": "abuse_confidence", "operator": ">=", "value": 50, "reputation": "SCORE_PROBABLY_MALICIOUS"}]
GN = [{"metric": "riot", "operator": "==", "value": True, "reputation": "SCORE_SAFE"}]


def test_rules_and_strategies(admin_client, db):
    o = _obs(db, "203.0.113.1", virustotal=("suspicious", {"malicious": 2, "total": 90}),
             abuseipdb=("malicious", {"abuse_confidence": 80}), greynoise=("harmless", {"riot": True}))
    _rules(admin_client, "virustotal", VT)
    _rules(admin_client, "abuseipdb", ABUSE)
    _rules(admin_client, "greynoise", GN)

    def normalized():
        return admin_client.get(f"/api/observables/{o.id}").json()["normalized"]

    n = normalized()  # default: most severe
    assert n["reputation"] == "SCORE_PROBABLY_MALICIOUS" and n["decided_by"] == "abuseipdb" and n["differs"] is True
    vt = next(c for c in n["contributions"] if c["provider"] == "virustotal")
    assert vt["reputation"] == "SCORE_SUSPICIOUS_OR_RISKY" and vt["actual"] == 2  # first matching rule wins

    _settings(admin_client, strategy="lowest_severity")
    assert normalized()["reputation"] == "SCORE_SAFE"
    _settings(admin_client, strategy="priority", provider_order=["virustotal", "abuseipdb", "greynoise"])
    assert normalized()["decided_by"] == "virustotal"
    _settings(admin_client, strategy="most_common")
    assert normalized()["reputation"] == "SCORE_PROBABLY_MALICIOUS"  # all tie at 1 -> most severe


def test_fallback_to_builtin_verdicts(admin_client, db):
    o = _obs(db, "203.0.113.2", otx=("suspicious", {"pulses": 3}))
    assert admin_client.get(f"/api/observables/{o.id}").json()["normalized"] is None
    _settings(admin_client, fallback_verdicts=True)
    n = admin_client.get(f"/api/observables/{o.id}").json()["normalized"]
    assert n["reputation"] == "SCORE_SUSPICIOUS_OR_RISKY" and n["contributions"][0]["source"] == "verdict"


def test_rule_validation_and_recommended(admin_client):
    bad = [
        ([{"metric": "nope", "operator": ">=", "value": 1, "reputation": "SCORE_MALICIOUS"}], "Unknown signal"),
        ([{"metric": "malicious_engines", "operator": "==", "value": "x", "reputation": "SCORE_MALICIOUS"}], "needs a number"),
        ([{"metric": "verdict", "operator": ">=", "value": "malicious", "reputation": "SCORE_MALICIOUS"}], "not valid"),
        ([{"metric": "malicious_engines", "operator": ">=", "value": 1, "reputation": "SCORE_BAD"}], "Unknown reputation"),
    ]
    for rules, msg in bad:
        r = admin_client.put("/api/normalization/rules/virustotal", json=rules)
        assert r.status_code == 422 and msg in r.json()["detail"]
    assert admin_client.put("/api/normalization/rules/nope", json=[]).status_code == 404
    _rules(admin_client, "virustotal", VT)
    r = admin_client.post("/api/normalization/recommended").json()
    providers = {x["provider"] for x in r["rules"]}
    assert providers == {"virustotal", "otx", "abuseipdb", "urlscan", "recordedfuture", "greynoise", "emailrep"}
    # Existing rules untouched; only the safe-side catch-alls are appended (escalating rules would never match).
    assert [(x["metric"], x["value"], x["reputation"]) for x in r["rules"] if x["provider"] == "virustotal"] == [
        ("malicious_engines", 5, "SCORE_MALICIOUS"), ("malicious_engines", 1, "SCORE_SUSPICIOUS_OR_RISKY"),
        ("malicious_engines", 0, "SCORE_PROBABLY_SAFE"), ("result", "Not found", "SCORE_PROBABLY_SAFE")]
    assert r["added"] == sum(len(v) for k, v in norm.RECOMMENDED.items() if k != "virustotal") + 2
    assert admin_client.post("/api/normalization/recommended").json()["added"] == 0  # idempotent
    cfg = admin_client.get("/api/normalization").json()
    vt = next(p for p in cfg["providers"] if p["id"] == "virustotal")
    assert {m["id"] for m in vt["metrics"]} >= {"malicious_engines", "malicious_ratio", "verdict"}


def test_preview_and_apply_only_escalates(admin_client, db):
    up = _obs(db, "198.51.100.1", "SCORE_SAFE", virustotal=("malicious", {"malicious": 9, "total": 90}))
    down = _obs(db, "198.51.100.2", "SCORE_MALICIOUS", greynoise=("harmless", {"riot": True}))
    _obs(db, "198.51.100.3", "SCORE_UNKNOWN", otx=("unknown", {"pulses": 0}))  # no rule -> no opinion
    _rules(admin_client, "virustotal", VT)
    _rules(admin_client, "greynoise", GN)
    p = admin_client.post("/api/normalization/preview", json={}).json()
    assert (p["enriched"], p["with_opinion"], p["differs"], p["would_apply"]) == (3, 2, 2, 1)
    assert {c["value"]: c["applies"] for c in p["changes"]} == {"198.51.100.1": True, "198.51.100.2": False}
    # Preview a draft setting without saving it.
    assert admin_client.post("/api/normalization/preview", json={"settings": {"only_escalate": False}}).json()["would_apply"] == 2

    assert admin_client.post("/api/normalization/apply").json() == {"changed": 1}
    db.expire_all()
    assert db.get(Observable, up.id).reputation == "SCORE_MALICIOUS" and db.get(Observable, up.id).pinned is True
    assert db.get(Observable, down.id).reputation == "SCORE_MALICIOUS"  # not lowered
    events = admin_client.get(f"/api/observables/{up.id}/history").json()["items"]
    assert any(e["kind"] == "reputation_changed" and e["detail"]["cause"] == "normalization" for e in events)


def test_auto_mode_applies_after_enrichment(admin_client, db):
    admin_client.post("/api/integrations", json={"provider": "abuseipdb", "api_key": "key-" + "x" * 20})
    _rules(admin_client, "abuseipdb", ABUSE)
    _settings(admin_client, mode="auto")
    oid = admin_client.post("/api/observables", json={"type": IP, "value": "192.0.2.80"}).json()["id"]
    with respx.mock() as mock:
        mock.get("https://api.abuseipdb.com/api/v2/check").mock(return_value=httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 64, "totalReports": 20, "numDistinctUsers": 9}}))
        body = admin_client.post(f"/api/observables/{oid}/enrich").json()
    assert body["reputation"] == "SCORE_PROBABLY_MALICIOUS"
    assert body["normalized"]["differs"] is False and body["normalized"]["decided_by"] == "abuseipdb"


def test_apply_single_observable_can_lower(admin_client, db):
    o = _obs(db, "198.51.100.9", "SCORE_MALICIOUS", greynoise=("harmless", {"riot": True}))
    assert admin_client.post(f"/api/observables/{o.id}/normalize").status_code == 400  # no rules yet
    _rules(admin_client, "greynoise", GN)
    body = admin_client.post(f"/api/observables/{o.id}/normalize").json()
    assert body["reputation"] == "SCORE_SAFE" and body["normalized"]["differs"] is False


def test_not_found_and_clean_results_map_to_probably_safe(admin_client, db):
    admin_client.post("/api/normalization/recommended")
    nf = Observable(type="TYPE_ID_IP_ADDRESS", value="198.51.100.40", value_norm="198.51.100.40", reputation="SCORE_UNKNOWN")
    nf.intel.append(IntelEnrichment(provider="virustotal", status="not_found", summary=_verdict_summary("unknown", "Not found", {}, "")))
    clean = _obs(db, "198.51.100.41", "SCORE_OTHER", otx=("unknown", {"pulses": 0}), recordedfuture=("harmless", {"risk_score": 5}))
    err = Observable(type="TYPE_ID_IP_ADDRESS", value="198.51.100.42", value_norm="198.51.100.42", reputation="SCORE_UNKNOWN")
    err.intel.append(IntelEnrichment(provider="virustotal", status="error", summary={}, error="boom"))
    db.add_all([nf, err])
    db.commit()
    cfg = norm.load_config(db)
    r = norm.evaluate(cfg, nf)
    assert r["reputation"] == "SCORE_PROBABLY_SAFE" and r["contributions"][0]["metric"] == "result"
    assert r["contributions"][0]["actual"] == "Not found"
    assert norm.evaluate(cfg, db.get(Observable, clean.id))["reputation"] == "SCORE_PROBABLY_SAFE"
    assert norm.evaluate(cfg, err) is None  # errors carry no information
    # Unknown/Other -> Probably safe is a raise in severity, so "only raise severity" still applies it.
    assert norm.should_apply(cfg, nf, r)
    malicious = _obs(db, "198.51.100.43", "SCORE_UNKNOWN", virustotal=("malicious", {"malicious": 9, "total": 90}), otx=("unknown", {"pulses": 0}))
    assert norm.evaluate(cfg, malicious)["reputation"] == "SCORE_MALICIOUS"  # most severe still wins
