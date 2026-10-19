"""AbuseIPDB, urlscan.io, Recorded Future, GreyNoise and EmailRep.io enrichment (mocked provider APIs)."""

import httpx
import pytest
import respx

IP, HOST, URL, EMAIL = "TYPE_ID_IP_ADDRESS", "TYPE_ID_HOSTNAME", "TYPE_ID_URL", "TYPE_ID_EMAIL_ADDRESS"


def _setup(client, provider, type_id, value):
    assert client.post("/api/integrations", json={"provider": provider, "api_key": "key-" + "x" * 20}).status_code == 201
    return client.post("/api/observables", json={"type": type_id, "value": value}).json()["id"]


def _enrich(client, obs_id):
    r = client.post(f"/api/observables/{obs_id}/enrich")
    assert r.status_code == 200, r.text
    body = r.json()
    return body["intel"][0], body["enrichment"]


def test_abuseipdb(admin_client):
    oid = _setup(admin_client, "abuseipdb", IP, "203.0.113.20")
    raw = {"data": {"ipAddress": "203.0.113.20", "abuseConfidenceScore": 87, "totalReports": 412, "numDistinctUsers": 120,
                    "countryCode": "NL", "isp": "Example Hosting", "usageType": "Data Center/Web Hosting/Transit",
                    "isTor": False, "isWhitelisted": False, "lastReportedAt": "2026-10-10T08:00:00+00:00"}}
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get("https://api.abuseipdb.com/api/v2/check").mock(return_value=httpx.Response(200, json=raw))
        intel, enrichment = _enrich(admin_client, oid)
        req = route.calls[0].request
        assert req.headers["Key"] == "key-" + "x" * 20 and req.url.params["ipAddress"] == "203.0.113.20"
    s = intel["summary"]
    assert s["verdict"] == "malicious" and s["headline"] == "Abuse confidence 87% · 412 reports from 120 users"
    assert {"label": "ISP", "value": "Example Hosting"} in s["facts"] and s["link"].endswith("/check/203.0.113.20")
    assert enrichment["abuseipdb"] == raw


def test_urlscan_url_search_and_not_found(admin_client):
    oid = _setup(admin_client, "urlscan", URL, "https://phish.example/login")
    raw = {"total": 3, "results": [
        {"_id": "abc-123", "task": {"time": "2026-10-12T10:00:00Z", "tags": ["phishing"]},
         "page": {"url": "https://phish.example/login", "ip": "198.51.100.7", "country": "US"}, "verdicts": {"malicious": True}},
        {"_id": "def-456", "task": {}, "page": {}, "verdicts": {"malicious": False}}]}
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get("https://urlscan.io/api/v1/search/").mock(return_value=httpx.Response(200, json=raw))
        intel, _ = _enrich(admin_client, oid)
        assert route.calls[0].request.url.params["q"] == 'page.url:"https://phish.example/login"'
        assert route.calls[0].request.headers["API-Key"].startswith("key-")
    s = intel["summary"]
    assert s["verdict"] == "malicious" and s["headline"] == "Seen in 3 scans · 1 flagged malicious"
    assert s["link"] == "https://urlscan.io/result/abc-123/" and "phishing" in s["tags"]

    host = admin_client.post("/api/observables", json={"type": HOST, "value": "clean.example"}).json()["id"]
    with respx.mock() as mock:
        route = mock.get("https://urlscan.io/api/v1/search/").mock(return_value=httpx.Response(200, json={"total": 0, "results": []}))
        intel, _ = _enrich(admin_client, host)
        assert route.calls[0].request.url.params["q"] == "domain:clean.example"
    assert intel["status"] == "not_found"


def test_recorded_future(admin_client):
    oid = _setup(admin_client, "recordedfuture", HOST, "evil.example")
    raw = {"data": {"intelCard": "https://app.recordedfuture.com/live/sc/entity/idn%3Aevil.example",
                    "risk": {"score": 72, "criticalityLabel": "Malicious", "riskSummary": "5 of 52 Risk Rules currently observed.",
                             "rules": 5, "evidenceDetails": [
                                 {"rule": "Recent Phishing Host", "criticality": 3}, {"rule": "Historical Malware", "criticality": 1}]}}}
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get("https://api.recordedfuture.com/v2/domain/evil.example").mock(return_value=httpx.Response(200, json=raw))
        intel, _ = _enrich(admin_client, oid)
        assert route.calls[0].request.headers["X-RFToken"].startswith("key-")
    s = intel["summary"]
    assert s["verdict"] == "malicious" and s["headline"].startswith("Risk score 72/99 · Malicious")
    assert s["tags"][0] == "Recent Phishing Host" and s["link"].startswith("https://app.recordedfuture.com/")


@pytest.mark.parametrize("payload,verdict,headline", [
    ({"noise": True, "riot": False, "classification": "malicious", "name": "unknown", "link": "https://viz.greynoise.io/ip/x"},
     "malicious", "Internet scanner · classified malicious"),
    ({"noise": False, "riot": True, "classification": "benign", "name": "Google Public DNS"},
     "harmless", "Known benign service: Google Public DNS"),
    ({"noise": True, "riot": False, "classification": "unknown", "name": "unknown"}, "suspicious",
     "Internet scanner · classified unknown"),
])
def test_greynoise(admin_client, payload, verdict, headline):
    oid = _setup(admin_client, "greynoise", IP, "192.0.2.60")
    with respx.mock() as mock:
        route = mock.get("https://api.greynoise.io/v3/community/192.0.2.60").mock(return_value=httpx.Response(200, json=payload))
        intel, _ = _enrich(admin_client, oid)
        assert route.calls[0].request.headers["key"].startswith("key-")
    assert intel["summary"]["verdict"] == verdict and intel["summary"]["headline"] == headline


def test_greynoise_not_observed(admin_client):
    oid = _setup(admin_client, "greynoise", IP, "192.0.2.61")
    with respx.mock() as mock:
        mock.get("https://api.greynoise.io/v3/community/192.0.2.61").mock(
            return_value=httpx.Response(404, json={"ip": "192.0.2.61", "noise": False, "riot": False, "message": "IP not observed"}))
        intel, _ = _enrich(admin_client, oid)
    assert intel["status"] == "not_found"


def test_emailrep(admin_client):
    oid = _setup(admin_client, "emailrep", EMAIL, "ceo@spoofed.example")
    raw = {"email": "ceo@spoofed.example", "reputation": "low", "suspicious": True, "references": 2,
           "details": {"blacklisted": False, "malicious_activity": False, "credentials_leaked": True, "data_breach": True,
                       "spam": False, "disposable": False, "domain_reputation": "low", "spoofable": True, "profiles": ["twitter"]}}
    with respx.mock(assert_all_called=True) as mock:
        route = mock.get("https://emailrep.io/ceo@spoofed.example").mock(return_value=httpx.Response(200, json=raw))
        intel, enrichment = _enrich(admin_client, oid)
        req = route.calls[0].request
        assert req.headers["Key"].startswith("key-") and req.headers["User-Agent"].startswith("Beacon-")
    s = intel["summary"]
    assert s["verdict"] == "suspicious" and s["headline"] == "Reputation low · suspicious · 2 references"
    assert set(s["tags"]) == {"Credentials leaked", "In a data breach", "Spoofable"}
    assert enrichment["emailrep"]["details"]["data_breach"] is True


def test_capabilities_cover_new_types(admin_client):
    for provider in ("abuseipdb", "greynoise", "emailrep", "urlscan"):
        admin_client.post("/api/integrations", json={"provider": provider, "api_key": "key-" + "x" * 20})
    caps = admin_client.get("/api/integrations/capabilities").json()
    assert caps["TYPE_ID_EMAIL_ADDRESS"] == ["emailrep"]
    assert set(caps["TYPE_ID_IP_ADDRESS"]) == {"abuseipdb", "greynoise", "urlscan"}
