import httpx
import respx

VT = "https://www.virustotal.com/api/v3"
OTX = "https://otx.alienvault.com/api/v1"

VT_IP = {"data": {"id": "203.0.113.5", "type": "ip_address", "attributes": {
    "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 20, "timeout": 0},
    "reputation": -12, "tags": ["scanner"]}}}
OTX_IP = {"indicator": "203.0.113.5", "reputation": 0, "pulse_info": {"count": 2, "pulses": [
    {"name": "Mirai scanners", "tags": ["mirai", "botnet"]}, {"name": "SSH brute force", "tags": ["ssh"]}]}}


def _connect(client, provider, key="k" * 32):
    r = client.post("/api/integrations", json={"provider": provider, "api_key": key})
    assert r.status_code == 201, r.text
    return r.json()


def test_integration_management(admin_client):
    providers = {p["id"]: p for p in admin_client.get("/api/integrations/providers").json()}
    assert set(providers) == {"virustotal", "otx", "abuseipdb", "urlscan", "recordedfuture", "greynoise", "emailrep"}
    assert "TYPE_ID_URL" in providers["virustotal"]["types"] and providers["emailrep"]["types"] == ["TYPE_ID_EMAIL_ADDRESS"]
    assert all(p["monogram"] for p in providers.values())
    vt = _connect(admin_client, "virustotal", "secret-key-1234")
    assert vt["key_hint"] == "…1234" and "api_key" not in vt and "api_key_enc" not in vt
    assert admin_client.post("/api/integrations", json={"provider": "virustotal", "api_key": "x" * 20}).status_code == 409
    assert admin_client.post("/api/integrations", json={"provider": "nope", "api_key": "x" * 20}).status_code == 400
    caps = admin_client.get("/api/integrations/capabilities").json()
    assert caps["TYPE_ID_IP_ADDRESS"] == ["virustotal"] and "TYPE_ID_EMAIL_ADDRESS" not in caps
    admin_client.patch(f"/api/integrations/{vt['id']}", json={"enabled": False})
    assert admin_client.get("/api/integrations/capabilities").json() == {}

    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{OTX}/users/me").mock(return_value=httpx.Response(200, json={"username": "analyst1"}))
        mock.get(f"{VT}/ip_addresses/8.8.8.8").mock(return_value=httpx.Response(401, json={"error": {}}))
        r = admin_client.post("/api/integrations/test", json={"provider": "otx", "api_key": "otx-key-123456"}).json()
        assert r == {"ok": True, "message": "Connected to AlienVault OTX as analyst1"}
        r = admin_client.post("/api/integrations/test", json={"provider": "virustotal"}).json()  # stored key
        assert r["ok"] is False and "rejected the API key" in r["message"]
    assert next(i for i in admin_client.get("/api/integrations").json() if i["provider"] == "virustotal")["last_status"] == "error"


def test_enrich_observable_stores_summary_and_raw_json(admin_client):
    _connect(admin_client, "virustotal")
    _connect(admin_client, "otx")
    obs = admin_client.post("/api/observables", json={"type": "TYPE_ID_IP_ADDRESS", "value": "203.0.113.5"}).json()
    email = admin_client.post("/api/observables", json={"type": "TYPE_ID_EMAIL_ADDRESS", "value": "a@b.example"}).json()

    with respx.mock(assert_all_called=False) as mock:
        vt_route = mock.get(f"{VT}/ip_addresses/203.0.113.5").mock(return_value=httpx.Response(200, json=VT_IP))
        mock.get(f"{OTX}/indicators/IPv4/203.0.113.5/general").mock(return_value=httpx.Response(200, json=OTX_IP))
        r = admin_client.post(f"/api/observables/{obs['id']}/enrich")
        assert r.status_code == 200, r.text
        assert vt_route.calls[0].request.headers["x-apikey"] == "k" * 32
    body = r.json()
    intel = {e["provider"]: e for e in body["intel"]}
    assert intel["virustotal"]["summary"]["verdict"] == "malicious"
    assert intel["virustotal"]["summary"]["headline"] == "7/88 engines flag as malicious"
    assert intel["virustotal"]["summary"]["suggested_reputation"] == "SCORE_MALICIOUS"
    assert intel["virustotal"]["summary"]["link"] == "https://www.virustotal.com/gui/ip-address/203.0.113.5"
    assert intel["otx"]["summary"]["verdict"] == "suspicious" and intel["otx"]["summary"]["stats"]["pulses"] == 2
    # Raw provider responses live in the observable's enrichment field.
    assert body["enrichment"] == {"virustotal": VT_IP, "otx": OTX_IP}
    assert body["has_enrichment"] is True
    assert admin_client.get("/api/observables", params={"has_enrichment": True}).json()["total"] == 1

    kinds = [e["kind"] for e in admin_client.get(f"/api/observables/{obs['id']}/history").json()["items"]]
    assert kinds.count("intel_enriched") == 2

    # Unsupported type is refused.
    assert admin_client.post(f"/api/observables/{email['id']}/enrich").status_code == 400


def test_enrich_not_found_url_and_rate_limit_bulk(admin_client):
    _connect(admin_client, "virustotal")
    url = admin_client.post("/api/observables", json={"type": "TYPE_ID_URL", "value": "https://evil.example/x"}).json()
    ip = admin_client.post("/api/observables", json={"type": "TYPE_ID_IP_ADDRESS", "value": "198.51.100.3"}).json()
    email = admin_client.post("/api/observables", json={"type": "TYPE_ID_EMAIL_ADDRESS", "value": "c@d.example"}).json()
    with respx.mock(assert_all_called=False) as mock:
        # URL id = base64url(url) without padding
        mock.get(f"{VT}/urls/aHR0cHM6Ly9ldmlsLmV4YW1wbGUveA").mock(return_value=httpx.Response(404, json={}))
        mock.get(f"{VT}/ip_addresses/198.51.100.3").mock(return_value=httpx.Response(429, json={}))
        r = admin_client.post("/api/observables/bulk-enrich", json={"ids": [url["id"], ip["id"], email["id"]]}).json()
    assert r["enriched"] == 2 and r["skipped"] == 1 and r["not_found"] == 1 and r["errors"] == 1
    assert "rate limit" in r["first_error"]
    detail = admin_client.get(f"/api/observables/{url['id']}").json()
    assert detail["intel"][0]["status"] == "not_found" and detail["enrichment"] == {}


def test_viewer_cannot_manage_or_enrich(admin_client):
    _connect(admin_client, "otx")
    obs = admin_client.post("/api/observables", json={"type": "TYPE_ID_IP_ADDRESS", "value": "192.0.2.77"}).json()
    admin_client.post("/api/users", json={"username": "v", "password": "viewerpass1", "role": "viewer", "must_change_password": False})
    admin_client.cookies.clear()
    admin_client.post("/api/auth/login", json={"username": "v", "password": "viewerpass1"})
    assert admin_client.get("/api/integrations").status_code == 200
    assert admin_client.post("/api/integrations", json={"provider": "virustotal", "api_key": "x" * 20}).status_code == 403
    assert admin_client.post(f"/api/observables/{obs['id']}/enrich").status_code == 403
