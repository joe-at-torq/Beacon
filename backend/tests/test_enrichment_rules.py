from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest
import respx

from app.db import SessionLocal
from app.intel import enrichment_rules as er
from app.intel import queue
from app.intel.providers import PROVIDERS
from app.intel.providers import _verdict_summary as summary
from app.models import EnrichmentJob, EnrichmentRule, Integration, IntelEnrichment, Observable, ObservableEvent, utcnow
from app.security import encrypt
from app.sync import engine
from app.sync.engine import run_sync
from tests.fake_torq import FakeTorq
from tests.test_sync import _workspaces

VT = "https://www.virustotal.com/api/v3"
ABUSE = "https://api.abuseipdb.com/api/v2/check"
IP, IPV4, IPV6 = "TYPE_ID_IP_ADDRESS", "SUB_TYPE_ID_IP_ADDRESS_IPV4", "SUB_TYPE_ID_IP_ADDRESS_IPV6"
MAL = "SCORE_MALICIOUS"
VT_OK = {"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 0, "harmless": 60, "undetected": 20}}}}
ABUSE_OK = {"data": {"abuseConfidenceScore": 90, "totalReports": 12, "numDistinctUsers": 5}}


@pytest.fixture(autouse=True)
def _fresh_queue():
    queue.reset_state()
    yield
    queue.reset_state()


def _connect(client, provider):
    assert client.post("/api/integrations", json={"provider": provider, "api_key": "k" * 32}).status_code == 201


def _rule(client, **kw):
    body = {"name": "Malicious IPv4", "type": IP, "sub_types": [IPV4], "reputations": [MAL],
            "providers": ["virustotal", "abuseipdb"], "refresh_days": 7} | kw
    r = client.post("/api/enrichment-rules", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def _create(client, value, reputation=MAL):
    r = client.post("/api/observables", json={"type": IP, "value": value, "reputation": reputation})
    assert r.status_code == 201, r.text
    return r.json()


def _jobs(**filters):
    with SessionLocal() as db:
        return db.query(EnrichmentJob).filter_by(**filters).order_by(EnrichmentJob.id).all()


def _mock_ok(mock):
    mock.get(url__regex=rf"{VT}/ip_addresses/.*").mock(return_value=httpx.Response(200, json=VT_OK))
    mock.get(ABUSE).mock(return_value=httpx.Response(200, json=ABUSE_OK))


def test_provider_sub_type_support():
    assert PROVIDERS["urlscan"].supports("TYPE_ID_FILE_HASH", "SUB_TYPE_ID_FILE_HASH_SHA256")
    assert not PROVIDERS["urlscan"].supports("TYPE_ID_FILE_HASH", "SUB_TYPE_ID_FILE_HASH_MD5")
    assert PROVIDERS["urlscan"].supports("TYPE_ID_FILE_HASH", "SUB_TYPE_ID_UNKNOWN")  # benefit of the doubt
    assert not PROVIDERS["greynoise"].supports(IP, IPV6) and PROVIDERS["greynoise"].supports(IP, IPV4)
    assert PROVIDERS["virustotal"].supports("TYPE_ID_FILE_HASH", "SUB_TYPE_ID_FILE_HASH_MD5")
    assert not PROVIDERS["virustotal"].supports("TYPE_ID_HOSTNAME", "SUB_TYPE_ID_HOSTNAME_NETBIOS")


def test_matching_and_shortest_window():
    obs = SimpleNamespace(type=IP, sub_type=IPV4, reputation=MAL)
    r1 = SimpleNamespace(enabled=True, type=IP, sub_types=[], reputations=[], providers=["virustotal"], refresh_days=30)
    r2 = SimpleNamespace(enabled=True, type=IP, sub_types=[IPV4], reputations=[MAL], providers=["virustotal", "greynoise"], refresh_days=1)
    r3 = SimpleNamespace(enabled=True, type=IP, sub_types=[IPV6], reputations=[], providers=["abuseipdb"], refresh_days=0)
    r4 = SimpleNamespace(enabled=False, type=IP, sub_types=[], reputations=[], providers=["otx"], refresh_days=0)
    out = er.providers_for([r1, r2, r3, r4], obs, {"virustotal", "greynoise", "abuseipdb", "otx"})
    assert out == {"virustotal": (1, r2, False), "greynoise": (1, r2, False)}  # r3 is IPv6-only, r4 disabled
    assert er.providers_for([r2], obs, {"virustotal"}) == {"virustotal": (1, r2, False)}  # inactive providers dropped
    now = utcnow()
    assert er.is_fresh("ok", now - timedelta(days=2), 7, now) and not er.is_fresh("ok", now - timedelta(days=8), 7, now)
    assert er.is_fresh("not_found", now - timedelta(days=400), -1, now) and not er.is_fresh("ok", now, 0, now)
    assert not er.is_fresh("error", now, 7, now)


def test_rule_validation_crud_and_permissions(admin_client):
    bad = {"name": "x", "type": "TYPE_ID_FILE_HASH", "sub_types": ["SUB_TYPE_ID_FILE_HASH_MD5"], "providers": ["urlscan"]}
    r = admin_client.post("/api/enrichment-rules", json=bad)
    assert r.status_code == 422 and "urlscan.io can't enrich MD5" in r.text
    r = admin_client.post("/api/enrichment-rules", json=bad | {"sub_types": [IPV4], "providers": ["virustotal"]})
    assert r.status_code == 422 and "don't belong" in r.text
    assert admin_client.post("/api/enrichment-rules", json=bad | {"providers": []}).status_code == 422
    # Types without sub types (e.g. email) need none; generic Unknown/Other are accepted for any type.
    email = {"name": "Emails", "type": "TYPE_ID_EMAIL_ADDRESS", "providers": ["emailrep"]}
    assert admin_client.post("/api/enrichment-rules", json=email).status_code == 201
    assert admin_client.post("/api/enrichment-rules", json=email | {"sub_types": ["SUB_TYPE_ID_UNKNOWN"]}).status_code == 201
    for r in admin_client.get("/api/enrichment-rules").json()["rules"]:
        admin_client.delete(f"/api/enrichment-rules/{r['id']}")
    rule = _rule(admin_client)
    cfg = admin_client.get("/api/enrichment-rules").json()
    assert cfg["rules"][0]["name"] == "Malicious IPv4" and cfg["limits"]["virustotal"]["per_minute"] == 4
    assert next(p for p in cfg["providers"] if p["id"] == "urlscan")["sub_types"]["TYPE_ID_FILE_HASH"] == ["SUB_TYPE_ID_FILE_HASH_SHA256"]
    r = admin_client.put(f"/api/enrichment-rules/{rule['id']}", json={**rule, "refresh_days": 30})
    assert r.status_code == 200 and r.json()["refresh_days"] == 30
    assert admin_client.put("/api/enrichment-rules/settings", json={"limits": {"virustotal": {"per_minute": 2, "per_day": 9}}}).json()["limits"]["virustotal"] == {"per_minute": 2, "per_day": 9}
    admin_client.post("/api/users", json={"username": "v", "password": "viewerpass1", "role": "viewer", "must_change_password": False})
    admin_client.cookies.clear()
    admin_client.post("/api/auth/login", json={"username": "v", "password": "viewerpass1"})
    assert admin_client.get("/api/enrichment-rules").status_code == 200
    assert admin_client.post("/api/enrichment-rules", json=rule).status_code == 403
    assert admin_client.post(f"/api/enrichment-rules/{rule['id']}/run").status_code == 403
    assert admin_client.delete(f"/api/enrichment-rules/{rule['id']}").status_code == 403


async def test_manual_create_enqueues_and_worker_enriches(admin_client):
    _connect(admin_client, "virustotal")
    _connect(admin_client, "abuseipdb")
    _connect(admin_client, "emailrep")
    rule = _rule(admin_client)
    hit = _create(admin_client, "203.0.113.5")
    _create(admin_client, "203.0.113.6", "SCORE_PROBABLY_SAFE")  # reputation doesn't match
    _create(admin_client, "2001:db8::5")  # IPv6: sub type doesn't match
    jobs = _jobs()
    assert [(j.observable_id, j.provider, j.reason, j.rule_name) for j in jobs] == [
        (hit["id"], "virustotal", "new", "Malicious IPv4"), (hit["id"], "abuseipdb", "new", "Malicious IPv4")]
    with respx.mock(assert_all_called=False) as mock:
        _mock_ok(mock)
        assert await queue.process_queue() == {"done": 2}
    assert {j.status for j in _jobs()} == {"done"}
    detail = admin_client.get(f"/api/observables/{hit['id']}").json()
    assert {i["provider"]: i["status"] for i in detail["intel"]} == {"virustotal": "ok", "abuseipdb": "ok"}
    assert {i["fetched_by"] for i in detail["intel"]} == {"rule:Malicious IPv4"}
    with SessionLocal() as db:
        ev = db.query(ObservableEvent).filter_by(observable_id=hit["id"], kind="intel_enriched").all()
        assert len(ev) == 2 and all(e.actor == "rule:Malicious IPv4" and e.detail["rule_id"] == rule["id"] for e in ev)
    stats = admin_client.get("/api/enrichment-rules").json()["rules"][0]["stats"]
    assert stats == {"queued": 0, "done": 2, "error": 0, "skipped": 0}


async def test_rate_limit_daily_cap_and_preview(admin_client):
    _connect(admin_client, "virustotal")
    for i in range(5):
        _create(admin_client, f"198.51.100.{i + 1}")  # before the rule: nothing queued
    assert _jobs() == []
    rule = _rule(admin_client, providers=["virustotal"])
    prev = admin_client.post("/api/enrichment-rules/preview", json={**rule}).json()
    assert prev["matching"] == 5 and prev["jobs"] == 5 and prev["providers"][0]["provider"] == "virustotal"
    assert prev["providers"][0]["eta_seconds"] == 75  # 5 lookups at 4/min
    admin_client.put("/api/enrichment-rules/settings", json={"limits": {"virustotal": {"per_minute": 2, "per_day": 3}}})
    assert admin_client.post(f"/api/enrichment-rules/{rule['id']}/run").json() == {"queued": 5, "providers": {"virustotal": 5}}
    assert admin_client.post(f"/api/enrichment-rules/{rule['id']}/run").json()["queued"] == 0  # already queued
    with respx.mock(assert_all_called=False) as mock:
        _mock_ok(mock)
        assert await queue.process_queue() == {"done": 2}  # per-minute window
        assert await queue.process_queue() == {}
        queue._window.clear()  # a minute later
        assert await queue.process_queue() == {"done": 1}  # daily cap of 3
        queue._window.clear()
        assert await queue.process_queue() == {}
    assert len(_jobs(status="queued")) == 2
    q = admin_client.get("/api/enrichment-rules/queue").json()
    vt = next(p for p in q["providers"] if p["provider"] == "virustotal")
    assert vt["used_today"] == 3 and vt["queued"] == 2 and q["done_today"] == 3
    # Fresh results are skipped by preview/run; a zero window always re-enriches.
    assert admin_client.post("/api/enrichment-rules/preview", json={**rule}).json()["jobs"] == 0  # 3 fresh, 2 queued
    assert admin_client.post("/api/enrichment-rules/preview", json={**rule, "refresh_days": 0}).json()["jobs"] == 3


async def test_429_cooldown_keeps_good_result_and_401_does_not_drain(admin_client):
    _connect(admin_client, "virustotal")
    _connect(admin_client, "abuseipdb")
    obs = _create(admin_client, "203.0.113.9")
    with SessionLocal() as db:
        db.query(EnrichmentJob).delete()
        db.add(IntelEnrichment(observable_id=obs["id"], provider="virustotal", status="ok", fetched_by="x",
                               summary=summary("malicious", "old", {}, ""), fetched_at=utcnow() - timedelta(days=30)))
        db.commit()
    rule = _rule(admin_client)
    assert admin_client.post(f"/api/enrichment-rules/{rule['id']}/run").json()["queued"] == 2
    with respx.mock(assert_all_called=False) as mock:
        mock.get(url__regex=rf"{VT}/ip_addresses/.*").mock(return_value=httpx.Response(429, json={}))
        mock.get(ABUSE).mock(return_value=httpx.Response(401, json={}))
        assert await queue.process_queue() == {"rate_limited": 1, "key_rejected": 1}
        queue._window.clear()
        assert await queue.process_queue() == {}  # both providers cooling down
    jobs = {j.provider: j for j in _jobs()}
    assert all(j.status == "queued" and j.attempts == 0 and j.not_before > utcnow() for j in jobs.values())
    q = admin_client.get("/api/enrichment-rules/queue").json()
    reasons = {p["provider"]: p["cooldown_reason"] for p in q["providers"]}
    assert reasons["virustotal"] == "Rate limit reached (429)" and reasons["abuseipdb"] == "API key rejected"
    intel = {i["provider"]: i for i in admin_client.get(f"/api/observables/{obs['id']}").json()["intel"]}
    assert intel["virustotal"]["status"] == "ok" and intel["virustotal"]["summary"]["headline"] == "old"
    assert "abuseipdb" not in intel  # no error rows written for a rejected key


async def test_errors_retry_then_fail_and_deleted_observable_dropped(admin_client):
    _connect(admin_client, "virustotal")
    gone = _create(admin_client, "203.0.113.20")
    flaky = _create(admin_client, "203.0.113.21")

    def vt(request):
        if request.url.path.endswith("203.0.113.20"):
            with SessionLocal() as db:  # deleted while the lookup is in flight
                db.delete(db.get(Observable, gone["id"]))
                db.commit()
            return httpx.Response(200, json=VT_OK)
        return httpx.Response(500, json={})

    with respx.mock(assert_all_called=False) as mock:
        mock.get(url__regex=rf"{VT}/ip_addresses/.*").mock(side_effect=vt)
        _rule(admin_client, providers=["virustotal"], reputations=[])
        assert admin_client.post(f"/api/enrichment-rules/{1}/run").json()["queued"] == 2
        assert await queue.process_queue() == {"dropped": 1, "retry": 1}
        with SessionLocal() as db:
            for j in db.query(EnrichmentJob).filter_by(status="queued"):
                j.not_before = utcnow()
            db.commit()
        queue._window.clear()
        assert await queue.process_queue() == {"retry": 1}
        with SessionLocal() as db:
            for j in db.query(EnrichmentJob).filter_by(status="queued"):
                j.not_before = utcnow()
            db.commit()
        queue._window.clear()
        assert await queue.process_queue() == {"error": 1}
    job = _jobs()[-1]
    assert job.status == "error" and job.attempts == 3 and job.observable_id == flaky["id"]
    assert admin_client.get(f"/api/observables/{flaky['id']}").json()["intel"][0]["status"] == "error"
    assert admin_client.get("/api/enrichment-rules/queue").json()["recent_errors"][0]["value"] == "203.0.113.21"


async def test_disabled_integration_paused_queue_and_running_sync(admin_client):
    _connect(admin_client, "virustotal")
    integ = admin_client.get("/api/integrations").json()[0]
    _rule(admin_client, providers=["virustotal"])
    _create(admin_client, "203.0.113.30")
    admin_client.patch(f"/api/integrations/{integ['id']}", json={"enabled": False})
    assert await queue.process_queue() == {}
    q = admin_client.get("/api/enrichment-rules/queue").json()
    assert next(p for p in q["providers"] if p["provider"] == "virustotal")["blocked"] == "Integration disabled"
    admin_client.patch(f"/api/integrations/{integ['id']}", json={"enabled": True})
    admin_client.put("/api/enrichment-rules/settings", json={"paused": True})
    assert await queue.process_queue() == {"skipped": "paused"}
    admin_client.put("/api/enrichment-rules/settings", json={"paused": False})
    async with engine._lock:
        assert await queue.process_queue() == {"skipped": "sync running"}
    assert len(_jobs(status="queued")) == 1


def test_disable_delete_cancel_and_restart_reset(admin_client):
    _connect(admin_client, "virustotal")
    rule = _rule(admin_client, providers=["virustotal"])
    _create(admin_client, "203.0.113.40")
    _create(admin_client, "203.0.113.41")
    with SessionLocal() as db:
        db.query(EnrichmentJob).filter_by(observable_id=db.query(Observable).filter_by(value="203.0.113.41").one().id).update(
            {"status": "running"})
        db.commit()
    assert queue.reset_running() == 1
    r = admin_client.patch(f"/api/enrichment-rules/{rule['id']}/enabled?enabled=false")
    assert r.status_code == 200 and {j.status for j in _jobs()} == {"cancelled"}
    assert admin_client.post(f"/api/enrichment-rules/{rule['id']}/run").status_code == 400  # disabled
    admin_client.patch(f"/api/enrichment-rules/{rule['id']}/enabled?enabled=true")
    assert admin_client.post(f"/api/enrichment-rules/{rule['id']}/run").json()["queued"] == 2
    assert admin_client.delete(f"/api/enrichment-rules/{rule['id']}").status_code == 204
    assert {j.status for j in _jobs()} == {"cancelled"} and all(j.rule_id is None for j in _jobs())


def test_v1_api(admin_client):
    _connect(admin_client, "virustotal")
    r = admin_client.post("/api/v1/enrichment-rules", json={"name": "v1 rule", "type": IP, "providers": ["virustotal"]})
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    assert r.json()["refresh_days"] == 7 and r.json()["stats"] == {"queued": 0, "done": 0, "error": 0, "skipped": 0}
    assert r.json()["skip_when_busy"] is False
    assert [x["name"] for x in admin_client.get("/api/v1/enrichment-rules").json()] == ["v1 rule"]
    assert admin_client.patch(f"/api/v1/enrichment-rules/{rid}", json={"reputations": [MAL]}).json()["reputations"] == [MAL]
    assert admin_client.patch(f"/api/v1/enrichment-rules/{rid}", json={"providers": ["emailrep"]}).status_code == 422
    _create(admin_client, "203.0.113.50")  # auto-queued by the rule
    assert admin_client.post(f"/api/v1/enrichment-rules/{rid}/run").json() == {"queued": 0, "providers": {}}
    assert admin_client.get("/api/v1/enrichment-rules/queue").json()["queued"] == 1
    assert admin_client.get(f"/api/v1/enrichment-rules/{rid}").json()["stats"]["queued"] == 1
    assert admin_client.delete(f"/api/v1/enrichment-rules/{rid}").status_code == 204
    spec = admin_client.get("/api/v1/openapi.json").json()
    assert "/enrichment-rules/{rule_id}/run" in spec["paths"]


async def test_sync_enqueues_only_observables_new_to_central(db):
    with FakeTorq() as fake:
        ws = _workspaces(db, fake, ("A", "B"))
        a, b = fake.workspace("cid-A"), fake.workspace("cid-B")
        a.add(IP, "198.51.100.10", MAL, sub_type=IPV4)
        await run_sync()
        db.add(Integration(provider="virustotal", name="VirusTotal", api_key_enc=encrypt("k" * 32)))
        db.add(EnrichmentRule(name="Sync rule", type=IP, sub_types=[IPV4], reputations=[MAL], providers=["virustotal"]))
        db.commit()
        b.add(IP, "198.51.100.10", MAL, sub_type=IPV4)  # existing observable, newly linked in B
        b.add(IP, "198.51.100.11", MAL, sub_type=IPV4)  # new to central
        b.add(IP, "198.51.100.12", "SCORE_PROBABLY_SAFE", sub_type=IPV4)  # new, but reputation doesn't match
        await run_sync()
        assert ws  # workspaces were created
    db.expire_all()
    queued = [(db.get(Observable, j.observable_id).value, j.provider, j.reason) for j in db.query(EnrichmentJob).all()]
    assert queued == [("198.51.100.11", "virustotal", "new")]


async def test_manual_enrich_respects_sub_types(admin_client):
    _connect(admin_client, "urlscan")
    r = admin_client.post("/api/observables", json={"type": "TYPE_ID_FILE_HASH", "value": "d41d8cd98f00b204e9800998ecf8427e"})
    obs = r.json()
    assert obs["sub_type"] == "SUB_TYPE_ID_FILE_HASH_MD5"
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(url__regex=r"https://urlscan\.io/.*").mock(return_value=httpx.Response(200, json={"results": []}))
        res = admin_client.post(f"/api/observables/{obs['id']}/enrich")
    assert not route.called and res.json().get("intel", []) == []  # urlscan.io only looks up SHA-256 hashes


async def test_dashboard_enrichment_widget(admin_client):
    _connect(admin_client, "virustotal")
    _connect(admin_client, "abuseipdb")
    manual = _create(admin_client, "203.0.113.60", "SCORE_PROBABLY_SAFE")  # no rule yet
    _rule(admin_client)
    auto = _create(admin_client, "203.0.113.61")  # queued by the rule
    failing = _create(admin_client, "203.0.113.62", "SCORE_PROBABLY_SAFE")
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{VT}/ip_addresses/203.0.113.62").mock(return_value=httpx.Response(500, json={}))  # before the catch-all
        _mock_ok(mock)
        admin_client.post(f"/api/observables/{manual['id']}/enrich")
        assert await queue.process_queue() == {"done": 2}
        admin_client.post(f"/api/observables/{failing['id']}/enrich", json={"providers": ["virustotal"]})
    d = admin_client.get("/api/dashboard/enrichment?range=7d").json()
    assert d["bucket"] == "day" and len(d["points"]) == 7 and d["points"][-1]["total"] == 4
    assert d["totals"] == {"lookups": 4, "automatic": 2, "manual": 2, "observables": 2}
    assert {p["provider"]: p["lookups"] for p in d["providers"]} == {"virustotal": 2, "abuseipdb": 2}
    assert d["points"][-1]["providers"] == {"virustotal": 2, "abuseipdb": 2}
    assert (d["points"][-1]["automatic"], d["points"][-1]["manual"]) == (2, 2)
    assert d["verdicts"] == {"malicious": 4}
    assert d["coverage"] == {"enriched": 2, "observables": 3} and d["failing_now"] == 1
    assert auto["id"]
    assert admin_client.get("/api/dashboard/enrichment?range=all").json()["totals"]["lookups"] == 4


def test_skip_when_busy_only_waits_when_every_rule_wants_to():
    obs = SimpleNamespace(type=IP, sub_type=IPV4, reputation=MAL)
    skip = SimpleNamespace(enabled=True, type=IP, sub_types=[], reputations=[], providers=["virustotal", "otx"], refresh_days=7, skip_when_busy=True)
    wait = SimpleNamespace(enabled=True, type=IP, sub_types=[], reputations=[], providers=["virustotal"], refresh_days=30, skip_when_busy=False)
    out = er.providers_for([skip, wait], obs, {"virustotal", "otx"})
    assert out["virustotal"][2] is False and out["otx"][2] is True


async def test_skip_busy_integration_and_enrich_with_the_others(admin_client):
    _connect(admin_client, "virustotal")
    _connect(admin_client, "otx")
    rule = _rule(admin_client, providers=["virustotal", "otx"], reputations=[], skip_when_busy=True)
    assert rule["skip_when_busy"] is True
    admin_client.put("/api/enrichment-rules/settings", json={"limits": {"virustotal": {"per_minute": 10, "per_day": 1}}})
    a, b = _create(admin_client, "203.0.113.70"), _create(admin_client, "203.0.113.71")
    with respx.mock(assert_all_called=False) as mock:
        _mock_ok(mock)
        mock.get(url__regex=r"https://otx\.alienvault\.com/.*").mock(return_value=httpx.Response(200, json={"pulse_info": {"count": 0}}))
        assert await queue.process_queue() == {"done": 3}  # VirusTotal's daily budget allows one
        assert await queue.process_queue() == {"skipped_busy": 1}  # the other VirusTotal lookup is skipped, not queued
    jobs = {(j.observable_id, j.provider): j for j in _jobs()}
    vt_skipped = [j for j in jobs.values() if j.status == "skipped"]
    assert len(vt_skipped) == 1 and vt_skipped[0].provider == "virustotal"
    assert vt_skipped[0].error == "Skipped: VirusTotal daily limit reached"
    assert {j.status for (o, p), j in jobs.items() if p == "otx"} == {"done"}  # both enriched with OTX
    assert admin_client.get("/api/enrichment-rules").json()["rules"][0]["stats"]["skipped"] == 1
    # A 429 skips instead of requeueing; a waiting rule would requeue (covered above).
    c = _create(admin_client, "203.0.113.72")
    with SessionLocal() as db:
        db.query(EnrichmentJob).filter_by(observable_id=c["id"], provider="virustotal").delete()
        db.commit()
    admin_client.put("/api/enrichment-rules/settings", json={"limits": {"virustotal": {"per_minute": 10, "per_day": 100}}})
    # Run re-queues the earlier skipped VirusTotal lookup too (it never ran), plus the new one.
    assert admin_client.post(f"/api/enrichment-rules/{rule['id']}/run").json()["providers"] == {"virustotal": 2}
    with respx.mock(assert_all_called=False) as mock:
        mock.get(url__regex=rf"{VT}/ip_addresses/.*").mock(return_value=httpx.Response(429, json={}))
        mock.get(url__regex=r"https://otx\.alienvault\.com/.*").mock(return_value=httpx.Response(200, json={"pulse_info": {"count": 0}}))
        out = await queue.process_queue()
    assert out["rate_limited"] == 2
    vt = [j for j in _jobs(provider="virustotal") if j.reason == "manual_run"]
    assert len(vt) == 2 and all(j.status == "skipped" and "rate limit" in j.error for j in vt)
    assert a["id"] and b["id"]
