from app.models import Observable, ObservableLink, Rule, SyncRun, Tombstone, Workspace
from app.security import encrypt
from app.settings_store import set_setting
from app.sync.engine import run_sync
from tests.fake_torq import FakeTorq

IP = "TYPE_ID_IP_ADDRESS"
HOST = "TYPE_ID_HOSTNAME"
IPV4 = "SUB_TYPE_ID_IP_ADDRESS_IPV4"


def _workspaces(db, fake: FakeTorq, names=("A", "B", "C")) -> dict[str, Workspace]:
    out = {}
    for i, name in enumerate(names):
        cid = f"cid-{name}"
        fake.workspace(cid)
        ws = Workspace(name=name, region="us", client_id=cid, client_secret_enc=encrypt(f"secret-{cid}"),
                       priority=(i + 1) * 10)
        db.add(ws)
        out[name] = ws
    db.commit()
    return out


def _obs(db, value: str) -> Observable:
    db.expire_all()
    return db.query(Observable).filter_by(value_norm=value).one()


async def test_directional_ipv4_rule(db):
    with FakeTorq() as fake:
        ws = _workspaces(db, fake)
        a, b, c = (fake.workspace(f"cid-{n}") for n in "ABC")
        a.add(IP, "1.1.1.1", "SCORE_MALICIOUS")
        a.add(IP, "2001:db8::1", "SCORE_MALICIOUS")
        a.add(HOST, "evil.com", "SCORE_MALICIOUS")
        b.add(IP, "2.2.2.2", "SCORE_SUSPICIOUS_OR_RISKY")
        db.add(Rule(name="A to B,C IPv4", source_workspace_ids=[ws["A"].id],
                    target_workspace_ids=[ws["B"].id, ws["C"].id], types=[IP], sub_types=[IPV4]))
        db.commit()

        run_id = await run_sync()
        run = db.get(SyncRun, run_id)
        assert run.status == "ok", run.errors
        assert run.pulled == 4 and run.created_central == 4 and run.pushed_created == 2

        assert b.find("1.1.1.1") and c.find("1.1.1.1")
        assert not b.find("2001:db8::1") and not c.find("evil.com")
        assert not a.find("2.2.2.2")  # nothing flows back to A
        assert not c.find("2.2.2.2")

        # Second run is idempotent; pulled-back pushed copies keep their "pushed" relation.
        run2 = db.get(SyncRun, await run_sync())
        assert run2.pushed_created == 0 and run2.pushed_updated == 0
        relations = {link.workspace_id: link.relation for link in _obs(db, "1.1.1.1").links}
        assert relations == {ws["A"].id: "origin", ws["B"].id: "pushed", ws["C"].id: "pushed"}


async def test_pushed_copy_does_not_propagate_transitively(db):
    with FakeTorq() as fake:
        ws = _workspaces(db, fake)
        fake.workspace("cid-A").add(IP, "9.9.9.9", "SCORE_MALICIOUS")
        db.add(Rule(name="A->B", source_workspace_ids=[ws["A"].id], target_workspace_ids=[ws["B"].id]))
        db.add(Rule(name="B->C", source_workspace_ids=[ws["B"].id], target_workspace_ids=[ws["C"].id]))
        db.commit()
        await run_sync()
        await run_sync()
        assert fake.workspace("cid-B").find("9.9.9.9")
        assert not fake.workspace("cid-C").find("9.9.9.9")


async def test_collision_highest_severity_and_update_push(db):
    with FakeTorq() as fake:
        ws = _workspaces(db, fake, names=("A", "B"))
        fake.workspace("cid-A").add(IP, "3.3.3.3", "SCORE_MALICIOUS", "known C2")
        fake.workspace("cid-B").add(IP, "3.3.3.3", "SCORE_SAFE")
        db.add(Rule(name="A->B", source_workspace_ids=[ws["A"].id], target_workspace_ids=[ws["B"].id]))
        db.commit()

        run = db.get(SyncRun, await run_sync())
        obs = _obs(db, "3.3.3.3")
        assert obs.reputation == "SCORE_MALICIOUS" and obs.description == "known C2"
        assert run.conflicts == 1 and run.pushed_updated == 1 and run.pushed_created == 0
        remote_b = fake.workspace("cid-B").find("3.3.3.3")
        assert remote_b["reputation"] == {"id": "SCORE_MALICIOUS"}
        assert remote_b["description"] == "known C2"


async def test_workspace_priority_strategy(db):
    with FakeTorq() as fake:
        _workspaces(db, fake, names=("A", "B"))
        fake.workspace("cid-A").add(IP, "4.4.4.4", "SCORE_SAFE")
        fake.workspace("cid-B").add(IP, "4.4.4.4", "SCORE_MALICIOUS")
        set_setting(db, "collision_strategy", "workspace_priority")
        db.commit()
        await run_sync()
        assert _obs(db, "4.4.4.4").reputation == "SCORE_SAFE"  # A has priority 10 < 20


async def test_pinned_observable_not_overwritten(db, admin_client):
    with FakeTorq() as fake:
        ws = _workspaces(db, fake, names=("A", "B"))
        remote = fake.workspace("cid-A")
        oid = remote.add(IP, "5.5.5.5", "SCORE_SAFE")
        db.add(Rule(name="central->all", source_workspace_ids=["central"]))
        db.commit()
        await run_sync()
        obs = _obs(db, "5.5.5.5")

        r = admin_client.patch(f"/api/observables/{obs.id}", json={"reputation": "SCORE_MALICIOUS"})
        assert r.status_code == 200 and r.json()["pinned"] is True

        remote.observables[oid]["reputation"] = {"id": "SCORE_VERY_SAFE"}
        await run_sync()
        assert _obs(db, "5.5.5.5").reputation == "SCORE_MALICIOUS"
        # The central edit is pushed out via the "central" source rule, including back to A.
        assert remote.observables[oid]["reputation"] == {"id": "SCORE_MALICIOUS"}
        assert fake.workspace("cid-B").find("5.5.5.5")["reputation"] == {"id": "SCORE_MALICIOUS"}
        assert ws  # silence unused


async def test_tombstone_blocks_reimport(db, admin_client):
    with FakeTorq() as fake:
        _workspaces(db, fake, names=("A",))
        fake.workspace("cid-A").add(HOST, "bad.example", "SCORE_MALICIOUS")
        await run_sync()
        obs = _obs(db, "bad.example")
        assert admin_client.delete(f"/api/observables/{obs.id}").status_code == 204
        await run_sync()
        db.expire_all()
        assert db.query(Observable).filter_by(value_norm="bad.example").count() == 0
        assert db.query(Tombstone).count() == 1


async def test_failed_workspace_is_isolated(db):
    with FakeTorq() as fake:
        ws = _workspaces(db, fake, names=("A", "B"))
        ws["B"].client_secret_enc = encrypt("wrong")
        db.commit()
        fake.workspace("cid-A").add(IP, "6.6.6.6", "SCORE_MALICIOUS")
        db.add(Rule(name="A->B", source_workspace_ids=[ws["A"].id]))
        db.commit()
        run = db.get(SyncRun, await run_sync())
        assert run.status == "partial" and run.pulled == 1 and run.pushed_created == 0
        db.expire_all()
        assert db.get(Workspace, ws["B"].id).last_sync_status == "error"
        assert db.get(Workspace, ws["A"].id).last_sync_status == "ok"


async def test_removed_remote_drops_link(db):
    with FakeTorq() as fake:
        _workspaces(db, fake, names=("A",))
        remote = fake.workspace("cid-A")
        oid = remote.add(IP, "7.7.7.7")
        await run_sync()
        del remote.observables[oid]
        await run_sync()
        db.expire_all()
        assert db.query(ObservableLink).count() == 0
        assert db.query(Observable).filter_by(value_norm="7.7.7.7").count() == 1  # history kept centrally


async def test_forbidden_everywhere_points_at_key_scope(db):
    import httpx

    with FakeTorq() as fake:
        _workspaces(db, fake, names=("A",))
        forbidden = httpx.Response(403, json={"error": {"status_code": 403, "status": "forbidden"}})
        fake.router.post("https://api.torq.io/public/v1alpha/observables/query").mock(return_value=forbidden)
        fake.router.get("https://api.torq.io/public/v1alpha/workflows").mock(return_value=forbidden)
        run = db.get(SyncRun, await run_sync())
        assert "every endpoint" in run.errors[0] and "IP access rules" in run.errors[0]


async def test_forbidden_only_observables_points_at_role(db):
    import httpx

    with FakeTorq() as fake:
        _workspaces(db, fake, names=("A",))
        fake.router.post("https://api.torq.io/public/v1alpha/observables/query").mock(
            return_value=httpx.Response(403, json={"error": {"status_code": 403, "status": "forbidden"}})
        )
        fake.router.get("https://api.torq.io/public/v1alpha/workflows").mock(return_value=httpx.Response(200, json={}))
        run = db.get(SyncRun, await run_sync())
        assert "role lacks permission for observables" in run.errors[0]


async def test_eu_workspace_uses_eu_endpoints(db):
    with FakeTorq() as fake:
        fake.workspace("cid-EU").add(IP, "8.8.4.4", "SCORE_MALICIOUS")
        db.add(Workspace(name="EU", region="eu", client_id="cid-EU", client_secret_enc=encrypt("secret-cid-EU")))
        db.commit()
        run = db.get(SyncRun, await run_sync())
        assert run.status == "ok" and run.pulled == 1
        hosts = {call.request.url.host for call in fake.router.calls}
        assert hosts == {"auth.eu.torq.io", "api.eu.torq.io"}


async def test_api_call_log_records_token_first_and_redacts_secrets(db, admin_client):
    from app.models import SyncApiCall

    with FakeTorq() as fake:
        _workspaces(db, fake, names=("A",))
        fake.workspace("cid-A").add(IP, "1.0.0.1")
        run_id = await run_sync()
        db.expire_all()
        run = db.get(SyncRun, run_id)
        calls = db.query(SyncApiCall).filter_by(run_id=run_id).order_by(SyncApiCall.id).all()
        assert run.api_calls == len(calls) >= 2 and run.api_errors == 0
        first, second = calls[0], calls[1]
        assert first.url == "https://auth.torq.io/v1/auth/token" and first.status_code == 200
        assert first.request_body == "grant_type=client_credentials"
        assert first.request_headers["authorization"] == "Basic ***redacted***"
        assert first.request_headers["content-type"] == "application/x-www-form-urlencoded"
        assert first.request_headers["accept"] == "application/json"
        assert first.request_headers["accept-language"] == "en_US"
        assert '"access_token": "***redacted***"' in first.response_body
        assert second.url == "https://api.torq.io/public/v1alpha/observables/query"
        assert second.request_headers["authorization"] == "Bearer ***redacted***"
        assert '"page_size": 500' in second.request_body
        blob = " ".join(f"{c.request_headers} {c.request_body} {c.response_body}" for c in calls)
        assert "secret-cid-A" not in blob and "tok-cid-A" not in blob

        r = admin_client.get(f"/api/sync/runs/{run_id}/calls").json()
        assert r["total"] == len(calls) and r["items"][0]["method"] == "POST"
        assert admin_client.get(f"/api/sync/runs/{run_id}/calls", params={"failed_only": True}).json()["total"] == 0


async def test_enrichment_is_captured_per_workspace(db, admin_client):
    with FakeTorq() as fake:
        _workspaces(db, fake, names=("A",))
        remote = fake.workspace("cid-A")
        enrichment = {"ai_summary": "Known scanner", "virus_total": {"malicious": 12}}
        oid = remote.add(IP, "45.9.148.3", "SCORE_MALICIOUS", enrichment=enrichment)
        remote.add(IP, "45.9.148.4")
        await run_sync()

        listing = admin_client.get("/api/observables", params={"has_enrichment": True}).json()
        assert listing["total"] == 1
        item = listing["items"][0]
        assert item["value"] == "45.9.148.3" and item["has_enrichment"] is True
        assert "enrichment" not in item["links"][0]  # list view stays light
        assert admin_client.get("/api/observables", params={"has_enrichment": False}).json()["total"] == 1

        detail = admin_client.get(f"/api/observables/{item['id']}").json()
        assert detail["links"][0]["enrichment"] == enrichment
        assert detail["links"][0]["enrichment_updated_at"] == "2024-11-06T08:00:00Z"

        # Enrichment removed in Torq is cleared on the next sync.
        remote.observables[oid]["enrichment"] = {}
        await run_sync()
        detail = admin_client.get(f"/api/observables/{item['id']}").json()
        assert detail["has_enrichment"] is False and detail["links"][0]["enrichment"] is None


async def test_jp_workspace_uses_jp_endpoints(db, admin_client):
    with FakeTorq() as fake:
        fake.workspace("cid-JP").add(IP, "8.8.8.8", "SCORE_SAFE")
        r = admin_client.post("/api/workspaces", json={"name": "Tokyo", "region": "jp", "client_id": "cid-JP",
                                                       "client_secret": "secret-cid-JP"})
        assert r.status_code == 201 and r.json()["region"] == "jp"
        run = db.get(SyncRun, await run_sync())
        assert run.status == "ok" and run.pulled == 1
        urls = {str(call.request.url) for call in fake.router.calls}
        assert urls == {"https://auth.jp.torq.io/v1/auth/token", "https://api.jp.torq.io/public/v1alpha/observables/query"}
    assert admin_client.post("/api/workspaces", json={"name": "Bad", "region": "au", "client_id": "x",
                                                      "client_secret": "y"}).status_code == 422
