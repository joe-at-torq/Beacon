"""Public v1 API: API keys, role enforcement, observables, query, rules, sync, OpenAPI and Postman export."""

from datetime import timedelta

from app.models import ApiKey, Workspace, utcnow
from app.security import encrypt
from tests.fake_torq import FakeTorq

IP = "TYPE_ID_IP_ADDRESS"


def _key(admin_client, role="analyst", **kw) -> str:
    r = admin_client.post("/api/api-keys", json={"name": f"{role}-key", "role": role, **kw})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["key"].startswith("bcn_") and body["prefix"] == body["key"][:10]
    return body["key"]


def _h(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def test_api_key_lifecycle_and_roles(admin_client, db):
    viewer, analyst, admin = (_key(admin_client, r) for r in ("viewer", "analyst", "admin"))
    listed = admin_client.get("/api/api-keys").json()
    assert {k["role"] for k in listed} == {"viewer", "analyst", "admin"} and all("key" not in k for k in listed)
    admin_client.cookies.clear()  # from here on: API keys only
    c = admin_client

    assert c.get("/api/v1/observables").status_code == 401
    assert c.get("/api/v1/observables", headers=_h("bcn_bogus")).status_code == 401
    assert c.get("/api/v1/observables", headers=_h(viewer)).status_code == 200
    body = {"type": IP, "value": "203.0.113.9", "reputation": "SCORE_MALICIOUS"}
    assert c.post("/api/v1/observables", json=body, headers=_h(viewer)).status_code == 403
    assert c.post("/api/v1/observables", json=body, headers=_h(analyst)).status_code == 201
    rule = {"name": "r", "types": [IP]}
    assert c.post("/api/v1/rules", json=rule, headers=_h(analyst)).status_code == 403
    assert c.post("/api/v1/rules", json=rule, headers=_h(admin)).status_code == 201

    record = db.query(ApiKey).filter_by(role="viewer").one()
    assert record.last_used_at is not None
    record.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    r = c.get("/api/v1/observables", headers=_h(viewer))
    assert r.status_code == 401 and "expired" in r.json()["detail"]


def test_revoked_key_and_session_fallback(admin_client):
    key = _key(admin_client, "viewer")
    key_id = admin_client.get("/api/api-keys").json()[0]["id"]
    assert admin_client.get("/api/v1/rules").status_code == 200  # signed-in session works without a key
    assert admin_client.delete(f"/api/api-keys/{key_id}").status_code == 204
    admin_client.cookies.clear()
    assert admin_client.get("/api/v1/rules", headers=_h(key)).status_code == 401


def test_observable_crud_lookup_and_query(admin_client):
    key = _key(admin_client, "analyst")
    admin_client.cookies.clear()
    c, h = admin_client, _h(key)
    created = c.post("/api/v1/observables", json={"type": IP, "value": "2001:0db8::0001", "reputation": "SCORE_MALICIOUS",
                                                  "description": "c2"}, headers=h).json()
    assert created["sub_type"] == "SUB_TYPE_ID_IP_ADDRESS_IPV6" and created["origin"] == "manual"
    c.post("/api/v1/observables", json={"type": IP, "value": "198.51.100.1", "reputation": "SCORE_SAFE"}, headers=h)
    c.post("/api/v1/observables", json={"type": "TYPE_ID_HOSTNAME", "value": "evil.example",
                                        "reputation": "SCORE_PROBABLY_MALICIOUS"}, headers=h)
    assert c.post("/api/v1/observables", json={"type": IP, "value": "2001:db8::1"}, headers=h).status_code == 409

    # Lookup normalizes the value.
    found = c.get("/api/v1/observables/lookup", params={"type": IP, "value": "2001:DB8:0:0::1"}, headers=h)
    assert found.status_code == 200 and found.json()["id"] == created["id"]
    assert c.get("/api/v1/observables/lookup", params={"type": IP, "value": "10.0.0.1"}, headers=h).status_code == 404

    q = c.post("/api/v1/observables/query", json={"types": [IP], "min_severity": 8}, headers=h).json()
    assert q["total"] == 1 and q["items"][0]["id"] == created["id"]
    q = c.post("/api/v1/observables/query", json={"min_severity": 8, "sort": "value", "order": "asc"}, headers=h).json()
    assert [i["value"] for i in q["items"]] == ["2001:0db8::0001", "evil.example"]
    q = c.post("/api/v1/observables/query", json={"search": "c2", "page_size": 1}, headers=h).json()
    assert q["total"] == 1 and q["page_size"] == 1
    future = (utcnow() + timedelta(days=1)).isoformat() + "Z"
    assert c.post("/api/v1/observables/query", json={"first_observed": {"from": future}}, headers=h).json()["total"] == 0
    assert c.get("/api/v1/observables", params={"type": "TYPE_ID_HOSTNAME"}, headers=h).json()["total"] == 1

    oid = created["id"]
    patched = c.patch(f"/api/v1/observables/{oid}", json={"reputation": "SCORE_SAFE"}, headers=h).json()
    assert patched["reputation"] == "SCORE_SAFE" and patched["pinned"] is True
    history = c.get(f"/api/v1/observables/{oid}/history", headers=h).json()
    assert history["items"][0]["actor"] == "api:analyst-key"
    assert c.post(f"/api/v1/observables/{oid}/revert", headers=h).status_code == 400  # manual: always authoritative
    assert c.delete(f"/api/v1/observables/{oid}", headers=h).status_code == 204
    assert c.get(f"/api/v1/observables/{oid}", headers=h).status_code == 404


def test_rules_crud(admin_client, db):
    for name in ("A", "B"):
        db.add(Workspace(name=name, client_id=name, client_secret_enc=encrypt("x")))
    db.commit()
    a, b = (w.id for w in db.query(Workspace).order_by(Workspace.name))
    key = _key(admin_client, "admin")
    admin_client.cookies.clear()
    c, h = admin_client, _h(key)
    rule = c.post("/api/v1/rules", json={"name": "A to B", "source_workspace_ids": [a], "target_workspace_ids": [b],
                                         "types": [IP], "sub_types": ["SUB_TYPE_ID_IP_ADDRESS_IPV4"]}, headers=h).json()
    assert c.get(f"/api/v1/rules/{rule['id']}", headers=h).json()["name"] == "A to B"
    paused = c.patch(f"/api/v1/rules/{rule['id']}", json={"enabled": False}, headers=h).json()
    assert paused["enabled"] is False and paused["types"] == [IP] and paused["target_workspace_ids"] == [b]
    replaced = c.put(f"/api/v1/rules/{rule['id']}", json={"name": "Any to all"}, headers=h).json()
    assert replaced["source_workspace_ids"] == [] and replaced["enabled"] is True
    assert c.post("/api/v1/rules", json={"name": "bad", "target_workspace_ids": [999]}, headers=h).status_code == 400
    assert c.post("/api/v1/rules", json={"name": "bad", "types": ["NOPE"]}, headers=h).status_code == 422
    assert c.post("/api/v1/rules/preview", headers=h).json()["total_create"] == 0
    assert len(c.get("/api/v1/rules", headers=h).json()) == 1
    assert c.delete(f"/api/v1/rules/{rule['id']}", headers=h).status_code == 204
    assert c.get(f"/api/v1/rules/{rule['id']}", headers=h).status_code == 404


def test_sync_via_api(admin_client, db):
    with FakeTorq() as fake:
        fake.workspace("cid-A").add(IP, "192.0.2.50", "SCORE_MALICIOUS")
        db.add(Workspace(name="A", client_id="cid-A", client_secret_enc=encrypt("secret-cid-A")))
        db.commit()
        key = _key(admin_client, "analyst")
        admin_client.cookies.clear()
        c, h = admin_client, _h(key)
        r = c.post("/api/v1/sync", headers=h)
        assert r.status_code == 202, r.text
        run_id = r.json()["run_id"]
        assert r.json()["run_url"] == f"/api/v1/sync/runs/{run_id}"
        # The TestClient runs the background task on its loop; poll until it finishes.
        for _ in range(50):
            run = c.get(f"/api/v1/sync/runs/{run_id}", headers=h).json()
            if run["status"] != "running":
                break
            import time
            time.sleep(0.1)
        assert run["status"] == "ok" and run["pulled"] == 1 and run["triggered_by"] == "api:analyst-key"
        assert c.get("/api/v1/sync/status", headers=h).json()["last_run"]["id"] == run_id
        assert c.post("/api/v1/sync", json={"workspace_id": 999}, headers=h).status_code == 404


def test_openapi_swagger_and_postman(client):
    spec = client.get("/api/v1/openapi.json").json()
    assert spec["info"]["title"] == "Beacon API" and spec["servers"][0]["url"] == "/api/v1"
    assert "/observables/query" in spec["paths"] and "/api/observables" not in spec["paths"]
    assert spec["components"]["securitySchemes"]["ApiKey"]["scheme"] == "bearer"
    html = client.get("/api/v1/docs")
    assert html.status_code == 200 and "/swagger/swagger-ui-bundle.js" in html.text and "<script>" not in html.text

    r = client.get("/api/v1/postman.json")
    assert "Beacon API.postman_collection.json" in r.headers["content-disposition"]
    col = r.json()
    assert col["info"]["schema"].endswith("v2.1.0/collection.json")
    assert col["auth"]["bearer"][0]["value"] == "{{apiKey}}"
    assert {v["key"] for v in col["variable"]} == {"baseUrl", "apiKey"}
    assert col["variable"][0]["value"].endswith("/api/v1")
    folders = {f["name"]: f["item"] for f in col["item"]}
    assert set(folders) == {"Observables", "Database query", "Rules", "Enrichment rules", "Sync", "Reference"}
    operations = sum(len([m for m in ops if m in ("get", "post", "put", "patch", "delete")]) for ops in spec["paths"].values())
    assert sum(len(items) for items in folders.values()) == operations
    query = next(i for i in folders["Database query"] if i["name"] == "Query the database")
    assert query["request"]["url"]["raw"] == "{{baseUrl}}/observables/query"
    assert '"min_severity": 8' in query["request"]["body"]["raw"]
    get_one = next(i for i in folders["Observables"] if i["name"] == "Get an observable")
    assert get_one["request"]["url"]["path"] == ["observables", ":obs_id"]
