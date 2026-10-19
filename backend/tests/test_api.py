def test_default_login_requires_password_change(client):
    assert client.get("/api/observables").status_code == 401
    r = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200 and r.json()["must_change_password"] is True
    assert client.get("/api/observables").status_code == 403
    r = client.post("/api/auth/change-password", json={"current_password": "admin", "new_password": "short"})
    assert r.status_code == 422
    r = client.post("/api/auth/change-password",
                    json={"current_password": "admin", "new_password": "N3w-Password"})
    assert r.status_code == 200 and r.json()["must_change_password"] is False
    assert client.get("/api/observables").status_code == 200


def test_bad_login(client):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code == 401


def test_user_management_and_roles(admin_client):
    r = admin_client.post("/api/users", json={"username": "viewer1", "password": "viewerpass1", "role": "viewer",
                                              "must_change_password": False})
    assert r.status_code == 201
    assert admin_client.post("/api/users", json={"username": "viewer1", "password": "viewerpass1"}).status_code == 409
    me = admin_client.get("/api/auth/me").json()
    assert admin_client.delete(f"/api/users/{me['id']}").status_code == 400

    admin_client.post("/api/auth/logout")
    admin_client.cookies.clear()
    assert admin_client.post("/api/auth/login", json={"username": "viewer1", "password": "viewerpass1"}).status_code == 200
    assert admin_client.get("/api/observables").status_code == 200
    assert admin_client.get("/api/users").status_code == 403
    r = admin_client.post("/api/observables", json={"type": "TYPE_ID_IP_ADDRESS", "value": "1.2.3.4"})
    assert r.status_code == 403


def test_observable_crud(admin_client):
    r = admin_client.post("/api/observables", json={"type": "TYPE_ID_IP_ADDRESS", "value": "10.0.0.1",
                                                    "reputation": "SCORE_MALICIOUS", "description": "test"})
    assert r.status_code == 201
    body = r.json()
    assert body["sub_type"] == "SUB_TYPE_ID_IP_ADDRESS_IPV4" and body["origin"] == "manual"
    assert admin_client.post("/api/observables", json={"type": "TYPE_ID_IP_ADDRESS",
                                                       "value": "10.0.0.1"}).status_code == 409
    assert admin_client.post("/api/observables", json={"type": "TYPE_ID_IP_ADDRESS",
                                                       "value": "not-an-ip"}).status_code == 422
    listing = admin_client.get("/api/observables", params={"search": "10.0", "reputation": "SCORE_MALICIOUS"}).json()
    assert listing["total"] == 1
    listing = admin_client.get("/api/observables", params={"sort": "reputation", "order": "asc"}).json()
    assert listing["total"] == 1
    r = admin_client.post("/api/observables/bulk", json={"ids": [body["id"]], "action": "set_reputation",
                                                         "reputation": "SCORE_SAFE"})
    assert r.json()["affected"] == 1
    assert admin_client.get(f"/api/observables/{body['id']}").json()["reputation"] == "SCORE_SAFE"


def test_workspace_and_rule_crud(admin_client):
    r = admin_client.post("/api/workspaces", json={"name": "Prod", "client_id": "x", "client_secret": "y"})
    assert r.status_code == 201
    ws_id = r.json()["id"]
    assert "client_secret" not in r.json() and "client_secret_enc" not in r.json()
    r2 = admin_client.post("/api/workspaces", json={"name": "Dev", "client_id": "x2", "client_secret": "y2"})
    dev_id = r2.json()["id"]

    r = admin_client.post("/api/rules", json={"name": "Prod->Dev", "source_workspace_ids": [ws_id],
                                              "target_workspace_ids": [dev_id], "types": ["TYPE_ID_IP_ADDRESS"],
                                              "sub_types": ["SUB_TYPE_ID_IP_ADDRESS_IPV4"]})
    assert r.status_code == 201
    rule_id = r.json()["id"]
    assert admin_client.post("/api/rules", json={"name": "bad", "types": ["NOPE"]}).status_code == 422
    assert admin_client.post("/api/rules", json={"name": "bad", "target_workspace_ids": [999]}).status_code == 400

    preview = admin_client.post("/api/rules/preview", json={}).json()
    assert preview["total_create"] == 0

    # Deleting the only target disables the rule rather than widening it to "all".
    assert admin_client.delete(f"/api/workspaces/{dev_id}").status_code == 204
    rule = next(r for r in admin_client.get("/api/rules").json() if r["id"] == rule_id)
    assert rule["enabled"] is False and rule["target_workspace_ids"] == []


def test_settings_and_dashboard(admin_client):
    r = admin_client.put("/api/settings", json={"collision_strategy": "most_recent", "sync_interval_minutes": 5})
    assert r.json()["collision_strategy"] == "most_recent"
    assert admin_client.put("/api/settings", json={"collision_strategy": "bogus"}).status_code == 422
    d = admin_client.get("/api/dashboard").json()
    assert d["totals"]["observables"] == 0 and len(d["growth"]) == 30
    assert admin_client.get("/api/meta").json()["types"]
    assert admin_client.get("/api/sync/status").json()["running"] is False


def test_connection_test_uses_saved_region(admin_client):
    import respx
    import httpx

    ws = admin_client.post("/api/workspaces", json={"name": "EU", "region": "eu", "client_id": "c",
                                                    "client_secret": "s"}).json()
    with respx.mock(assert_all_called=False) as mock:
        mock.post("https://auth.eu.torq.io/v1/auth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 3600}))
        mock.post("https://api.eu.torq.io/public/v1alpha/observables/query").mock(
            return_value=httpx.Response(200, json={"observables": []}))
        r = admin_client.post("/api/workspaces/test", json={"workspace_id": ws["id"]})
        assert r.json()["ok"] is True
        assert {c.request.url.host for c in mock.calls} == {"auth.eu.torq.io", "api.eu.torq.io"}


def test_observed_over_time(admin_client, db):
    from datetime import timedelta

    from app.models import Observable, utcnow

    now = utcnow()
    for i, (first_days, last_days) in enumerate([(2, 1), (2, 0), (20, 3), (200, 10), (500, 400)]):
        db.add(Observable(type="TYPE_ID_IP_ADDRESS", value=f"10.9.0.{i}", value_norm=f"10.9.0.{i}",
                          first_observed_at=now - timedelta(days=first_days),
                          last_observed_at=now - timedelta(days=last_days), links=[]))
    db.commit()

    r = admin_client.get("/api/dashboard/observed", params={"range": "7d"}).json()
    assert r["bucket"] == "day" and len(r["points"]) == 7
    assert r["totals"] == {"first_observed": 2, "last_observed": 3}
    assert r["first_observed_before"] == 3
    assert r["points"][-1]["last_observed"] == 1  # observed today

    r = admin_client.get("/api/dashboard/observed", params={"range": "12m"}).json()
    assert r["bucket"] == "week" and r["totals"]["first_observed"] == 4
    assert all(p["start"] <= p["end"] for p in r["points"])

    r = admin_client.get("/api/dashboard/observed", params={"range": "all"}).json()
    assert r["bucket"] == "week" and r["totals"] == {"first_observed": 5, "last_observed": 5}
    assert admin_client.get("/api/dashboard/observed", params={"range": "5y"}).status_code == 422


def test_user_preferences(admin_client):
    assert admin_client.get("/api/auth/preferences").json() == {}
    layout = {"lg": [{"i": "flows", "x": 0, "y": 0, "w": 12, "h": 14}]}
    r = admin_client.patch("/api/auth/preferences", json={"dashboard_layout": layout, "flow_view": {"k": 1.5}})
    assert r.json() == {"dashboard_layout": layout, "flow_view": {"k": 1.5}}
    # Keys merge independently; null removes a key.
    assert admin_client.patch("/api/auth/preferences", json={"flow_view": {"k": 2}}).json()["dashboard_layout"] == layout
    assert admin_client.patch("/api/auth/preferences", json={"dashboard_layout": None}).json() == {"flow_view": {"k": 2}}
    assert admin_client.patch("/api/auth/preferences", json={"blob": "x" * 70_000}).status_code == 413
    # Preferences are per user.
    admin_client.post("/api/users", json={"username": "other", "password": "otherpass1", "must_change_password": False})
    admin_client.cookies.clear()
    admin_client.post("/api/auth/login", json={"username": "other", "password": "otherpass1"})
    assert admin_client.get("/api/auth/preferences").json() == {}
