import base64
from datetime import timedelta

import httpx
import pytest
import respx

from app.db import SessionLocal
from app.feeds import poller
from app.models import Feed, Observable, Tombstone, utcnow
from app.routers.taxii import COLLECTION_ID
from app.stix.serializer import indicator_id

IP, MAL, SUS, PS = "TYPE_ID_IP_ADDRESS", "SCORE_MALICIOUS", "SCORE_SUSPICIOUS_OR_RISKY", "SCORE_PROBABLY_SAFE"
OBJ = f"/taxii2/beacon/collections/{COLLECTION_ID}/objects/"
H = {"Accept": "application/taxii+json;version=2.1"}


@pytest.fixture
def taxii(admin_client):
    admin_client.put("/api/feeds/taxii-server", json={"enabled": True, "min_reputation": SUS})
    key = admin_client.post("/api/api-keys", json={"name": "SIEM", "role": "viewer"}).json()["key"]
    for i, rep in enumerate([MAL, MAL, SUS, PS]):
        admin_client.post("/api/observables", json={"type": IP, "value": f"203.0.113.{i + 1}", "reputation": rep})
    admin_client.cookies.clear()  # TAXII ignores session cookies; API keys only
    return admin_client, key


def _bearer(key):
    return H | {"Authorization": f"Bearer {key}"}


def test_discovery_collections_auth(taxii):
    client, key = taxii
    assert client.get("/taxii2/", headers=H).status_code == 401
    assert "Basic" in client.get("/taxii2/", headers=H).headers["www-authenticate"]
    assert client.get("/taxii2/", headers=H | {"Authorization": "Bearer bcn_nope"}).status_code == 401
    d = client.get("/taxii2/", headers=_bearer(key))
    assert d.status_code == 200 and d.headers["content-type"].startswith("application/taxii+json")
    assert d.json()["default"].endswith("/taxii2/beacon/")
    basic = base64.b64encode(f"anyone:{key}".encode()).decode()
    cols = client.get("/taxii2/beacon/collections/", headers=H | {"Authorization": f"Basic {basic}"}).json()["collections"]
    assert cols[0]["id"] == COLLECTION_ID and cols[0]["can_write"] is False
    assert client.get("/taxii2/beacon/collections/", headers={"Accept": "text/html", "Authorization": f"Bearer {key}"}).status_code == 406
    assert client.get("/taxii2/nope/", headers=_bearer(key)).status_code == 404


def test_objects_threshold_paging_and_filters(taxii):
    client, key = taxii
    full = client.get(OBJ, headers=_bearer(key))
    objs = full.json()["objects"]
    assert {o["name"] for o in objs} == {"203.0.113.1", "203.0.113.2", "203.0.113.3"}  # Probably safe not published
    o = next(x for x in objs if x["name"] == "203.0.113.1")
    assert o["id"] == indicator_id(IP, "203.0.113.1") and o["pattern"] == "[ipv4-addr:value = '203.0.113.1']"
    assert o["indicator_types"] == ["malicious-activity"] and o["x_beacon_reputation"] == MAL and "revoked" not in o
    assert full.headers["X-TAXII-Date-Added-First"] <= full.headers["X-TAXII-Date-Added-Last"]
    # Paging (limit 1) walks every object exactly once, even with identical timestamps.
    with SessionLocal() as s:
        same = utcnow() - timedelta(minutes=5)
        s.query(Observable).update({"changed_at": same})
        s.commit()
    seen, nxt = [], None
    for _ in range(10):
        page = client.get(OBJ, params={"limit": 1, **({"next": nxt} if nxt else {})}, headers=_bearer(key)).json()
        seen += [x["name"] for x in page["objects"]]
        if not page["more"]:
            break
        nxt = page["next"]
    assert sorted(seen) == ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
    assert client.get(OBJ, params={"match[type]": "malware"}, headers=_bearer(key)).json()["objects"] == []
    one = client.get(OBJ, params={"match[id]": o["id"]}, headers=_bearer(key)).json()["objects"]
    assert [x["name"] for x in one] == ["203.0.113.1"]
    single = client.get(f"{OBJ}{o['id']}/", headers=_bearer(key)).json()["objects"]
    assert single[0]["id"] == o["id"]
    man = client.get(f"/taxii2/beacon/collections/{COLLECTION_ID}/manifest/", headers=_bearer(key)).json()
    assert {m["id"] for m in man["objects"]} == {x["id"] for x in objs}


def test_incremental_clients_get_revocations(taxii):
    client, key = taxii
    first = client.get(OBJ, headers=_bearer(key))
    cursor = first.headers["X-TAXII-Date-Added-Last"]
    with SessionLocal() as s:
        down = s.query(Observable).filter_by(value="203.0.113.2").one()
        down.reputation = PS  # downgraded below the threshold
        gone = s.query(Observable).filter_by(value="203.0.113.3").one()
        s.add(Tombstone(type=gone.type, value_norm=gone.value_norm, value=gone.value, deleted_by="admin",
                        deleted_at=utcnow() + timedelta(seconds=1)))
        s.delete(gone)
        s.commit()
    inc = client.get(OBJ, params={"added_after": cursor}, headers=_bearer(key)).json()["objects"]
    states = {o["name"]: o.get("revoked", False) for o in inc}
    assert states == {"203.0.113.2": True, "203.0.113.3": True}
    # A full download doesn't include retractions.
    assert all(not o.get("revoked") for o in client.get(OBJ, headers=_bearer(key)).json()["objects"])


def test_disabled_server_is_hidden(admin_client):
    key = admin_client.post("/api/api-keys", json={"name": "k", "role": "viewer"}).json()["key"]
    assert admin_client.get("/taxii2/", headers=_bearer(key)).status_code == 404


async def test_round_trip_feed_ingests_beacons_own_taxii(taxii, db):
    client, key = taxii
    base = "https://beacon.example"
    with respx.mock(assert_all_called=False) as mock:
        def proxy(request: httpx.Request):
            r = client.get(request.url.raw_path.decode(), headers=dict(request.headers))
            return httpx.Response(r.status_code, content=r.content, headers=dict(r.headers))

        mock.route(host="beacon.example").mock(side_effect=proxy)
        feed = Feed(name="Beacon itself", url=f"{base}/taxii2/", collection_id=COLLECTION_ID, auth="header",
                    header_name="Authorization", default_reputation=SUS)
        from app.security import encrypt

        feed.secret_enc = encrypt(f"Bearer {key}")
        db.add(feed)
        db.commit()
        out = await poller.poll_feed(feed.id)
    assert "error" not in out, out
    assert out["linked"] == 3 and out["created"] == 0  # same database: links, nothing new
