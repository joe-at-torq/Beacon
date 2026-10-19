import json

import httpx
import pytest
import respx

from app.db import SessionLocal
from app.feeds import client, poller
from app.models import Feed, FeedLink, Observable, Rule

DISCOVERY = "https://taxii.example/taxii2/"
ROOT = "https://taxii.example/api1/"
OBJECTS = f"{ROOT}collections/col-1/objects/"
BUNDLE = "https://feeds.example/indicators.json"
MAL = "SCORE_MALICIOUS"


def ind(n, pattern=None, **kw):
    return {"type": "indicator", "spec_version": "2.1", "id": f"indicator--{n:04d}",
            "pattern": pattern or f"[ipv4-addr:value = '198.51.100.{n}']", "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00Z", **kw}


def _feed(db, **kw):
    feed = Feed(name=kw.pop("name", "TAXII test"), url=kw.pop("url", DISCOVERY), collection_id=kw.pop("collection_id", "col-1"),
                default_reputation=MAL, **kw)
    db.add(feed)
    db.commit()
    return feed.id


def _mock_server(mock, pages):
    mock.get(DISCOVERY).mock(return_value=httpx.Response(200, json={"title": "T", "default": "/api1/", "api_roots": ["/api1/"]}))
    mock.get(f"{ROOT}collections/").mock(return_value=httpx.Response(200, json={"collections": [
        {"id": "col-1", "title": "Indicators", "can_read": True}, {"id": "col-2", "title": "Other"}]}))
    calls = []

    def objects(request):
        calls.append(dict(request.url.params))
        idx = int(request.url.params.get("next", "0"))
        status, objs, last = pages[idx]
        if status != 200:
            return httpx.Response(status, headers={"Retry-After": "0"}, json={})
        more = idx + 1 < len(pages)
        body = {"more": more, "objects": objs, **({"next": str(idx + 1)} if more else {})}
        return httpx.Response(200, json=body, headers={"X-TAXII-Date-Added-Last": last} if last else {})

    mock.get(OBJECTS).mock(side_effect=objects)
    return calls


async def test_taxii_paging_cursor_and_retry(db):
    feed_id = _feed(db)
    pages = [
        (200, [ind(1), ind(2)], "2026-03-01T00:00:00.000Z"),
        (200, [ind(3, revoked=True), ind(4)], "2026-03-02T00:00:00.000Z"),
        (200, [ind(5, pattern="[domain-name:value = 'evil.example']")], None),
    ]
    with respx.mock(assert_all_called=False) as mock:
        calls = _mock_server(mock, pages)
        out = await poller.poll_feed(feed_id)
    assert out["created"] == 4 and "error" not in out
    assert all(c["match[type]"] == "indicator" for c in calls)
    assert len({c["added_after"] for c in calls}) == 1  # same added_after for every page of a run
    with SessionLocal() as s:
        feed = s.get(Feed, feed_id)
        assert feed.last_status == "ok" and feed.stats["created"] == 4
        assert feed.cursor.endswith("Z") and feed.cursor > "2026-03-02"  # last page had no header: poll start - overlap
        assert s.query(FeedLink).filter_by(feed_id=feed_id, active=True).count() == 4
        assert s.query(Observable).filter_by(value_norm="198.51.100.3").first() is None  # revoked
    # Next poll uses the stored cursor.
    with respx.mock(assert_all_called=False) as mock:
        calls = _mock_server(mock, [(429, [], None), (200, [], None)][1:])
        await poller.poll_feed(feed_id)
    assert calls[0]["added_after"] == feed.cursor


async def test_taxii_retry_after_and_failure_resume(db):
    feed_id = _feed(db)
    with respx.mock(assert_all_called=False) as mock:
        mock.get(DISCOVERY).mock(return_value=httpx.Response(200, json={"api_roots": [ROOT]}))
        seq = iter([httpx.Response(429, headers={"Retry-After": "0"}, json={}),
                    httpx.Response(200, json={"more": True, "next": "p2", "objects": [ind(10)]},
                                   headers={"X-TAXII-Date-Added-Last": "2026-04-01T00:00:00.000Z"}),
                    httpx.Response(500, text="boom")])
        mock.get(OBJECTS).mock(side_effect=lambda r: next(seq))
        out = await poller.poll_feed(feed_id)
    assert "500" in out["error"] and out["created"] == 1
    with SessionLocal() as s:
        feed = s.get(Feed, feed_id)
        assert feed.last_status == "error" and feed.cursor == "2026-04-01T00:00:00.000Z"  # resumes after page 1


async def test_bundle_url_etag_and_snapshot(db):
    feed_id = _feed(db, name="Bundle", kind="stix_url", url=BUNDLE, collection_id="")
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [ind(20), ind(21), {"type": "malware", "id": "malware--1"}]}
    with respx.mock(assert_all_called=False) as mock:
        route = mock.get(BUNDLE).mock(return_value=httpx.Response(200, json=bundle, headers={"ETag": '"v1"'}))
        assert (await poller.poll_feed(feed_id))["created"] == 2
        route.mock(side_effect=lambda r: httpx.Response(304) if r.headers.get("If-None-Match") == '"v1"' else httpx.Response(500))
        assert (await poller.poll_feed(feed_id))["created"] == 0  # unchanged
        bundle["objects"] = [ind(21)]
        route.mock(return_value=httpx.Response(200, json=bundle, headers={"ETag": '"v2"'}))
        assert (await poller.poll_feed(feed_id))["deactivated"] == 1  # 198.51.100.20 left the snapshot
    with SessionLocal() as s:
        assert s.get(Feed, feed_id).etag == '"v2"'
        assert s.query(FeedLink).filter_by(feed_id=feed_id, active=True).count() == 1


def test_feed_api_crud_collections_and_delete_cleanup(admin_client, monkeypatch):
    monkeypatch.setattr("app.routers.feeds._start_poll", lambda feed_id: None)
    with respx.mock(assert_all_called=False) as mock:
        _mock_server(mock, [(200, [], None)])
        cols = admin_client.post("/api/feeds/collections", json={"url": DISCOVERY}).json()
        assert [c["id"] for c in cols] == ["col-1", "col-2"]
        test = admin_client.post("/api/feeds/test", json={"url": DISCOVERY, "collection_id": "col-9"}).json()
        assert test["ok"] is False and "isn't on the server" in test["message"]
    body = {"name": "CISA", "kind": "taxii21", "url": DISCOVERY, "collection_id": "col-1", "auth": "basic",
            "username": "u", "secret": "s3cret", "poll_minutes": 30}
    assert admin_client.post("/api/feeds", json=body | {"collection_id": ""}).status_code == 400
    assert admin_client.post("/api/feeds", json=body | {"url": "ftp://x"}).status_code == 422
    r = admin_client.post("/api/feeds", json=body)
    assert r.status_code == 201, r.text
    feed = r.json()
    assert feed["secret_set"] is True and "secret" not in feed and "s3cret" not in json.dumps(feed)
    upd = admin_client.put(f"/api/feeds/{feed['id']}", json={**body, "secret": None, "poll_minutes": 120}).json()
    assert upd["poll_minutes"] == 120 and upd["secret_set"] is True  # secret kept when omitted
    # Rules can name the feed; deleting the feed strips it and disables a rule left without sources.
    rule = admin_client.post("/api/rules", json={"name": "Feed to all", "source_workspace_ids": [f"feed:{feed['id']}"]})
    assert rule.status_code in (200, 201), rule.text
    assert admin_client.post("/api/rules", json={"name": "bad", "source_workspace_ids": ["feed:999"]}).status_code == 400
    assert admin_client.delete(f"/api/feeds/{feed['id']}").status_code == 204
    r2 = next(x for x in admin_client.get("/api/rules").json() if x["name"] == "Feed to all")
    assert r2["source_workspace_ids"] == [] and r2["enabled"] is False
    assert admin_client.get("/api/feeds").json() == []


def test_viewer_cannot_manage_feeds(admin_client):
    admin_client.post("/api/users", json={"username": "v", "password": "viewerpass1", "role": "viewer", "must_change_password": False})
    admin_client.cookies.clear()
    admin_client.post("/api/auth/login", json={"username": "v", "password": "viewerpass1"})
    assert admin_client.get("/api/feeds").status_code == 200
    assert admin_client.post("/api/feeds", json={"name": "x", "url": BUNDLE, "kind": "stix_url"}).status_code == 403
