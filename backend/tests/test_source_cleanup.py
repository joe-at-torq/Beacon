"""Deleting a workspace, feed or integration can also remove what came only from it."""

from app.feeds import ingest
from app.feeds.textlist import parse
from app.models import Feed, IntelEnrichment, Observable, ObservableLink, Tombstone, Workspace
from app.security import encrypt

IP = "TYPE_ID_IP_ADDRESS"


def _ws(db, name):
    ws = Workspace(name=name, region="us", client_id=f"cid-{name}", client_secret_enc=encrypt("x"))
    db.add(ws)
    db.commit()
    return ws


def _obs(db, value, **kw):
    o = Observable(type=IP, value=value, value_norm=value, origin=kw.pop("origin", "workspace"), **kw)
    db.add(o)
    db.flush()
    return o


def _link(db, obs, ws, relation="origin", rid=None):
    db.add(ObservableLink(observable_id=obs.id, workspace_id=ws.id, remote_id=rid or f"{obs.id}-{ws.id}", relation=relation))


def _values(db):
    db.expire_all()
    return sorted(o.value for o in db.query(Observable).all())


def test_workspace_delete_removes_only_its_exclusive_observables(admin_client, db):
    a, b = _ws(db, "A"), _ws(db, "B")
    only_a = _obs(db, "192.0.2.1", value_source=str(a.id))
    pushed = _obs(db, "192.0.2.2", value_source=str(a.id))
    both = _obs(db, "192.0.2.3", value_source=str(a.id))
    edited = _obs(db, "192.0.2.4", value_source="central", pinned=True)
    only_b = _obs(db, "192.0.2.5", value_source=str(b.id))
    for o in (only_a, pushed, both, edited):
        _link(db, o, a)
    _link(db, pushed, b, "pushed")  # Beacon copied it to B
    _link(db, both, b)  # also seen natively in B
    _link(db, only_b, b)
    db.commit()
    impact = admin_client.get(f"/api/workspaces/{a.id}/delete-impact").json()
    assert impact == {"observables": 2, "with_copies": 1}
    assert admin_client.delete(f"/api/workspaces/{a.id}?remove_observables=true").status_code == 204
    assert _values(db) == ["192.0.2.3", "192.0.2.4", "192.0.2.5"]
    # Tombstoned only where a copy remains in another workspace (it would otherwise come back on the next sync).
    assert [t.value_norm for t in db.query(Tombstone).all()] == ["192.0.2.2"]


def test_workspace_delete_keeps_observables_by_default(admin_client, db):
    a = _ws(db, "A")
    o = _obs(db, "192.0.2.9", value_source=str(a.id))
    _link(db, o, a)
    db.commit()
    assert admin_client.delete(f"/api/workspaces/{a.id}").status_code == 204
    assert _values(db) == ["192.0.2.9"]


def test_feed_delete_removes_only_feed_exclusive_observables(admin_client, db):
    ws = _ws(db, "A")
    feed = Feed(name="List", kind="text_list", list_type="ip", url="https://x.example/l.txt", default_reputation="SCORE_MALICIOUS")
    other = Feed(name="Other", kind="text_list", list_type="ip", url="https://y.example/l.txt", default_reputation="SCORE_MALICIOUS")
    native = _obs(db, "198.51.100.1", value_source=str(ws.id))
    _link(db, native, ws)
    db.add_all([feed, other])
    db.commit()
    ingest.upsert(db, feed, parse("198.51.100.1\n198.51.100.2\n198.51.100.3\n198.51.100.4\n", "ip", "SCORE_MALICIOUS").items, mode="match")
    ingest.upsert(db, other, parse("198.51.100.3\n", "ip", "SCORE_MALICIOUS").items, mode="match")
    db.commit()
    pushed = db.query(Observable).filter_by(value_norm="198.51.100.4").one()
    _link(db, pushed, ws, "pushed")
    db.commit()
    assert admin_client.get(f"/api/feeds/{feed.id}/delete-impact").json() == {"observables": 2, "with_copies": 1}
    assert admin_client.delete(f"/api/feeds/{feed.id}?remove_observables=true").status_code == 204
    # .1 is native in a workspace, .3 is listed by another feed: kept. .2 and .4 came only from the feed.
    assert _values(db) == ["198.51.100.1", "198.51.100.3"]
    assert [t.value_norm for t in db.query(Tombstone).all()] == ["198.51.100.4"]


def test_integration_delete_can_remove_enrichment(admin_client, db):
    assert admin_client.post("/api/integrations", json={"provider": "virustotal", "api_key": "k" * 32}).status_code == 201
    integ = admin_client.get("/api/integrations").json()[0]
    o = _obs(db, "203.0.113.1")
    db.add_all([IntelEnrichment(observable_id=o.id, provider="virustotal", status="ok", summary={}),
                IntelEnrichment(observable_id=o.id, provider="otx", status="ok", summary={})])
    db.commit()
    assert admin_client.get(f"/api/integrations/{integ['id']}/delete-impact").json() == {"enrichments": 1}
    assert admin_client.delete(f"/api/integrations/{integ['id']}?remove_enrichment=true").status_code == 204
    db.expire_all()
    assert [e.provider for e in db.query(IntelEnrichment).all()] == ["otx"]
    assert _values(db) == ["203.0.113.1"]  # observables themselves are untouched
