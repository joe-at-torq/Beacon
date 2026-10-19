import httpx
import respx

from app.db import SessionLocal
from app.feeds import ingest, poller
from app.feeds.textlist import parse
from app.models import Feed, FeedLink, Observable, ObservableEvent

OPENPHISH = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
ET_IPS = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
IP, URL, HOST, HASH = "TYPE_ID_IP_ADDRESS", "TYPE_ID_URL", "TYPE_ID_HOSTNAME", "TYPE_ID_FILE_HASH"
MAL, PMAL, SUS, PS, UNK = "SCORE_MALICIOUS", "SCORE_PROBABLY_MALICIOUS", "SCORE_SUSPICIOUS_OR_RISKY", "SCORE_PROBABLY_SAFE", "SCORE_UNKNOWN"


def _feed(db, **kw):
    feed = Feed(name=kw.pop("name", "ET compromised"), kind="text_list", url=kw.pop("url", ET_IPS),
                list_type=kw.pop("list_type", "ip"), default_reputation=kw.pop("default_reputation", MAL), **kw)
    db.add(feed)
    db.commit()
    return feed


def _poll(db, feed, text):
    stats = ingest.upsert(db, feed, parse(text, feed.list_type, feed.default_reputation).items, mode="match")
    ingest.finish_snapshot(db, feed, stats, revert=True)
    db.commit()
    db.expire_all()
    return stats


def _obs(db, value, type_id=IP):
    return db.query(Observable).filter_by(type=type_id, value_norm=value).one()


# ---- Parser ------------------------------------------------------------------------------------------

def test_parse_rules():
    text = "\n".join([
        "# Emerging Threats", "; also a comment", "// and this", "", "198.51.100.1", "198.51.100.2   # trailing note",
        "198.51.100.3,extra,columns", "198.51.100.0/24", "198.51.100.9/32", "198.51.100.1", "not an ip",
        "﻿198.51.100.4",
    ])
    r = parse(text, "ip", MAL)
    assert [i.value for i in r.items] == ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.9", "198.51.100.4"]
    assert r.skipped == 2 and r.counts == {"IP address": 5} and len({i.stix_id for i in r.items}) == 5
    urls = parse("https://phish.example/login?x=1#frag\nhxxp://evil[.]example/a\nexample.org/path\n203.0.113.0/24", "url", MAL)
    assert [i.value for i in urls.items] == ["https://phish.example/login?x=1#frag", "http://evil.example/a", "http://example.org/path"]
    assert urls.skipped == 1
    doms = parse("*.Bad.Example.\nevil[.]example\n1.2.3.4", "domain", MAL)
    assert [i.value_norm for i in doms.items] == ["bad.example", "evil.example"] and doms.skipped == 1
    auto = parse(f"1.2.3.4\nhttps://x.example/p\n{'A' * 64}\nbad.example\nhost.example/path\njunk", "auto", MAL)
    assert [(i.type, i.value) for i in auto.items] == [
        (IP, "1.2.3.4"), (URL, "https://x.example/p"), (HASH, "a" * 64), (HOST, "bad.example"), (URL, "http://host.example/path")]
    assert auto.skipped == 1


# ---- Match / delta / revert --------------------------------------------------------------------------

def test_match_mode_sets_existing_reputations_and_reverts_on_removal(db):
    feed = _feed(db)
    db.add_all([
        Observable(type=IP, value="198.51.100.10", value_norm="198.51.100.10", reputation=PS, origin="workspace", value_source="3"),
        Observable(type=IP, value="198.51.100.11", value_norm="198.51.100.11", reputation="SCORE_MALICIOUS", origin="workspace"),
        Observable(type=IP, value="198.51.100.12", value_norm="198.51.100.12", reputation=PS, origin="manual", pinned=True,
                   value_source="central"),
    ])
    db.commit()
    feed.default_reputation = SUS  # match lowers too
    db.commit()
    s1 = _poll(db, feed, "198.51.100.10\n198.51.100.11\n198.51.100.12\n198.51.100.13\n")
    assert (s1.created, s1.linked, s1.escalated) == (1, 3, 2)
    raised, lowered, pinned, new = (_obs(db, f"198.51.100.1{i}") for i in range(4))
    assert raised.reputation == SUS and raised.value_source == f"feed:{feed.id}"
    assert lowered.reputation == SUS  # matched down from Malicious
    assert pinned.reputation == PS  # centrally edited: untouched
    assert new.reputation == SUS and new.origin == "feed"
    # Same list again: nothing changes, no new history.
    before = db.query(ObservableEvent).count()
    s2 = _poll(db, feed, "198.51.100.10\n198.51.100.11\n198.51.100.12\n198.51.100.13\n")
    assert db.query(ObservableEvent).count() == before and (s2.created, s2.linked, s2.escalated, s2.deactivated) == (0, 0, 0, 0)
    # An analyst changes .11 in the meantime; then .10, .11 and .13 leave the list.
    lowered.reputation = PMAL
    db.commit()
    s3 = _poll(db, feed, "198.51.100.12\n")
    assert s3.deactivated == 3 and s3.reverted == 2
    raised, lowered, pinned, new = (_obs(db, f"198.51.100.1{i}") for i in range(4))
    assert raised.reputation == PS and raised.value_source == "3"  # restored, incl. its source
    assert lowered.reputation == PMAL  # changed since: left alone
    assert new.reputation == UNK  # created by the list: back to Unknown
    causes = [e.detail.get("cause") for e in db.query(ObservableEvent).filter_by(observable_id=raised.id, kind="reputation_changed")]
    assert causes == ["feed", "feed_removed"]
    # Back on the list later: matched again, with a fresh restore point.
    _poll(db, feed, "198.51.100.10\n198.51.100.12\n")
    assert _obs(db, "198.51.100.10").reputation == SUS


def test_reputation_setting_change_reapplies_and_two_feeds_hand_over(db):
    a = _feed(db, name="A")
    b = _feed(db, name="B", url="https://b.example/ips.txt")
    db.add(Observable(type=IP, value="203.0.113.5", value_norm="203.0.113.5", reputation=PS, origin="workspace"))
    db.commit()
    _poll(db, a, "203.0.113.5\n203.0.113.6\n")
    _poll(db, b, "203.0.113.5\n")
    assert db.query(Observable).filter_by(value_norm="203.0.113.5").count() == 1
    assert _obs(db, "203.0.113.5").reputation == MAL
    a.default_reputation = SUS  # feed setting changed: re-applied to everything A lists
    db.commit()
    s = _poll(db, a, "203.0.113.5\n203.0.113.6\n")
    assert s.escalated == 2 and _obs(db, "203.0.113.5").reputation == SUS and _obs(db, "203.0.113.6").reputation == SUS
    # A drops the shared value while B still lists it: no revert yet...
    b.default_reputation = SUS
    db.commit()
    _poll(db, a, "203.0.113.6\n")
    assert _obs(db, "203.0.113.5").reputation == SUS
    # ...and when B drops it too, the original reputation comes back.
    _poll(db, b, "")
    assert _obs(db, "203.0.113.5").reputation == PS


# ---- Poller + API ------------------------------------------------------------------------------------

async def test_poller_with_example_feeds_delta_and_etag(db):
    ips = _feed(db, name="ET compromised IPs")
    urls = _feed(db, name="OpenPhish", url=OPENPHISH, list_type="url", default_reputation=PMAL)
    state = {"ips": "198.51.100.1\n198.51.100.2\n198.51.100.3\n", "etag": '"v1"'}

    def et(request):
        if request.headers.get("If-None-Match") == state["etag"]:
            return httpx.Response(304)
        return httpx.Response(200, text=state["ips"], headers={"ETag": state["etag"], "Content-Type": "text/plain"})

    with respx.mock(assert_all_called=False) as mock:
        mock.get(ET_IPS).mock(side_effect=et)
        mock.get(OPENPHISH).mock(return_value=httpx.Response(200, text="https://login-phish.example/a\nhttps://bank-phish.example/b\n"))
        assert (await poller.poll_feed(ips.id))["created"] == 3
        assert (await poller.poll_feed(urls.id))["created"] == 2
        assert (await poller.poll_feed(ips.id))["created"] == 0  # 304: unchanged, nothing read
        state.update(ips="198.51.100.2\n198.51.100.3\n198.51.100.4\n", etag='"v2"')
        out = await poller.poll_feed(ips.id)  # only the delta: +1, -1
    assert (out["created"], out["deactivated"], out["reverted"]) == (1, 1, 1)
    with SessionLocal() as s:
        assert s.query(FeedLink).filter_by(feed_id=ips.id, active=True).count() == 3
        assert s.query(Observable).filter_by(value_norm="198.51.100.1").one().reputation == UNK
        assert s.query(Observable).filter_by(type=URL, value_norm="https://login-phish.example/a").one().reputation == PMAL
        assert s.get(Feed, ips.id).etag == '"v2"'


def test_text_list_api(admin_client, monkeypatch):
    started = []
    monkeypatch.setattr("app.routers.feeds._start_poll", lambda feed_id: started.append(feed_id))
    with respx.mock(assert_all_called=False) as mock:
        mock.get(ET_IPS).mock(return_value=httpx.Response(200, text="# list\n198.51.100.1\n198.51.100.2\nnope\n"))
        t = admin_client.post("/api/feeds/test", json={"kind": "text_list", "url": ET_IPS, "list_type": "ip"}).json()
        assert t["ok"] and t["counts"] == {"IP address": 2} and t["skipped"] == 1 and "2 IP addresses" in t["message"]
        bad = admin_client.post("/api/feeds/test", json={"kind": "text_list", "url": ET_IPS, "list_type": "url"}).json()
        assert bad["ok"] is False
    body = {"name": "ET", "kind": "text_list", "url": ET_IPS, "list_type": "ip", "default_reputation": MAL, "poll_minutes": 60}
    r = admin_client.post("/api/feeds", json=body)
    assert r.status_code == 201, r.text
    feed = r.json()
    assert feed["list_type"] == "ip" and feed["kind"] == "text_list" and started == [feed["id"]]
    # Changing the reputation re-reads the list so it reaches every listed value.
    upd = admin_client.put(f"/api/feeds/{feed['id']}", json=body | {"default_reputation": SUS})
    assert upd.status_code == 200 and started == [feed["id"], feed["id"]]
    admin_client.put(f"/api/feeds/{feed['id']}", json=body | {"default_reputation": SUS, "poll_minutes": 120})
    assert len(started) == 2  # other changes don't


def test_database_source_filter(admin_client, db):
    from app.models import ObservableLink, Workspace
    from app.security import encrypt

    ws = Workspace(name="WS", region="us", client_id="cid-x", client_secret_enc=encrypt("x"))
    db.add(ws)
    db.commit()
    native = Observable(type=IP, value="192.0.2.1", value_norm="192.0.2.1", origin="workspace", value_source=str(ws.id))
    pushed = Observable(type=IP, value="192.0.2.2", value_norm="192.0.2.2", origin="manual", pinned=True, value_source="central")
    db.add_all([native, pushed])
    db.flush()
    db.add_all([ObservableLink(observable_id=native.id, workspace_id=ws.id, remote_id="1", relation="origin"),
                ObservableLink(observable_id=pushed.id, workspace_id=ws.id, remote_id="2", relation="pushed")])
    feed = _feed(db)
    db.commit()
    _poll(db, feed, "192.0.2.3\n192.0.2.1\n")
    _poll(db, feed, "192.0.2.1\n")  # 192.0.2.3 left the list: still "from" the feed

    def values(**params):
        r = admin_client.get("/api/observables", params=params)
        return sorted(o["value"] for o in r.json()["items"])

    assert values(source=str(ws.id)) == ["192.0.2.1"]  # native only, not the pushed copy
    assert values(workspace_id=ws.id) == ["192.0.2.1", "192.0.2.2"]  # "present in" keeps its meaning
    assert values(source="central") == ["192.0.2.2"]
    assert values(source=f"feed:{feed.id}") == ["192.0.2.1", "192.0.2.3"]
    assert values(source=["central", f"feed:{feed.id}"]) == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    q = admin_client.post("/api/v1/observables/query", json={"sources": ["central"]}).json()
    assert [o["value"] for o in q["items"]] == ["192.0.2.2"]
