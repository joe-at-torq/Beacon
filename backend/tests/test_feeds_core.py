from datetime import datetime, timedelta
from types import SimpleNamespace

from app.feeds import ingest
from app.models import Feed, FeedLink, Observable, ObservableEvent, Rule, Tombstone, utcnow
from app.stix.parser import extract, parse_indicator, parse_objects, reputation_for
from app.sync.engine import origin_set, plan_push
from app.sync.rules import evaluate, node_id, rule_edge_pairs

IP, HOST, HASH, URL, EMAIL = "TYPE_ID_IP_ADDRESS", "TYPE_ID_HOSTNAME", "TYPE_ID_FILE_HASH", "TYPE_ID_URL", "TYPE_ID_EMAIL_ADDRESS"
MAL, SUS, PS, UNK = "SCORE_MALICIOUS", "SCORE_SUSPICIOUS_OR_RISKY", "SCORE_PROBABLY_SAFE", "SCORE_UNKNOWN"
SHA256 = "a" * 64


def ind(pattern, id_="indicator--1", **kw):
    return {"type": "indicator", "spec_version": "2.1", "id": id_, "pattern": pattern, "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00Z", **kw}


# ---- Parser --------------------------------------------------------------------------------------------

def test_pattern_extraction_table():
    cases = [
        ("[ipv4-addr:value = '198.51.100.1']", [(IP, "198.51.100.1")]),
        ("[ipv4-addr:value = '198.51.100.0/24']", []),
        ("[ipv4-addr:value = '198.51.100.7/32']", [(IP, "198.51.100.7")]),
        ("[ipv6-addr:value = '2001:db8::1/128']", [(IP, "2001:db8::1")]),
        ("[domain-name:value = 'evil.example' OR url:value = 'http://evil.example/x']", [(HOST, "evil.example"), (URL, "http://evil.example/x")]),
        (f"[file:hashes.'SHA-256' = '{SHA256}' AND file:name = 'x.exe']", [(HASH, SHA256)]),
        (f"[file:hashes.SHA256 = '{SHA256}']", [(HASH, SHA256)]),
        ("[file:hashes.'SHA-512' = '" + "b" * 128 + "']", []),
        ("[email-message:from_ref.value = 'bad@evil.example']", [(EMAIL, "bad@evil.example")]),
        ("[url:value LIKE '%evil%'] OR [ipv4-addr:value != '1.1.1.1'] OR [ipv4-addr:value NOT = '2.2.2.2']", []),
        ("[url:value = 'http://x/it\\'s']", [(URL, "http://x/it's")]),
    ]
    for pattern, expected in cases:
        assert extract(pattern) == expected, pattern


def test_indicator_states_and_reputation():
    now = datetime(2026, 6, 1)
    assert parse_indicator(ind("[ipv4-addr:value = '1.2.3.4']", pattern_type="snort"), MAL) == []
    v20 = {"type": "indicator", "id": "indicator--2", "pattern": "[domain-name:value = 'old.example']", "labels": ["anomalous-activity"]}
    assert parse_indicator(v20, MAL, now=now)[0].reputation == SUS  # STIX 2.0: no pattern_type, labels
    assert parse_indicator(ind("[ipv4-addr:value = '1.2.3.4']", revoked=True), MAL, now=now)[0].active is False
    assert parse_indicator(ind("[ipv4-addr:value = '1.2.3.4']", valid_until="2026-02-01T00:00:00Z"), MAL, now=now)[0].active is False
    assert parse_indicator(ind("[ipv4-addr:value = '1.2.3.4']", confidence=20), MAL, 50, now=now)[0].active is False
    assert parse_indicator(ind("[ipv4-addr:value = '1.2.3.4']", confidence=80), MAL, 50, now=now)[0].active is True
    assert reputation_for({"indicator_types": ["benign"]}, MAL) == PS
    assert reputation_for({"indicator_types": ["malicious-activity"]}, SUS) == MAL
    assert reputation_for({}, SUS) == SUS
    objs = [ind("[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '1.2.3.4']"), {"type": "malware", "id": "malware--1"}]
    assert len(parse_objects(objs, MAL)) == 1  # duplicate value in one indicator, non-indicators ignored


# ---- Rules -------------------------------------------------------------------------------------------

def test_empty_source_rules_never_match_feeds_and_node_ids():
    obs = SimpleNamespace(type=IP, sub_type="SUB_TYPE_ID_IP_ADDRESS_IPV4", reputation=MAL)
    any_source = SimpleNamespace(enabled=True, source_workspace_ids=[], target_workspace_ids=[], types=[], sub_types=[],
                                 min_reputation=None, sync_updates=True)
    feed_rule = SimpleNamespace(**{**vars(any_source), "source_workspace_ids": ["feed:3"]})
    assert evaluate([any_source], {"feed:3"}, 1, obs) is None
    assert evaluate([any_source], {"feed:3", "2"}, 1, obs) is True  # also seen natively in workspace 2
    assert evaluate([feed_rule], {"feed:3"}, 1, obs) is True
    assert evaluate([feed_rule], {"feed:4"}, 1, obs) is None
    assert node_id("feed:3") == "feed:3" and node_id(5) == "ws:5" and node_id("central") == "central"
    assert ("feed:3", "ws:1") in rule_edge_pairs(feed_rule, [1, 2])
    assert all(not s.startswith("feed:") for s, _ in rule_edge_pairs(any_source, [1, 2]))


# ---- Ingest ------------------------------------------------------------------------------------------

def _feed(db, **kw):
    feed = Feed(name=kw.pop("name", "Test feed"), url="https://taxii.example/api1/", default_reputation=MAL, **kw)
    db.add(feed)
    db.commit()
    return feed


def _events(db, obs_id, kind=None):
    q = db.query(ObservableEvent).filter_by(observable_id=obs_id)
    return q.filter_by(kind=kind).all() if kind else q.all()


def test_ingest_creates_links_escalates_and_is_idempotent(db):
    feed = _feed(db)
    safe = Observable(type=IP, value="203.0.113.10", value_norm="203.0.113.10", reputation=PS, origin="workspace", value_source="1")
    pinned = Observable(type=IP, value="203.0.113.11", value_norm="203.0.113.11", reputation=PS, pinned=True, origin="manual",
                        value_source="central")
    db.add_all([safe, pinned, Tombstone(type=HOST, value_norm="deleted.example", value="deleted.example")])
    db.commit()
    objs = [
        ind("[ipv4-addr:value = '203.0.113.10']", "indicator--a"),
        ind("[ipv4-addr:value = '203.0.113.11']", "indicator--b"),
        ind("[domain-name:value = 'New.Example.']", "indicator--c"),
        ind("[domain-name:value = 'deleted.example']", "indicator--d"),
        ind("[domain-name:value = 'gone.example']", "indicator--e", revoked=True),
    ]
    stats = ingest.upsert(db, feed, parse_objects(objs, MAL))
    db.commit()
    assert (stats.created, stats.linked, stats.escalated, stats.skipped_tombstoned) == (1, 2, 1, 1)
    new = db.query(Observable).filter_by(value_norm="new.example").one()
    assert new.origin == "feed" and new.value_source == f"feed:{feed.id}" and not new.pinned and new.reputation == MAL
    assert new.changed_at is not None
    assert db.query(Observable).filter_by(value_norm="gone.example").first() is None  # revoked: never created
    db.refresh(safe)
    db.refresh(pinned)
    assert safe.reputation == MAL and not safe.pinned and safe.value_source == f"feed:{feed.id}"
    assert pinned.reputation == PS  # centrally edited: untouched
    assert [e.detail["cause"] for e in _events(db, safe.id, "reputation_changed")] == ["feed"]
    assert len(_events(db, pinned.id, "seen_in_feed")) == 1
    # Feed membership makes it a rule source; never "central" (it isn't pinned).
    assert origin_set(new) == {f"feed:{feed.id}"}
    before = db.query(ObservableEvent).count()
    stats2 = ingest.upsert(db, feed, parse_objects(objs, MAL))
    db.commit()
    assert db.query(ObservableEvent).count() == before and stats2.created == stats2.linked == stats2.escalated == 0
    # An analyst downgrade isn't fought on every poll (no change in the feed).
    safe.reputation = PS
    db.commit()
    ingest.upsert(db, feed, parse_objects(objs, MAL))
    db.commit()
    db.refresh(safe)
    assert safe.reputation == PS


def test_revocation_snapshot_and_expiry(db):
    feed = _feed(db, kind="stix_url")
    objs = [ind("[domain-name:value = 'a.example']", "indicator--1"),
            ind("[domain-name:value = 'b.example']", "indicator--2", valid_until="2099-01-01T00:00:00Z")]
    ingest.upsert(db, feed, parse_objects(objs, MAL))
    db.commit()
    a = db.query(Observable).filter_by(value_norm="a.example").one()
    b = db.query(Observable).filter_by(value_norm="b.example").one()
    # Snapshot without "a": its listing is deactivated; the observable itself stays.
    stats = ingest.upsert(db, feed, parse_objects(objs[1:], MAL))
    ingest.finish_snapshot(db, feed, stats)
    db.commit()
    db.expire_all()
    assert origin_set(a) == set() and db.get(Observable, a.id) is not None
    assert len(_events(db, a.id, "removed_from_feed")) == 1
    # Revoked later: deactivated too.
    ingest.upsert(db, feed, parse_objects([ind("[domain-name:value = 'b.example']", "indicator--2", revoked=True)], MAL))
    db.commit()
    db.expire_all()
    assert origin_set(b) == set()
    # Expiry by valid_until and by the feed's max age.
    c = ingest.upsert(db, feed, parse_objects([ind("[domain-name:value = 'c.example']", "indicator--3",
                                                     valid_until=(utcnow() + timedelta(hours=1)).isoformat() + "Z")], MAL))
    db.commit()
    assert ingest.expire(db, now=utcnow() + timedelta(hours=2)) == 1
    db.commit()
    feed.max_age_days = 1
    ingest.upsert(db, feed, parse_objects([ind("[domain-name:value = 'd.example']", "indicator--4")], MAL))
    db.commit()
    assert ingest.expire(db, now=utcnow() + timedelta(days=2)) == 1
    db.commit()
    assert c.created == 1


def test_plan_push_respects_feed_sources(db):
    from app.models import Workspace
    from app.security import encrypt

    feed = _feed(db)
    ws = Workspace(name="T", region="us", client_id="cid-T", client_secret_enc=encrypt("x"))
    db.add(ws)
    db.commit()
    ingest.upsert(db, feed, parse_objects([ind("[domain-name:value = 'push.example']")], MAL))
    db.commit()
    obs = db.query(Observable).filter_by(value_norm="push.example").one()
    base = {"enabled": True, "types": [], "sub_types": [], "min_reputation": None, "sync_updates": True}
    any_rule = Rule(name="any", source_workspace_ids=[], target_workspace_ids=[ws.id], **base)
    assert plan_push([obs], [any_rule], [ws]) == []
    feed_rule = Rule(name="feed", source_workspace_ids=[f"feed:{feed.id}"], target_workspace_ids=[ws.id], **base)
    ops = plan_push([obs], [feed_rule], [ws])
    assert [(op.kind, op.observable.value) for op in ops] == [("create", "push.example")]


async def test_feed_observable_seen_in_workspace_keeps_feed_source_and_flows(db, admin_client):
    from app.models import SyncRun
    from app.settings_store import set_setting
    from app.sync.engine import run_sync
    from tests.fake_torq import FakeTorq
    from tests.test_sync import _workspaces

    with FakeTorq() as fake:
        ws = _workspaces(db, fake, ("A", "B"))
        a, b = fake.workspace("cid-A"), fake.workspace("cid-B")
        feed = _feed(db)
        ingest.upsert(db, feed, parse_objects([ind("[domain-name:value = 'feed-only.example']", "indicator--x"),
                                              ind("[domain-name:value = 'both.example']", "indicator--y")], MAL))
        db.commit()
        a.add(HOST, "both.example", SUS)  # also seen natively in workspace A
        db.add(Rule(name="Feed to B", source_workspace_ids=[f"feed:{feed.id}"], target_workspace_ids=[ws["B"].id]))
        db.commit()
        run = db.get(SyncRun, await run_sync())
        assert run.status == "ok", run.errors
        db.expire_all()
        both = db.query(Observable).filter_by(value_norm="both.example").one()
        assert f"feed:{feed.id}" in origin_set(both) and str(ws["A"].id) in origin_set(both)
        assert b.find("feed-only.example") and b.find("both.example") and not a.find("feed-only.example")
        flows = admin_client.get("/api/dashboard/flows").json()
        node = next(n for n in flows["nodes"] if n["id"] == f"feed:{feed.id}")
        assert node["kind"] == "feed" and node["listed"] == 2
        e = next(e for e in flows["edges"] if e["source"] == f"feed:{feed.id}" and e["target"] == f"ws:{ws['B'].id}")
        assert e["count"] == 2 and e["allowed"]
        # Push cap: only N changes per run.
        ingest.upsert(db, feed, parse_objects([ind(f"[domain-name:value = 'cap{i}.example']", f"indicator--c{i}") for i in range(5)], MAL))
        set_setting(db, "max_pushes_per_run", 2)
        db.commit()
        run = db.get(SyncRun, await run_sync())
        assert run.pushed_created == 2 and any("capped" in e for e in run.errors)


def test_no_duplicates_when_the_value_already_exists(db):
    """Feed values match existing observables by type + normalized value, whatever their source or spelling."""
    feed, other = _feed(db), _feed(db, name="Second feed")
    existing = [
        Observable(type=HOST, value="Known.Example", value_norm="known.example", origin="workspace", value_source="1"),
        Observable(type=IP, value="2001:db8::7", value_norm="2001:db8::7", origin="manual", pinned=True, value_source="central"),
        Observable(type=HASH, value=SHA256, value_norm=SHA256, origin="workspace", value_source="1"),
        Observable(type=URL, value="http://bad.example/x", value_norm="http://bad.example/x", origin="workspace"),
    ]
    db.add_all(existing)
    db.commit()
    objs = [
        ind("[domain-name:value = 'KNOWN.example.']", "indicator--1"),  # case + trailing dot
        ind("[ipv6-addr:value = '2001:0db8:0000:0000:0000:0000:0000:0007']", "indicator--2"),  # expanded IPv6
        ind(f"[file:hashes.'SHA-256' = '{SHA256.upper()}']", "indicator--3"),  # upper-case hash
        ind("[url:value = 'hxxp://bad[.]example/x']", "indicator--4"),  # defanged
        ind("[domain-name:value = 'known.example']", "indicator--5"),  # a second indicator naming the same value
    ]
    stats = ingest.upsert(db, feed, parse_objects(objs, MAL))
    ingest.upsert(db, other, parse_objects(objs[:1], MAL))  # another feed listing it too
    db.commit()
    assert stats.created == 0 and db.query(Observable).count() == 4
    db.expire_all()
    known = db.query(Observable).filter_by(value_norm="known.example").one()
    assert {(lk.feed_id, lk.stix_id) for lk in db.query(FeedLink).filter_by(observable_id=known.id)} == {
        (feed.id, "indicator--1"), (feed.id, "indicator--5"), (other.id, "indicator--1")}
    assert origin_set(known) >= {f"feed:{feed.id}", f"feed:{other.id}"}


async def test_sync_after_feed_links_instead_of_duplicating(db):
    from app.sync.engine import run_sync
    from tests.fake_torq import FakeTorq
    from tests.test_sync import _workspaces

    with FakeTorq() as fake:
        _workspaces(db, fake, ("A",))
        feed = _feed(db)
        ingest.upsert(db, feed, parse_objects([ind("[domain-name:value = 'shared.example']")], MAL))
        db.commit()
        fake.workspace("cid-A").add(HOST, "SHARED.example", SUS)
        await run_sync()
    db.expire_all()
    rows = db.query(Observable).filter_by(value_norm="shared.example").all()
    assert len(rows) == 1 and rows[0].origin == "feed" and len(rows[0].links) == 1


async def test_concurrent_create_retries_the_page(db, monkeypatch):
    """Someone creates the same value while a page is being written: the page is retried and links to it."""
    from app.db import SessionLocal
    from app.feeds import poller

    feed = _feed(db)
    parsed = parse_objects([ind("[domain-name:value = 'race.example']")], MAL)
    real = ingest.upsert
    calls = []

    def racing_upsert(session, f, items, stats=None, now=None):
        if not calls:
            with SessionLocal() as other:  # committed between our lookup and our insert
                other.add(Observable(type=HOST, value="race.example", value_norm="race.example", origin="manual"))
                other.commit()
            calls.append(1)
            session.add(Observable(type=HOST, value="race.example", value_norm="race.example", origin="feed"))
            session.flush()
        return real(session, f, items, stats, now)

    monkeypatch.setattr(ingest, "upsert", racing_upsert)
    assert poller._write(feed.id, lambda s, f: ingest.upsert(s, f, parsed)) is True
    db.expire_all()
    assert db.query(Observable).filter_by(value_norm="race.example").count() == 1
    assert db.query(FeedLink).count() == 1
