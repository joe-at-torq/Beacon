from app.models import Rule
from tests.fake_torq import FakeTorq
from tests.test_sync import HOST, IP, _workspaces, run_sync


def _edge(data, src, tgt):
    return next((e for e in data["edges"] if e["source"] == src and e["target"] == tgt), None)


async def test_flow_graph(db, admin_client):
    with FakeTorq() as fake:
        ws = _workspaces(db, fake)  # A, B, C
        a, b, c = (f"ws:{ws[n].id}" for n in "ABC")
        fake.workspace("cid-A").add(IP, "203.0.113.1", "SCORE_MALICIOUS")
        fake.workspace("cid-A").add(IP, "203.0.113.2", "SCORE_MALICIOUS")
        fake.workspace("cid-A").add(HOST, "evil.example", "SCORE_MALICIOUS")
        ab = Rule(name="A->B", source_workspace_ids=[ws["A"].id], target_workspace_ids=[ws["B"].id])
        off = Rule(name="C->A (off)", enabled=False, source_workspace_ids=[ws["C"].id],
                   target_workspace_ids=[ws["A"].id])
        db.add_all([ab, off])
        db.commit()
        await run_sync()

        data = admin_client.get("/api/dashboard/flows").json()
        e = _edge(data, a, b)
        assert e["count"] == 3 and e["rules"] == [ab.id] and e["allowed"] is True
        assert e["pending_create"] == 0
        nodes = {n["id"]: n for n in data["nodes"]}
        assert nodes[a]["native"] == 3 and nodes[a]["synced_out"] == 3
        assert nodes[b]["synced_in"] == 3 and nodes["central"]["total"] == 3

        # Disabled rule: listed, but its direction is not allowed.
        assert _edge(data, c, a)["allowed"] is False
        assert next(r for r in data["rules"] if r["id"] == off.id)["edges"] == [[c, a]]

        # A new rule shows as an allowed path with no traffic yet, with pending creates.
        db.add(Rule(name="A->C IPs", source_workspace_ids=[ws["A"].id], target_workspace_ids=[ws["C"].id],
                    types=[IP]))
        db.commit()
        data = admin_client.get("/api/dashboard/flows").json()
        ac = _edge(data, a, c)
        assert ac["count"] == 0 and ac["allowed"] is True and ac["pending_create"] == 2
        assert {n["id"]: n for n in data["nodes"]}[c]["pending_in"] == 2
        assert data["totals"]["pending"] == 2

        # Type filter narrows counts.
        data = admin_client.get("/api/dashboard/flows", params={"type": HOST}).json()
        assert _edge(data, a, b)["count"] == 1 and _edge(data, a, c)["pending_create"] == 0


async def test_central_flows(db, admin_client):
    with FakeTorq() as fake:
        ws = _workspaces(db, fake, names=("A", "B"))
        db.add(Rule(name="central everywhere", source_workspace_ids=["central"]))
        db.commit()
        admin_client.post("/api/observables", json={"type": IP, "value": "198.51.100.9", "reputation": "SCORE_MALICIOUS"})
        data = admin_client.get("/api/dashboard/flows").json()
        assert _edge(data, "central", f"ws:{ws['A'].id}")["pending_create"] == 1
        await run_sync()
        data = admin_client.get("/api/dashboard/flows").json()
        e = _edge(data, "central", f"ws:{ws['B'].id}")
        assert e["count"] == 1 and e["allowed"] is True and e["pending_create"] == 0
        assert {n["id"]: n for n in data["nodes"]}["central"]["manual"] == 1
