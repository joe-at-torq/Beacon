from tests.fake_torq import FakeTorq
from tests.test_sync import IP, _obs, _workspaces, run_sync


async def test_associated_cases_count_is_summed_across_workspaces(db, admin_client):
    with FakeTorq() as fake:
        ws = _workspaces(db, fake, names=("A", "B"))
        a, b = fake.workspace("cid-A"), fake.workspace("cid-B")
        a_id = a.add(IP, "203.0.113.70", "SCORE_MALICIOUS", cases=3)
        b.add(IP, "203.0.113.70", "SCORE_MALICIOUS", cases=4)
        a.add(IP, "203.0.113.71", cases=1)
        await run_sync()
        assert _obs(db, "203.0.113.70").associated_cases_count == 7

        listing = admin_client.get("/api/observables", params={"sort": "associated_cases_count", "order": "desc"}).json()
        top = listing["items"][0]
        assert top["value"] == "203.0.113.70" and top["associated_cases_count"] == 7
        assert {(l["workspace_name"], l["associated_cases_count"]) for l in top["links"]} == {("A", 3), ("B", 4)}
        assert listing["items"][1]["associated_cases_count"] == 1

        detail = admin_client.get(f"/api/observables/{top['id']}").json()
        assert detail["associated_cases_count"] == 7

        # Counts follow the workspaces on the next sync...
        a.observables[a_id]["associated_cases_count"] = 10
        await run_sync()
        assert _obs(db, "203.0.113.70").associated_cases_count == 14

        # ...and drop a workspace's share when it is disconnected.
        assert admin_client.delete(f"/api/workspaces/{ws['B'].id}").status_code == 204
        assert admin_client.get(f"/api/observables/{top['id']}").json()["associated_cases_count"] == 10
