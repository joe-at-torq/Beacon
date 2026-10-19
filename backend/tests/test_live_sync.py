"""Live sync progress published for the flow graph while a sync runs."""

import copy

from app.models import Rule
from app.sync import engine
from tests.fake_torq import FakeTorq
from tests.test_sync import IP, _workspaces, run_sync


async def test_live_progress_during_sync(db, admin_client):
    with FakeTorq(page_size_cap=500) as fake:
        ws = _workspaces(db, fake, names=("A", "B"))
        a, b = f"ws:{ws['A'].id}", f"ws:{ws['B'].id}"
        for i in range(3):
            fake.workspace("cid-A").add(IP, f"203.0.113.{i}", "SCORE_MALICIOUS")
        db.add(Rule(name="A->B", source_workspace_ids=[ws["A"].id], target_workspace_ids=[ws["B"].id]))
        db.commit()

        seen = {"pull": [], "push": []}
        orig_query, orig_create = fake._query, fake._create

        def query(request):
            seen["pull"].append((engine.state.phase, copy.deepcopy(engine.state.live)))
            return orig_query(request)

        def create(request):
            seen["push"].append((engine.state.phase, copy.deepcopy(engine.state.live)))
            return orig_create(request)

        fake._query, fake._create = query, create
        # Re-register routes so respx calls the wrapped handlers.
        fake.router.post("https://api.torq.io/public/v1alpha/observables/query").mock(side_effect=query)
        fake.router.post("https://api.torq.io/public/v1alpha/observables").mock(side_effect=create)

        await run_sync()

        phase, live = seen["pull"][0]
        assert phase == "pull"
        statuses = {w["name"]: w["pull"] for w in live["workspaces"].values()}
        assert "running" in statuses.values() and set(statuses) == {"A", "B"}

        phase, live = seen["push"][-1]
        assert phase == "push"
        edge = live["edges"][f"{a}>{b}"]
        assert edge["total"] == 3 and 0 <= edge["done"] < 3
        target = live["workspaces"][str(ws["B"].id)]
        assert target["push_total"] == 3 and target["pull"] == "done"

        # After the run the live state is cleared and the status API reports none.
        assert engine.state.live == {} and engine.state.running is False
        assert admin_client.get("/api/sync/status").json()["live"] is None
