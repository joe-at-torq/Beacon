"""A reputation change made in any workspace must update the central database."""

from app.models import ObservableEvent, Rule, SyncRun
from tests.fake_torq import FakeTorq
from tests.test_sync import IP, _obs, _workspaces, run_sync


def _rep(remote, oid):
    return remote.observables[oid]["reputation"]["id"]


async def test_change_on_synced_copy_updates_central_and_is_not_reverted(db):
    """The reported bug: editing a copy Beacon pushed into a workspace was ignored, then overwritten."""
    with FakeTorq() as fake:
        _workspaces(db, fake, names=("A", "B"))
        a, b = fake.workspace("cid-A"), fake.workspace("cid-B")
        a_id = a.add(IP, "46.21.153.107", "SCORE_MALICIOUS")
        db.add(Rule(name="mesh"))  # any -> all, propagate updates
        db.commit()
        await run_sync()
        b_id = b.find("46.21.153.107")["id"]

        b.observables[b_id]["reputation"] = {"id": "SCORE_PROBABLY_MALICIOUS"}
        run = db.get(SyncRun, await run_sync())

        assert _obs(db, "46.21.153.107").reputation == "SCORE_PROBABLY_MALICIOUS"
        assert _rep(b, b_id) == "SCORE_PROBABLY_MALICIOUS"  # not pushed back over the user's edit
        assert _rep(a, a_id) == "SCORE_PROBABLY_MALICIOUS"  # mesh rule carries the change to A
        assert run.updated_central == 1
        ev = db.query(ObservableEvent).filter_by(kind="reputation_changed", run_id=run.id).one()
        assert ev.workspace_name == "B" and ev.detail["cause"] == "workspace_change"

        # Stable afterwards: nothing flips back on the next sync.
        run = db.get(SyncRun, await run_sync())
        assert _obs(db, "46.21.153.107").reputation == "SCORE_PROBABLY_MALICIOUS"
        assert run.updated_central == 0 and run.pushed_updated == 0


async def test_change_respects_rule_direction(db):
    """With only A -> B allowed, a change made in B updates central but does not flow back to A."""
    with FakeTorq() as fake:
        ws = _workspaces(db, fake, names=("A", "B"))
        a, b = fake.workspace("cid-A"), fake.workspace("cid-B")
        a_id = a.add(IP, "203.0.113.50", "SCORE_MALICIOUS")
        db.add(Rule(name="A->B", source_workspace_ids=[ws["A"].id], target_workspace_ids=[ws["B"].id]))
        db.commit()
        await run_sync()
        b_id = b.find("203.0.113.50")["id"]
        b.observables[b_id]["reputation"] = {"id": "SCORE_SAFE"}
        await run_sync()
        assert _obs(db, "203.0.113.50").reputation == "SCORE_SAFE"
        assert _rep(a, a_id) == "SCORE_MALICIOUS"
        assert _rep(b, b_id) == "SCORE_SAFE"


async def test_downgrade_wins_even_with_highest_severity(db):
    """Highest-severity no longer pins central to an old, higher verdict once a workspace changes it."""
    with FakeTorq() as fake:
        _workspaces(db, fake, names=("A", "B"))
        a, b = fake.workspace("cid-A"), fake.workspace("cid-B")
        a_id = a.add(IP, "198.51.100.77", "SCORE_MALICIOUS")
        b.add(IP, "198.51.100.77", "SCORE_MALICIOUS")
        await run_sync()
        a.observables[a_id]["reputation"] = {"id": "SCORE_SAFE"}
        await run_sync()
        assert _obs(db, "198.51.100.77").reputation == "SCORE_SAFE"
        await run_sync()
        assert _obs(db, "198.51.100.77").reputation == "SCORE_SAFE"


async def test_pinned_observable_ignores_workspace_change(db, admin_client):
    with FakeTorq() as fake:
        _workspaces(db, fake, names=("A",))
        a = fake.workspace("cid-A")
        a_id = a.add(IP, "192.0.2.10", "SCORE_SAFE")
        await run_sync()
        obs = _obs(db, "192.0.2.10")
        admin_client.patch(f"/api/observables/{obs.id}", json={"reputation": "SCORE_MALICIOUS"})
        a.observables[a_id]["reputation"] = {"id": "SCORE_VERY_SAFE"}
        await run_sync()
        assert _obs(db, "192.0.2.10").reputation == "SCORE_MALICIOUS"
        ev = db.query(ObservableEvent).filter_by(kind="workspace_reputation_changed").one()
        assert ev.detail["pinned"] is True


async def test_strategy_change_remerges(db, admin_client):
    with FakeTorq() as fake:
        _workspaces(db, fake, names=("A", "B"))
        fake.workspace("cid-A").add(IP, "192.0.2.20", "SCORE_SAFE")
        fake.workspace("cid-B").add(IP, "192.0.2.20", "SCORE_MALICIOUS")
        await run_sync()
        assert _obs(db, "192.0.2.20").reputation == "SCORE_MALICIOUS"
        admin_client.put("/api/settings", json={"collision_strategy": "workspace_priority"})
        assert _obs(db, "192.0.2.20").reputation == "SCORE_SAFE"  # A has the better priority
        ev = db.query(ObservableEvent).filter_by(kind="reputation_changed").order_by(ObservableEvent.id.desc()).first()
        assert ev.detail["cause"] == "strategy_change" and ev.actor == "admin"
