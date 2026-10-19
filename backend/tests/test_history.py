from app import history
from app.models import Observable, ObservableEvent, Rule
from tests.fake_torq import FakeTorq
from tests.test_sync import IP, _obs, _workspaces, run_sync


def _kinds(admin_client, obs_id):
    items = admin_client.get(f"/api/observables/{obs_id}/history").json()["items"]
    return [(e["kind"], e["workspace_name"], e["actor"]) for e in reversed(items)], items


async def test_observable_timeline_lifecycle(db, admin_client):
    with FakeTorq() as fake:
        ws = _workspaces(db, fake)  # A, B, C
        a, b, c = (fake.workspace(f"cid-{n}") for n in "ABC")
        a_id = a.add(IP, "203.0.113.9", "SCORE_SAFE", enrichment={"ai_summary": "benign"})
        b_id = b.add(IP, "203.0.113.9", "SCORE_MALICIOUS")
        db.add(Rule(name="A->C", source_workspace_ids=[ws["A"].id], target_workspace_ids=[ws["C"].id]))
        db.commit()

        await run_sync()
        obs = _obs(db, "203.0.113.9")
        kinds, items = _kinds(admin_client, obs.id)
        assert kinds == [
            ("created", "A", "sync"),
            ("enrichment_added", "A", "sync"),
            ("seen_in_workspace", "B", "sync"),
            ("reputation_changed", "B", "sync"),
            ("pushed_to_workspace", "C", "sync"),
        ]
        merge = next(e for e in items if e["kind"] == "reputation_changed")
        assert (merge["old_value"], merge["new_value"]) == ("SCORE_SAFE", "SCORE_MALICIOUS")
        assert merge["detail"]["cause"] == "merge" and merge["detail"]["strategy"] == "highest_severity"
        assert all(e["run_id"] for e in items)

        # A workspace changes its verdict -> recorded, merged, and pushed to C.
        b.observables[b_id]["reputation"] = {"id": "SCORE_SUSPICIOUS_OR_RISKY"}
        await run_sync()
        kinds, items = _kinds(admin_client, obs.id)
        assert kinds[5:] == [
            ("workspace_reputation_changed", "B", "sync"),
            ("reputation_changed", "B", "sync"),
            ("updated_in_workspace", "C", "sync"),
        ]
        pushed = items[0]
        assert pushed["detail"]["changes"]["reputation"] == {"old": "SCORE_MALICIOUS", "new": "SCORE_SUSPICIOUS_OR_RISKY"}

        # A manual edit pins the observable; reverting restores the merged value.
        admin_client.patch(f"/api/observables/{obs.id}", json={"reputation": "SCORE_MALICIOUS"})
        admin_client.post(f"/api/observables/{obs.id}/unpin")
        kinds, items = _kinds(admin_client, obs.id)
        assert [k for k, *_ in kinds[8:]] == ["reputation_changed", "pinned", "unpinned", "reputation_changed"]
        assert items[3]["actor"] == "admin" and items[3]["detail"]["cause"] == "manual"
        assert items[0]["detail"]["cause"] == "revert" and items[0]["new_value"] == "SCORE_SUSPICIOUS_OR_RISKY"

        # Disappearing from a workspace is recorded.
        del a.observables[a_id]
        await run_sync()
        kinds, _ = _kinds(admin_client, obs.id)
        assert ("removed_from_workspace", "A", "sync") in kinds

        only = admin_client.get(f"/api/observables/{obs.id}/history", params={"kind": "pushed_to_workspace"}).json()
        assert only["total"] == 1


async def test_disconnecting_workspace_is_recorded(db, admin_client):
    with FakeTorq() as fake:
        ws = _workspaces(db, fake, names=("A",))
        fake.workspace("cid-A").add(IP, "198.51.100.1")
        await run_sync()
        obs = _obs(db, "198.51.100.1")
        assert admin_client.delete(f"/api/workspaces/{ws['A'].id}").status_code == 204
        kinds, items = _kinds(admin_client, obs.id)
        assert kinds[-1] == ("removed_from_workspace", "A", "admin")
        assert items[0]["detail"]["reason"] == "workspace disconnected from Beacon"


def test_manual_observable_history_and_backfill(db, admin_client):
    r = admin_client.post("/api/observables", json={"type": IP, "value": "192.0.2.44", "reputation": "SCORE_SAFE"})
    kinds, _ = _kinds(admin_client, r.json()["id"])
    assert kinds == [("created", "", "admin")]

    legacy = Observable(type=IP, value="192.0.2.45", value_norm="192.0.2.45", origin="workspace", links=[])
    db.add(legacy)
    db.commit()
    assert history.backfill(db) == 1
    db.commit()
    events = db.query(ObservableEvent).filter_by(observable_id=legacy.id).all()
    assert [e.kind for e in events] == ["created"] and events[0].detail["backfilled"] is True
    assert history.backfill(db) == 0
