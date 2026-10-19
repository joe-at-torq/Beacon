import asyncio

import pytest

from app.models import Observable, Rule, SyncRun
from app.services import observables as obs_svc
from app.sync import engine, priority
from app.sync.engine import run_sync
from tests.fake_torq import FakeTorq
from tests.test_sync import _workspaces

IP, IPV4, HOST = "TYPE_ID_IP_ADDRESS", "SUB_TYPE_ID_IP_ADDRESS_IPV4", "TYPE_ID_HOSTNAME"
MAL, PMAL, SAFE = "SCORE_MALICIOUS", "SCORE_PROBABLY_MALICIOUS", "SCORE_PROBABLY_SAFE"


@pytest.fixture(autouse=True)
def _clear():
    priority.requests.clear()
    priority._pending = None
    priority._last_started = 0.0
    yield
    priority.requests.clear()


def _create(db, value, reputation, type_id=IP):
    obs = obs_svc.create(db, obs_svc.ObservableCreate(type=type_id, value=value, reputation=reputation), "admin")
    db.commit()
    return obs


def test_rule_api_accepts_priority_reputations(admin_client):
    body = {"name": "Prio", "types": [IP], "priority_reputations": [MAL, PMAL, MAL]}
    r = admin_client.post("/api/rules", json=body)
    assert r.status_code in (200, 201), r.text
    assert r.json()["priority_reputations"] == [MAL, PMAL]  # de-duplicated
    assert admin_client.post("/api/rules", json=body | {"priority_reputations": ["SCORE_NOPE"]}).status_code == 422
    v1 = admin_client.patch(f"/api/v1/rules/{r.json()['id']}", json={"priority_reputations": [MAL]})
    assert v1.status_code == 200 and v1.json()["priority_reputations"] == [MAL]


def test_changes_made_in_beacon_request_a_priority_sync(db):
    db.add(Rule(name="Prio IPv4", types=[IP], sub_types=[IPV4], priority_reputations=[MAL, PMAL]))
    db.commit()
    _create(db, "203.0.113.80", SAFE)
    _create(db, "evil.example", MAL, HOST)  # type doesn't match the rule
    assert priority.requests == []
    hit = _create(db, "203.0.113.81", MAL)
    assert priority.requests == ["Malicious: 203.0.113.81"]
    # A manual edit to a priority reputation also triggers; edits to other fields don't.
    safe = db.query(Observable).filter_by(value="203.0.113.80").one()
    obs_svc.manual_edit(safe, "admin", None, "just a note")
    db.commit()
    assert len(priority.requests) == 1
    obs_svc.manual_edit(safe, "admin", PMAL, None)
    db.commit()
    assert priority.requests[-1] == "Probably malicious: 203.0.113.80"
    # Disabled rules and rolled-back changes don't.
    db.query(Rule).update({"enabled": False})
    db.commit()
    _create(db, "203.0.113.82", MAL)
    assert len(priority.requests) == 2
    assert hit.id


async def test_sync_run_changes_do_not_trigger_and_priority_run_pushes(db):
    with FakeTorq() as fake:
        ws = _workspaces(db, fake, ("A", "B"))
        a, b = fake.workspace("cid-A"), fake.workspace("cid-B")
        a.add(IP, "198.51.100.90", MAL, sub_type=IPV4)
        db.add(Rule(name="Central to B", source_workspace_ids=["central"], target_workspace_ids=[ws["B"].id],
                    types=[IP], priority_reputations=[MAL]))
        db.commit()
        await run_sync()  # pulls a malicious observable: pushed by its own run, no priority sync
        assert priority.requests == []

        _create(db, "198.51.100.91", MAL)
        assert priority.requests == ["Malicious: 198.51.100.91"]
        run_id = await priority.run(priority.requests[-1])
        assert run_id is not None
        for _ in range(100):
            await asyncio.sleep(0.05)
            if not engine.state.running:
                break
        db.expire_all()
        run = db.get(SyncRun, run_id)
        assert run.trigger == "priority" and run.triggered_by == "Malicious: 198.51.100.91" and run.status == "ok"
        assert b.find("198.51.100.91") and not a.find("198.51.100.91")


async def test_request_during_a_running_sync_runs_right_after(db):
    with FakeTorq() as fake:
        _workspaces(db, fake, ("A",))
        async with engine._lock:
            assert await priority.run("Malicious: x") is None
        assert priority._pending == "Malicious: x"
        priority.after_sync_run()
        assert priority.requests[-1] == "Malicious: x" and priority._pending is None


async def test_priority_sync_respects_disabled_syncing(admin_client, db):
    admin_client.put("/api/settings", json={"sync_enabled": False})
    with FakeTorq() as fake:
        _workspaces(db, fake, ("A",))
        assert await priority.run("Malicious: y") is None


async def test_requests_schedule_one_debounced_job():
    from app.scheduler import scheduler

    scheduler.start()
    try:
        priority.request("Malicious: a")
        priority.request("Malicious: b")  # coalesces into the job already scheduled
        jobs = [j for j in scheduler.get_jobs() if j.id == priority.JOB_ID]
        assert len(jobs) == 1 and jobs[0].args == ("Malicious: a",)
        from datetime import UTC, datetime

        wait = (jobs[0].next_run_time - datetime.now(UTC)).total_seconds()
        assert priority.DEBOUNCE_SECONDS - 1 <= wait <= priority.MIN_GAP_SECONDS + 1
    finally:
        scheduler.remove_all_jobs()
        scheduler.shutdown(wait=False)
