from datetime import datetime
from types import SimpleNamespace

from app.sync.collision import Candidate, resolve
from app.sync.rules import CENTRAL, evaluate
from app.torq.mapping import build_payload, infer_sub_type, normalize_value, parse_remote, parse_ts


def test_normalize_values():
    assert normalize_value("TYPE_ID_IP_ADDRESS", " 2001:0db8:0000::0001 ") == "2001:db8::1"
    assert normalize_value("TYPE_ID_HOSTNAME", "Evil.COM.") == "evil.com"
    assert normalize_value("TYPE_ID_MAC_ADDRESS", "00-B0-D0-63-C2-26") == "00:b0:d0:63:c2:26"
    assert normalize_value("TYPE_ID_FILE_HASH", "ABCDEF") == "abcdef"
    assert normalize_value("TYPE_ID_USER_NAME", " John ") == "John"


def test_infer_sub_type():
    assert infer_sub_type("TYPE_ID_IP_ADDRESS", "10.0.0.1") == "SUB_TYPE_ID_IP_ADDRESS_IPV4"
    assert infer_sub_type("TYPE_ID_IP_ADDRESS", "::1") == "SUB_TYPE_ID_IP_ADDRESS_IPV6"
    assert infer_sub_type("TYPE_ID_FILE_HASH", "a" * 64) == "SUB_TYPE_ID_FILE_HASH_SHA256"
    assert infer_sub_type("TYPE_ID_FILE_HASH", "a" * 32) == "SUB_TYPE_ID_FILE_HASH_MD5"
    assert infer_sub_type("TYPE_ID_IP_ADDRESS", "::1", "SUB_TYPE_ID_OTHER") == "SUB_TYPE_ID_OTHER"


def test_parse_remote_and_payload():
    raw = {
        "id": 28,
        "value": {"ip": "8.8.8.8"},
        "type": {"id": "TYPE_ID_IP_ADDRESS", "name": "IP address"},
        "reputation": {"id": "SCORE_MALICIOUS", "name": "Malicious"},
        "first_observed_at": "2024-11-05T13:31:41.123456789Z",
    }
    r = parse_remote(raw)
    assert r.remote_id == "28" and r.value == "8.8.8.8" and r.sub_type == "SUB_TYPE_ID_IP_ADDRESS_IPV4"
    assert r.first_observed_at == datetime(2024, 11, 5, 13, 31, 41, 123456)
    assert parse_remote({"id": 1, "value": {}}) is None
    payload = build_payload("TYPE_ID_IP_ADDRESS", "SUB_TYPE_ID_IP_ADDRESS_IPV4", "8.8.8.8", "SCORE_SAFE", "")
    assert payload == {
        "type": {"id": "TYPE_ID_IP_ADDRESS"},
        "value": {"ip": "8.8.8.8"},
        "reputation": {"id": "SCORE_SAFE"},
        "sub_type": {"id": "SUB_TYPE_ID_IP_ADDRESS_IPV4"},
    }
    assert parse_ts("garbage") is None


def _cands():
    return [
        Candidate(1, 10, "SCORE_SAFE", "from A", datetime(2024, 1, 3)),
        Candidate(2, 5, "SCORE_MALICIOUS", "from B", datetime(2024, 1, 1)),
        Candidate(3, 20, "SCORE_SUSPICIOUS_OR_RISKY", "", datetime(2024, 1, 2)),
    ]


def test_collision_strategies():
    hs = resolve(_cands(), "highest_severity")
    assert (hs.reputation, hs.description, hs.conflict) == ("SCORE_MALICIOUS", "from B", True)
    mr = resolve(_cands(), "most_recent")
    assert (mr.reputation, mr.description) == ("SCORE_SAFE", "from A")
    wp = resolve(_cands(), "workspace_priority")
    assert wp.reputation == "SCORE_MALICIOUS"  # workspace 2 has priority 5
    cc = resolve(_cands(), "highest_severity", "concat")
    assert cc.description == "from B\n---\nfrom A"
    single = resolve([Candidate(1, 1, "SCORE_SAFE", "", None)], "highest_severity")
    assert single.conflict is False
    unknown_winner = resolve(
        [Candidate(1, 1, "SCORE_UNKNOWN", "", datetime(2024, 2, 1)), Candidate(2, 2, "SCORE_SAFE", "", None)],
        "most_recent",
    )
    assert unknown_winner.reputation == "SCORE_SAFE"


def _rule(**kw):
    base = dict(enabled=True, source_workspace_ids=[], target_workspace_ids=[], types=[], sub_types=[],
                min_reputation=None, sync_updates=True)
    base.update(kw)
    return SimpleNamespace(**base)


def _obs(type_="TYPE_ID_IP_ADDRESS", sub="SUB_TYPE_ID_IP_ADDRESS_IPV4", rep="SCORE_MALICIOUS"):
    return SimpleNamespace(type=type_, sub_type=sub, reputation=rep)


def test_rule_direction_and_filters():
    rule = _rule(source_workspace_ids=[1], target_workspace_ids=[2, 3], types=["TYPE_ID_IP_ADDRESS"],
                 sub_types=["SUB_TYPE_ID_IP_ADDRESS_IPV4"])
    assert evaluate([rule], {"1"}, 2, _obs()) is True
    assert evaluate([rule], {"1"}, 3, _obs()) is True
    assert evaluate([rule], {"2"}, 1, _obs()) is None  # reverse direction blocked
    assert evaluate([rule], {"1"}, 2, _obs(sub="SUB_TYPE_ID_IP_ADDRESS_IPV6")) is None
    assert evaluate([rule], {"1"}, 2, _obs(type_="TYPE_ID_HOSTNAME", sub="SUB_TYPE_ID_UNKNOWN")) is None
    # The target itself never counts as a source.
    assert evaluate([_rule()], {"2"}, 2, _obs()) is None
    assert evaluate([_rule(min_reputation="SCORE_MALICIOUS")], {"1"}, 2, _obs(rep="SCORE_SAFE")) is None
    assert evaluate([_rule(sync_updates=False)], {"1"}, 2, _obs()) is False
    assert evaluate([_rule(source_workspace_ids=[CENTRAL])], {CENTRAL}, 2, _obs()) is True
    assert evaluate([_rule(enabled=False)], {"1"}, 2, _obs()) is None
