"""In-memory fake of the Torq observables API, wired up through respx."""

import base64
import json
from dataclasses import dataclass, field

import httpx
import respx

from app.torq.mapping import TYPES


@dataclass
class FakeWorkspace:
    client_id: str
    observables: dict[int, dict] = field(default_factory=dict)
    creates: list[dict] = field(default_factory=list)
    patches: list[tuple[int, dict]] = field(default_factory=list)

    def add(self, type_id: str, value: str, reputation: str = "SCORE_UNKNOWN", description: str = "",
            sub_type: str = "SUB_TYPE_ID_UNKNOWN", enrichment: dict | None = None, cases: int = 0) -> int:
        oid = FakeTorq.next_id()
        field_name = TYPES[type_id][1]
        self.observables[oid] = {
            "id": oid,
            "type": {"id": type_id},
            "sub_type": {"id": sub_type},
            "value": {field_name: value},
            "reputation": {"id": reputation},
            "description": description,
            "first_observed_at": "2024-11-05T13:31:41.123456789Z",
            "last_observed_at": "2024-11-05T13:31:41Z",
            "enrichment": enrichment or {},
            "associated_cases_count": cases,
            "enrichment_updated_at": "2024-11-06T08:00:00Z" if enrichment else None,
        }
        return oid

    def find(self, value: str) -> dict | None:
        for o in self.observables.values():
            if value in o["value"].values():
                return o
        return None


class FakeTorq:
    _counter = 1000

    @classmethod
    def next_id(cls) -> int:
        cls._counter += 1
        return cls._counter

    def __init__(self, page_size_cap: int = 2):
        self.workspaces: dict[str, FakeWorkspace] = {}
        # Small page cap to exercise pagination.
        self.page_size_cap = page_size_cap
        self.router = respx.mock(assert_all_called=False)

    def workspace(self, client_id: str) -> FakeWorkspace:
        return self.workspaces.setdefault(client_id, FakeWorkspace(client_id))

    def _ws_from_token(self, request: httpx.Request) -> FakeWorkspace | None:
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        return self.workspaces.get(token.removeprefix("tok-"))

    def _token(self, request: httpx.Request) -> httpx.Response:
        user, _, secret = base64.b64decode(request.headers["Authorization"].split()[1]).decode().partition(":")
        if user not in self.workspaces or secret != f"secret-{user}":
            return httpx.Response(401, json={"error": "invalid_client"})
        return httpx.Response(200, json={"access_token": f"tok-{user}", "expires_in": 3600, "token_type": "Bearer"})

    def _query(self, request: httpx.Request) -> httpx.Response:
        ws = self._ws_from_token(request)
        if ws is None:
            return httpx.Response(401)
        body = json.loads(request.content or b"{}")
        size = min(body.get("page_size", 100), self.page_size_cap)
        start = int(body.get("page_token") or 0)
        items = sorted(ws.observables.values(), key=lambda o: o["id"])
        page = items[start : start + size]
        nxt = str(start + size) if start + size < len(items) else ""
        return httpx.Response(200, json={"observables": page, "next_page_token": nxt})

    def _create(self, request: httpx.Request) -> httpx.Response:
        ws = self._ws_from_token(request)
        if ws is None:
            return httpx.Response(401)
        obs = json.loads(request.content)["observable"]
        ws.creates.append(obs)
        value = next(iter(obs["value"].values()))
        existing = ws.find(value)
        if existing:
            return httpx.Response(200, json={"observable": existing})
        oid = ws.add(obs["type"]["id"], value, obs.get("reputation", {}).get("id", "SCORE_UNKNOWN"),
                     obs.get("description", ""), obs.get("sub_type", {}).get("id", "SUB_TYPE_ID_UNKNOWN"))
        return httpx.Response(200, json={"observable": ws.observables[oid]})

    def _patch(self, request: httpx.Request, oid: str) -> httpx.Response:
        ws = self._ws_from_token(request)
        if ws is None:
            return httpx.Response(401)
        body = json.loads(request.content)
        ws.patches.append((int(oid), body))
        obs = ws.observables.get(int(oid))
        if obs is None:
            return httpx.Response(404)
        for f in body["update_mask"].split(","):
            obs[f] = body["observable"][f]
        return httpx.Response(200, json={"observable": obs})

    def __enter__(self) -> "FakeTorq":
        self.router.__enter__()
        for auth in ("https://auth.torq.io", "https://auth.eu.torq.io", "https://auth.jp.torq.io"):
            self.router.post(f"{auth}/v1/auth/token").mock(side_effect=self._token)
        for api in ("https://api.torq.io/public", "https://api.eu.torq.io/public", "https://api.jp.torq.io/public"):
            self.router.post(f"{api}/v1alpha/observables/query").mock(side_effect=self._query)
            self.router.post(f"{api}/v1alpha/observables").mock(side_effect=self._create)
            self.router.patch(url__regex=rf"{api}/v1alpha/observables/(?P<oid>\d+)").mock(side_effect=self._patch)
        return self

    def __exit__(self, *exc) -> None:
        self.router.__exit__(*exc)
