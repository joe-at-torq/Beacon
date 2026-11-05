"""Async client for the Torq public API (observables)."""

import asyncio
import json as jsonlib
import logging
import time
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime

import httpx

log = logging.getLogger("beacon.torq")

# (auth base, public API base). Public API paths live under /public, e.g. /public/v1alpha/observables/query.
REGIONS = {
    "us": ("https://auth.torq.io", "https://api.torq.io/public"),
    "eu": ("https://auth.eu.torq.io", "https://api.eu.torq.io/public"),
    "jp": ("https://auth.jp.torq.io", "https://api.jp.torq.io/public"),
}

# Torq allows 50 req/s per API key; stay comfortably below it.
MAX_RPS = 40
MAX_RETRIES = 4
PAGE_SIZE = 500
# Max characters of a request/response body kept in the API call log.
MAX_LOGGED_BODY = 16_000
REDACTED = "***redacted***"
_SKIP_RESPONSE_HEADERS = {"set-cookie"}

# Receives one dict per HTTP attempt (see TorqClient._send).
Recorder = Callable[[dict], None]


class TorqError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class TorqClient:
    def __init__(
        self,
        region: str,
        client_id: str,
        client_secret: str,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 30.0,
        recorder: Recorder | None = None,
    ):
        if region not in REGIONS:
            raise ValueError(f"Unknown region {region!r}")
        self.auth_url, self.api_url = REGIONS[region]
        self.client_id = client_id
        self.client_secret = client_secret
        # Mirror the headers used in Torq's API documentation examples.
        self._http = httpx.AsyncClient(
            transport=transport,
            timeout=timeout,
            headers={"Accept": "application/json", "Accept-Language": "en_US", "User-Agent": "Beacon/1.0"},
        )
        self._token: str | None = None
        self._token_expiry = 0.0
        self._token_lock = asyncio.Lock()
        self._rate_lock = asyncio.Lock()
        self._next_slot = 0.0
        self.recorder = recorder

    async def __aenter__(self) -> "TorqClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        await self._http.aclose()

    @staticmethod
    def _body_text(content: bytes | None) -> str:
        if not content:
            return ""
        text = content.decode("utf-8", errors="replace")
        try:
            data = jsonlib.loads(text)
            if isinstance(data, dict) and "access_token" in data:
                data = {**data, "access_token": REDACTED}
            text = jsonlib.dumps(data, indent=2)
        except ValueError:
            pass
        if len(text) > MAX_LOGGED_BODY:
            text = text[:MAX_LOGGED_BODY] + f"\n… truncated ({len(text) - MAX_LOGGED_BODY} more characters)"
        return text

    async def _send(self, method: str, url: str, attempt: int = 0, **kwargs) -> httpx.Response:
        """Perform one HTTP attempt and hand the full request/response details to the recorder."""
        auth = kwargs.pop("auth", None)
        request = self._http.build_request(method, url, **kwargs)
        started, ts = time.monotonic(), datetime.now(UTC)
        response: httpx.Response | None = None
        error: str | None = None
        try:
            response = await self._http.send(request, auth=auth)
            return response
        except httpx.HTTPError as e:
            error = f"{type(e).__name__}: {e}"
            raise
        finally:
            if self.recorder is not None:
                headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
                if "authorization" in headers:
                    scheme = headers["authorization"].split(" ", 1)[0]
                    headers["authorization"] = f"{scheme} {REDACTED}"
                try:
                    self.recorder(
                        {
                            "ts": ts.replace(tzinfo=None),
                            "method": method,
                            "url": str(request.url),
                            "attempt": attempt + 1,
                            "request_headers": headers,
                            "request_body": self._body_text(request.content),
                            "status_code": response.status_code if response is not None else None,
                            "duration_ms": int((time.monotonic() - started) * 1000),
                            "response_headers": {
                                k: v for k, v in response.headers.items() if k.lower() not in _SKIP_RESPONSE_HEADERS
                            }
                            if response is not None
                            else {},
                            "response_body": self._body_text(response.content) if response is not None else "",
                            "error": error,
                        }
                    )
                except Exception:  # never let logging break the sync
                    log.exception("API call recorder failed")

    async def get_token(self, force: bool = False) -> str:
        async with self._token_lock:
            if not force and self._token and time.monotonic() < self._token_expiry - 60:
                return self._token
            try:
                resp = await self._send(
                    "POST",
                    f"{self.auth_url}/v1/auth/token",
                    auth=(self.client_id, self.client_secret),
                    data={"grant_type": "client_credentials"},
                )
            except httpx.HTTPError as e:
                raise TorqError(f"Authentication request failed: {e}") from e
            if resp.status_code != 200:
                raise TorqError(f"Authentication failed ({resp.status_code}): {resp.text[:200]}", resp.status_code)
            body = resp.json()
            self._token = body["access_token"]
            self._token_expiry = time.monotonic() + float(body.get("expires_in", 3600))
            return self._token

    async def _throttle(self) -> None:
        async with self._rate_lock:
            now = time.monotonic()
            wait = self._next_slot - now
            self._next_slot = max(now, self._next_slot) + 1.0 / MAX_RPS
        if wait > 0:
            await asyncio.sleep(wait)

    async def _request(self, method: str, path: str, json: dict | None = None) -> dict:
        refreshed = False
        for attempt in range(MAX_RETRIES + 1):
            token = await self.get_token()
            await self._throttle()
            try:
                resp = await self._send(
                    method,
                    f"{self.api_url}{path}",
                    attempt=attempt,
                    json=json,
                    headers={"Authorization": f"Bearer {token}"},
                )
            except httpx.HTTPError as e:
                if attempt >= MAX_RETRIES:
                    raise TorqError(f"{method} {path} failed: {e}") from e
                await asyncio.sleep(min(2**attempt, 20))
                continue
            if resp.status_code == 401 and not refreshed:
                refreshed = True
                await self.get_token(force=True)
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt >= MAX_RETRIES:
                    raise TorqError(f"{method} {path} failed ({resp.status_code})", resp.status_code)
                retry_after = resp.headers.get("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else min(2**attempt, 20)
                await asyncio.sleep(delay)
                continue
            if resp.status_code == 403:
                raise TorqError(
                    f"{method} {path} was denied (403 Forbidden): the API key authenticated, but Torq refused "
                    "the request.",
                    403,
                )
            if resp.status_code >= 400:
                raise TorqError(f"{method} {path} failed ({resp.status_code}): {resp.text[:300]}", resp.status_code)
            return resp.json() if resp.content else {}
        raise TorqError(f"{method} {path} failed after retries")

    async def diagnose_forbidden(self) -> str:
        """After a 403, probe a basic endpoint to tell a key-wide denial from a missing permission."""
        try:
            await self._request("GET", "/v1alpha/workflows")
        except TorqError as e:
            if e.status == 403:
                return (
                    f"Torq denies this key on every endpoint (even listing workflows at {self.api_url}), so the "
                    "role is unlikely to be the cause. Check in Torq that the service API key is created in or "
                    "shared with this workspace "
                    "(cross-workspace keys may need approval), has not expired, and that no IP access rules "
                    "block this server's public IP."
                )
            return f"Diagnostic request also failed: {e}"
        except Exception as e:  # diagnosis is best-effort and must never break a sync
            return f"Diagnostic request could not run: {e!r}"
        return (
            "Other endpoints work, so the key's role lacks permission for observables. Give the service API "
            "key a role that can view and edit cases/observables."
        )

    async def iter_observables(self, page_size: int = PAGE_SIZE) -> AsyncIterator[dict]:
        page_token: str | None = None
        while True:
            body: dict = {"page_size": page_size, "order_by": "first_seen", "order": "asc"}
            if page_token:
                body["page_token"] = page_token
            data = await self._request("POST", "/v1alpha/observables/query", json=body)
            for obs in data.get("observables") or []:
                yield obs
            page_token = data.get("next_page_token")
            if not page_token:
                break

    async def test_connection(self) -> int:
        """Authenticate and fetch a single page; returns the number of observables on it."""
        data = await self._request("POST", "/v1alpha/observables/query", json={"page_size": 1})
        return len(data.get("observables") or [])

    async def create_observable(self, observable: dict) -> dict:
        data = await self._request("POST", "/v1alpha/observables", json={"observable": observable})
        return data.get("observable", data)

    async def update_observable(self, remote_id: str, reputation: str | None, description: str | None) -> dict:
        mask, obs = [], {}
        if description is not None:
            mask.append("description")
            obs["description"] = description
        if reputation is not None:
            mask.append("reputation")
            obs["reputation"] = {"id": reputation}
        if not mask:
            return {}
        data = await self._request(
            "PATCH", f"/v1alpha/observables/{remote_id}", json={"observable": obs, "update_mask": ",".join(mask)}
        )
        return data.get("observable", data)
