"""HTTP access to TAXII 2.1 servers and STIX 2.x bundle URLs."""

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

TAXII = "application/taxii+json;version=2.1"
STIX = "application/stix+json;version=2.1"
TIMEOUT = 60.0
PAGE_LIMIT = 1000
MAX_RETRIES = 3
USER_AGENT = "Beacon-Threat-Intelligence-Manager/1.0"


class FeedError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


@dataclass
class Credentials:
    auth: str = "none"  # none | basic | header
    username: str = ""
    secret: str = ""
    header_name: str = ""

    def httpx_auth(self):
        return httpx.BasicAuth(self.username, self.secret) if self.auth == "basic" else None

    def headers(self) -> dict:
        if self.auth == "header" and self.header_name:
            return {self.header_name: self.secret}
        return {}


@dataclass
class Page:
    objects: list[dict]
    more: bool
    next: str | None
    date_added_last: str | None


def _client(creds: Credentials, accept: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=TIMEOUT, follow_redirects=True, auth=creds.httpx_auth(),
        headers={"Accept": accept, "User-Agent": USER_AGENT, **creds.headers()},
    )


def _slash(url: str) -> str:
    return url if url.endswith("/") else url + "/"


async def _get(client: httpx.AsyncClient, url: str, **kw) -> httpx.Response:
    """GET with Retry-After handling for 429 / 503."""
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = await client.get(url, **kw)
        except httpx.HTTPError as e:
            raise FeedError(f"Could not reach {url}: {e!r}") from None
        if resp.status_code in (429, 503) and attempt < MAX_RETRIES:
            try:
                wait = min(60.0, float(resp.headers.get("Retry-After", 2 ** attempt)))
            except ValueError:
                wait = 2.0 ** attempt
            await asyncio.sleep(wait)
            continue
        return resp
    return resp


def _raise_for(resp: httpx.Response, what: str) -> None:
    if resp.status_code in (401, 403):
        raise FeedError(f"{what}: credentials rejected ({resp.status_code})", resp.status_code)
    if resp.status_code == 404:
        raise FeedError(f"{what}: not found (404)", 404)
    if resp.status_code == 429:
        raise FeedError(f"{what}: rate limited (429)", 429)
    if resp.status_code >= 400:
        raise FeedError(f"{what} failed ({resp.status_code}): {resp.text[:200]}", resp.status_code)


def _json(resp: httpx.Response, what: str) -> dict:
    try:
        data = resp.json()
    except ValueError:
        raise FeedError(f"{what}: the response isn't JSON") from None
    if not isinstance(data, dict):
        raise FeedError(f"{what}: unexpected response")
    return data


async def api_root(url: str, creds: Credentials) -> str:
    """Resolve a URL to a TAXII API root: either it is one, or it's a discovery URL that lists them."""
    url = _slash(url)
    async with _client(creds, TAXII) as c:
        resp = await _get(c, url)
        _raise_for(resp, "TAXII server")
        data = _json(resp, "TAXII server")
        if "api_roots" in data or "default" in data:  # discovery document
            root = data.get("default") or (data.get("api_roots") or [None])[0]
            if not root:
                raise FeedError("The TAXII server lists no API roots")
            return _slash(urljoin(url, root))
        return url


async def collections(url: str, creds: Credentials) -> list[dict]:
    root = await api_root(url, creds)
    async with _client(creds, TAXII) as c:
        resp = await _get(c, root + "collections/")
        _raise_for(resp, "Collections")
        data = _json(resp, "Collections")
    return [
        {"id": col.get("id"), "title": col.get("title") or col.get("id"), "description": col.get("description") or "",
         "can_read": bool(col.get("can_read", True))}
        for col in data.get("collections") or [] if col.get("id")
    ]


async def taxii_pages(url: str, collection_id: str, creds: Credentials, added_after: str | None,
                      limit: int = PAGE_LIMIT) -> AsyncIterator[Page]:
    """Indicator objects added after the cursor, page by page (same added_after for every page of a run)."""
    root = await api_root(url, creds)
    objects_url = f"{root}collections/{collection_id}/objects/"
    next_token: str | None = None
    async with _client(creds, TAXII) as c:
        while True:
            params = {"match[type]": "indicator", "limit": str(limit)}
            if added_after:
                params["added_after"] = added_after
            if next_token:
                params["next"] = next_token
            resp = await _get(c, objects_url, params=params)
            _raise_for(resp, "TAXII objects")
            data = _json(resp, "TAXII objects")
            page = Page(objects=list(data.get("objects") or []), more=bool(data.get("more")), next=data.get("next"),
                        date_added_last=resp.headers.get("X-TAXII-Date-Added-Last"))
            yield page
            if not page.more or not page.next:
                return
            next_token = page.next


async def bundle(url: str, creds: Credentials, etag: str = "", last_modified: str = "") -> tuple[list[dict] | None, str, str]:
    """A STIX bundle's objects, or None when unchanged since the last fetch (304)."""
    headers = {}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    async with _client(creds, f"{STIX}, application/json") as c:
        resp = await _get(c, url, headers=headers)
    if resp.status_code == 304:
        return None, etag, last_modified
    _raise_for(resp, "STIX bundle")
    data = _json(resp, "STIX bundle")
    if data.get("type") != "bundle" and "objects" not in data:
        raise FeedError("The URL didn't return a STIX bundle")
    return list(data.get("objects") or []), resp.headers.get("ETag", ""), resp.headers.get("Last-Modified", "")


MAX_TEXT_BYTES = 50 * 1024 * 1024


async def text(url: str, creds: Credentials, etag: str = "", last_modified: str = "") -> tuple[str | None, str, str]:
    """A plain-text list, or None when unchanged since the last fetch (304)."""
    headers = {}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    async with _client(creds, "text/plain, */*") as c:
        resp = await _get(c, url, headers=headers)
    if resp.status_code == 304:
        return None, etag, last_modified
    _raise_for(resp, "Threat list")
    if len(resp.content) > MAX_TEXT_BYTES:
        raise FeedError(f"Threat list is larger than {MAX_TEXT_BYTES // (1024 * 1024)} MB")
    return resp.text, resp.headers.get("ETag", ""), resp.headers.get("Last-Modified", "")
