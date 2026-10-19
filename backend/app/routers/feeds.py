import asyncio
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from app import history
from app.audit import log_event
from app.db import get_db
from app.feeds import client, poller
from app.models import Feed, FeedLink, Observable, Rule, User
from app.security import encrypt, get_active_user, require_admin, require_analyst
from app.serializers import iso
from app.services import source_cleanup
from app.torq.mapping import REPUTATIONS

router = APIRouter(prefix="/api/feeds", tags=["feeds"])


def fmt_n(n: int) -> str:
    return f"{n:,}"


def _plural(label: str, n: int) -> str:
    if n == 1:
        return label
    return label + ("es" if label.endswith(("ss", "sh")) else "s")
_tasks: set[asyncio.Task] = set()


class FeedIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    kind: Literal["taxii21", "stix_url", "text_list"] = "taxii21"
    url: str = Field(min_length=8, max_length=2048)
    list_type: Literal["ip", "url", "domain", "auto"] = Field("auto", description="Text lists: what each line holds")
    collection_id: str = Field("", max_length=128)
    auth: Literal["none", "basic", "header"] = "none"
    username: str = Field("", max_length=256)
    secret: str | None = Field(None, max_length=4096, description="Password or header value; omit to keep the stored one")
    header_name: str = Field("", max_length=128)
    poll_minutes: int = Field(60, ge=5, le=10080)
    initial_lookback_days: int = Field(30, ge=0, le=3650)
    max_age_days: int = Field(0, ge=0, le=3650)
    default_reputation: str = "SCORE_MALICIOUS"
    min_confidence: int = Field(0, ge=0, le=100)
    enrich_new: bool = False
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def _url(cls, v):
        v = v.strip()
        if not v.lower().startswith(("https://", "http://")):
            raise ValueError("The URL must start with https:// (or http://)")
        return v

    @field_validator("default_reputation")
    @classmethod
    def _rep(cls, v):
        if v not in REPUTATIONS:
            raise ValueError("Unknown reputation")
        return v


class ProbeIn(BaseModel):
    kind: Literal["taxii21", "stix_url", "text_list"] = "taxii21"
    list_type: Literal["ip", "url", "domain", "auto"] = "auto"
    url: str
    collection_id: str = ""
    auth: Literal["none", "basic", "header"] = "none"
    username: str = ""
    secret: str | None = None
    header_name: str = ""
    feed_id: int | None = Field(None, description="Use this feed's stored secret when no secret is given")


def feed_out(feed: Feed, listed: int = 0) -> dict:
    return {
        "id": feed.id, "name": feed.name, "kind": feed.kind, "url": feed.url, "collection_id": feed.collection_id,
        "list_type": feed.list_type or "auto",
        "auth": feed.auth, "username": feed.username, "secret_set": bool(feed.secret_enc), "header_name": feed.header_name,
        "poll_minutes": feed.poll_minutes, "initial_lookback_days": feed.initial_lookback_days,
        "max_age_days": feed.max_age_days, "default_reputation": feed.default_reputation,
        "min_confidence": feed.min_confidence, "enrich_new": feed.enrich_new, "enabled": feed.enabled,
        "last_poll_at": iso(feed.last_poll_at), "last_status": feed.last_status, "last_error": feed.last_error,
        "stats": feed.stats or {}, "listed": listed, "polling": feed.id in poller._polling,
        "created_at": iso(feed.created_at),
    }


def _get(db: Session, feed_id: int) -> Feed:
    feed = db.get(Feed, feed_id)
    if not feed:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Feed not found")
    return feed


def _apply(feed: Feed, body: FeedIn) -> None:
    for k, v in body.model_dump(exclude={"secret"}).items():
        setattr(feed, k, v)
    if body.secret is not None:
        feed.secret_enc = encrypt(body.secret) if body.secret else ""
    if body.kind == "taxii21" and not body.collection_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Choose a TAXII collection")


def _creds(db: Session, body: ProbeIn) -> client.Credentials:
    secret = body.secret
    if secret is None and body.feed_id:
        secret = poller.credentials(_get(db, body.feed_id)).secret
    return client.Credentials(auth=body.auth, username=body.username, secret=secret or "", header_name=body.header_name)


def _start_poll(feed_id: int) -> None:
    task = asyncio.create_task(poller.poll_feed(feed_id))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


@router.get("")
def list_feeds(db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    counts = poller.listed_counts(db)
    return [feed_out(f, counts.get(f.id, 0)) for f in db.query(Feed).order_by(Feed.id).all()]


@router.post("", status_code=201)
async def create_feed(body: FeedIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    feed = Feed()
    _apply(feed, body)
    db.add(feed)
    log_event(db, admin.username, "create_feed", "feed", feed.name)
    db.commit()
    if feed.enabled:
        _start_poll(feed.id)
    return feed_out(feed)


@router.put("/{feed_id:int}")
async def update_feed(feed_id: int, body: FeedIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    feed = _get(db, feed_id)
    reset = (feed.kind, feed.url, feed.collection_id) != (body.kind, body.url.strip(), body.collection_id)
    # A text list's reputation (or how it's read) changed: re-read it so the change reaches every listed value.
    reapply = feed.kind == "text_list" and (feed.default_reputation, feed.list_type) != (body.default_reputation, body.list_type)
    _apply(feed, body)
    if reset or reapply:
        feed.cursor = feed.etag = feed.last_modified = ""
    log_event(db, admin.username, "update_feed", "feed", feed.name)
    db.commit()
    if (reset or reapply) and feed.enabled:
        _start_poll(feed.id)
    return feed_out(feed, poller.listed_counts(db).get(feed.id, 0))


@router.patch("/{feed_id:int}/enabled")
def set_enabled(feed_id: int, enabled: bool, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    feed = _get(db, feed_id)
    feed.enabled = enabled
    log_event(db, admin.username, "enable_feed" if enabled else "disable_feed", "feed", feed.name)
    db.commit()
    return feed_out(feed, poller.listed_counts(db).get(feed.id, 0))


@router.get("/{feed_id:int}/delete-impact")
def delete_impact(feed_id: int, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    """How many observables came only from this feed (what "also remove its observables" would delete)."""
    _get(db, feed_id)
    return source_cleanup.impact(db, f"feed:{feed_id}")


@router.delete("/{feed_id:int}", status_code=204)
def delete_feed(feed_id: int, remove_observables: bool = False, db: Session = Depends(get_db),
                admin: User = Depends(require_admin)):
    _get(db, feed_id)
    removed = source_cleanup.remove_exclusive(db, f"feed:{feed_id}", admin.username) if remove_observables else None
    feed = _get(db, feed_id)
    token = f"feed:{feed.id}"
    # Strip the feed from rules; a rule left without sources would widen to "any", so disable it instead.
    for rule in db.query(Rule).all():
        sources = list(rule.source_workspace_ids or [])
        if token in sources:
            sources = [s for s in sources if s != token]
            rule.source_workspace_ids = sources
            if not sources:
                rule.enabled = False
    listed = {lk.observable_id for lk in db.query(FeedLink).filter_by(feed_id=feed.id, active=True)}
    for obs in db.query(Observable).filter(Observable.id.in_(listed)) if listed else []:
        history.record(obs, history.REMOVED_FROM_FEED, actor=admin.username, feed_id=feed.id, feed_name=feed.name,
                       reason="feed removed from Beacon")
    db.query(Observable).filter(Observable.value_source == token).update({"value_source": None}, synchronize_session=False)
    db.delete(feed)
    log_event(db, admin.username, "delete_feed", "feed",
              feed.name + (f" ({removed['deleted']} observables removed, {removed['tombstoned']} tombstoned)" if removed else ""))
    db.commit()


@router.post("/{feed_id:int}/poll", status_code=202)
def poll_now(feed_id: int, db: Session = Depends(get_db), user: User = Depends(require_analyst)):
    feed = _get(db, feed_id)
    if feed.id in poller._polling:
        return {"started": False, "message": "Already polling"}
    log_event(db, user.username, "poll_feed", "feed", feed.name)
    db.commit()
    _start_poll(feed.id)
    return {"started": True}


@router.post("/collections")
async def list_collections(body: ProbeIn, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    """Collections on a TAXII server (for the picker in the feed dialog)."""
    try:
        return await client.collections(body.url, _creds(db, body))
    except client.FeedError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from None


@router.post("/test")
async def test_feed(body: ProbeIn, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    """Check that the feed is reachable and how many indicators a first page/bundle holds."""
    from app.stix.parser import parse_objects

    creds = _creds(db, body)
    try:
        if body.kind == "text_list":
            from app.feeds import textlist

            content, _etag, _lm = await client.text(body.url, creds)
            result = textlist.parse(content or "", body.list_type, "SCORE_MALICIOUS")
            if not result.items:
                return {"ok": False, "message": f"No usable values found ({result.skipped} line(s) skipped)"}
            counts = ", ".join(f"{fmt_n(n)} {_plural(label, n)}" for label, n in result.counts.items())
            skipped = f", {fmt_n(result.skipped)} line(s) skipped" if result.skipped else ""
            return {"ok": True, "message": f"{counts}{skipped} · e.g. {', '.join(result.samples[:3])}",
                    "counts": result.counts, "skipped": result.skipped, "samples": result.samples}
        if body.kind == "stix_url":
            objects, _etag, _lm = await client.bundle(body.url, creds)
            parsed = parse_objects(objects or [], "SCORE_MALICIOUS")
            return {"ok": True, "message": f"Bundle has {len(objects or [])} objects, {len(parsed)} usable indicator value(s)"}
        cols = await client.collections(body.url, creds)
        if body.collection_id and not any(c["id"] == body.collection_id for c in cols):
            return {"ok": False, "message": "Connected, but that collection isn't on the server"}
        return {"ok": True, "message": f"Connected: {len(cols)} collection(s) available"}
    except client.FeedError as e:
        return {"ok": False, "message": str(e)}


# ---- Beacon's TAXII server settings -------------------------------------------------------------------


class TaxiiServerIn(BaseModel):
    enabled: bool
    min_reputation: str = "SCORE_SUSPICIOUS_OR_RISKY"
    types: list[str] = []
    sources: list[int | str] = Field(default=[], description='Workspace ids, "central" and/or "feed:<id>". Empty = all.')

    @field_validator("min_reputation")
    @classmethod
    def _rep(cls, v):
        if v not in REPUTATIONS:
            raise ValueError("Unknown reputation")
        return v

    @field_validator("types")
    @classmethod
    def _types(cls, v):
        from app.torq.mapping import TYPES

        bad = [t for t in v if t not in TYPES]
        if bad:
            raise ValueError(f"Unknown types: {bad}")
        return v


def _taxii_out(db: Session) -> dict:
    from app.routers.taxii import API_ROOT, COLLECTION_ID
    from app.settings_store import get_setting

    cfg = get_setting(db, "taxii_collection") or {}
    return {
        "enabled": bool(get_setting(db, "taxii_enabled")), "min_reputation": cfg.get("min_reputation", "SCORE_SUSPICIOUS_OR_RISKY"),
        "types": cfg.get("types", []), "sources": cfg.get("sources", []),
        "discovery_path": "/taxii2/", "api_root_path": f"/taxii2/{API_ROOT}/", "collection_id": COLLECTION_ID,
        "objects_path": f"/taxii2/{API_ROOT}/collections/{COLLECTION_ID}/objects/",
    }


@router.get("/taxii-server")
def get_taxii_server(db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    return _taxii_out(db)


@router.put("/taxii-server")
def update_taxii_server(body: TaxiiServerIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    from app.models import Workspace
    from app.settings_store import set_setting

    ws_ids = {w.id for w in db.query(Workspace).all()}
    feed_ids = {f"feed:{f.id}" for f in db.query(Feed).all()}
    sources = []
    for s in body.sources:
        s = int(s) if isinstance(s, str) and s.isdigit() else s
        if s != "central" and s not in ws_ids and s not in feed_ids:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown source {s!r}")
        sources.append(s)
    set_setting(db, "taxii_enabled", body.enabled)
    set_setting(db, "taxii_collection", {"min_reputation": body.min_reputation, "types": body.types, "sources": sources})
    log_event(db, admin.username, "update_taxii_server", "settings", "enabled" if body.enabled else "disabled")
    db.commit()
    return _taxii_out(db)
