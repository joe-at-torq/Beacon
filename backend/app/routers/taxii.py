"""Beacon's read-only TAXII 2.1 server: one collection of STIX indicators built from the central database.

Paging is a keyset on (date_added, kind, id) over two streams: observables (date_added = changed_at) and deleted
observables (tombstones, date_added = deleted_at, published as revoked indicators). Revoked versions, for deleted
observables and for ones that fell below the collection's minimum reputation, are only sent to incremental
clients (``added_after``): a first full download shouldn't be flooded with retractions for indicators it never had.
"""

import base64
import binascii
import json
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from app.api_v1.auth import ROLE_RANK, Principal, principal_for_key
from app.services.observables import source_clause
from app.db import get_db
from app.models import Observable, ObservableEvent, Tombstone
from app.settings_store import get_setting
from app.stix.parser import parse_time
from app.stix.serializer import NAMESPACE, indicator, indicator_id, revoked_tombstone, ts
from app.torq.mapping import REPUTATIONS, severity

TAXII = "application/taxii+json;version=2.1"
STIX = "application/stix+json;version=2.1"
API_ROOT = "beacon"
COLLECTION_ID = str(uuid.uuid5(NAMESPACE, "beacon-indicators"))
MAX_LIMIT = 1000

router = APIRouter(prefix="/taxii2", tags=["taxii"], include_in_schema=False)


class TaxiiResponse(JSONResponse):
    media_type = TAXII


def _error(code: int, title: str, description: str = "", headers: dict | None = None) -> HTTPException:
    return HTTPException(code, {"title": title, "description": description, "http_status": str(code)}, headers=headers)


def _check_accept(request: Request) -> None:
    accept = request.headers.get("accept", "*/*").lower()
    if not any(t in accept for t in ("application/taxii+json", "application/json", "*/*", "application/*")):
        raise _error(406, "Not acceptable", f"Use Accept: {TAXII}")


def taxii_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    """API keys only (viewer or above): Authorization: Bearer <key>, or HTTP Basic with the key as the password."""
    _check_accept(request)
    if not get_setting(db, "taxii_enabled"):
        raise _error(404, "Not found", "The TAXII server is disabled")

    def unauthorized(message: str) -> HTTPException:
        return _error(401, "Unauthorized", message, {"WWW-Authenticate": 'Basic realm="Beacon TAXII"'})

    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value:
        key = value.strip()
    elif scheme.lower() == "basic" and value:
        try:
            key = base64.b64decode(value.strip()).decode().partition(":")[2]
        except (binascii.Error, UnicodeDecodeError):
            raise unauthorized("Malformed Basic credentials") from None
    else:
        raise unauthorized("Send a Beacon API key as Bearer, or as the Basic password")
    principal = principal_for_key(db, key, unauthorized)
    if ROLE_RANK.get(principal.role, -1) < ROLE_RANK["viewer"]:
        raise _error(403, "Forbidden")
    return principal


def _collection_cfg(db: Session) -> dict:
    cfg = get_setting(db, "taxii_collection") or {}
    return {"min_reputation": cfg.get("min_reputation") or "SCORE_SUSPICIOUS_OR_RISKY",
            "types": list(cfg.get("types") or []), "sources": list(cfg.get("sources") or [])}


def _source_filter(sources: list):
    """Published sources: feeds count only while they still list the observable."""
    return source_clause(sources, feeds_ever=False)


def _published(obs: Observable, min_rep: str) -> bool:
    return severity(obs.reputation) >= severity(min_rep)


def _previously_published(db: Session, obs_ids: list[int], min_rep: str) -> set[int]:
    """Observables (among these) whose reputation once met the threshold: their downgrade is a retraction."""
    if not obs_ids:
        return set()
    published = [r for r in REPUTATIONS if severity(r) >= severity(min_rep)]
    rows = db.query(ObservableEvent.observable_id).filter(
        ObservableEvent.observable_id.in_(obs_ids),
        or_(and_(ObservableEvent.kind == "reputation_changed", ObservableEvent.old_value.in_(published)),
            and_(ObservableEvent.kind == "created", ObservableEvent.new_value.in_(published))),
    ).distinct()
    return {i for (i,) in rows}


def _cursor_decode(token: str | None):
    if not token:
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(token.encode() + b"==").decode())
        return datetime.fromisoformat(data["t"]), int(data["k"]), int(data["i"])
    except (ValueError, KeyError, binascii.Error, TypeError):
        raise _error(400, "Bad request", "Invalid next token") from None


def _cursor_encode(t: datetime, k: int, i: int) -> str:
    return base64.urlsafe_b64encode(json.dumps({"t": t.isoformat(), "k": k, "i": i}).encode()).decode().rstrip("=")


def _page(db: Session, added_after: datetime | None, cursor, limit: int, ids: set[str] | None):
    """Up to `limit` (date_added, kind, row) entries after the cursor, plus whether more exist."""
    cfg = _collection_cfg(db)
    incremental = added_after is not None
    oq = db.query(Observable).filter(Observable.changed_at.is_not(None))
    if cfg["types"]:
        oq = oq.filter(Observable.type.in_(cfg["types"]))
    if cfg["sources"]:
        oq = oq.filter(_source_filter(cfg["sources"]))
    if ids is not None:
        oq = oq.filter(Observable.stix_id.in_(ids))
    if added_after:
        oq = oq.filter(Observable.changed_at > added_after)
    tq = db.query(Tombstone)
    if cfg["types"]:
        tq = tq.filter(Tombstone.type.in_(cfg["types"]))
    if added_after:
        tq = tq.filter(Tombstone.deleted_at > added_after)
    if cursor:
        t, k, i = cursor
        if k == 0:  # last entry was an observable: later observables at t, then every tombstone at t
            oq = oq.filter(or_(Observable.changed_at > t, and_(Observable.changed_at == t, Observable.id > i)))
            tq = tq.filter(Tombstone.deleted_at >= t)
        else:  # last entry was a tombstone: observables at t are all done
            oq = oq.filter(Observable.changed_at > t)
            tq = tq.filter(or_(Tombstone.deleted_at > t, and_(Tombstone.deleted_at == t, Tombstone.id > i)))
    oq = oq.order_by(Observable.changed_at, Observable.id)
    tq = tq.order_by(Tombstone.deleted_at, Tombstone.id)

    entries: list[tuple[datetime, int, object, dict]] = []
    batch = max(limit * 2, 200)
    # Observables: skip ones that aren't published (or, for full downloads, below the threshold).
    offset = 0
    while len(entries) <= limit:
        rows = oq.offset(offset).limit(batch).all()
        if not rows:
            break
        offset += len(rows)
        was_published = _previously_published(db, [o.id for o in rows if not _published(o, cfg["min_reputation"])],
                                              cfg["min_reputation"]) if incremental else set()
        for o in rows:
            ok = _published(o, cfg["min_reputation"])
            if not ok and o.id not in was_published:
                continue  # never published: nothing to retract
            obj = indicator(o, revoked=not ok)
            if obj:
                entries.append((o.changed_at, 0, o, obj))
        if len(rows) < batch:
            break
    if incremental or ids is not None:
        for tomb in tq.limit(limit + 1).all():
            obj = revoked_tombstone(tomb)
            if obj and (ids is None or obj["id"] in ids):
                entries.append((tomb.deleted_at, 1, tomb, obj))
    entries.sort(key=lambda e: (e[0], e[1], e[2].id))
    return entries[:limit], len(entries) > limit


def _envelope(entries, more: bool) -> TaxiiResponse:
    body: dict = {"more": more, "objects": [e[3] for e in entries]}
    headers = {}
    if entries:
        if more:
            last = entries[-1]
            body["next"] = _cursor_encode(last[0], last[1], last[2].id)
        headers = {"X-TAXII-Date-Added-First": ts(entries[0][0]), "X-TAXII-Date-Added-Last": ts(entries[-1][0])}
    return TaxiiResponse(body, headers=headers)


def _collection(db: Session) -> dict:
    cfg = _collection_cfg(db)
    return {
        "id": COLLECTION_ID, "title": "Beacon indicators",
        "description": f"Observables from Beacon's central database rated at least {cfg['min_reputation']}",
        "can_read": True, "can_write": False, "media_types": [STIX],
    }


def _check_collection(collection_id: str) -> None:
    if collection_id != COLLECTION_ID:
        raise _error(404, "Not found", "Unknown collection")


def _type_ok(match_type: str | None) -> bool:
    return not match_type or "indicator" in {t.strip() for t in match_type.split(",")}


@router.get("/", response_class=TaxiiResponse)
def discovery(request: Request, _: Principal = Depends(taxii_principal)):
    root = str(request.url_for("api_root_info", api_root=API_ROOT))
    return TaxiiResponse({"title": "Beacon TAXII server", "description": "Threat indicators from Beacon",
                          "default": root, "api_roots": [root]})


@router.get("/{api_root}/", name="api_root_info", response_class=TaxiiResponse)
def api_root_info(api_root: str, _: Principal = Depends(taxii_principal)):
    if api_root != API_ROOT:
        raise _error(404, "Not found", "Unknown API root")
    return TaxiiResponse({"title": "Beacon", "versions": [TAXII], "max_content_length": 10 * 1024 * 1024})


@router.get("/{api_root}/collections/", response_class=TaxiiResponse)
def collections(api_root: str, db: Session = Depends(get_db), _: Principal = Depends(taxii_principal)):
    if api_root != API_ROOT:
        raise _error(404, "Not found", "Unknown API root")
    return TaxiiResponse({"collections": [_collection(db)]})


@router.get("/{api_root}/collections/{collection_id}/", response_class=TaxiiResponse)
def collection(api_root: str, collection_id: str, db: Session = Depends(get_db), _: Principal = Depends(taxii_principal)):
    _check_collection(collection_id)
    return TaxiiResponse(_collection(db))


@router.get("/{api_root}/collections/{collection_id}/objects/", response_class=TaxiiResponse)
def objects(
    api_root: str, collection_id: str, db: Session = Depends(get_db), _: Principal = Depends(taxii_principal),
    added_after: str | None = None, limit: int = Query(MAX_LIMIT, ge=1), next: str | None = None,
    match_type: str | None = Query(None, alias="match[type]"), match_id: str | None = Query(None, alias="match[id]"),
):
    _check_collection(collection_id)
    if not _type_ok(match_type):
        return _envelope([], False)
    after = parse_time(added_after) if added_after else None
    if added_after and after is None:
        raise _error(400, "Bad request", "added_after must be an RFC 3339 timestamp")
    ids = {i.strip() for i in match_id.split(",")} if match_id else None
    entries, more = _page(db, after, _cursor_decode(next), min(limit, MAX_LIMIT), ids)
    return _envelope(entries, more)


@router.get("/{api_root}/collections/{collection_id}/objects/{object_id}/", response_class=TaxiiResponse)
def get_object(api_root: str, collection_id: str, object_id: str, db: Session = Depends(get_db),
               _: Principal = Depends(taxii_principal)):
    _check_collection(collection_id)
    entries, _more = _page(db, None, None, MAX_LIMIT, {object_id})
    if not entries:
        obs = db.query(Observable).filter_by(stix_id=object_id).first()
        tomb = next((t for t in db.query(Tombstone).all() if indicator_id(t.type, t.value_norm) == object_id), None)
        if obs is None and tomb is None:
            raise _error(404, "Not found", "Unknown object")
        cfg = _collection_cfg(db)
        obj = indicator(obs, revoked=not _published(obs, cfg["min_reputation"])) if obs else revoked_tombstone(tomb)
        return TaxiiResponse({"more": False, "objects": [obj] if obj else []})
    return _envelope(entries, False)


@router.get("/{api_root}/collections/{collection_id}/manifest/", response_class=TaxiiResponse)
def manifest(
    api_root: str, collection_id: str, db: Session = Depends(get_db), _: Principal = Depends(taxii_principal),
    added_after: str | None = None, limit: int = Query(MAX_LIMIT, ge=1), next: str | None = None,
    match_type: str | None = Query(None, alias="match[type]"),
):
    _check_collection(collection_id)
    if not _type_ok(match_type):
        return TaxiiResponse({"more": False, "objects": []})
    after = parse_time(added_after) if added_after else None
    entries, more = _page(db, after, _cursor_decode(next), min(limit, MAX_LIMIT), None)
    resp = _envelope(entries, more)
    body = json.loads(resp.body)
    body["objects"] = [{"id": o["id"], "date_added": ts(e[0]), "version": o["modified"], "media_type": STIX}
                       for e, o in zip(entries, body["objects"], strict=True)]
    return TaxiiResponse(body, headers={k: v for k, v in resp.headers.items() if k.lower().startswith("x-taxii")})


@router.get("/{api_root}/collections/{collection_id}/objects/{object_id}/versions/", response_class=TaxiiResponse)
def versions(api_root: str, collection_id: str, object_id: str, db: Session = Depends(get_db),
             principal: Principal = Depends(taxii_principal)):
    resp = get_object(api_root, collection_id, object_id, db, principal)
    objs = json.loads(resp.body)["objects"]
    return TaxiiResponse({"more": False, "versions": [o["modified"] for o in objs]})
