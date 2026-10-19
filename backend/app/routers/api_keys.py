import hashlib
import secrets
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import log_event
from app.db import get_db
from app.models import ApiKey, User, utcnow
from app.security import require_admin
from app.serializers import iso

router = APIRouter(prefix="/api/api-keys", tags=["api-keys"])

KEY_PREFIX = "tim_"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


class ApiKeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    role: Literal["viewer", "analyst", "admin"] = "viewer"
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


def key_out(k: ApiKey) -> dict:
    now = utcnow()
    state = "revoked" if k.revoked else "expired" if k.expires_at and k.expires_at < now else "active"
    return {
        "id": k.id,
        "name": k.name,
        "prefix": k.prefix,
        "role": k.role,
        "created_by": k.created_by,
        "created_at": iso(k.created_at),
        "last_used_at": iso(k.last_used_at),
        "expires_at": iso(k.expires_at),
        "status": state,
    }


@router.get("")
def list_keys(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return [key_out(k) for k in db.query(ApiKey).order_by(ApiKey.revoked, ApiKey.id.desc()).all()]


@router.post("", status_code=201)
def create_key(body: ApiKeyIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Create a key. The plaintext key is returned only in this response."""
    key = generate_key()
    record = ApiKey(
        name=body.name.strip(),
        prefix=key[: len(KEY_PREFIX) + 6],
        key_hash=hash_key(key),
        role=body.role,
        created_by=admin.username,
        expires_at=utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None,
    )
    db.add(record)
    log_event(db, admin.username, "create_api_key", "api_key", f"{record.name} ({record.role})")
    db.commit()
    return {**key_out(record), "key": key}


@router.delete("/{key_id}", status_code=204)
def revoke_key(key_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    record = db.get(ApiKey, key_id)
    if not record:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    record.revoked = True
    log_event(db, admin.username, "revoke_api_key", "api_key", record.name)
    db.commit()
