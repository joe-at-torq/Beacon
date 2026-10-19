"""Authentication for the public v1 API: Beacon API keys (bearer) or, for convenience, the UI session cookie."""

from dataclasses import dataclass
from datetime import timedelta

from fastapi import Cookie, Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import ApiKey, utcnow
from app.routers.api_keys import hash_key
from app.security import get_current_user

ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}

bearer = HTTPBearer(
    auto_error=False,
    scheme_name="ApiKey",
    description="Beacon API key created in **Settings → API**, sent as `Authorization: Bearer tim_…`.",
)


@dataclass
class Principal:
    name: str
    role: str
    kind: str  # api_key | user

    @property
    def actor(self) -> str:
        """Name recorded in audit logs and observable history."""
        return f"api:{self.name}" if self.kind == "api_key" else self.name


def _unauthorized(message: str) -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, message, headers={"WWW-Authenticate": "Bearer"})


def principal_for_key(db: Session, raw_key: str, unauthorized=None) -> Principal:
    """Look up an API key (hashed) and return its principal; raises 401 for unknown, revoked or expired keys."""
    unauthorized = unauthorized or _unauthorized
    key = db.query(ApiKey).filter_by(key_hash=hash_key(raw_key)).first()
    now = utcnow()
    if key is None or key.revoked:
        raise unauthorized("Invalid or revoked API key")
    if key.expires_at and key.expires_at < now:
        raise unauthorized("API key has expired")
    if key.last_used_at is None or now - key.last_used_at > timedelta(seconds=30):
        key.last_used_at = now
        db.commit()
    return Principal(name=key.name, role=key.role, kind="api_key")


def api_principal(
    creds: HTTPAuthorizationCredentials | None = Security(bearer),
    db: Session = Depends(get_db),
    tim_session: str | None = Cookie(default=None, include_in_schema=False),
) -> Principal:
    if creds is not None:
        return principal_for_key(db, creds.credentials)
    if tim_session:
        try:
            user = get_current_user(db, tim_session)
        except HTTPException:
            raise _unauthorized("Session expired; sign in again or use an API key") from None
        if user.must_change_password:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Password change required")
        return Principal(name=user.username, role=user.role, kind="user")
    raise _unauthorized("Missing API key: send Authorization: Bearer <key>")


def require(role: str):
    """Dependency enforcing a minimum role (viewer < analyst < admin)."""

    def checker(p: Principal = Depends(api_principal)) -> Principal:
        if ROLE_RANK.get(p.role, -1) < ROLE_RANK[role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"This operation requires the {role} role")
        return p

    return checker


read_access = require("viewer")
write_access = require("analyst")
admin_access = require("admin")
