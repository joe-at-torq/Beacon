import json
import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from cryptography.fernet import Fernet
from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import config
from app.db import get_db
from app.models import User

COOKIE_NAME = "tim_session"
ROLES = ("admin", "analyst", "viewer")

_secrets: dict | None = None


def load_secrets() -> dict:
    """Load (or create on first run) the instance secrets file in the data dir."""
    global _secrets
    if _secrets is not None:
        return _secrets
    path = config.secrets_path
    if path.exists():
        _secrets = json.loads(path.read_text())
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        _secrets = {
            "fernet_key": Fernet.generate_key().decode(),
            "jwt_secret": secrets.token_urlsafe(48),
        }
        path.write_text(json.dumps(_secrets))
        path.chmod(0o600)
    return _secrets


def reset_secrets_cache() -> None:
    global _secrets
    _secrets = None


def _fernet() -> Fernet:
    return Fernet(load_secrets()["fernet_key"].encode())


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    return _fernet().decrypt(value.encode()).decode()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def create_session_token(user: User) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user.id),
        "iat": now,
        "exp": now + timedelta(hours=config.session_hours),
        # Invalidates sessions when the password changes.
        "pwh": user.password_hash[-12:],
    }
    return jwt.encode(payload, load_secrets()["jwt_secret"], algorithm="HS256")


def get_current_user(
    db: Session = Depends(get_db),
    tim_session: str | None = Cookie(default=None),
) -> User:
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    if not tim_session:
        raise unauthorized
    try:
        payload = jwt.decode(tim_session, load_secrets()["jwt_secret"], algorithms=["HS256"])
    except jwt.PyJWTError:
        raise unauthorized from None
    user = db.get(User, int(payload.get("sub", 0)))
    if not user or user.password_hash[-12:] != payload.get("pwh"):
        raise unauthorized
    return user


def get_active_user(user: User = Depends(get_current_user)) -> User:
    """Authenticated user who is not blocked by a pending mandatory password change."""
    if user.must_change_password:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Password change required")
    return user


def require_role(*roles: str):
    def checker(user: User = Depends(get_active_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user

    return checker


require_admin = require_role("admin")
require_analyst = require_role("admin", "analyst")
