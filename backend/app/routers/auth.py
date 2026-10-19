import json
import time
from collections import defaultdict
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import log_event
from app.config import config
from app.db import get_db
from app.models import User, utcnow
from app.security import (
    COOKIE_NAME,
    create_session_token,
    get_active_user,
    get_current_user,
    hash_password,
    verify_password,
)
from app.serializers import user_out

router = APIRouter(prefix="/api/auth", tags=["auth"])

MAX_FAILURES = 10
LOCKOUT_SECONDS = 300
_failures: dict[str, list[float]] = defaultdict(list)


class LoginIn(BaseModel):
    username: str
    password: str


MAX_PREFERENCES_BYTES = 64_000


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)


def _set_cookie(response: Response, user: User) -> None:
    response.set_cookie(
        COOKIE_NAME,
        create_session_token(user),
        httponly=True,
        secure=config.secure_cookies,
        samesite="strict",
        max_age=config.session_hours * 3600,
        path="/",
    )


def _throttle_key(request: Request, username: str) -> str:
    host = request.client.host if request.client else "?"
    return f"{host}:{username.lower()}"


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    key = _throttle_key(request, body.username)
    now = time.monotonic()
    _failures[key] = [t for t in _failures[key] if now - t < LOCKOUT_SECONDS]
    if len(_failures[key]) >= MAX_FAILURES:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts, try again later")

    user = db.query(User).filter(User.username == body.username).first()
    if not user or not verify_password(body.password, user.password_hash):
        _failures[key].append(now)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    _failures.pop(key, None)
    user.last_login = utcnow()
    log_event(db, user.username, "login", "user", "")
    db.commit()
    _set_cookie(response, user)
    return user_out(user)


@router.post("/logout")
def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return user_out(user)


@router.post("/change-password")
def change_password(
    body: ChangePasswordIn,
    response: Response,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "New password must differ from the current one")
    if body.new_password.lower() == user.username.lower():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Password must not equal the username")
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    log_event(db, user.username, "change_password", "user", "")
    db.commit()
    _set_cookie(response, user)
    return user_out(user)


@router.get("/preferences")
def get_preferences(user: User = Depends(get_active_user)):
    return user.preferences or {}


@router.patch("/preferences")
def update_preferences(
    body: dict[str, Any] = Body(...),
    user: User = Depends(get_active_user),
    db: Session = Depends(get_db),
):
    """Merge top-level keys into the user's preferences; a null value removes that key."""
    prefs = dict(user.preferences or {})
    for key, value in body.items():
        if value is None:
            prefs.pop(key, None)
        else:
            prefs[key] = value
    if len(json.dumps(prefs)) > MAX_PREFERENCES_BYTES:
        raise HTTPException(413, "Preferences are too large")
    user.preferences = prefs
    db.commit()
    return prefs
