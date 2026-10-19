from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import log_event
from app.db import get_db
from app.models import User
from app.security import hash_password, require_admin
from app.serializers import user_out

router = APIRouter(prefix="/api/users", tags=["users"])

Role = Literal["admin", "analyst", "viewer"]


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$")
    password: str = Field(min_length=8, max_length=128)
    role: Role = "viewer"
    must_change_password: bool = True


class UserUpdate(BaseModel):
    role: Role | None = None
    password: str | None = Field(default=None, min_length=8, max_length=128)
    must_change_password: bool | None = None


def _admin_count(db: Session) -> int:
    return db.query(User).filter(User.role == "admin").count()


@router.get("")
def list_users(db: Session = Depends(get_db), _: User = Depends(require_admin)):
    return [user_out(u) for u in db.query(User).order_by(User.username).all()]


@router.post("", status_code=201)
def create_user(body: UserCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already exists")
    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        role=body.role,
        must_change_password=body.must_change_password,
    )
    db.add(user)
    log_event(db, admin.username, "create_user", "user", f"{body.username} ({body.role})")
    db.commit()
    return user_out(user)


@router.patch("/{user_id}")
def update_user(user_id: int, body: UserUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if body.role and body.role != user.role:
        if user.role == "admin" and _admin_count(db) <= 1:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot demote the last admin")
        user.role = body.role
    if body.password:
        user.password_hash = hash_password(body.password)
        user.must_change_password = True if body.must_change_password is None else body.must_change_password
    elif body.must_change_password is not None:
        user.must_change_password = body.must_change_password
    log_event(db, admin.username, "update_user", "user", user.username)
    db.commit()
    return user_out(user)


@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You cannot delete your own account")
    if user.role == "admin" and _admin_count(db) <= 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot delete the last admin")
    db.delete(user)
    log_event(db, admin.username, "delete_user", "user", user.username)
    db.commit()
