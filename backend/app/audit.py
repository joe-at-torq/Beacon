from sqlalchemy.orm import Session

from app.models import AuditEvent


def log_event(db: Session, username: str, action: str, entity: str = "", detail: str = "") -> None:
    db.add(AuditEvent(username=username, action=action, entity=entity, detail=detail[:2000]))
