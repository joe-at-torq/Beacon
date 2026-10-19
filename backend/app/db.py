from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
SessionLocal = sessionmaker(autoflush=False, expire_on_commit=False)


def init_engine(url: str) -> Engine:
    global _engine
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    _engine = create_engine(url, connect_args=connect_args)

    if url.startswith("sqlite"):

        @event.listens_for(_engine, "connect")
        def _sqlite_pragmas(dbapi_conn, _record):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.close()

    SessionLocal.configure(bind=_engine)
    from app import models  # noqa: F401  ensure models are registered

    Base.metadata.create_all(_engine)
    _add_missing_columns(_engine)
    _backfill(_engine)
    return _engine


def _backfill(engine: Engine) -> None:
    """One-off data fills for columns added after the fact (idempotent)."""
    from app.stix.serializer import indicator_id

    with engine.begin() as conn:
        conn.execute(text("UPDATE observables SET changed_at = COALESCE(updated_at, created_at) WHERE changed_at IS NULL"))
        rows = conn.execute(text("SELECT id, type, value_norm FROM observables WHERE stix_id IS NULL")).all()
        if rows:
            conn.execute(text("UPDATE observables SET stix_id = :sid WHERE id = :id"),
                         [{"sid": indicator_id(t, v), "id": i} for i, t, v in rows])


def _add_missing_columns(engine: Engine) -> None:
    """Minimal forward-only migration: add columns that exist in the models but not yet in the database."""
    insp = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if not insp.has_table(table.name):
                continue
            existing = {c["name"] for c in insp.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing:
                    continue
                col_type = column.type.compile(dialect=engine.dialect)
                default = column.default.arg if column.default is not None and column.default.is_scalar else None
                clause = f" DEFAULT {default!r}" if isinstance(default, (int, str)) and not isinstance(default, bool) else ""
                if isinstance(default, bool):
                    clause = f" DEFAULT {int(default)}"
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {col_type}{clause}'))


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("Database engine not initialised")
    return _engine


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
