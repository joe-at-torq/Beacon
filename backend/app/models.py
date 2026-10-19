from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, event
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    """Naive UTC timestamp (SQLite has no timezone support)."""
    return datetime.now(UTC).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # admin | analyst | viewer
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    # Per-user UI state (dashboard layout, flow graph zoom, ...), merged key by key.
    preferences: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    region: Mapped[str] = mapped_column(String(8), default="us")  # us | eu | jp
    client_id: Mapped[str] = mapped_column(String(256))
    client_secret_enc: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_sync_status: Mapped[str | None] = mapped_column(String(16), nullable=True)  # ok | error
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    links: Mapped[list["ObservableLink"]] = relationship(back_populates="workspace", cascade="all, delete-orphan")


class Observable(Base):
    __tablename__ = "observables"
    __table_args__ = (UniqueConstraint("type", "value_norm", name="uq_observable_type_value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(48), index=True)
    sub_type: Mapped[str] = mapped_column(String(48), default="SUB_TYPE_ID_UNKNOWN", index=True)
    value: Mapped[str] = mapped_column(Text)
    value_norm: Mapped[str] = mapped_column(Text, index=True)
    reputation: Mapped[str] = mapped_column(String(48), default="SCORE_UNKNOWN", index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    first_observed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_observed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    origin: Mapped[str] = mapped_column(String(16), default="workspace")  # workspace | manual | feed
    # Who asserted the current central value: a workspace id (as text) or "central". Counts as a push
    # source, so a change made in any workspace can flow on (subject to rules).
    value_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Sum of associated cases across every workspace copy (kept in sync after each pull).
    associated_cases_count: Mapped[int] = mapped_column(Integer, default=0, index=True)
    # When the reputation or description last changed (or the observable was added). Unlike updated_at it
    # isn't touched by bulk bookkeeping updates, so it can drive TAXII paging.
    changed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    # Deterministic STIX indicator id (uuid5 of type + normalized value), for the TAXII server.
    stix_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    links: Mapped[list["ObservableLink"]] = relationship(
        back_populates="observable", cascade="all, delete-orphan", lazy="selectin"
    )
    intel: Mapped[list["IntelEnrichment"]] = relationship(cascade="all, delete-orphan", lazy="selectin")
    # Feeds currently listing this observable (active links only; read-only view used by sync rules).
    feed_sources: Mapped[list["FeedLink"]] = relationship(
        primaryjoin="and_(Observable.id == FeedLink.observable_id, FeedLink.active == True)",  # noqa: E712
        viewonly=True, lazy="selectin",
    )


class ObservableLink(Base):
    __tablename__ = "observable_links"
    __table_args__ = (
        UniqueConstraint("workspace_id", "remote_id", name="uq_link_ws_remote"),
        UniqueConstraint("workspace_id", "observable_id", name="uq_link_ws_observable"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    observable_id: Mapped[int] = mapped_column(ForeignKey("observables.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    remote_id: Mapped[str] = mapped_column(String(64))
    remote_reputation: Mapped[str] = mapped_column(String(48), default="SCORE_UNKNOWN")
    remote_description: Mapped[str] = mapped_column(Text, default="")
    remote_updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    relation: Mapped[str] = mapped_column(String(16), default="origin")  # origin | pushed
    last_synced_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # Workspace-side enrichment JSON (can be large, so it is only loaded when accessed).
    remote_cases_count: Mapped[int] = mapped_column(Integer, default=0)
    has_enrichment: Mapped[bool] = mapped_column(Boolean, default=False)
    remote_enrichment: Mapped[dict | None] = mapped_column(JSON, nullable=True, deferred=True)
    remote_enrichment_updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    observable: Mapped[Observable] = relationship(back_populates="links")
    workspace: Mapped[Workspace] = relationship(back_populates="links")


class ObservableEvent(Base):
    """One entry in an observable's change history."""

    __tablename__ = "observable_events"
    __table_args__ = (Index("ix_observable_events_obs_ts", "observable_id", "ts"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    observable_id: Mapped[int] = mapped_column(ForeignKey("observables.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    kind: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(64), default="sync")  # username, or "sync"
    workspace_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    workspace_name: Mapped[str] = mapped_column(String(128), default="")
    run_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    field: Mapped[str | None] = mapped_column(String(32), nullable=True)
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)

    # No back-reference: history is loaded explicitly, never with the observable.
    observable: Mapped[Observable] = relationship()


class Integration(Base):
    """Connection to a threat-intelligence provider (VirusTotal, AlienVault OTX, ...)."""

    __tablename__ = "integrations"

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), unique=True)  # one connection per provider
    name: Mapped[str] = mapped_column(String(128), default="")
    api_key_enc: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(16), nullable=True)  # ok | error
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class IntelEnrichment(Base):
    """Latest result of enriching an observable through a Beacon integration (one row per provider)."""

    __tablename__ = "intel_enrichments"
    __table_args__ = (UniqueConstraint("observable_id", "provider", name="uq_intel_obs_provider"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    observable_id: Mapped[int] = mapped_column(ForeignKey("observables.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="ok")  # ok | not_found | error
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    data: Mapped[dict | None] = mapped_column(JSON, nullable=True, deferred=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    fetched_by: Mapped[str] = mapped_column(String(64), default="")


class ApiKey(Base):
    """Bearer token for the public v1 API. Only a hash of the key is stored."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    prefix: Mapped[str] = mapped_column(String(16), index=True)  # first characters, for display/lookup
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    role: Mapped[str] = mapped_column(String(16), default="viewer")  # viewer | analyst | admin
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class NormalizationRule(Base):
    """Maps a threat-intel provider signal to a Torq reputation (first matching rule per provider wins)."""

    __tablename__ = "normalization_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    metric: Mapped[str] = mapped_column(String(48))
    operator: Mapped[str] = mapped_column(String(4))  # >= > <= < == !=
    value: Mapped[dict | list | str | int | float | bool | None] = mapped_column(JSON)
    reputation: Mapped[str] = mapped_column(String(48))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    order: Mapped[int] = mapped_column(Integer, default=0)


class EnrichmentRule(Base):
    """Automatically enrich new observables of a type/sub-type/reputation with the chosen providers."""

    __tablename__ = "enrichment_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    type: Mapped[str] = mapped_column(String(48))
    sub_types: Mapped[list] = mapped_column(JSON, default=list)  # empty = any
    reputations: Mapped[list] = mapped_column(JSON, default=list)  # empty = any
    providers: Mapped[list] = mapped_column(JSON, default=list)
    refresh_days: Mapped[int] = mapped_column(Integer, default=7)  # -1 = never re-enrich, 0 = always
    # Skip an integration that's out of capacity (daily limit, rate-limited, disabled) instead of waiting for it.
    skip_when_busy: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class EnrichmentJob(Base):
    """One queued provider lookup for one observable, worked off by the rate-limited enrichment queue."""

    __tablename__ = "enrichment_jobs"
    __table_args__ = (
        Index("ix_enrichment_jobs_due", "status", "provider", "not_before"),
        Index("ix_enrichment_jobs_obs_provider", "observable_id", "provider"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    observable_id: Mapped[int] = mapped_column(ForeignKey("observables.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(32))
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("enrichment_rules.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_name: Mapped[str] = mapped_column(String(64), default="")
    refresh_days: Mapped[int] = mapped_column(Integer, default=7)
    skip_when_busy: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(String(16), default="new")  # new | manual_run
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|running|done|skipped|error|cancelled
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    not_before: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")


class Feed(Base):
    """An external STIX 2.x / TAXII 2.1 feed whose indicators are ingested into the central database."""

    __tablename__ = "feeds"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(16), default="taxii21")  # taxii21 | stix_url | text_list
    url: Mapped[str] = mapped_column(Text)  # TAXII API root, STIX bundle URL or plain-text list URL
    list_type: Mapped[str] = mapped_column(String(16), default="auto")  # text lists: ip | url | domain | auto
    collection_id: Mapped[str] = mapped_column(String(128), default="")
    auth: Mapped[str] = mapped_column(String(16), default="none")  # none | basic | header
    username: Mapped[str] = mapped_column(String(256), default="")
    secret_enc: Mapped[str] = mapped_column(Text, default="")  # password or header value (encrypted)
    header_name: Mapped[str] = mapped_column(String(128), default="")
    poll_minutes: Mapped[int] = mapped_column(Integer, default=60)
    initial_lookback_days: Mapped[int] = mapped_column(Integer, default=30)
    max_age_days: Mapped[int] = mapped_column(Integer, default=0)  # 0 = keep until revoked/expired
    default_reputation: Mapped[str] = mapped_column(String(48), default="SCORE_MALICIOUS")
    min_confidence: Mapped[int] = mapped_column(Integer, default=0)
    enrich_new: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    cursor: Mapped[str] = mapped_column(String(64), default="")  # TAXII added_after
    etag: Mapped[str] = mapped_column(String(256), default="")
    last_modified: Mapped[str] = mapped_column(String(64), default="")
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(16), nullable=True)  # ok | error
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class FeedLink(Base):
    """An observable listed by a feed (one row per STIX indicator that names it)."""

    __tablename__ = "feed_links"
    __table_args__ = (UniqueConstraint("feed_id", "stix_id", "observable_id", name="uq_feed_link"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    feed_id: Mapped[int] = mapped_column(ForeignKey("feeds.id", ondelete="CASCADE"), index=True)
    observable_id: Mapped[int] = mapped_column(ForeignKey("observables.id", ondelete="CASCADE"), index=True)
    stix_id: Mapped[str] = mapped_column(String(128))
    reputation: Mapped[str] = mapped_column(String(48), default="SCORE_UNKNOWN")
    valid_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # Text-list feeds set the observable's reputation; what they set and what it replaced, to revert on removal.
    applied_reputation: Mapped[str | None] = mapped_column(String(48), nullable=True)
    prev_reputation: Mapped[str | None] = mapped_column(String(48), nullable=True)
    prev_value_source: Mapped[str | None] = mapped_column(String(32), nullable=True)


class Tombstone(Base):
    __tablename__ = "tombstones"
    __table_args__ = (UniqueConstraint("type", "value_norm", name="uq_tombstone_type_value"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(48))
    value_norm: Mapped[str] = mapped_column(Text)
    value: Mapped[str] = mapped_column(Text, default="")
    deleted_by: Mapped[str] = mapped_column(String(64), default="")
    deleted_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    order: Mapped[int] = mapped_column(Integer, default=0)
    # List of workspace ids (ints) and/or the token "central". Empty = any source.
    source_workspace_ids: Mapped[list] = mapped_column(JSON, default=list)
    # List of workspace ids. Empty = every workspace except the source.
    target_workspace_ids: Mapped[list] = mapped_column(JSON, default=list)
    types: Mapped[list] = mapped_column(JSON, default=list)
    sub_types: Mapped[list] = mapped_column(JSON, default=list)
    min_reputation: Mapped[str | None] = mapped_column(String(48), nullable=True)
    sync_updates: Mapped[bool] = mapped_column(Boolean, default=True)
    # Reputations that start a sync right away (instead of waiting for the interval) when Beacon sets them.
    priority_reputations: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict | list | str | int | bool | None] = mapped_column(JSON)


class SyncRun(Base):
    __tablename__ = "sync_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    trigger: Mapped[str] = mapped_column(String(16), default="manual")  # schedule | manual | api | priority
    triggered_by: Mapped[str] = mapped_column(String(64), default="")
    workspace_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running | ok | partial | error
    pulled: Mapped[int] = mapped_column(Integer, default=0)
    created_central: Mapped[int] = mapped_column(Integer, default=0)
    updated_central: Mapped[int] = mapped_column(Integer, default=0)
    conflicts: Mapped[int] = mapped_column(Integer, default=0)
    pushed_created: Mapped[int] = mapped_column(Integer, default=0)
    pushed_updated: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list] = mapped_column(JSON, default=list)
    api_calls: Mapped[int] = mapped_column(Integer, default=0)
    api_errors: Mapped[int] = mapped_column(Integer, default=0)


class SyncApiCall(Base):
    """One HTTP attempt made against the Torq API during a sync run (for debugging)."""

    __tablename__ = "sync_api_calls"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("sync_runs.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    workspace_name: Mapped[str] = mapped_column(String(128), default="")
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    method: Mapped[str] = mapped_column(String(8))
    url: Mapped[str] = mapped_column(Text)
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    request_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    request_body: Mapped[str] = mapped_column(Text, default="")
    response_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    response_body: Mapped[str] = mapped_column(Text, default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    username: Mapped[str] = mapped_column(String(64), default="system")
    action: Mapped[str] = mapped_column(String(64))
    entity: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[str] = mapped_column(Text, default="")


@event.listens_for(Session, "before_flush")
def _stamp_changed_at(session: Session, _ctx, _instances) -> None:
    """Keep Observable.changed_at current on insert and on reputation/description changes, on every write path."""
    from app.stix.serializer import indicator_id

    now = utcnow()
    for obj in session.new:
        if isinstance(obj, Observable):
            if obj.changed_at is None:
                obj.changed_at = now
            if obj.stix_id is None and obj.value_norm:
                obj.stix_id = indicator_id(obj.type, obj.value_norm)
    for obj in session.dirty:
        if isinstance(obj, Observable):
            attrs = sa_inspect(obj).attrs
            if attrs.reputation.history.has_changes() or attrs.description.history.has_changes():
                obj.changed_at = now
