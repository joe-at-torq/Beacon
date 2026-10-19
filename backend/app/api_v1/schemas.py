"""Request/response models for the public v1 API (these drive the OpenAPI/Swagger documentation)."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# ---- Shared ----------------------------------------------------------------------------------------


class ErrorOut(BaseModel):
    detail: Any = Field(description="Human-readable error message (or a list of validation errors)")


ERRORS = {
    400: {"model": ErrorOut, "description": "Bad request"},
    401: {"model": ErrorOut, "description": "Missing, invalid, revoked or expired API key"},
    403: {"model": ErrorOut, "description": "The API key's role does not allow this operation"},
}
NOT_FOUND = {404: {"model": ErrorOut, "description": "Not found"}}


# ---- Observables ------------------------------------------------------------------------------------


class ObservableLinkOut(BaseModel):
    workspace_id: int
    workspace_name: str
    relation: Literal["origin", "pushed"] = Field(description="origin = native to the workspace, pushed = synced in by Beacon")
    has_enrichment: bool
    associated_cases_count: int
    remote_id: str | None = None
    remote_reputation: str | None = None
    remote_description: str | None = None
    remote_updated_at: str | None = None
    last_synced_at: str | None = None
    enrichment: dict | None = Field(None, description="Torq workspace enrichment JSON (detail only)")
    enrichment_updated_at: str | None = None


class IntelOut(BaseModel):
    provider: str = Field(examples=["virustotal"])
    status: Literal["ok", "not_found", "error"]
    summary: dict = Field(description="verdict, headline, stats, suggested_reputation, link, tags")
    error: str | None = None
    fetched_at: str | None = None
    fetched_by: str


class ObservableOut(BaseModel):
    id: int
    type: str = Field(examples=["TYPE_ID_IP_ADDRESS"])
    sub_type: str = Field(examples=["SUB_TYPE_ID_IP_ADDRESS_IPV4"])
    value: str = Field(examples=["203.0.113.7"])
    reputation: str = Field(examples=["SCORE_MALICIOUS"])
    description: str
    first_observed_at: str | None
    last_observed_at: str | None
    created_at: str | None
    updated_at: str | None
    pinned: bool = Field(description="True when edited in Beacon: the central value is authoritative")
    origin: Literal["workspace", "manual", "feed"]
    has_enrichment: bool
    associated_cases_count: int = Field(description="Sum of associated cases across all workspaces")
    links: list[ObservableLinkOut] = Field(description="Copies of this observable in Torq workspaces")
    intel: list[IntelOut] = Field(description="Threat-intel enrichment summaries (VirusTotal, OTX, ...)")
    enrichment: dict | None = Field(None, description="Raw threat-intel API responses keyed by provider (detail only)")
    normalized: dict | None = Field(None, description="Reputation normalized from threat-intel enrichment (detail only)")


class ObservablePage(BaseModel):
    items: list[ObservableOut]
    total: int = Field(description="Total matches across all pages")
    page: int
    page_size: int


class TimeRange(BaseModel):
    from_: datetime | None = Field(None, alias="from", description="Inclusive lower bound (ISO 8601)")
    to: datetime | None = Field(None, description="Inclusive upper bound (ISO 8601)")

    model_config = {"populate_by_name": True}


SortKey = Literal["updated_at", "created_at", "first_observed_at", "last_observed_at", "value", "type",
                  "reputation", "associated_cases_count"]


class ObservableQuery(BaseModel):
    search: str = Field("", description="Substring match on value or description (case-insensitive)")
    types: list[str] = Field(default=[], description="Observable types, e.g. TYPE_ID_IP_ADDRESS")
    sub_types: list[str] = Field(default=[], description="Sub types, e.g. SUB_TYPE_ID_IP_ADDRESS_IPV4")
    reputations: list[str] = Field(default=[], description="Exact reputation scores, e.g. SCORE_MALICIOUS")
    min_severity: int | None = Field(None, ge=0, le=10, description="Minimum severity (0 unknown … 10 malicious)")
    workspace_ids: list[int] = Field(default=[], description="Present in any of these workspaces")
    sources: list[int | str] = Field(default=[], description='Came from any of these sources: workspace ids (first seen '
                                                             'natively there), "central" (created or edited in Beacon), '
                                                             '"feed:<id>" (listed by that feed)', examples=[["central", "feed:1"]])
    pinned: bool | None = Field(None, description="Only centrally edited (true) or not (false)")
    origin: Literal["workspace", "manual", "feed"] | None = None
    has_enrichment: bool | None = Field(None, description="Has workspace or threat-intel enrichment")
    first_observed: TimeRange | None = None
    last_observed: TimeRange | None = None
    min_cases: int | None = Field(None, ge=0, description="Minimum associated cases (all workspaces)")
    sort: SortKey = "updated_at"
    order: Literal["asc", "desc"] = "desc"
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)

    model_config = {"json_schema_extra": {"examples": [{
        "types": ["TYPE_ID_IP_ADDRESS"], "min_severity": 8, "last_observed": {"from": "2026-01-01T00:00:00Z"},
        "sort": "associated_cases_count", "order": "desc", "page": 1, "page_size": 100}]}}


class HistoryEventOut(BaseModel):
    id: int
    ts: str | None
    kind: str = Field(examples=["reputation_changed"])
    actor: str
    workspace_id: int | None
    workspace_name: str
    run_id: int | None
    field: str | None
    old_value: str | None
    new_value: str | None
    detail: dict


class HistoryPage(BaseModel):
    items: list[HistoryEventOut]
    total: int


# ---- Rules ------------------------------------------------------------------------------------------


class RuleOut(BaseModel):
    id: int
    name: str
    description: str
    enabled: bool
    order: int
    source_workspace_ids: list[int | str]
    target_workspace_ids: list[int]
    types: list[str]
    sub_types: list[str]
    min_reputation: str | None
    sync_updates: bool
    priority_reputations: list[str] = Field(default=[], description="Reputations that sync immediately",
                                            examples=[["SCORE_MALICIOUS"]])
    created_at: str | None
    updated_at: str | None


class RulePatch(BaseModel):
    """Partial update: only the provided fields change."""

    name: str | None = Field(None, min_length=1, max_length=128)
    description: str | None = None
    enabled: bool | None = None
    source_workspace_ids: list[int | str] | None = None
    target_workspace_ids: list[int] | None = None
    types: list[str] | None = None
    sub_types: list[str] | None = None
    min_reputation: str | None = None
    sync_updates: bool | None = None
    priority_reputations: list[str] | None = None

    model_config = {"json_schema_extra": {"examples": [{"enabled": False}]}}


class PreviewTarget(BaseModel):
    workspace_id: int
    workspace_name: str
    create: int
    update: int


class RulePreviewOut(BaseModel):
    total_create: int
    total_update: int
    targets: list[PreviewTarget]


# ---- Sync -------------------------------------------------------------------------------------------


class SyncRequest(BaseModel):
    workspace_id: int | None = Field(None, description="Sync only this workspace (pull from it and push to it)")


class SyncStarted(BaseModel):
    run_id: int
    status_url: str = Field(examples=["/api/v1/sync/status"])
    run_url: str = Field(examples=["/api/v1/sync/runs/42"])


class SyncRunOut(BaseModel):
    id: int
    started_at: str | None
    finished_at: str | None
    trigger: str = Field(examples=["api"])
    triggered_by: str
    workspace_id: int | None
    status: Literal["running", "ok", "partial", "error"]
    pulled: int
    created_central: int
    updated_central: int
    conflicts: int
    pushed_created: int
    pushed_updated: int
    errors: list[str]
    api_calls: int
    api_errors: int


class SyncStatusOut(BaseModel):
    running: bool
    run_id: int | None
    phase: str = Field(examples=["pull"])
    detail: str
    started_at: str | None
    next_run_at: str | None
    last_run: SyncRunOut | None
    live: dict | None = Field(None, description="Live per-workspace and per-direction progress while running")


# ---- Reference --------------------------------------------------------------------------------------


class WorkspaceOut(BaseModel):
    id: int
    name: str
    region: Literal["us", "eu", "jp"]
    enabled: bool
    priority: int
    last_sync_at: str | None
    last_sync_status: str | None
    origin_count: int
    pushed_count: int


class EnumItem(BaseModel):
    id: str
    label: str


class MetaOut(BaseModel):
    types: list[EnumItem]
    sub_types: list[dict]
    reputations: list[dict]


# ---- Enrichment rules -------------------------------------------------------------------------------


class EnrichmentRuleStats(BaseModel):
    queued: int = Field(description="Lookups waiting in the queue")
    done: int = Field(description="Lookups completed (kept for 7 days)")
    error: int = Field(description="Lookups that failed after retries (kept for 7 days)")
    skipped: int = Field(0, description="Lookups skipped: already fresh, or the integration was out of capacity")


class EnrichmentRuleOut(BaseModel):
    id: int
    name: str
    enabled: bool
    type: str = Field(examples=["TYPE_ID_IP_ADDRESS"])
    sub_types: list[str] = Field(examples=[["SUB_TYPE_ID_IP_ADDRESS_IPV4"]])
    reputations: list[str] = Field(examples=[["SCORE_MALICIOUS"]])
    providers: list[str] = Field(examples=[["virustotal", "abuseipdb"]])
    refresh_days: int = Field(description="0 = always look up, -1 = never re-enrich")
    skip_when_busy: bool = Field(description="Skip integrations that are out of capacity instead of waiting for them")
    created_by: str
    created_at: datetime | None
    updated_at: datetime | None
    stats: EnrichmentRuleStats


class EnrichmentRulePatch(BaseModel):
    name: str | None = None
    enabled: bool | None = None
    type: str | None = None
    sub_types: list[str] | None = None
    reputations: list[str] | None = None
    providers: list[str] | None = None
    refresh_days: int | None = None
    skip_when_busy: bool | None = None


class EnrichmentRunOut(BaseModel):
    queued: int = Field(description="Lookups added to the queue")
    providers: dict[str, int] = Field(description="Lookups queued per provider", examples=[{"virustotal": 42}])


class EnrichmentPreviewProvider(BaseModel):
    provider: str
    jobs: int
    eta_seconds: int = Field(description="Rough time to work these off at the provider's configured pace")


class EnrichmentPreviewOut(BaseModel):
    matching: int = Field(description="Observables the rule matches today")
    jobs: int = Field(description="Lookups 'run' would queue (fresh results and pending lookups are skipped)")
    capped: bool
    providers: list[EnrichmentPreviewProvider]
