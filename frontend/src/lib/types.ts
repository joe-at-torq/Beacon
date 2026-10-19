export type Role = "admin" | "analyst" | "viewer";

export interface User {
  id: number;
  username: string;
  role: Role;
  must_change_password: boolean;
  created_at: string | null;
  last_login: string | null;
}

export interface Workspace {
  id: number;
  name: string;
  region: "us" | "eu" | "jp";
  client_id: string;
  enabled: boolean;
  priority: number;
  created_at: string | null;
  last_sync_at: string | null;
  last_sync_status: "ok" | "error" | null;
  last_error: string | null;
  origin_count: number;
  pushed_count: number;
}

export interface ObservableLink {
  workspace_id: number;
  workspace_name: string;
  relation: "origin" | "pushed";
  has_enrichment: boolean;
  associated_cases_count: number;
  enrichment?: Record<string, unknown> | null;
  enrichment_updated_at?: string | null;
  remote_id?: string;
  remote_reputation?: string;
  remote_description?: string;
  remote_updated_at?: string | null;
  last_synced_at?: string | null;
}

export interface Observable {
  id: number;
  type: string;
  sub_type: string;
  value: string;
  reputation: string;
  description: string;
  first_observed_at: string | null;
  last_observed_at: string | null;
  created_at: string | null;
  updated_at: string | null;
  pinned: boolean;
  origin: "workspace" | "manual" | "feed";
  has_enrichment: boolean;
  associated_cases_count: number;
  links: ObservableLink[];
  intel: IntelEnrichment[];
  /** Raw threat-intel API responses keyed by provider (detail view only). */
  enrichment?: Record<string, unknown>;
  /** Reputation normalized from threat-intel enrichment (detail view only). */
  normalized?: NormalizedResult | null;
  /** STIX/TAXII feeds listing this observable (detail view only). */
  feeds?: ObservableFeedLink[];
}

export interface ObservableFeedLink {
  feed_id: number;
  feed_name: string;
  stix_id: string;
  reputation: string;
  valid_until: string | null;
  active: boolean;
  first_seen_at: string | null;
  last_seen_at: string | null;
}

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface Rule {
  id: number;
  name: string;
  description: string;
  enabled: boolean;
  order: number;
  source_workspace_ids: (number | string)[];
  target_workspace_ids: number[];
  types: string[];
  sub_types: string[];
  min_reputation: string | null;
  sync_updates: boolean;
  /** Reputations that start a sync right away when Beacon sets them */
  priority_reputations: string[];
}

export type RuleInput = Omit<Rule, "id" | "order">;

export interface RulePreview {
  total_create: number;
  total_update: number;
  targets: { workspace_id: number; workspace_name: string; create: number; update: number }[];
}

export interface SyncRun {
  id: number;
  started_at: string | null;
  finished_at: string | null;
  trigger: "schedule" | "manual" | "api" | "priority";
  triggered_by: string;
  workspace_id: number | null;
  status: "running" | "ok" | "partial" | "error";
  pulled: number;
  created_central: number;
  updated_central: number;
  conflicts: number;
  pushed_created: number;
  pushed_updated: number;
  errors: string[];
  api_calls: number;
  api_errors: number;
}

export interface ApiCall {
  id: number | null;
  ts: string | null;
  workspace_id: number | null;
  workspace_name: string;
  method: string;
  url: string;
  attempt: number;
  status_code: number | null;
  duration_ms: number;
  request_headers: Record<string, string>;
  request_body: string;
  response_headers: Record<string, string>;
  response_body: string;
  error: string | null;
}

export interface SyncStatus {
  running: boolean;
  run_id: number | null;
  phase: string;
  detail: string;
  started_at: string | null;
  next_run_at: string | null;
  last_run: SyncRun | null;
  live: SyncLive | null;
}

export interface SyncLive {
  workspaces: {
    workspace_id: number;
    name: string;
    pull: "pending" | "running" | "done" | "error";
    pulled: number;
    push_total: number;
    push_done: number;
    push_failed: number;
  }[];
  edges: { source: string; target: string; total: number; done: number }[];
}

export interface Settings {
  collision_strategy: "highest_severity" | "most_recent" | "workspace_priority";
  description_merge: "winner" | "concat";
  sync_enabled: boolean;
  sync_interval_minutes: number;
}

export interface Meta {
  types: { id: string; label: string }[];
  sub_types: { id: string; label: string; type: string | null }[];
  reputations: { id: string; label: string; severity: number }[];
}

export interface AuditEvent {
  id: number;
  ts: string | null;
  username: string;
  action: string;
  entity: string;
  detail: string;
}

export interface Dashboard {
  totals: {
    observables: number;
    malicious: number;
    suspicious: number;
    pinned: number;
    workspaces: number;
    workspaces_healthy: number;
    rules_active: number;
  };
  by_type: { id: string; label: string; count: number }[];
  by_reputation: { id: string; label: string; severity: number; count: number }[];
  workspaces: {
    id: number;
    name: string;
    region: "us" | "eu" | "jp";
    enabled: boolean;
    status: "ok" | "error" | null;
    last_sync_at: string | null;
    last_error: string | null;
    origin_count: number;
    pushed_count: number;
  }[];
  growth: { date: string; added: number; total: number }[];
  recent_runs: SyncRun[];
  recent_activity: AuditEvent[];
}

export interface ObservableEvent {
  id: number;
  ts: string | null;
  kind:
    | "created"
    | "seen_in_workspace"
    | "pushed_to_workspace"
    | "updated_in_workspace"
    | "removed_from_workspace"
    | "workspace_reputation_changed"
    | "reputation_changed"
    | "description_changed"
    | "pinned"
    | "unpinned"
    | "enrichment_added"
    | "enrichment_updated"
    | "enrichment_removed"
    | "seen_in_feed"
    | "removed_from_feed"
    | "intel_enriched";
  actor: string;
  workspace_id: number | null;
  workspace_name: string;
  run_id: number | null;
  field: string | null;
  old_value: string | null;
  new_value: string | null;
  detail: Record<string, any>;
}

export type ObservedRange = "7d" | "14d" | "30d" | "3m" | "6m" | "9m" | "12m" | "all";

export interface ObservedSeries {
  range: ObservedRange;
  bucket: "day" | "week" | "month";
  start: string;
  end: string;
  points: { start: string; end: string; first_observed: number; last_observed: number }[];
  totals: { first_observed: number; last_observed: number };
  first_observed_before: number;
  undated: number;
}

export interface FlowWorkspaceNode {
  id: string;
  workspace_id: number;
  name: string;
  region: "us" | "eu" | "jp";
  enabled: boolean;
  status: "ok" | "error" | null;
  native: number;
  synced_in: number;
  synced_out: number;
  pending_in: number;
}

export interface FlowFeedNode {
  id: string;
  kind: "feed";
  feed_id: number;
  feed_kind?: "taxii21" | "stix_url" | "text_list";
  name: string;
  enabled: boolean;
  status: "ok" | "error" | null;
  listed: number;
  synced_out: number;
  pending_out: number;
}

export interface FlowCentralNode {
  id: "central";
  name: string;
  total: number;
  manual: number;
  synced_out: number;
}

export interface FlowEdge {
  source: string;
  target: string;
  count: number;
  pending_create: number;
  pending_update: number;
  rules: number[];
  allowed: boolean;
}

export interface FlowRule {
  id: number;
  name: string;
  enabled: boolean;
  sync_updates: boolean;
  types: string[];
  sub_types: string[];
  min_reputation: string | null;
  sources: (number | string)[];
  targets: number[];
  edges: [string, string][];
}

export interface FlowGraphData {
  nodes: (FlowWorkspaceNode | FlowCentralNode | FlowFeedNode)[];
  edges: FlowEdge[];
  spokes: { workspace_id: number; native: number }[];
  feed_spokes?: { feed_id: number; listed: number }[];
  rules: FlowRule[];
  totals: { observables: number; synced: number; pending: number };
}

export interface IntelSummary {
  verdict?: "malicious" | "suspicious" | "harmless" | "unknown";
  headline?: string;
  stats?: Record<string, unknown>;
  suggested_reputation?: string | null;
  link?: string;
  tags?: string[];
  facts?: { label: string; value: string | number | boolean }[];
}

export interface IntelEnrichment {
  provider: string;
  status: "ok" | "not_found" | "error";
  summary: IntelSummary;
  error: string | null;
  fetched_at: string | null;
  fetched_by: string;
}

export interface IntelProvider {
  id: string;
  name: string;
  description: string;
  types: string[];
  key_help: string;
  docs_url: string;
  color: string;
  monogram?: string;
  /** Sub-type restrictions per type; a type that isn't listed accepts all of its sub-types. */
  sub_types?: Record<string, string[]>;
}

export interface Integration {
  id: number;
  provider: string;
  provider_name: string;
  name: string;
  enabled: boolean;
  key_hint: string;
  types: string[];
  created_at: string | null;
  last_test_at: string | null;
  last_status: "ok" | "error" | null;
  last_error: string | null;
}

export interface NormContribution {
  provider: string;
  reputation: string;
  rule_id: number | null;
  metric: string;
  metric_label: string;
  operator: string;
  threshold: unknown;
  actual: unknown;
  unit: string;
  source: "rule" | "verdict";
}

export interface NormalizedResult {
  reputation: string;
  label: string;
  decided_by: string;
  strategy: NormStrategy;
  current: string;
  differs: boolean;
  contributions: NormContribution[];
}

export type NormStrategy = "highest_severity" | "lowest_severity" | "most_common" | "priority";

export interface NormMetric {
  id: string;
  label: string;
  kind: "number" | "enum" | "bool";
  options: string[] | null;
  unit: string;
  help: string;
  operators: string[];
}

export interface NormRule {
  id?: number;
  provider?: string;
  metric: string;
  operator: string;
  value: string | number | boolean | null;
  reputation: string;
  enabled: boolean;
  order?: number;
}

export interface NormSettings {
  mode: "suggest" | "auto";
  strategy: NormStrategy;
  only_escalate: boolean;
  fallback_verdicts: boolean;
  provider_order: string[];
}

export interface NormConfig {
  settings: NormSettings;
  rules: NormRule[];
  providers: { id: string; name: string; color: string; monogram: string; types: string[]; metrics: NormMetric[] }[];
}

export interface NormPreview {
  enriched: number;
  with_opinion: number;
  differs: number;
  would_apply: number;
  distribution: { reputation: string; label: string; count: number }[];
  changes: {
    id: number;
    type: string;
    value: string;
    current: string;
    normalized: string;
    decided_by: string;
    applies: boolean;
    escalation: boolean;
    contributions: NormContribution[];
  }[];
}

export interface EnrichmentRuleInput {
  name: string;
  enabled: boolean;
  type: string;
  sub_types: string[];
  reputations: string[];
  providers: string[];
  /** 0 = always look up, -1 = never re-enrich */
  refresh_days: number;
  /** Skip integrations that are out of capacity instead of waiting for them */
  skip_when_busy: boolean;
}

export interface EnrichmentRule extends EnrichmentRuleInput {
  id: number;
  created_by: string;
  created_at: string | null;
  updated_at: string | null;
  stats: { queued: number; done: number; error: number; skipped: number };
}

export interface EnrichmentProviderQueue {
  provider: string;
  name: string;
  queued: number;
  used_today: number;
  used_last_minute: number;
  done_today: number;
  errors_today: number;
  per_minute: number;
  per_day: number;
  blocked: string | null;
  cooldown_until: string | null;
  cooldown_reason: string | null;
}

export interface EnrichmentQueue {
  paused: boolean;
  queued: number;
  running: number;
  done_today: number;
  errors_today: number;
  skipped_today: number;
  providers: EnrichmentProviderQueue[];
  recent_errors: { id: number; provider: string; observable_id: number; value: string; rule_name: string; error: string; finished_at: string | null }[];
}

export interface EnrichmentConfig {
  rules: EnrichmentRule[];
  providers: { id: string; name: string; color: string; monogram: string; types: string[]; sub_types: Record<string, string[]> }[];
  limits: Record<string, { per_minute: number; per_day: number }>;
  queue: EnrichmentQueue;
}

export interface EnrichmentPreview {
  matching: number;
  jobs: number;
  capped: boolean;
  providers: { provider: string; jobs: number; eta_seconds: number }[];
}

export interface EnrichmentSeries {
  range: ObservedRange;
  bucket: "day" | "week" | "month";
  start: string;
  end: string;
  points: { start: string; end: string; total: number; automatic: number; manual: number; providers: Record<string, number> }[];
  totals: { lookups: number; automatic: number; manual: number; observables: number };
  providers: { provider: string; name: string; lookups: number }[];
  verdicts: Record<string, number>;
  coverage: { enriched: number; observables: number };
  failing_now: number;
}

export interface Feed {
  id: number;
  name: string;
  kind: "taxii21" | "stix_url" | "text_list";
  url: string;
  collection_id: string;
  /** Text lists: what each line holds */
  list_type: "ip" | "url" | "domain" | "auto";
  auth: "none" | "basic" | "header";
  username: string;
  secret_set: boolean;
  header_name: string;
  poll_minutes: number;
  initial_lookback_days: number;
  max_age_days: number;
  default_reputation: string;
  min_confidence: number;
  enrich_new: boolean;
  enabled: boolean;
  last_poll_at: string | null;
  last_status: "ok" | "error" | null;
  last_error: string | null;
  stats: { indicators?: number; created?: number; linked?: number; escalated?: number; deactivated?: number; reverted?: number; skipped_tombstoned?: number; duration_seconds?: number };
  listed: number;
  polling: boolean;
  created_at: string | null;
}

export type FeedInput = Omit<Feed, "id" | "secret_set" | "last_poll_at" | "last_status" | "last_error" | "stats" | "listed" | "polling" | "created_at"> & {
  secret?: string | null;
};

export interface TaxiiCollection {
  id: string;
  title: string;
  description: string;
  can_read: boolean;
}

export interface TaxiiServerConfig {
  enabled: boolean;
  min_reputation: string;
  types: string[];
  sources: (number | string)[];
  discovery_path: string;
  api_root_path: string;
  collection_id: string;
  objects_path: string;
}
