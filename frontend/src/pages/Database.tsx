import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import {
  ArrowDown,
  Braces,
  Briefcase,
  History,
  LayoutList,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  Copy,
  Database as DatabaseIcon,
  FilterX,
  Pin,
  Plus,
  RotateCcw,
  Search,
  Sparkles,
  Trash2,
  Rss,
} from "lucide-react";
import { Fragment, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { PageHeader, PinnedMark, ReputationBadge, TypeBadge } from "@/components/bits";
import { EnrichmentPanel } from "@/components/EnrichmentPanel";
import { NormalizedBanner } from "@/components/NormalizationPanel";
import { ObservableLifeline } from "@/components/ObservableLifeline";
import { RegionFlag, WorkspaceName } from "@/components/RegionFlag";
import { useFeeds } from "@/lib/feeds";
import { useRegionOf } from "@/lib/workspaces";
import { providerName, useCapabilities, useProviders } from "@/lib/integrations";
import { ObservableTimeline } from "@/components/ObservableTimeline";
import { Segmented } from "@/components/ui/segmented";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useConfirm } from "@/components/ui/confirm";
import { Modal, Sheet } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty";
import { Field, Input, Textarea } from "@/components/ui/input";
import { MultiSelect } from "@/components/ui/multi-select";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Tooltip } from "@/components/ui/tooltip";
import { del, get, patch, post, qs } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { repLabel, subTypeLabel, typeLabel, useMeta } from "@/lib/meta";
import type { Observable, Page, Workspace } from "@/lib/types";
import { cn, errorMessage, fmt, formatDate, timeAgo } from "@/lib/utils";

type SortKey = "value" | "type" | "reputation" | "associated_cases_count" | "last_observed_at" | "updated_at";
const PAGE_SIZE = 50;

function useDebounced<T>(value: T, ms = 300) {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

function useWorkspaces() {
  return useQuery({ queryKey: ["workspaces"], queryFn: () => get<Workspace[]>("/workspaces") });
}

function useInvalidateObservables() {
  const qc = useQueryClient();
  return () => {
    ["observables", "observable", "observable-history", "dashboard", "rule-preview"].forEach((k) => qc.invalidateQueries({ queryKey: [k] }));
  };
}

function RepSelect({ value, onChange, className }: { value: string; onChange: (v: string) => void; className?: string }) {
  const meta = useMeta();
  const reps = [...(meta.data?.reputations ?? [])].sort((a, b) => a.severity - b.severity);
  return (
    <Select value={value} onChange={(e) => onChange(e.target.value)} className={className}>
      {reps.map((r) => (
        <option key={r.id} value={r.id}>
          {r.label}
        </option>
      ))}
    </Select>
  );
}

function WorkspaceChips({ obs }: { obs: Observable }) {
  if (obs.links.length === 0) {
    return <span className="text-xs text-muted-foreground">{obs.origin === "manual" ? "Central only" : obs.origin === "feed" ? "Feed only" : "—"}</span>;
  }
  const regionOf = useRegionOf();
  const shown = obs.links.slice(0, 2);
  const rest = obs.links.slice(2);
  return (
    <div className="flex items-center gap-1">
      {shown.map((l) => (
        <Tooltip key={l.workspace_id} content={l.relation === "origin" ? "Observed natively in this workspace" : "Synced into this workspace by Beacon"}>
          <span
            className={cn(
              "inline-flex max-w-[120px] items-center truncate whitespace-nowrap rounded-md px-1.5 py-0.5 text-[11px] font-medium",
              l.relation === "origin" ? "bg-muted text-foreground" : "border border-dashed text-muted-foreground",
            )}
          >
            <RegionFlag region={regionOf(l.workspace_id)} height={9} className="mr-1" />
            <span className="truncate">{l.workspace_name}</span>
          </span>
        </Tooltip>
      ))}
      {rest.length > 0 && (
        <Tooltip content={rest.map((l) => l.workspace_name).join(", ")}>
          <span className="whitespace-nowrap rounded-md px-1 text-[11px] text-muted-foreground hover:text-foreground">+{rest.length}</span>
        </Tooltip>
      )}
    </div>
  );
}

function AddObservableDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const meta = useMeta();
  const invalidate = useInvalidateObservables();
  const [type, setType] = useState("TYPE_ID_IP_ADDRESS");
  const [subType, setSubType] = useState("SUB_TYPE_ID_UNKNOWN");
  const [value, setValue] = useState("");
  const [reputation, setReputation] = useState("SCORE_MALICIOUS");
  const [description, setDescription] = useState("");
  const subTypes = (meta.data?.sub_types ?? []).filter((s) => s.type === type);

  const m = useMutation({
    mutationFn: () => post<Observable>("/observables", { type, sub_type: subType, value, reputation, description }),
    onSuccess: () => {
      toast.success("Observable added");
      invalidate();
      setValue("");
      setDescription("");
      onOpenChange(false);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Add observable"
      description="Manually created observables are authoritative and sync via rules with the “Central” source."
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => m.mutate()} loading={m.isPending} disabled={!value.trim()}>Add observable</Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Type">
          <Select
            value={type}
            onChange={(e) => {
              setType(e.target.value);
              setSubType("SUB_TYPE_ID_UNKNOWN");
            }}
          >
            {(meta.data?.types ?? []).filter((t) => t.id !== "TYPE_ID_UNKNOWN").map((t) => (
              <option key={t.id} value={t.id}>{t.label}</option>
            ))}
          </Select>
        </Field>
        <Field label="Sub type" hint={subTypes.length ? "Leave as Auto to detect" : undefined}>
          <Select value={subType} onChange={(e) => setSubType(e.target.value)} disabled={!subTypes.length}>
            <option value="SUB_TYPE_ID_UNKNOWN">Auto</option>
            {subTypes.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
          </Select>
        </Field>
        <Field label="Value" className="sm:col-span-2">
          <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder="e.g. 203.0.113.7" className="font-mono" autoFocus />
        </Field>
        <Field label="Reputation" className="sm:col-span-2">
          <RepSelect value={reputation} onChange={setReputation} />
        </Field>
        <Field label="Description" className="sm:col-span-2">
          <Textarea value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Context, source, campaign…" />
        </Field>
      </div>
    </Modal>
  );
}

function ObservableDrawer({ id, onClose }: { id: number | null; onClose: () => void }) {
  const meta = useMeta();
  const regionOf = useRegionOf();
  const { can } = useAuth();
  const confirm = useConfirm();
  const invalidate = useInvalidateObservables();
  const q = useQuery({
    queryKey: ["observable", id],
    queryFn: () => get<Observable>(`/observables/${id}`),
    enabled: id !== null,
  });
  const o = q.data;
  const [reputation, setReputation] = useState("");
  const [description, setDescription] = useState("");
  useEffect(() => {
    if (o) {
      setReputation(o.reputation);
      setDescription(o.description);
    }
  }, [o]);
  const dirty = !!o && (reputation !== o.reputation || description !== o.description);
  const [tab, setTab] = useState<"overview" | "timeline" | "enrichment">("overview");
  useEffect(() => setTab("overview"), [id]);

  const save = useMutation({
    mutationFn: () => patch<Observable>(`/observables/${id}`, { reputation, description }),
    onSuccess: () => {
      toast.success("Saved — this observable is now centrally authoritative");
      invalidate();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const unpin = useMutation({
    mutationFn: () => post<Observable>(`/observables/${id}/unpin`),
    onSuccess: () => {
      toast.success("Reverted to merged workspace values");
      invalidate();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const caps = useCapabilities();
  const providers = useProviders();
  const enrichProviders = o ? caps.data?.[o.type] ?? [] : [];
  const [justEnriched, setJustEnriched] = useState<string | undefined>();
  const enrich = useMutation({
    mutationFn: () => post<Observable>(`/observables/${id}/enrich`),
    onSuccess: (res) => {
      const failed = res.intel.filter((i) => i.status === "error");
      if (failed.length) toast.error(`Enrichment partly failed: ${failed[0].error}`);
      else toast.success(`Enriched via ${enrichProviders.map((p) => providerName(providers.data, p)).join(" & ")}`);
      setJustEnriched(enrichProviders[0] ? `intel:${enrichProviders[0]}` : undefined);
      setTab("enrichment");
      invalidate();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const applyRep = useMutation({
    mutationFn: (rep: string) => patch<Observable>(`/observables/${id}`, { reputation: rep }),
    onSuccess: () => {
      toast.success("Reputation updated from threat intel");
      invalidate();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const normalize = useMutation({
    mutationFn: () => post<Observable>(`/observables/${id}/normalize`),
    onSuccess: (r) => {
      toast.success(`Reputation set to the normalized value: ${repLabel(r.reputation)}`);
      invalidate();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: () => del(`/observables/${id}`),
    onSuccess: () => {
      toast.success("Observable deleted");
      invalidate();
      onClose();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  const editable = can("edit");

  return (
    <Sheet
      open={id !== null}
      onOpenChange={(open) => !open && onClose()}
      className="max-w-[min(1200px,100vw)] md:w-[80vw]"
      title={o ? <span className="font-mono">{o.value}</span> : "Observable"}
      description={o ? `${typeLabel(o.type)} · ${subTypeLabel(o.sub_type, meta.data)}` : undefined}
      footer={
        o && editable ? (
          <>
            <Button
              variant="ghost"
              className="mr-auto text-destructive hover:bg-destructive/10"
              onClick={async () => {
                if (
                  await confirm({
                    title: "Delete observable?",
                    description: "It will be removed from the central database and blocked from being re-imported. Workspaces keep their copies.",
                    confirmLabel: "Delete",
                    destructive: true,
                  })
                )
                  remove.mutate();
              }}
            >
              <Trash2 /> Delete
            </Button>
            <Button variant="outline" disabled={!dirty} onClick={() => { setReputation(o.reputation); setDescription(o.description); }}>
              Reset
            </Button>
            <Button onClick={() => save.mutate()} disabled={!dirty} loading={save.isPending}>Save changes</Button>
          </>
        ) : undefined
      }
    >
      {!o ? (
        <div className="space-y-3">
          <Skeleton className="h-10" />
          <Skeleton className="h-24" />
          <Skeleton className="h-40" />
        </div>
      ) : (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-2">
            <TypeBadge value={o.type} />
            <ReputationBadge value={o.reputation} />
            {o.origin === "manual" && <Badge tone="outline">Created manually</Badge>}
            {o.origin === "feed" && <Badge tone="outline"><Rss className="size-3" /> From feed</Badge>}
            {o.pinned && (
              <Badge tone="primary">
                <Pin className="size-3" /> Centrally edited
              </Badge>
            )}
            <div className="ml-auto flex items-center gap-1">
              {editable && enrichProviders.length > 0 && (
                <Tooltip content={`Look up in ${enrichProviders.map((p) => providerName(providers.data, p)).join(" & ")}`}>
                  <Button size="sm" variant="subtle" onClick={() => enrich.mutate()} loading={enrich.isPending}>
                    {!enrich.isPending && <Sparkles />} Enrich
                  </Button>
                </Tooltip>
              )}
              <Button variant="ghost" size="sm" onClick={() => navigator.clipboard.writeText(o.value).then(() => toast.success("Copied"))}>
                <Copy /> Copy
              </Button>
            </div>
          </div>

          <Segmented
            value={tab}
            onChange={setTab}
            options={[
              { value: "overview", label: <><LayoutList /> Overview</> },
              { value: "timeline", label: <><History /> Timeline</> },
              ...(o.has_enrichment || o.intel.length ? [{ value: "enrichment" as const, label: <><Braces /> Enrichment</> }] : []),
            ]}
          />

          {tab === "timeline" && <ObservableTimeline id={o.id} />}
          {tab === "enrichment" && o.normalized && (
            <NormalizedBanner
              result={o.normalized}
              providers={providers.data}
              onApply={editable ? () => normalize.mutate() : undefined}
              applying={normalize.isPending}
            />
          )}
          {tab === "enrichment" && (o.has_enrichment || o.intel.length > 0) && (
            <EnrichmentPanel
              links={o.links}
              intel={o.intel}
              raw={o.enrichment}
              currentReputation={o.reputation}
              onApplyReputation={editable && !o.normalized ? (rep) => applyRep.mutate(rep) : undefined}
              regionOf={regionOf}
              preferSource={justEnriched}
            />
          )}
          {tab === "overview" && (
          <>
          <dl className="grid grid-cols-2 gap-4 rounded-xl border bg-muted/30 p-4 text-sm lg:grid-cols-[auto_repeat(4,minmax(0,1fr))] lg:items-center lg:gap-6">
            <div className="col-span-2 flex items-center gap-3 lg:col-span-1 lg:border-r lg:pr-6">
              <span className="grid size-9 place-items-center rounded-xl bg-accent text-accent-foreground">
                <Briefcase className="size-4" />
              </span>
              <div>
                <dt className="text-xs text-muted-foreground">Associated cases (all workspaces)</dt>
                <dd className="text-lg font-semibold tabular">{fmt(o.associated_cases_count)}</dd>
              </div>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">First observed</dt>
              <dd className="mt-0.5">{formatDate(o.first_observed_at)}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Last observed</dt>
              <dd className="mt-0.5">{formatDate(o.last_observed_at)}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Added to Beacon</dt>
              <dd className="mt-0.5">{formatDate(o.created_at)}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Updated</dt>
              <dd className="mt-0.5">{formatDate(o.updated_at)}</dd>
            </div>
          </dl>

          <ObservableLifeline obs={o} regionOf={regionOf} />

          <div className="grid gap-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
          <div className="space-y-4">
            <Field label="Reputation">
              {editable ? <RepSelect value={reputation} onChange={setReputation} /> : <ReputationBadge value={o.reputation} />}
            </Field>
            <Field label="Description">
              {editable ? (
                <Textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={8} />
              ) : (
                <p className="whitespace-pre-wrap text-sm">{o.description || "—"}</p>
              )}
            </Field>
            {o.pinned && o.origin !== "manual" && editable && (
              <div className="flex items-center justify-between gap-3 rounded-xl border border-primary/30 bg-primary/5 p-3 text-sm">
                <span className="text-muted-foreground">Central edits override workspace values during sync.</span>
                <Button size="sm" variant="outline" onClick={() => unpin.mutate()} loading={unpin.isPending}>
                  <RotateCcw /> Revert
                </Button>
              </div>
            )}
          </div>

          <div>
            <h4 className="mb-2 text-sm font-semibold">Workspace copies</h4>
            {o.links.length === 0 ? (
              <p className="text-sm text-muted-foreground">Not present in any workspace yet.</p>
            ) : (
              <div className="overflow-hidden rounded-xl border">
                <table className="w-full text-sm">
                  <thead className="bg-muted/50 text-xs text-muted-foreground">
                    <tr>
                      <th className="px-3 py-2 text-left font-medium">Workspace</th>
                      <th className="px-3 py-2 text-left font-medium">Relation</th>
                      <th className="px-3 py-2 text-left font-medium">Remote reputation</th>
                      <th className="px-3 py-2 text-right font-medium">Cases</th>
                      <th className="px-3 py-2 text-left font-medium">Synced</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {o.links.map((l) => (
                      <tr key={l.workspace_id}>
                        <td className="px-3 py-2">
                          <div className="font-medium">
                            <WorkspaceName name={l.workspace_name} region={regionOf(l.workspace_id)} />
                          </div>
                          <div className="font-mono text-[11px] text-muted-foreground">#{l.remote_id}</div>
                        </td>
                        <td className="px-3 py-2">
                          <Badge tone={l.relation === "origin" ? "neutral" : "outline"}>{l.relation === "origin" ? "Native" : "Synced in"}</Badge>
                        </td>
                        <td className="px-3 py-2">
                          <ReputationBadge value={l.remote_reputation ?? "SCORE_UNKNOWN"} />
                          {l.remote_reputation !== o.reputation && (
                            <div className="mt-1 text-[11px] text-muted-foreground">differs from central</div>
                          )}
                        </td>
                        <td className="px-3 py-2 text-right tabular">{fmt(l.associated_cases_count)}</td>
                        <td className="px-3 py-2 text-xs text-muted-foreground">{timeAgo(l.last_synced_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {!!o.feeds?.length && (
              <div className="mt-6">
                <h4 className="mb-2 flex items-center gap-1.5 text-sm font-semibold"><Rss className="size-4 text-muted-foreground" /> Listed by STIX/TAXII feeds</h4>
                <div className="overflow-hidden rounded-xl border">
                  <table className="w-full text-sm">
                    <thead className="bg-muted/50 text-xs text-muted-foreground">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium">Feed</th>
                        <th className="px-3 py-2 text-left font-medium">Feed reputation</th>
                        <th className="px-3 py-2 text-left font-medium">Valid until</th>
                        <th className="px-3 py-2 text-left font-medium">Last seen</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y">
                      {o.feeds.map((f) => (
                        <tr key={`${f.feed_id}-${f.stix_id}`} className={cn(!f.active && "opacity-55")}>
                          <td className="px-3 py-2">
                            <div className="font-medium">{f.feed_name}</div>
                            <div className="truncate font-mono text-[11px] text-muted-foreground" title={f.stix_id}>{f.stix_id}</div>
                          </td>
                          <td className="px-3 py-2"><ReputationBadge value={f.reputation} /></td>
                          <td className="px-3 py-2 text-xs text-muted-foreground">{f.valid_until ? formatDate(f.valid_until, false) : "—"}{!f.active && " · inactive"}</td>
                          <td className="px-3 py-2 text-xs text-muted-foreground">{timeAgo(f.last_seen_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
          </div>
          </>
          )}
        </div>
      )}
    </Sheet>
  );
}

function CasesCount({ obs }: { obs: Observable }) {
  const regionOf = useRegionOf();
  const n = obs.associated_cases_count;
  const breakdown = obs.links.filter((l) => l.associated_cases_count > 0);
  const content = (
    <span className={cn("inline-flex items-center gap-1 tabular", n ? "font-medium" : "text-muted-foreground")}>
      <Briefcase className="size-3.5 text-muted-foreground" />
      {fmt(n)}
    </span>
  );
  if (!breakdown.length) return content;
  return (
    <Tooltip
      content={
        <div className="space-y-0.5">
          {breakdown.map((l) => (
            <div key={l.workspace_id} className="flex justify-between gap-4">
              <WorkspaceName name={l.workspace_name} region={regionOf(l.workspace_id)} />
              <span className="tabular">{fmt(l.associated_cases_count)}</span>
            </div>
          ))}
        </div>
      }
    >
      {content}
    </Tooltip>
  );
}

function InlineEnrichment({ id }: { id: number }) {
  const regionOf = useRegionOf();
  const q = useQuery({ queryKey: ["observable", id], queryFn: () => get<Observable>(`/observables/${id}`) });
  if (!q.data) return <Skeleton className="h-32" />;
  return <EnrichmentPanel links={q.data.links} intel={q.data.intel} raw={q.data.enrichment} regionOf={regionOf} />;
}

function SortHeader({
  label,
  k,
  sort,
  order,
  onSort,
  className,
}: {
  label: string;
  k: SortKey;
  sort: SortKey;
  order: "asc" | "desc";
  onSort: (k: SortKey) => void;
  className?: string;
}) {
  const active = sort === k;
  return (
    <th className={cn("px-4 py-3 text-left font-medium", className)}>
      <button onClick={() => onSort(k)} className={cn("inline-flex items-center gap-1 transition-colors hover:text-foreground", active && "text-foreground")}>
        {label}
        {active && (order === "asc" ? <ArrowUp className="size-3" /> : <ArrowDown className="size-3" />)}
      </button>
    </th>
  );
}

export default function DatabasePage() {
  const meta = useMeta();
  const workspaces = useWorkspaces();
  const { can } = useAuth();
  const confirm = useConfirm();
  const invalidate = useInvalidateObservables();

  const [search, setSearch] = useState("");
  const [types, setTypes] = useState<string[]>([]);
  const [reps, setReps] = useState<string[]>([]);
  const [searchParams] = useSearchParams();
  // "?workspace=<id>" (e.g. from the dashboard flow graph) pre-filters to one workspace.
  const [wsIds, setWsIds] = useState<number[]>(() => {
    const id = Number(searchParams.get("workspace"));
    return Number.isInteger(id) && id > 0 ? [id] : [];
  });
  // "?source=central|feed:<id>|<workspace id>" pre-filters to where observables came from.
  const [sources, setSources] = useState<(number | string)[]>(() => {
    const src = searchParams.get("source");
    return src ? [/^\d+$/.test(src) ? Number(src) : src] : [];
  });
  const [pinnedOnly, setPinnedOnly] = useState(false);
  const [enrichedOnly, setEnrichedOnly] = useState(false);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [sort, setSort] = useState<SortKey>("updated_at");
  const [order, setOrder] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [openId, setOpenId] = useState<number | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [bulkRep, setBulkRep] = useState("SCORE_MALICIOUS");
  const debounced = useDebounced(search);

  const filterKey = JSON.stringify([debounced, types, reps, wsIds, sources, pinnedOnly, enrichedOnly, sort, order]);
  useEffect(() => {
    setPage(1);
    setSelected(new Set());
  }, [filterKey]);

  const q = useQuery({
    queryKey: ["observables", filterKey, page],
    queryFn: () =>
      get<Page<Observable>>(
        "/observables" +
          qs({
            page,
            page_size: PAGE_SIZE,
            search: debounced,
            type: types,
            reputation: reps,
            workspace_id: wsIds,
            source: sources.map(String),
            pinned: pinnedOnly ? true : undefined,
            has_enrichment: enrichedOnly ? true : undefined,
            sort,
            order,
          }),
      ),
    placeholderData: keepPreviousData,
  });

  const items = q.data?.items ?? [];
  const total = q.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const hasFilters = !!(search || types.length || reps.length || wsIds.length || sources.length || pinnedOnly || enrichedOnly);

  const typeOptions = useMemo(() => (meta.data?.types ?? []).map((t) => ({ value: t.id, label: t.label })), [meta.data]);
  const repOptions = useMemo(
    () => [...(meta.data?.reputations ?? [])].sort((a, b) => b.severity - a.severity).map((r) => ({ value: r.id, label: r.label })),
    [meta.data],
  );
  const wsOptions = useMemo(() => (workspaces.data ?? []).map((w) => ({ value: w.id, label: w.name })), [workspaces.data]);
  const feeds = useFeeds();
  const sourceOptions = useMemo(
    () => [
      { value: "central" as number | string, label: "Central", hint: "Beacon" },
      ...(workspaces.data ?? []).map((w) => ({ value: w.id as number | string, label: w.name, hint: "workspace" })),
      ...(feeds.data ?? []).map((f) => ({ value: `feed:${f.id}` as number | string, label: f.name, hint: "feed" })),
    ],
    [workspaces.data, feeds.data],
  );

  const onSort = (k: SortKey) => {
    if (sort === k) setOrder(order === "asc" ? "desc" : "asc");
    else {
      setSort(k);
      setOrder(k === "value" || k === "type" ? "asc" : "desc");
    }
  };

  const allOnPage = items.length > 0 && items.every((o) => selected.has(o.id));
  const toggleAll = () => {
    const next = new Set(selected);
    if (allOnPage) items.forEach((o) => next.delete(o.id));
    else items.forEach((o) => next.add(o.id));
    setSelected(next);
  };
  const toggleOne = (id: number) => {
    const next = new Set(selected);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setSelected(next);
  };

  const bulk = useMutation({
    mutationFn: (action: "delete" | "set_reputation" | "unpin") =>
      post<{ affected: number }>("/observables/bulk", { ids: [...selected], action, reputation: bulkRep }),
    onSuccess: (r) => {
      toast.success(`${fmt(r.affected)} observable(s) updated`);
      setSelected(new Set());
      invalidate();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  const caps = useCapabilities();
  const canEnrichAny = !!caps.data && Object.keys(caps.data).length > 0;
  const bulkEnrich = useMutation({
    mutationFn: () =>
      post<{ enriched: number; skipped: number; ok: number; not_found: number; errors: number; first_error: string | null }>(
        "/observables/bulk-enrich",
        { ids: [...selected].slice(0, 50) },
      ),
    onSuccess: (r) => {
      const msg = `${fmt(r.enriched)} enriched${r.skipped ? `, ${fmt(r.skipped)} not supported` : ""}${r.not_found ? `, ${fmt(r.not_found)} unknown to the provider` : ""}`;
      if (r.errors) toast.error(`${msg}, ${fmt(r.errors)} failed`, { description: r.first_error ?? undefined });
      else toast.success(msg);
      invalidate();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  const clearFilters = () => {
    setSearch("");
    setTypes([]);
    setReps([]);
    setWsIds([]);
    setSources([]);
    setPinnedOnly(false);
    setEnrichedOnly(false);
  };

  const toggleExpanded = (id: number) => {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setExpanded(next);
  };

  return (
    <>
      <PageHeader
        title="Database"
        description="The central observable database, combined from every connected workspace"
        actions={
          can("edit") && (
            <Button onClick={() => setAddOpen(true)}>
              <Plus /> Add observable
            </Button>
          )
        }
      />

      <Card className="mb-4 p-3">
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-[minmax(220px,1.3fr)_1fr_1fr_1fr_1fr_auto]">
          <Input icon={<Search />} placeholder="Search values or descriptions…" value={search} onChange={(e) => setSearch(e.target.value)} />
          <MultiSelect options={typeOptions} value={types} onChange={setTypes} placeholder="All types" />
          <MultiSelect options={repOptions} value={reps} onChange={setReps} placeholder="All reputations" />
          <Tooltip content="Where observables came from: a workspace (first seen there), Central (created or edited in Beacon) or a feed">
            <div>
              <MultiSelect options={sourceOptions} value={sources} onChange={setSources} placeholder="Any source" />
            </div>
          </Tooltip>
          <Tooltip content="Observables present in these workspaces, including copies Beacon synced there">
            <div>
              <MultiSelect options={wsOptions} value={wsIds} onChange={setWsIds} placeholder="Any workspace" emptyLabel="No workspaces" />
            </div>
          </Tooltip>
          <div className="flex items-center gap-3 px-1">
            <label className="flex items-center gap-2 whitespace-nowrap text-sm text-muted-foreground">
              <Switch checked={pinnedOnly} onCheckedChange={setPinnedOnly} aria-label="Edited only" /> Edited only
            </label>
            <label className="flex items-center gap-2 whitespace-nowrap text-sm text-muted-foreground">
              <Switch checked={enrichedOnly} onCheckedChange={setEnrichedOnly} aria-label="Enriched only" /> Enriched
            </label>
            <AnimatePresence>
              {hasFilters && (
                <motion.div initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.8 }}>
                  <Tooltip content="Clear filters">
                    <Button variant="ghost" size="icon" onClick={clearFilters} aria-label="Clear filters">
                      <FilterX />
                    </Button>
                  </Tooltip>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </Card>

      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] text-sm">
            <thead className="border-b bg-muted/40 text-xs text-muted-foreground">
              <tr>
                <th className="w-8 pl-3" aria-label="Enrichment" />
                {can("edit") && (
                  <th className="w-10 px-4 py-3">
                    <input type="checkbox" checked={allOnPage} onChange={toggleAll} className="size-4 accent-[hsl(var(--primary))]" aria-label="Select page" />
                  </th>
                )}
                <SortHeader label="Value" k="value" sort={sort} order={order} onSort={onSort} />
                <SortHeader label="Type" k="type" sort={sort} order={order} onSort={onSort} />
                <SortHeader label="Reputation" k="reputation" sort={sort} order={order} onSort={onSort} />
                <SortHeader label="Cases" k="associated_cases_count" sort={sort} order={order} onSort={onSort} className="text-right" />
                <th className="px-4 py-3 text-left font-medium">Workspaces</th>
                <SortHeader label="Last observed" k="last_observed_at" sort={sort} order={order} onSort={onSort} />
                <SortHeader label="Updated" k="updated_at" sort={sort} order={order} onSort={onSort} />
              </tr>
            </thead>
            <tbody className={cn("divide-y transition-opacity", q.isFetching && q.isPlaceholderData && "opacity-60")}>
              {q.isLoading &&
                Array.from({ length: 8 }).map((_, i) => (
                  <tr key={i}>
                    <td colSpan={9} className="px-4 py-3">
                      <Skeleton className="h-6" />
                    </td>
                  </tr>
                ))}
              {items.map((o, i) => (
                <Fragment key={o.id}>
                  <motion.tr
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0, transition: { delay: Math.min(i * 0.012, 0.25) } }}
                    onClick={() => setOpenId(o.id)}
                    className={cn(
                      "group cursor-pointer transition-colors hover:bg-muted/40",
                      selected.has(o.id) && "bg-accent/50",
                      expanded.has(o.id) && "bg-muted/30",
                    )}
                  >
                    <td className="pl-3" onClick={(e) => e.stopPropagation()}>
                      {o.has_enrichment && (
                        <Tooltip content={expanded.has(o.id) ? "Hide enrichment" : "Show enrichment"}>
                          <button
                            onClick={() => toggleExpanded(o.id)}
                            className="grid size-6 place-items-center rounded-md text-muted-foreground transition-colors hover:bg-muted hover:text-primary"
                            aria-expanded={expanded.has(o.id)}
                            aria-label={`Toggle enrichment for ${o.value}`}
                          >
                            <ChevronRight className={cn("size-4 transition-transform", expanded.has(o.id) && "rotate-90 text-primary")} />
                          </button>
                        </Tooltip>
                      )}
                    </td>
                    {can("edit") && (
                      <td className="px-4 py-2.5" onClick={(e) => e.stopPropagation()}>
                        <input type="checkbox" checked={selected.has(o.id)} onChange={() => toggleOne(o.id)} className="size-4 accent-[hsl(var(--primary))]" aria-label={`Select ${o.value}`} />
                      </td>
                    )}
                    <td className="max-w-[340px] px-4 py-2.5">
                      <div className="flex items-center gap-2">
                        <span className="truncate font-mono text-[13px]" title={o.value}>{o.value}</span>
                        {o.pinned && <PinnedMark />}
                        {o.has_enrichment && (
                          <Tooltip content="Has enrichment data">
                            <Braces className="size-3.5 shrink-0 text-primary/70" />
                          </Tooltip>
                        )}
                      </div>
                      {o.description && <div className="truncate text-xs text-muted-foreground">{o.description}</div>}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex flex-col items-start gap-0.5">
                        <TypeBadge value={o.type} />
                        {o.sub_type !== "SUB_TYPE_ID_UNKNOWN" && (
                          <span className="text-[11px] text-muted-foreground">{subTypeLabel(o.sub_type, meta.data)}</span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <ReputationBadge value={o.reputation} />
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <CasesCount obs={o} />
                    </td>
                    <td className="px-4 py-2.5">
                      <WorkspaceChips obs={o} />
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-xs text-muted-foreground">{timeAgo(o.last_observed_at)}</td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-xs text-muted-foreground">{timeAgo(o.updated_at)}</td>
                  </motion.tr>
                  <AnimatePresence initial={false}>
                    {expanded.has(o.id) && (
                      <tr className="!border-t-0 bg-muted/30">
                        <td colSpan={9} className="p-0">
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: "auto", opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.22, ease: [0.22, 1, 0.36, 1] }}
                            className="overflow-hidden"
                          >
                            <div className="px-12 pb-4 pt-1">
                              <InlineEnrichment id={o.id} />
                            </div>
                          </motion.div>
                        </td>
                      </tr>
                    )}
                  </AnimatePresence>
                </Fragment>
              ))}
            </tbody>
          </table>
          {!q.isLoading && items.length === 0 && (
            <EmptyState
              icon={<DatabaseIcon />}
              title={hasFilters ? "No matching observables" : "The database is empty"}
              description={hasFilters ? "Try adjusting your filters." : "Connect a workspace and run a sync, or add an observable manually."}
              action={hasFilters ? <Button variant="outline" onClick={clearFilters}>Clear filters</Button> : undefined}
            />
          )}
        </div>
        <div className="flex items-center justify-between gap-4 border-t px-4 py-3 text-xs text-muted-foreground">
          <span className="tabular">
            {total === 0 ? "0 results" : `${fmt((page - 1) * PAGE_SIZE + 1)}–${fmt(Math.min(page * PAGE_SIZE, total))} of ${fmt(total)}`}
          </span>
          <div className="flex items-center gap-2">
            <span className="tabular">Page {page} of {pages}</span>
            <Button variant="outline" size="icon-sm" disabled={page <= 1} onClick={() => setPage(page - 1)} aria-label="Previous page">
              <ChevronLeft />
            </Button>
            <Button variant="outline" size="icon-sm" disabled={page >= pages} onClick={() => setPage(page + 1)} aria-label="Next page">
              <ChevronRight />
            </Button>
          </div>
        </div>
      </Card>

      {/* Bulk action bar */}
      <AnimatePresence>
        {selected.size > 0 && (
          <motion.div
            initial={{ y: 80, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            exit={{ y: 80, opacity: 0 }}
            transition={{ type: "spring", stiffness: 400, damping: 32 }}
            className="fixed inset-x-0 bottom-6 z-40 mx-auto flex w-fit items-center gap-3 rounded-2xl border bg-popover/90 px-4 py-2.5 shadow-2xl backdrop-blur-xl"
          >
            <span className="text-sm font-medium tabular">{fmt(selected.size)} selected</span>
            <div className="h-5 w-px bg-border" />
            <RepSelect value={bulkRep} onChange={setBulkRep} className="w-48" />
            <Button size="sm" variant="subtle" onClick={() => bulk.mutate("set_reputation")} loading={bulk.isPending}>
              Set {repLabel(bulkRep).toLowerCase()}
            </Button>
            {canEnrichAny && (
              <Tooltip content={selected.size > 50 ? "Enriches the first 50 selected (provider rate limits)" : "Look up selected observables in your threat-intel integrations"}>
                <Button size="sm" variant="subtle" onClick={() => bulkEnrich.mutate()} loading={bulkEnrich.isPending}>
                  {!bulkEnrich.isPending && <Sparkles />} Enrich
                </Button>
              </Tooltip>
            )}
            <Button size="sm" variant="ghost" onClick={() => bulk.mutate("unpin")}>
              <RotateCcw /> Revert edits
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={async () => {
                if (
                  await confirm({
                    title: `Delete ${fmt(selected.size)} observable(s)?`,
                    description: "They'll be removed centrally and blocked from re-import.",
                    confirmLabel: "Delete",
                    destructive: true,
                  })
                )
                  bulk.mutate("delete");
              }}
            >
              <Trash2 /> Delete
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>
              Cancel
            </Button>
          </motion.div>
        )}
      </AnimatePresence>

      <ObservableDrawer id={openId} onClose={() => setOpenId(null)} />
      <AddObservableDialog open={addOpen} onOpenChange={setAddOpen} />
    </>
  );
}
