import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, ArrowRight, Check, ChevronDown, Clock, Info, Pause, Pencil, Play, Plus, Sparkles, Trash2, Wand2, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { ReputationBadge, TypeBadge } from "@/components/bits";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { useConfirm } from "@/components/ui/confirm";
import { Modal } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty";
import { Field, Input } from "@/components/ui/input";
import { MultiSelect } from "@/components/ui/multi-select";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { ProviderLogo } from "@/pages/settings/IntegrationsTab";
import { del, get, patch, post, put } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useIntegrations } from "@/lib/integrations";
import { subTypeLabel, typeLabel, useMeta } from "@/lib/meta";
import type { EnrichmentConfig, EnrichmentPreview, EnrichmentQueue, EnrichmentRule, EnrichmentRuleInput, Meta } from "@/lib/types";
import { cn, errorMessage, fmt, timeAgo } from "@/lib/utils";

type ProviderInfo = EnrichmentConfig["providers"][number];

const REFRESH: { value: number; label: string }[] = [
  { value: 7, label: "Skip if enriched in the last 7 days" },
  { value: 1, label: "Skip if enriched in the last day" },
  { value: 30, label: "Skip if enriched in the last 30 days" },
  { value: 0, label: "Always look up again" },
  { value: -1, label: "Never re-enrich (any result counts)" },
];
const refreshShort = (d: number) => (d < 0 ? "never re-enriches" : d === 0 ? "always re-enriches" : `refreshes after ${d} day${d === 1 ? "" : "s"}`);

const EMPTY: EnrichmentRuleInput = { name: "", enabled: true, type: "TYPE_ID_IP_ADDRESS", sub_types: [], reputations: [], providers: [], refresh_days: 7, skip_when_busy: false };

export function formatEta(seconds: number) {
  if (seconds < 90) return `${Math.max(1, Math.round(seconds))} s`;
  if (seconds < 5400) return `${Math.round(seconds / 60)} min`;
  if (seconds < 2 * 86400) return `${(seconds / 3600).toFixed(1)} h`;
  return `${(seconds / 86400).toFixed(1)} days`;
}

/** Whether a provider can enrich the type (and at least one selected sub-type), plus a note for partial coverage. */
export function coverage(p: Pick<ProviderInfo, "types" | "sub_types">, type: string, subTypes: string[], meta?: Meta) {
  if (!p.types.includes(type)) return { supported: false, note: null as string | null };
  const allowed = p.sub_types?.[type];
  if (!allowed?.length) return { supported: true, note: null };
  const supported = subTypes.length === 0 || subTypes.some((s) => allowed.includes(s));
  const missing = subTypes.length === 0 || subTypes.some((s) => !allowed.includes(s));
  return { supported, note: missing ? `${allowed.map((s) => subTypeLabel(s, meta)).join(", ")} only` : null };
}

function useEnrichmentConfig() {
  return useQuery({ queryKey: ["enrichment-rules"], queryFn: () => get<EnrichmentConfig>("/enrichment-rules") });
}

function invalidateAll(qc: ReturnType<typeof useQueryClient>) {
  ["enrichment-rules", "enrichment-queue"].forEach((k) => qc.invalidateQueries({ queryKey: [k] }));
}

// ---- Queue ---------------------------------------------------------------------------------------------

function QueueCard({ providers, admin }: { providers: ProviderInfo[]; admin: boolean }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const integrations = useIntegrations();
  const q = useQuery({
    queryKey: ["enrichment-queue"],
    queryFn: () => get<EnrichmentQueue>("/enrichment-rules/queue"),
    refetchInterval: (query) => (query.state.data && query.state.data.queued + query.state.data.running > 0 ? 3000 : 20000),
  });
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<Record<string, { per_minute: number; per_day: number }>>({});
  const [showErrors, setShowErrors] = useState(false);
  const d = q.data;

  const settings = useMutation({
    mutationFn: (body: { paused?: boolean; limits?: typeof draft }) => put<EnrichmentConfig>("/enrichment-rules/settings", body),
    onSuccess: (cfg) => {
      qc.setQueryData(["enrichment-rules"], cfg);
      qc.setQueryData(["enrichment-queue"], cfg.queue);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const clear = useMutation({
    mutationFn: () => post<{ cancelled: number }>("/enrichment-rules/queue/clear"),
    onSuccess: (r) => {
      toast.success(`${fmt(r.cancelled)} queued lookup(s) cancelled`);
      invalidateAll(qc);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  if (!d) return <Skeleton className="h-56 rounded-2xl" />;
  const connected = new Set((integrations.data ?? []).map((i) => i.provider));
  const rows = d.providers.filter((p) => connected.has(p.provider) || p.queued > 0 || p.used_today > 0);
  const working = d.queued + d.running > 0;
  const status = d.paused ? (
    <Badge tone="warning"><Pause className="size-3" /> Paused</Badge>
  ) : working ? (
    <Badge tone="primary"><motion.span animate={{ opacity: [1, 0.3, 1] }} transition={{ repeat: Infinity, duration: 1.4 }} className="size-1.5 rounded-full bg-current" /> Working</Badge>
  ) : (
    <Badge tone="success"><Check className="size-3" /> Idle</Badge>
  );
  const info = (id: string) => providers.find((p) => p.id === id) ?? { id, name: id, color: "#888", monogram: id.slice(0, 2).toUpperCase() };

  return (
    <Card className="flex flex-col">
      <CardHeader
        title={<span className="inline-flex items-center gap-2">Lookup queue {status}</span>}
        description="Rule lookups are paced per provider. Manual Enrich in the Database isn't counted against these limits."
        action={
          admin && (
            <div className="flex shrink-0 gap-1">
              <Button size="sm" variant="ghost" onClick={() => settings.mutate({ paused: !d.paused })} loading={settings.isPending && !editing}>
                {d.paused ? <><Play /> Resume</> : <><Pause /> Pause</>}
              </Button>
              {d.queued > 0 && (
                <Button
                  size="sm"
                  variant="ghost"
                  className="text-destructive hover:bg-destructive/10"
                  onClick={async () => {
                    if (await confirm({ title: `Cancel ${fmt(d.queued)} queued lookup(s)?`, description: "Rules keep running for new observables.", confirmLabel: "Cancel lookups", destructive: true }))
                      clear.mutate();
                  }}
                >
                  <XCircle /> Clear
                </Button>
              )}
            </div>
          )
        }
      />
      <CardBody className="space-y-4">
        <div className="grid grid-cols-4 gap-2 text-center">
          {[
            ["Queued", d.queued],
            ["Running", d.running],
            ["Done today", d.done_today],
            ["Errors today", d.errors_today],
          ].map(([label, v]) => (
            <div key={label as string} className="rounded-xl bg-muted/40 p-2.5">
              <div className={cn("text-lg font-semibold tabular", label === "Errors today" && (v as number) > 0 && "text-destructive")}>{fmt(v as number)}</div>
              <div className="text-[11px] text-muted-foreground">{label}</div>
            </div>
          ))}
        </div>

        {rows.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Connect a threat-intel provider in <Link to="/settings/integrations" className="text-primary hover:underline">Settings → Integrations</Link> to use enrichment rules.
          </p>
        ) : (
          <div className="space-y-2.5">
            <div className="flex items-center justify-between text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              <span>Today's usage</span>
              {admin && !editing && (
                <button className="normal-case tracking-normal text-primary hover:underline" onClick={() => { setDraft(Object.fromEntries(rows.map((r) => [r.provider, { per_minute: r.per_minute, per_day: r.per_day }]))); setEditing(true); }}>
                  Edit limits
                </button>
              )}
            </div>
            {rows.map((p) => {
              const pct = Math.min(100, (p.used_today / Math.max(1, p.per_day)) * 100);
              return (
                <div key={p.provider} className="flex items-center gap-3 text-xs">
                  <ProviderLogo provider={info(p.provider)} size={24} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-medium">{p.name}</span>
                      {p.queued > 0 && <span className="text-muted-foreground">· {fmt(p.queued)} queued</span>}
                      {p.blocked && <Badge tone="warning">{p.blocked}</Badge>}
                      {p.cooldown_until && (
                        <Badge tone="danger" title={p.cooldown_reason ?? ""}>
                          <Clock className="size-3" /> {p.cooldown_reason}: retry {timeAgo(p.cooldown_until).replace(" ago", "")}
                        </Badge>
                      )}
                    </div>
                    {editing ? (
                      <div className="mt-1 flex items-center gap-2">
                        <Input type="number" min={1} className="h-7 w-20 text-xs" value={draft[p.provider]?.per_minute ?? p.per_minute} onChange={(e) => setDraft((x) => ({ ...x, [p.provider]: { ...x[p.provider], per_minute: Number(e.target.value) } }))} />
                        <span className="text-muted-foreground">/ min</span>
                        <Input type="number" min={1} className="h-7 w-24 text-xs" value={draft[p.provider]?.per_day ?? p.per_day} onChange={(e) => setDraft((x) => ({ ...x, [p.provider]: { ...x[p.provider], per_day: Number(e.target.value) } }))} />
                        <span className="text-muted-foreground">/ day</span>
                      </div>
                    ) : (
                      <div className="mt-1 flex items-center gap-2">
                        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                          <motion.div className={cn("h-full rounded-full", pct >= 100 ? "bg-destructive" : pct > 80 ? "bg-warning" : "bg-primary")} initial={{ width: 0 }} animate={{ width: `${pct}%` }} />
                        </div>
                        <span className="w-28 shrink-0 text-right tabular text-muted-foreground">
                          {fmt(p.used_today)} / {fmt(p.per_day)} · {p.per_minute}/min
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
            {editing && (
              <div className="flex items-center justify-end gap-2 pt-1">
                <span className="mr-auto text-[11px] text-muted-foreground">Defaults are conservative free-tier guesses: check your provider plan.</span>
                <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>Cancel</Button>
                <Button size="sm" loading={settings.isPending} onClick={() => settings.mutate({ limits: draft }, { onSuccess: () => { setEditing(false); toast.success("Limits saved"); } })}>
                  Save limits
                </Button>
              </div>
            )}
          </div>
        )}

        {d.recent_errors.length > 0 && (
          <div className="rounded-xl border">
            <button className="flex w-full items-center gap-2 px-3 py-2 text-xs font-medium" onClick={() => setShowErrors((v) => !v)}>
              <AlertTriangle className="size-3.5 text-destructive" /> {d.recent_errors.length} recent failed lookup{d.recent_errors.length === 1 ? "" : "s"}
              <ChevronDown className={cn("ml-auto size-3.5 transition-transform", showErrors && "rotate-180")} />
            </button>
            <AnimatePresence initial={false}>
              {showErrors && (
                <motion.ul initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }} className="max-h-48 divide-y overflow-auto border-t text-xs">
                  {d.recent_errors.map((e) => (
                    <li key={e.id} className="px-3 py-1.5">
                      <div className="flex items-center gap-2">
                        <span className="truncate font-mono">{e.value}</span>
                        <span className="text-muted-foreground">· {info(e.provider).name}</span>
                        <span className="ml-auto shrink-0 text-muted-foreground">{timeAgo(e.finished_at)}</span>
                      </div>
                      <div className="truncate text-destructive/80" title={e.error}>{e.error}</div>
                    </li>
                  ))}
                </motion.ul>
              )}
            </AnimatePresence>
          </div>
        )}
      </CardBody>
    </Card>
  );
}

// ---- Rule cards ----------------------------------------------------------------------------------------

function RuleSummary({ rule, providers }: { rule: EnrichmentRuleInput; providers: ProviderInfo[] }) {
  const meta = useMeta();
  const info = (id: string) => providers.find((p) => p.id === id) ?? { id, name: id, color: "#888", monogram: id.slice(0, 2).toUpperCase() };
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-xs">
      <TypeBadge value={rule.type} />
      {rule.sub_types.map((s) => <Badge key={s} tone="outline">{subTypeLabel(s, meta.data)}</Badge>)}
      {rule.reputations.length ? rule.reputations.map((r) => <ReputationBadge key={r} value={r} />) : <span className="text-muted-foreground">any reputation</span>}
      <ArrowRight className="mx-1 size-3.5 text-muted-foreground" />
      {rule.providers.map((p) => (
        <span key={p} className="inline-flex items-center gap-1 rounded-lg border bg-card py-0.5 pl-0.5 pr-2 font-medium">
          <ProviderLogo provider={info(p)} size={18} /> {info(p).name}
        </span>
      ))}
    </div>
  );
}

function RuleCard({ rule, providers, onEdit }: { rule: EnrichmentRule; providers: ProviderInfo[]; onEdit: () => void }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const { can } = useAuth();
  const admin = can("admin");
  const info = (id: string) => providers.find((p) => p.id === id)?.name ?? id;

  const toggle = useMutation({
    mutationFn: (enabled: boolean) => patch(`/enrichment-rules/${rule.id}/enabled?enabled=${enabled}`),
    onSuccess: (_r, enabled) => !enabled && rule.stats.queued > 0 && toast.message(`${fmt(rule.stats.queued)} queued lookup(s) cancelled`),
    onSettled: () => invalidateAll(qc),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const run = useMutation({
    mutationFn: async () => {
      const preview = await post<EnrichmentPreview>("/enrichment-rules/preview", rule);
      if (preview.jobs === 0) {
        toast.message(preview.matching ? `All ${fmt(preview.matching)} matching observables are already enriched or queued` : "No observables match this rule yet");
        return null;
      }
      const ok = await confirm({
        title: `Queue ${fmt(preview.jobs)} lookup${preview.jobs === 1 ? "" : "s"}?`,
        description: (
          <div className="space-y-2">
            <p>{fmt(preview.matching)} observable(s) match “{rule.name}” today. Results already fresh for this rule's window are skipped.</p>
            <ul className="space-y-1 rounded-lg bg-muted/50 p-2 text-xs">
              {preview.providers.map((p) => (
                <li key={p.provider} className="flex justify-between gap-4">
                  <span>{info(p.provider)}: {fmt(p.jobs)} lookup{p.jobs === 1 ? "" : "s"}</span>
                  <span className="text-muted-foreground">≈ {formatEta(p.eta_seconds)}</span>
                </li>
              ))}
            </ul>
            {preview.capped && <p className="text-xs text-warning">Capped at 10,000 lookups per run.</p>}
          </div>
        ),
        confirmLabel: "Queue lookups",
      });
      return ok ? post<{ queued: number }>(`/enrichment-rules/${rule.id}/run`) : null;
    },
    onSuccess: (r) => {
      if (!r) return;
      toast.success(`${fmt(r.queued)} lookup(s) queued`);
      invalidateAll(qc);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  return (
    <motion.div layout initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, scale: 0.98 }}>
      <Card className={cn("p-4 transition-opacity", !rule.enabled && "opacity-60")}>
        <div className="flex items-start gap-3">
          <div className="grid size-9 shrink-0 place-items-center rounded-xl bg-accent text-accent-foreground">
            <Wand2 className="size-4" />
          </div>
          <div className="min-w-0 flex-1 space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="font-semibold">{rule.name}</h3>
              {!rule.enabled && <Badge tone="neutral">Disabled</Badge>}
              <span className="text-xs text-muted-foreground">
                New observables · {refreshShort(rule.refresh_days)}{rule.skip_when_busy && " · skips busy integrations"}
              </span>
            </div>
            <RuleSummary rule={rule} providers={providers} />
            <div className="flex flex-wrap gap-3 text-[11px] text-muted-foreground">
              <span className="tabular">{fmt(rule.stats.queued)} queued</span>
              <span className="tabular">{fmt(rule.stats.done)} done</span>
              {rule.stats.error > 0 && <span className="tabular text-destructive">{fmt(rule.stats.error)} failed</span>}
              {rule.stats.skipped > 0 && <span className="tabular">{fmt(rule.stats.skipped)} skipped</span>}
              <span>last 7 days</span>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-1">
            {can("edit") && (
              <Button size="sm" variant="subtle" onClick={() => run.mutate()} loading={run.isPending} disabled={!rule.enabled}>
                {!run.isPending && <Play />} Run on existing
              </Button>
            )}
            {admin && (
              <>
                <Button size="icon-sm" variant="ghost" onClick={onEdit} aria-label="Edit rule"><Pencil /></Button>
                <Button
                  size="icon-sm"
                  variant="ghost"
                  className="text-destructive hover:bg-destructive/10"
                  aria-label="Delete rule"
                  onClick={async () => {
                    if (!(await confirm({ title: `Delete “${rule.name}”?`, description: "Its queued lookups are cancelled. Stored enrichment results are kept.", confirmLabel: "Delete", destructive: true }))) return;
                    try {
                      await del(`/enrichment-rules/${rule.id}`);
                      toast.success("Enrichment rule deleted");
                      invalidateAll(qc);
                    } catch (e) {
                      toast.error(errorMessage(e));
                    }
                  }}
                >
                  <Trash2 />
                </Button>
                <Switch checked={rule.enabled} onCheckedChange={(v) => toggle.mutate(v)} aria-label="Enabled" />
              </>
            )}
          </div>
        </div>
      </Card>
    </motion.div>
  );
}

// ---- Editor --------------------------------------------------------------------------------------------

function RuleEditor({
  open,
  onOpenChange,
  initial,
  providers,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  initial: EnrichmentRule | null;
  providers: ProviderInfo[];
}) {
  const qc = useQueryClient();
  const meta = useMeta();
  const integrations = useIntegrations();
  const [draft, setDraft] = useState<EnrichmentRuleInput>(EMPTY);
  useEffect(() => {
    if (open) setDraft(initial ? { name: initial.name, enabled: initial.enabled, type: initial.type, sub_types: initial.sub_types, reputations: initial.reputations, providers: initial.providers, refresh_days: initial.refresh_days, skip_when_busy: initial.skip_when_busy } : EMPTY);
    // Keyed on the rule id: a background refetch of the rules list must not wipe an edit in progress.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, initial?.id]);

  const supportedTypes = useMemo(() => new Set(providers.flatMap((p) => p.types)), [providers]);
  const typeOptions = (meta.data?.types ?? []).filter((t) => !["TYPE_ID_UNKNOWN", "TYPE_ID_OTHER"].includes(t.id));
  const subTypeOptions = (meta.data?.sub_types ?? []).filter((s) => s.type === draft.type).map((s) => ({ value: s.id, label: s.label }));
  const repOptions = [...(meta.data?.reputations ?? [])].sort((a, b) => b.severity - a.severity).map((r) => ({ value: r.id, label: r.label }));
  const candidates = providers
    .map((p) => ({ p, ...coverage(p, draft.type, draft.sub_types, meta.data) }))
    .filter((c) => c.supported);
  const integ = (id: string) => integrations.data?.find((i) => i.provider === id);

  // Drop providers that no longer cover the chosen type/sub-types.
  useEffect(() => {
    const ok = new Set(candidates.map((c) => c.p.id));
    if (draft.providers.some((p) => !ok.has(p))) setDraft((d) => ({ ...d, providers: d.providers.filter((p) => ok.has(p)) }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft.type, draft.sub_types.join("|")]);

  const usableCandidates = candidates.filter((c) => integ(c.p.id)?.enabled);
  const blocker = !draft.name.trim()
    ? "Give the rule a name"
    : draft.providers.length === 0
      ? usableCandidates.length
        ? "Choose at least one integration"
        : `Connect an integration that can look up ${typeLabel(draft.type).toLowerCase()}s`
      : null;
  const valid = !blocker;
  const [debounced, setDebounced] = useState(draft);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(draft), 400);
    return () => clearTimeout(t);
  }, [draft]);
  const preview = useQuery({
    queryKey: ["enrichment-preview", debounced],
    queryFn: () => post<EnrichmentPreview>("/enrichment-rules/preview", { ...debounced, name: debounced.name || "Preview" }),
    enabled: open && debounced.providers.length > 0,
  });

  const save = useMutation({
    mutationFn: () => {
      const body = { ...draft, skip_when_busy: draft.providers.length > 1 && draft.skip_when_busy };
      return initial ? put(`/enrichment-rules/${initial.id}`, body) : post("/enrichment-rules", body);
    },
    onSuccess: () => {
      toast.success(initial ? "Enrichment rule updated" : "Enrichment rule created");
      invalidateAll(qc);
      onOpenChange(false);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={initial ? "Edit enrichment rule" : "New enrichment rule"}
      description="When an observable matching these filters enters the database, look it up with the chosen integrations."
      className="max-w-2xl"
      footer={
        <>
          {blocker && <span className="mr-auto self-center text-xs text-muted-foreground">{blocker}</span>}
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => save.mutate()} disabled={!valid} loading={save.isPending}>{initial ? "Save rule" : "Create rule"}</Button>
        </>
      }
    >
      <div className="space-y-5">
        <Field label="Name">
          <Input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="e.g. Enrich malicious IPv4" autoFocus maxLength={64} />
        </Field>
        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Type">
            <Select value={draft.type} onChange={(e) => setDraft({ ...draft, type: e.target.value, sub_types: [] })}>
              {typeOptions.map((t) => (
                <option key={t.id} value={t.id} disabled={!supportedTypes.has(t.id)}>
                  {t.label}{supportedTypes.has(t.id) ? "" : " (no integration)"}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Sub types">
            {subTypeOptions.length ? (
              <MultiSelect options={subTypeOptions} value={draft.sub_types} onChange={(v) => setDraft({ ...draft, sub_types: v })} placeholder="Any sub type" />
            ) : (
              <div className="flex h-9 items-center rounded-lg border border-dashed px-3 text-sm text-muted-foreground" title={`${typeLabel(draft.type)} has no sub types: the rule matches every ${typeLabel(draft.type).toLowerCase()}`}>
                Not applicable
              </div>
            )}
          </Field>
          <Field label="Reputation">
            <MultiSelect options={repOptions} value={draft.reputations} onChange={(v) => setDraft({ ...draft, reputations: v })} placeholder="Any reputation" />
          </Field>
        </div>

        <div>
          <div className="mb-1.5 flex items-baseline justify-between">
            <span className="text-sm font-medium">Enrich with</span>
            <span className="text-xs text-muted-foreground">Only integrations that can look up {draft.sub_types.length ? draft.sub_types.map((s) => subTypeLabel(s, meta.data)).join(" / ") : typeLabel(draft.type)} are shown</span>
          </div>
          {candidates.length === 0 ? (
            <p className="rounded-xl border border-dashed p-4 text-center text-sm text-muted-foreground">No integration supports this type{draft.sub_types.length ? " and sub type" : ""}.</p>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2">
              {candidates.map(({ p, note }) => {
                const i = integ(p.id);
                const usable = !!i?.enabled;
                const selected = draft.providers.includes(p.id);
                return (
                  <button
                    key={p.id}
                    type="button"
                    disabled={!usable && !selected}
                    onClick={() => setDraft((d) => ({ ...d, providers: selected ? d.providers.filter((x) => x !== p.id) : [...d.providers, p.id] }))}
                    className={cn(
                      "flex items-center gap-3 rounded-xl border p-3 text-left transition-all",
                      selected ? "border-primary bg-primary/5 ring-2 ring-primary/30" : "hover:bg-muted/50",
                      !usable && !selected && "cursor-not-allowed opacity-60 hover:bg-transparent",
                    )}
                  >
                    <ProviderLogo provider={p} size={30} />
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium">{p.name}</div>
                      <div className="truncate text-[11px] text-muted-foreground">
                        {usable ? note ?? "Supported" : i ? "Integration disabled" : "Not connected"}
                        {!usable && note ? ` · ${note}` : ""}
                      </div>
                    </div>
                    {selected ? (
                      <Check className="size-4 text-primary" />
                    ) : !usable ? (
                      <Link to="/settings/integrations" onClick={(e) => e.stopPropagation()} className="text-[11px] font-medium text-primary hover:underline">
                        Connect
                      </Link>
                    ) : null}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <AnimatePresence initial={false}>
          {draft.providers.length > 1 && (
            <motion.label
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="flex cursor-pointer items-start gap-3 overflow-hidden rounded-xl border p-3"
            >
              <Switch checked={draft.skip_when_busy} onCheckedChange={(v) => setDraft({ ...draft, skip_when_busy: v })} aria-label="Skip busy integrations" />
              <span className="text-sm">
                <span className="font-medium">Don't wait for busy integrations</span>
                <span className="mt-0.5 block text-xs text-muted-foreground">
                  {draft.skip_when_busy
                    ? "If an integration is out of capacity (daily limit reached, rate-limited or disabled), its lookup is skipped and the observable is enriched with the others."
                    : "Lookups for an integration that's out of capacity wait in the queue until it can take them again."}
                </span>
              </span>
            </motion.label>
          )}
        </AnimatePresence>

        <Field label="Re-enrichment" hint="New observables have no results yet, so this mostly matters for “Run on existing matches”.">
          <Select value={String(draft.refresh_days)} onChange={(e) => setDraft({ ...draft, refresh_days: Number(e.target.value) })}>
            {REFRESH.map((r) => <option key={r.value} value={r.value}>{r.label}</option>)}
          </Select>
        </Field>

        <div className="flex items-start gap-2 rounded-xl bg-muted/50 p-3 text-xs">
          <Sparkles className="mt-0.5 size-3.5 shrink-0 text-primary" />
          {draft.providers.length === 0 ? (
            <span className="text-muted-foreground">Pick at least one integration to see what this rule matches.</span>
          ) : !preview.data ? (
            <Skeleton className="h-4 w-56" />
          ) : (
            <span className="text-muted-foreground">
              <span className="font-medium text-foreground">{fmt(preview.data.matching)}</span> observable{preview.data.matching === 1 ? "" : "s"} in the database match today.
              {preview.data.jobs > 0
                ? <> “Run on existing matches” would queue <span className="font-medium text-foreground">{fmt(preview.data.jobs)}</span> lookup{preview.data.jobs === 1 ? "" : "s"} ({preview.data.providers.map((p) => `${providers.find((x) => x.id === p.provider)?.name ?? p.provider} ≈ ${formatEta(p.eta_seconds)}`).join(", ")}).</>
                : preview.data.matching > 0 ? " They're already enriched or queued." : ""}
            </span>
          )}
        </div>
      </div>
    </Modal>
  );
}

// ---- Panel ---------------------------------------------------------------------------------------------

export function EnrichmentRulesPanel({ newRuleSignal }: { newRuleSignal: number }) {
  const { can } = useAuth();
  const admin = can("admin");
  const q = useEnrichmentConfig();
  const [editing, setEditing] = useState<EnrichmentRule | null>(null);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (newRuleSignal) {
      setEditing(null);
      setOpen(true);
    }
  }, [newRuleSignal]);

  if (!q.data) return <div className="space-y-4"><Skeleton className="h-40 rounded-2xl" /><Skeleton className="h-32 rounded-2xl" /></div>;
  const { rules, providers } = q.data;

  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-[1fr_440px]">
        <div className="space-y-4">
          <Card className="flex gap-3 p-4 text-sm">
            <Info className="mt-0.5 size-4 shrink-0 text-primary" />
            <div className="space-y-1 text-muted-foreground">
              <p>
                Enrichment rules look up observables with your threat-intel integrations <span className="font-medium text-foreground">as soon as they enter the database</span>, whether they come from a sync or are created by hand. Every matching rule applies; their integrations are combined.
              </p>
              <p>
                Use <span className="font-medium text-foreground">Run on existing matches</span> to enrich observables that are already in the database. Lookups wait in a queue paced for each provider's quota, and with automatic normalization enabled, results update reputations too.
              </p>
            </div>
          </Card>
          {rules.length === 0 ? (
            <Card>
              <EmptyState
                icon={<Wand2 />}
                title="No enrichment rules yet"
                description="Example: enrich new malicious IPv4 addresses with VirusTotal and AbuseIPDB."
                action={admin && <Button onClick={() => { setEditing(null); setOpen(true); }}><Plus /> New enrichment rule</Button>}
              />
            </Card>
          ) : (
            <div className="space-y-3">
              <AnimatePresence initial={false}>
                {rules.map((r) => (
                  <RuleCard key={r.id} rule={r} providers={providers} onEdit={() => { setEditing(r); setOpen(true); }} />
                ))}
              </AnimatePresence>
            </div>
          )}
        </div>
        <QueueCard providers={providers} admin={admin} />
      </div>
      <RuleEditor open={open} onOpenChange={setOpen} initial={editing} providers={providers} />
    </div>
  );
}
