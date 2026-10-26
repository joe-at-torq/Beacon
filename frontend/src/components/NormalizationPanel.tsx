import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion, Reorder } from "framer-motion";
import { ArrowDown, ArrowRight, ArrowUp, GripVertical, Info, ListPlus, Plus, RefreshCw, Scale, Sparkles, Trash2, Wand2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { ReputationBadge } from "@/components/bits";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { useConfirm } from "@/components/ui/confirm";
import { Input } from "@/components/ui/input";
import { Segmented } from "@/components/ui/segmented";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { ProviderLogo } from "@/pages/settings/IntegrationsTab";
import { get, post, put } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useIntegrations } from "@/lib/integrations";
import { repColor, typeLabel, useMeta } from "@/lib/meta";
import type { NormalizedResult, NormConfig, NormContribution, NormMetric, NormPreview, NormRule, NormSettings, NormStrategy } from "@/lib/types";
import { cn, errorMessage, fmt } from "@/lib/utils";

const OP_LABEL: Record<string, string> = { ">=": "≥", ">": ">", "<=": "≤", "<": "<", "==": "=", "!=": "≠" };

const STRATEGIES: { value: NormStrategy; label: string; help: string }[] = [
  { value: "highest_severity", label: "Most severe", help: "The most severe reputation any source maps to wins. Safest for detection." },
  { value: "lowest_severity", label: "Least severe", help: "The least severe reputation wins, so every source must agree before escalating." },
  { value: "most_common", label: "Most common", help: "The reputation most sources agree on wins (ties go to the more severe one)." },
  { value: "priority", label: "Source priority", help: "The first source in your priority order that has an opinion wins." },
];

export function formatValue(v: unknown, unit = "") {
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (typeof v === "number") return `${fmt(v)}${unit === "%" ? "%" : unit ? ` ${unit}` : ""}`;
  return String(v ?? "—");
}

/** "Malicious engines 7 ≥ 5" */
export function describeContribution(c: NormContribution) {
  if (c.source === "verdict") return `Beacon verdict ${String(c.actual)}`;
  if (c.metric === "result") return c.actual === "Not found" ? "No reputation data returned" : "Data returned";
  return `${c.metric_label} ${formatValue(c.actual, c.unit)} ${OP_LABEL[c.operator] ?? c.operator} ${formatValue(c.threshold, c.unit)}`;
}

function RepSelect({ value, onChange, disabled }: { value: string; onChange: (v: string) => void; disabled?: boolean }) {
  const meta = useMeta();
  const reps = [...(meta.data?.reputations ?? [])].filter((r) => r.id !== "SCORE_OTHER").sort((a, b) => b.severity - a.severity);
  return (
    <div className="relative">
      <span className="pointer-events-none absolute left-2.5 top-1/2 z-10 size-2 -translate-y-1/2 rounded-full" style={{ background: repColor(value) }} />
      <Select value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled} className="[&_select]:pl-6">
        {reps.map((r) => (
          <option key={r.id} value={r.id}>{r.label}</option>
        ))}
      </Select>
    </div>
  );
}

function defaultValue(m: NormMetric): NormRule["value"] {
  return m.kind === "number" ? 1 : m.kind === "bool" ? true : m.options?.[0] ?? "";
}

function ValueInput({ metric, value, onChange, disabled }: { metric: NormMetric; value: NormRule["value"]; onChange: (v: NormRule["value"]) => void; disabled?: boolean }) {
  if (metric.kind === "number") {
    return (
      <div className="relative">
        <Input type="number" value={value === null ? "" : String(value)} onChange={(e) => onChange(e.target.value === "" ? null : Number(e.target.value))} disabled={disabled} className={cn(metric.unit && "pr-9")} />
        {metric.unit && <span className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-xs text-muted-foreground">{metric.unit}</span>}
      </div>
    );
  }
  if (metric.kind === "bool") {
    return (
      <Select value={value ? "true" : "false"} onChange={(e) => onChange(e.target.value === "true")} disabled={disabled}>
        <option value="true">Yes</option>
        <option value="false">No</option>
      </Select>
    );
  }
  return (
    <Select value={String(value ?? "")} onChange={(e) => onChange(e.target.value)} disabled={disabled}>
      {(metric.options ?? []).map((o) => <option key={o} value={o}>{o}</option>)}
    </Select>
  );
}

function ProviderRules({
  provider,
  saved,
  editable,
  connected,
  onSaved,
}: {
  provider: NormConfig["providers"][number];
  saved: NormRule[];
  editable: boolean;
  connected: boolean;
  onSaved: () => void;
}) {
  const strip = (rules: NormRule[]) => rules.map(({ metric, operator, value, reputation, enabled }) => ({ metric, operator, value, reputation, enabled }));
  const [draft, setDraft] = useState<NormRule[]>(strip(saved));
  useEffect(() => setDraft(strip(saved)), [JSON.stringify(strip(saved))]);
  const dirty = JSON.stringify(draft) !== JSON.stringify(strip(saved));
  const metricOf = (id: string) => provider.metrics.find((m) => m.id === id) ?? provider.metrics[0];
  const update = (i: number, patch: Partial<NormRule>) => setDraft((d) => d.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const move = (i: number, dir: -1 | 1) =>
    setDraft((d) => {
      const next = [...d];
      [next[i], next[i + dir]] = [next[i + dir], next[i]];
      return next;
    });

  const save = useMutation({
    mutationFn: () => put<NormConfig>(`/normalization/rules/${provider.id}`, draft),
    onSuccess: () => {
      toast.success(`${provider.name} mappings saved`);
      onSaved();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  return (
    <Card className="flex flex-col">
      <div className="flex items-start gap-3 px-5 pt-5">
        <ProviderLogo provider={provider} size={34} />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold">{provider.name}</h3>
            {connected ? <Badge tone="success">Connected</Badge> : <Badge tone="outline">Not connected</Badge>}
          </div>
          <p className="mt-0.5 truncate text-xs text-muted-foreground">{provider.types.map(typeLabel).join(" · ")}</p>
        </div>
        {draft.length > 0 && <span className="text-[11px] text-muted-foreground">First match wins</span>}
      </div>
      <div className="flex-1 space-y-2 px-5 py-4">
        {draft.length === 0 && (
          <p className="rounded-lg border border-dashed p-3 text-center text-xs text-muted-foreground">
            No mappings: {provider.name} won't influence the normalized reputation{editable ? "." : " until an admin adds one."}
          </p>
        )}
        <AnimatePresence initial={false}>
          {draft.map((rule, i) => {
            const m = metricOf(rule.metric);
            return (
              <motion.div
                key={i}
                layout
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: rule.enabled ? 1 : 0.55, y: 0 }}
                exit={{ opacity: 0, height: 0 }}
                className="grid grid-cols-[1fr_auto] gap-2 rounded-xl border bg-muted/20 p-2"
              >
                <div className="grid grid-cols-[minmax(0,1.4fr)_72px_minmax(0,1fr)_auto_minmax(0,1.3fr)] items-center gap-1.5">
                  <Select
                    value={rule.metric}
                    disabled={!editable}
                    onChange={(e) => {
                      const nm = metricOf(e.target.value);
                      update(i, { metric: nm.id, operator: nm.operators[0], value: defaultValue(nm) });
                    }}
                    title={m.help}
                  >
                    {provider.metrics.map((x) => <option key={x.id} value={x.id}>{x.label}</option>)}
                  </Select>
                  <Select value={rule.operator} onChange={(e) => update(i, { operator: e.target.value })} disabled={!editable}>
                    {m.operators.map((o) => <option key={o} value={o}>{OP_LABEL[o] ?? o}</option>)}
                  </Select>
                  <ValueInput metric={m} value={rule.value} onChange={(v) => update(i, { value: v })} disabled={!editable} />
                  <ArrowRight className="size-4 text-muted-foreground" />
                  <RepSelect value={rule.reputation} onChange={(v) => update(i, { reputation: v })} disabled={!editable} />
                </div>
                {editable && (
                  <div className="flex items-center gap-0.5">
                    <Switch checked={rule.enabled} onCheckedChange={(v) => update(i, { enabled: v })} aria-label="Enabled" />
                    <button onClick={() => move(i, -1)} disabled={i === 0} className="rounded p-1 text-muted-foreground hover:bg-muted disabled:opacity-30" aria-label="Move up"><ArrowUp className="size-3.5" /></button>
                    <button onClick={() => move(i, 1)} disabled={i === draft.length - 1} className="rounded p-1 text-muted-foreground hover:bg-muted disabled:opacity-30" aria-label="Move down"><ArrowDown className="size-3.5" /></button>
                    <button onClick={() => setDraft((d) => d.filter((_, j) => j !== i))} className="rounded p-1 text-destructive hover:bg-destructive/10" aria-label="Remove"><Trash2 className="size-3.5" /></button>
                  </div>
                )}
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
      {editable && (
        <div className="flex items-center gap-2 border-t px-5 py-3">
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              const m0 = provider.metrics[0];
              setDraft((d) => [...d, { metric: m0.id, operator: m0.operators[0], value: defaultValue(m0), reputation: "SCORE_SUSPICIOUS_OR_RISKY", enabled: true }]);
            }}
          >
            <Plus /> Add mapping
          </Button>
          <div className="flex-1" />
          <AnimatePresence>
            {dirty && (
              <motion.div initial={{ opacity: 0, x: 8 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0 }} className="flex gap-1.5">
                <Button size="sm" variant="ghost" onClick={() => setDraft(strip(saved))}>Discard</Button>
                <Button size="sm" onClick={() => save.mutate()} loading={save.isPending}>Save</Button>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}
    </Card>
  );
}

function SettingsCard({ config, editable, onChange }: { config: NormConfig; editable: boolean; onChange: (patch: Partial<NormSettings>) => void }) {
  const s = config.settings;
  const nameOf = (id: string) => config.providers.find((p) => p.id === id)?.name ?? id;
  const order = useMemo(() => {
    const known = s.provider_order.filter((p) => config.providers.some((x) => x.id === p));
    return [...known, ...config.providers.map((p) => p.id).filter((p) => !known.includes(p))];
  }, [s.provider_order, config.providers]);
  const [localOrder, setLocalOrder] = useState(order);
  useEffect(() => setLocalOrder(order), [order.join("|")]);

  return (
    <Card>
      <CardHeader title="How normalization works" description="Map each source's own signals to a Torq reputation, then combine the sources." />
      <CardBody className="space-y-5">
        <div>
          <div className="mb-1.5 text-xs font-medium text-muted-foreground">When a normalized reputation is available</div>
          <Segmented
            value={s.mode}
            onChange={(mode) => editable && onChange({ mode })}
            options={[
              { value: "auto", label: <><Wand2 /> Apply automatically</> },
              { value: "suggest", label: <><Info /> Suggest only</> },
            ]}
          />
          <p className="mt-1.5 text-xs text-muted-foreground">
            {s.mode === "auto"
              ? "After each enrichment the observable's reputation is set to the normalized value (centrally authoritative, synced via Central rules)."
              : "The normalized value is shown on each observable's Enrichment tab with an Apply button."}
          </p>
          {s.mode === "auto" && (
            <label className="mt-2 flex items-center gap-2 text-sm">
              <Switch checked={s.only_escalate} onCheckedChange={(v) => onChange({ only_escalate: v })} disabled={!editable} aria-label="Only raise severity" />
              Only raise severity automatically (never lower a reputation)
            </label>
          )}
        </div>
        <div>
          <div className="mb-1.5 text-xs font-medium text-muted-foreground">Combine sources</div>
          <Segmented value={s.strategy} onChange={(strategy) => editable && onChange({ strategy })} options={STRATEGIES.map(({ value, label }) => ({ value, label }))} />
          <p className="mt-1.5 text-xs text-muted-foreground">{STRATEGIES.find((x) => x.value === s.strategy)?.help}</p>
          <AnimatePresence>
            {s.strategy === "priority" && (
              <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                <Reorder.Group
                  axis="x"
                  values={localOrder}
                  onReorder={setLocalOrder}
                  className="mt-2 flex flex-wrap gap-1.5"
                >
                  {localOrder.map((id, i) => (
                    <Reorder.Item
                      key={id}
                      value={id}
                      dragListener={editable}
                      onDragEnd={() => onChange({ provider_order: localOrder })}
                      className={cn("flex select-none items-center gap-1 rounded-lg border bg-card px-2 py-1 text-xs font-medium", editable && "cursor-grab active:cursor-grabbing")}
                    >
                      {editable && <GripVertical className="size-3 text-muted-foreground" />}
                      <span className="tabular text-muted-foreground">{i + 1}.</span> {nameOf(id)}
                    </Reorder.Item>
                  ))}
                </Reorder.Group>
                <p className="mt-1 text-[11px] text-muted-foreground">Drag to set priority (first = highest).</p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
        <label className="flex items-start gap-2 text-sm">
          <Switch checked={s.fallback_verdicts} onCheckedChange={(v) => onChange({ fallback_verdicts: v })} disabled={!editable} aria-label="Fallback to verdicts" />
          <span>
            Use a source's built-in verdict when none of its mappings match
            <span className="block text-xs text-muted-foreground">Malicious → Malicious, Suspicious → Suspicious or risky, Harmless → Probably safe.</span>
          </span>
        </label>
      </CardBody>
    </Card>
  );
}

function PreviewCard({ canApply, refreshKey }: { canApply: boolean; refreshKey: string }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const q = useQuery({ queryKey: ["normalization-preview", refreshKey], queryFn: () => post<NormPreview>("/normalization/preview", {}) });
  const apply = useMutation({
    mutationFn: () => post<{ changed: number }>("/normalization/apply"),
    onSuccess: (r) => {
      toast.success(`${fmt(r.changed)} observable reputation(s) updated`);
      ["normalization-preview", "observables", "observable", "observable-history", "dashboard", "rule-preview", "dashboard-flows"].forEach((k) =>
        qc.invalidateQueries({ queryKey: [k] }),
      );
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const d = q.data;
  const maxCount = Math.max(1, ...(d?.distribution.map((x) => x.count) ?? [1]));
  return (
    <Card className="flex flex-col">
      <CardHeader
        title="Test against your data"
        description="What the current mappings produce for every observable with threat-intel enrichment"
        action={
          <Button size="sm" variant="ghost" onClick={() => q.refetch()} loading={q.isFetching}>
            {!q.isFetching && <RefreshCw />} Refresh
          </Button>
        }
      />
      <CardBody className="space-y-4">
        {!d ? (
          <Skeleton className="h-40" />
        ) : d.enriched === 0 ? (
          <p className="text-sm text-muted-foreground">No observables have threat-intel enrichment yet. Enrich observables from the Database first.</p>
        ) : (
          <>
            <div className="grid grid-cols-3 gap-2 text-center">
              {[
                ["Enriched", d.enriched],
                ["With an opinion", d.with_opinion],
                ["Would change", d.would_apply],
              ].map(([label, v]) => (
                <div key={label as string} className="rounded-xl bg-muted/40 p-3">
                  <div className="text-xl font-semibold tabular">{fmt(v as number)}</div>
                  <div className="text-[11px] text-muted-foreground">{label}</div>
                </div>
              ))}
            </div>
            <div className="space-y-1.5">
              {d.distribution.map((x) => (
                <div key={x.reputation} className="flex items-center gap-2 text-xs">
                  <span className="w-40 shrink-0">{x.reputation === "none" ? <span className="text-muted-foreground">No opinion</span> : <ReputationBadge value={x.reputation} />}</span>
                  <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
                    <motion.div className="h-full rounded-full" initial={{ width: 0 }} animate={{ width: `${(x.count / maxCount) * 100}%` }} style={{ background: x.reputation === "none" ? "var(--rep-0)" : repColor(x.reputation) }} />
                  </div>
                  <span className="w-10 text-right tabular text-muted-foreground">{fmt(x.count)}</span>
                </div>
              ))}
            </div>
            {d.changes.length > 0 && (
              <div className="max-h-64 overflow-auto rounded-xl border">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-muted text-muted-foreground">
                    <tr>
                      <th className="px-2 py-1.5 text-left font-medium">Observable</th>
                      <th className="px-2 py-1.5 text-left font-medium">Current → normalized</th>
                      <th className="px-2 py-1.5 text-left font-medium">Applies</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    {d.changes.map((c) => (
                      <tr key={c.id} title={c.contributions.map(describeContribution).join("\n")}>
                        <td className="max-w-[180px] truncate px-2 py-1.5 font-mono">{c.value}</td>
                        <td className="px-2 py-1.5">
                          <span className="inline-flex items-center gap-1">
                            <ReputationBadge value={c.current} /> <ArrowRight className="size-3 text-muted-foreground" /> <ReputationBadge value={c.normalized} />
                          </span>
                        </td>
                        <td className="px-2 py-1.5">{c.applies ? <Badge tone="success">Yes</Badge> : <Badge tone="outline" title="Blocked by 'only raise severity'">Lower: skipped</Badge>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {canApply && d.would_apply > 0 && (
              <Button
                className="w-full"
                onClick={async () => {
                  if (await confirm({ title: `Update ${fmt(d.would_apply)} observable reputation(s)?`, description: "Each becomes centrally authoritative and syncs to workspaces via rules with a Central source.", confirmLabel: "Apply" }))
                    apply.mutate();
                }}
                loading={apply.isPending}
              >
                <Sparkles /> Apply to {fmt(d.would_apply)} observable{d.would_apply === 1 ? "" : "s"}
              </Button>
            )}
          </>
        )}
      </CardBody>
    </Card>
  );
}

export function NormalizationPanel() {
  const qc = useQueryClient();
  const { can } = useAuth();
  const editable = can("admin");
  const integrations = useIntegrations();
  const q = useQuery({ queryKey: ["normalization"], queryFn: () => get<NormConfig>("/normalization") });
  const config = q.data;
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["normalization"] });
    qc.invalidateQueries({ queryKey: ["normalization-preview"] });
    qc.invalidateQueries({ queryKey: ["observable"] });
  };
  const saveSettings = useMutation({
    mutationFn: (patch: Partial<NormSettings>) => put<NormConfig>("/normalization/settings", patch),
    onSuccess: (cfg) => {
      qc.setQueryData(["normalization"], cfg);
      qc.invalidateQueries({ queryKey: ["normalization-preview"] });
      qc.invalidateQueries({ queryKey: ["observable"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const recommended = useMutation({
    mutationFn: () => post<NormConfig & { added: number }>("/normalization/recommended"),
    onSuccess: (r) => {
      toast.success(r.added ? `Added ${r.added} recommended mapping(s)` : "All recommended mappings are already in place");
      refresh();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  if (!config) return <div className="space-y-4"><Skeleton className="h-48 rounded-2xl" /><Skeleton className="h-64 rounded-2xl" /></div>;
  const connected = new Set((integrations.data ?? []).filter((i) => i.enabled).map((i) => i.provider));
  const rulesFor = (p: string) => config.rules.filter((r) => r.provider === p);
  // Connected sources first, then the rest.
  const providers = [...config.providers].sort((a, b) => Number(connected.has(b.id)) - Number(connected.has(a.id)));
  const refreshKey = JSON.stringify([config.settings, config.rules]);

  return (
    <div className="space-y-4">
      <Card className="flex flex-wrap items-center gap-3 p-4 text-sm">
        <Info className="size-4 shrink-0 text-primary" />
        <p className="min-w-0 flex-1 text-muted-foreground">
          Every source scores threats differently: VirusTotal counts engines, AbuseIPDB reports a confidence %, Recorded Future a risk score.
          Map each source's signals to <span className="font-medium text-foreground">Torq reputations</span> to get one consistent verdict per observable.
          Recommended mappings also turn clean results and lookups with no reputation data into <span className="font-medium text-foreground">Probably safe</span>, so enriched observables don't stay Unknown.
        </p>
        {editable && (
          <Button size="sm" variant="subtle" onClick={() => recommended.mutate()} loading={recommended.isPending}>
            {!recommended.isPending && <ListPlus />} Add recommended mappings
          </Button>
        )}
      </Card>
      <div className="grid gap-4 xl:grid-cols-2">
        <SettingsCard config={config} editable={editable} onChange={(patch) => saveSettings.mutate(patch)} />
        <PreviewCard canApply={can("edit")} refreshKey={refreshKey} />
      </div>
      <div className="grid gap-4 2xl:grid-cols-2">
        {providers.map((p) => (
          <ProviderRules key={p.id} provider={p} saved={rulesFor(p.id)} editable={editable} connected={connected.has(p.id)} onSaved={refresh} />
        ))}
      </div>
    </div>
  );
}

/** Drawer banner: the normalized reputation for one observable and which sources produced it. */
export function NormalizedBanner({
  result,
  providers,
  onApply,
  applying,
}: {
  result: NormalizedResult;
  providers?: { id: string; name: string; color: string; monogram?: string }[];
  onApply?: () => void;
  applying?: boolean;
}) {
  const p = (id: string) => providers?.find((x) => x.id === id) ?? { id, name: id, color: "var(--muted-foreground)", monogram: id.slice(0, 2).toUpperCase() };
  const strategy = STRATEGIES.find((s) => s.value === result.strategy)?.label ?? result.strategy;
  return (
    <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} className="overflow-hidden rounded-xl border bg-gradient-to-br from-accent/40 to-transparent">
      <div className="flex flex-wrap items-center gap-2 px-4 py-3">
        <Scale className="size-4 text-primary" />
        <span className="text-sm font-medium">Normalized reputation</span>
        <ReputationBadge value={result.reputation} />
        <div className="flex-1" />
        {!result.differs ? (
          <Badge tone="success">{result.mode === "auto" ? "Applied" : "Matches current"}</Badge>
        ) : result.mode === "auto" ? (
          // Automatic mode applies verdicts after enrichment; a difference here was held back or predates a change.
          onApply && (
            <Button size="sm" variant="ghost" onClick={onApply} loading={applying}>
              {result.blocked === "lower" ? "Apply anyway" : "Apply now"}
            </Button>
          )
        ) : (
          onApply && (
            <Button size="sm" onClick={onApply} loading={applying}>
              {!applying && <Sparkles />} Apply
            </Button>
          )
        )}
        <p className="basis-full text-xs text-muted-foreground">
          {strategy} · decided by {p(result.decided_by).name}
          {result.differs && result.mode === "auto" && (
            <span className="text-foreground">
              {" · "}
              {result.blocked === "lower"
                ? "Not applied automatically: it would lower the severity (only raise severity is on)."
                : "Mappings changed since the last enrichment; it applies on the next one."}
            </span>
          )}
        </p>
      </div>
      <ul className="divide-y border-t bg-card/60 text-xs">
        {result.contributions.map((c) => (
          <li key={c.provider} className="flex items-center gap-2 px-4 py-2">
            <ProviderLogo provider={p(c.provider)} size={20} />
            <span className="w-28 shrink-0 truncate font-medium">{p(c.provider).name}</span>
            <span className="min-w-0 flex-1 truncate text-muted-foreground" title={describeContribution(c)}>{describeContribution(c)}</span>
            <ReputationBadge value={c.reputation} />
          </li>
        ))}
      </ul>
    </motion.div>
  );
}
