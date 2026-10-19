import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion, Reorder, useDragControls } from "framer-motion";
import { ArrowRight, Database, GitBranch, Scale, GripVertical, Info, Pencil, Plus, RefreshCcw, Rss, Sparkles, Trash2, Wand2, Zap } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { PageHeader, ReputationBadge } from "@/components/bits";
import { RegionFlag } from "@/components/RegionFlag";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useConfirm } from "@/components/ui/confirm";
import { Modal } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty";
import { Field, Input } from "@/components/ui/input";
import { MultiSelect } from "@/components/ui/multi-select";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Segmented } from "@/components/ui/segmented";
import { Switch } from "@/components/ui/switch";
import { EnrichmentRulesPanel } from "@/components/EnrichmentRulesPanel";
import { NormalizationPanel } from "@/components/NormalizationPanel";
import { del, get, patch, post, put } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { feedIdOf, isFeedSource, useFeeds } from "@/lib/feeds";
import { severity, subTypeLabel, typeLabel, useMeta } from "@/lib/meta";
import type { Rule, RuleInput, RulePreview, Workspace } from "@/lib/types";
import { cn, errorMessage, fmt } from "@/lib/utils";

const EMPTY_RULE: RuleInput = {
  name: "",
  description: "",
  enabled: true,
  source_workspace_ids: [],
  target_workspace_ids: [],
  types: [],
  sub_types: [],
  min_reputation: null,
  sync_updates: true,
  priority_reputations: [],
};

function Chip({ children, tone = "solid" }: { children: React.ReactNode; tone?: "solid" | "muted" | "central" | "feed" }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium",
        tone === "solid" && "bg-card ring-1 ring-border",
        tone === "muted" && "bg-muted text-muted-foreground",
        tone === "central" && "bg-accent text-accent-foreground ring-1 ring-primary/20",
        tone === "feed" && "bg-card ring-1 ring-border ring-dashed",
      )}
    >
      {children}
    </span>
  );
}

function FlowArrow({ active }: { active: boolean }) {
  return (
    <div className="relative mx-1 flex h-6 w-16 shrink-0 items-center">
      <div className={cn("h-px w-full", active ? "bg-primary/40" : "bg-border")} />
      {active && (
        <motion.span
          className="absolute size-1.5 rounded-full bg-primary shadow-[0_0_8px_hsl(var(--primary))]"
          initial={{ left: "0%" }}
          animate={{ left: ["0%", "92%"] }}
          transition={{ duration: 1.6, repeat: Infinity, ease: "easeInOut" }}
        />
      )}
      <ArrowRight className={cn("absolute -right-1 size-3.5", active ? "text-primary" : "text-muted-foreground")} />
    </div>
  );
}

function RuleFlow({ rule, workspaces }: { rule: RuleInput; workspaces: Workspace[] }) {
  const feeds = useFeeds();
  const name = (id: number | string) =>
    id === "central"
      ? "Central (manual)"
      : isFeedSource(id)
        ? feeds.data?.find((f) => f.id === feedIdOf(id))?.name ?? "Feed"
        : workspaces.find((w) => w.id === id)?.name ?? `#${id}`;
  return (
    <div className="flex flex-wrap items-center gap-y-2">
      <div className="flex flex-wrap gap-1">
        {rule.source_workspace_ids.length === 0 ? (
          <Chip tone="muted">Any workspace</Chip>
        ) : (
          rule.source_workspace_ids.map((id) => (
            <Chip key={String(id)} tone={id === "central" ? "central" : isFeedSource(id) ? "feed" : "solid"}>
              {id === "central" ? (
                <Database className="size-3" />
              ) : isFeedSource(id) ? (
                <Rss className="size-3" />
              ) : (
                <RegionFlag region={workspaces.find((w) => w.id === id)?.region} height={9} />
              )}
              {name(id)}
            </Chip>
          ))
        )}
      </div>
      <FlowArrow active={rule.enabled} />
      <div className="flex flex-wrap gap-1">
        {rule.target_workspace_ids.length === 0 ? (
          <Chip tone="muted">All other workspaces</Chip>
        ) : (
          rule.target_workspace_ids.map((id) => (
            <Chip key={id}>
              <RegionFlag region={workspaces.find((w) => w.id === id)?.region} height={9} />
              {name(id)}
            </Chip>
          ))
        )}
      </div>
    </div>
  );
}

function RuleFilters({ rule }: { rule: RuleInput }) {
  const meta = useMeta();
  return (
    <div className="flex flex-wrap items-center gap-1.5 text-xs">
      {rule.types.length === 0 && rule.sub_types.length === 0 ? (
        <Badge tone="neutral">All observable types</Badge>
      ) : (
        <>
          {rule.types.map((t) => <Badge key={t} tone="primary">{typeLabel(t)}</Badge>)}
          {rule.sub_types.map((s) => <Badge key={s} tone="outline">{subTypeLabel(s, meta.data)} only</Badge>)}
        </>
      )}
      {rule.min_reputation && (
        <span className="inline-flex items-center gap-1 text-muted-foreground">
          · at least <ReputationBadge value={rule.min_reputation} />
        </span>
      )}
      <span className="text-muted-foreground">· {rule.sync_updates ? "creates & updates" : "creates only"}</span>
      {rule.priority_reputations?.length > 0 && (
        <span className="inline-flex flex-wrap items-center gap-1 text-muted-foreground">
          · <Zap className="size-3.5 text-warning" /> syncs immediately:
          {rule.priority_reputations.map((r) => <ReputationBadge key={r} value={r} />)}
        </span>
      )}
    </div>
  );
}

function RuleEditor({
  open,
  onOpenChange,
  initial,
  workspaces,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  initial: Rule | null;
  workspaces: Workspace[];
}) {
  const qc = useQueryClient();
  const meta = useMeta();
  const [draft, setDraft] = useState<RuleInput>(EMPTY_RULE);
  const minSeverity = draft.min_reputation ? severity(draft.min_reputation) : 1;
  const priorityOptions = [...(meta.data?.reputations ?? [])]
    .filter((r) => r.severity >= minSeverity)
    .sort((a, b) => b.severity - a.severity)
    .map((r) => ({ value: r.id, label: r.label }));
  useEffect(() => {
    const allowed = new Set(priorityOptions.map((o) => o.value));
    if (meta.data && draft.priority_reputations.some((r) => !allowed.has(r)))
      setDraft((d) => ({ ...d, priority_reputations: d.priority_reputations.filter((r) => allowed.has(r)) }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft.min_reputation, meta.data]);
  useEffect(() => {
    if (open) setDraft(initial ? { ...initial } : { ...EMPTY_RULE });
  }, [open, initial]);
  const set = <K extends keyof RuleInput>(k: K, v: RuleInput[K]) => setDraft((d) => ({ ...d, [k]: v }));

  const [debouncedDraft, setDebouncedDraft] = useState(draft);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedDraft(draft), 400);
    return () => clearTimeout(t);
  }, [draft]);
  const preview = useQuery({
    queryKey: ["rule-preview", "draft", debouncedDraft],
    queryFn: () => post<RulePreview>("/rules/preview", { rule: { ...debouncedDraft, name: debouncedDraft.name || "draft" } }),
    enabled: open,
  });

  const feeds = useFeeds();
  const sourceOptions = useMemo(
    () => [
      { value: "central" as number | string, label: "Central (manual & edited)" },
      ...workspaces.map((w) => ({ value: w.id as number | string, label: w.name })),
      ...(feeds.data ?? []).map((f) => ({ value: `feed:${f.id}` as number | string, label: f.name, hint: "STIX/TAXII feed" })),
    ],
    [workspaces, feeds.data],
  );
  const targetOptions = workspaces.map((w) => ({ value: w.id, label: w.name }));
  const typeOptions = (meta.data?.types ?? []).map((t) => ({ value: t.id, label: t.label }));
  const subTypeOptions = (meta.data?.sub_types ?? [])
    .filter((s) => s.type && (draft.types.length === 0 || draft.types.includes(s.type)))
    .map((s) => ({ value: s.id, label: s.label, hint: s.type ? typeLabel(s.type) : undefined }));

  const save = useMutation({
    mutationFn: () => (initial ? put<Rule>(`/rules/${initial.id}`, draft) : post<Rule>("/rules", draft)),
    onSuccess: () => {
      toast.success(initial ? "Rule updated" : "Rule created");
      qc.invalidateQueries({ queryKey: ["rules"] });
      qc.invalidateQueries({ queryKey: ["rule-preview"] });
      qc.invalidateQueries({ queryKey: ["dashboard-flows"] });
      onOpenChange(false);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={initial ? "Edit rule" : "New sync rule"}
      description="Choose where observables come from, where they may go, and which types qualify."
      className="max-w-2xl"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!draft.name.trim()}>
            {initial ? "Save rule" : "Create rule"}
          </Button>
        </>
      }
    >
      <div className="space-y-5">
        <div className="grid gap-4 sm:grid-cols-[1fr_auto]">
          <Field label="Name">
            <Input value={draft.name} onChange={(e) => set("name", e.target.value)} placeholder="e.g. Prod IPv4 → Dev & Staging" autoFocus />
          </Field>
          <Field label="Enabled">
            <div className="flex h-9 items-center">
              <Switch checked={draft.enabled} onCheckedChange={(v) => set("enabled", v)} aria-label="Enabled" />
            </div>
          </Field>
        </div>

        <div className="rounded-2xl border bg-muted/30 p-4">
          <div className="grid items-start gap-3 sm:grid-cols-[1fr_auto_1fr]">
            <Field label="From (sources)" hint="Where the observable was originally seen. Empty = any workspace or Central; feeds must be selected.">
              <MultiSelect
                options={sourceOptions}
                value={draft.source_workspace_ids}
                onChange={(v) => set("source_workspace_ids", v)}
                placeholder="Any workspace"
              />
            </Field>
            <div className="hidden pt-7 sm:block">
              <FlowArrow active />
            </div>
            <Field label="To (targets)" hint="Empty = every other workspace.">
              <MultiSelect options={targetOptions} value={draft.target_workspace_ids} onChange={(v) => set("target_workspace_ids", v)} placeholder="All other workspaces" />
            </Field>
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Observable types" hint="Empty = all types.">
            <MultiSelect options={typeOptions} value={draft.types} onChange={(v) => set("types", v)} placeholder="All types" />
          </Field>
          <Field label="Sub types" hint="e.g. restrict IPs to IPv4 only.">
            <MultiSelect options={subTypeOptions} value={draft.sub_types} onChange={(v) => set("sub_types", v)} placeholder="All sub types" />
          </Field>
          <Field label="Minimum reputation" hint="Only sync observables at least this severe.">
            <Select value={draft.min_reputation ?? ""} onChange={(e) => set("min_reputation", e.target.value || null)}>
              <option value="">No minimum</option>
              {[...(meta.data?.reputations ?? [])]
                .filter((r) => r.severity > 0)
                .sort((a, b) => a.severity - b.severity)
                .map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}
            </Select>
          </Field>
          <Field label="Propagate updates" hint="Also push reputation/description changes to existing copies.">
            <div className="flex h-9 items-center">
              <Switch checked={draft.sync_updates} onCheckedChange={(v) => set("sync_updates", v)} aria-label="Propagate updates" />
            </div>
          </Field>
        </div>

        <div className="rounded-2xl border p-4">
          <div className="mb-2 flex items-center gap-2 text-sm font-medium">
            <Zap className="size-4 text-warning" /> Priority sync
          </div>
          <Field
            label="Sync immediately when the reputation is"
            hint="When Beacon gives a matching observable one of these reputations (a manual edit, an API call or threat-intel normalization), a sync starts within seconds instead of waiting for the next interval. Observables first seen in a workspace are picked up by the next sync."
          >
            <MultiSelect
              options={priorityOptions}
              value={draft.priority_reputations}
              onChange={(v) => set("priority_reputations", v)}
              placeholder="None: wait for the sync interval"
            />
          </Field>
        </div>

        <motion.div layout className="flex items-start gap-3 rounded-2xl border border-primary/20 bg-gradient-to-br from-primary/10 to-transparent p-4">
          <Sparkles className="mt-0.5 size-4 shrink-0 text-primary" />
          <div className="min-w-0 flex-1 text-sm">
            <div className="font-medium">Impact preview</div>
            {preview.isLoading || !preview.data ? (
              <Skeleton className="mt-2 h-4 w-2/3" />
            ) : (
              <>
                <div className="text-muted-foreground">
                  On the next sync this rule alone would create{" "}
                  <span className="font-semibold text-foreground tabular">{fmt(preview.data.total_create)}</span> and update{" "}
                  <span className="font-semibold text-foreground tabular">{fmt(preview.data.total_update)}</span> observables.
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {preview.data.targets
                    .filter((t) => t.create || t.update)
                    .map((t) => (
                      <Badge key={t.workspace_id} tone="outline">
                        {t.workspace_name}: +{fmt(t.create)} / ~{fmt(t.update)}
                      </Badge>
                    ))}
                </div>
              </>
            )}
          </div>
        </motion.div>
      </div>
    </Modal>
  );
}

function RuleCard({
  rule,
  workspaces,
  editable,
  onEdit,
  onDelete,
  onToggle,
  onDragEnd,
}: {
  rule: Rule;
  workspaces: Workspace[];
  editable: boolean;
  onEdit: () => void;
  onDelete: () => void;
  onToggle: (v: boolean) => void;
  onDragEnd: () => void;
}) {
  const controls = useDragControls();
  return (
    <Reorder.Item
      value={rule}
      dragListener={false}
      dragControls={controls}
      onDragEnd={onDragEnd}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.98 }}
      whileDrag={{ scale: 1.01, boxShadow: "0 20px 40px -12px rgb(0 0 0 / 0.25)" }}
      className="list-none rounded-2xl"
    >
      <Card className={cn("group flex items-start gap-3 p-4 transition-opacity", !rule.enabled && "opacity-60")}>
        {editable && (
          <button
            onPointerDown={(e) => controls.start(e)}
            className="mt-1 cursor-grab touch-none rounded-md p-1 text-muted-foreground opacity-50 transition hover:bg-muted group-hover:opacity-100 active:cursor-grabbing"
            aria-label="Drag to reorder"
          >
            <GripVertical className="size-4" />
          </button>
        )}
        <div className="min-w-0 flex-1 space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-semibold">{rule.name}</h3>
            {!rule.enabled && <Badge tone="outline">Disabled</Badge>}
            {rule.description && <span className="truncate text-xs text-muted-foreground">{rule.description}</span>}
          </div>
          <RuleFlow rule={rule} workspaces={workspaces} />
          <RuleFilters rule={rule} />
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <Switch checked={rule.enabled} onCheckedChange={onToggle} disabled={!editable} aria-label="Enable rule" />
          {editable && (
            <>
              <Button variant="ghost" size="icon-sm" onClick={onEdit} aria-label="Edit rule" className="ml-2">
                <Pencil />
              </Button>
              <Button variant="ghost" size="icon-sm" onClick={onDelete} aria-label="Delete rule" className="text-destructive hover:bg-destructive/10">
                <Trash2 />
              </Button>
            </>
          )}
        </div>
      </Card>
    </Reorder.Item>
  );
}

export default function RulesPage() {
  const qc = useQueryClient();
  const { can } = useAuth();
  const confirm = useConfirm();
  const editable = can("admin");
  const rulesQ = useQuery({ queryKey: ["rules"], queryFn: () => get<Rule[]>("/rules") });
  const wsQ = useQuery({ queryKey: ["workspaces"], queryFn: () => get<Workspace[]>("/workspaces") });
  const previewQ = useQuery({ queryKey: ["rule-preview", "all", rulesQ.data], queryFn: () => post<RulePreview>("/rules/preview", {}), enabled: !!rulesQ.data });
  const [order, setOrder] = useState<Rule[]>([]);
  const orderRef = useRef<Rule[]>([]);
  const [editing, setEditing] = useState<Rule | null>(null);
  const [editorOpen, setEditorOpen] = useState(false);
  const workspaces = wsQ.data ?? [];
  const [params, setParams] = useSearchParams();
  const viewParam = params.get("view");
  const view = viewParam === "normalization" || viewParam === "enrichment" ? viewParam : "sync";
  const [newEnrichmentRule, setNewEnrichmentRule] = useState(0);

  useEffect(() => {
    if (rulesQ.data) {
      setOrder(rulesQ.data);
      orderRef.current = rulesQ.data;
    }
  }, [rulesQ.data]);

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["rules"] });
    qc.invalidateQueries({ queryKey: ["rule-preview"] });
    qc.invalidateQueries({ queryKey: ["dashboard-flows"] });
  };

  const persistOrder = () => {
    const ids = orderRef.current.map((r) => r.id);
    if (JSON.stringify(ids) === JSON.stringify(rulesQ.data?.map((r) => r.id))) return;
    post("/rules/reorder", { ids }).then(refresh).catch((e) => toast.error(errorMessage(e)));
  };

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => patch(`/rules/${id}/enabled?enabled=${enabled}`),
    onMutate: ({ id, enabled }) => setOrder((o) => o.map((r) => (r.id === id ? { ...r, enabled } : r))),
    onSettled: refresh,
    onError: (e) => toast.error(errorMessage(e)),
  });

  const remove = async (rule: Rule) => {
    if (!(await confirm({ title: `Delete “${rule.name}”?`, description: "Observables already synced stay in their workspaces.", confirmLabel: "Delete", destructive: true }))) return;
    try {
      await del(`/rules/${rule.id}`);
      toast.success("Rule deleted");
      refresh();
    } catch (e) {
      toast.error(errorMessage(e));
    }
  };

  return (
    <>
      <PageHeader
        title="Rules"
        description={
          view === "sync"
            ? "Control the direction of observable synchronization between workspaces"
            : view === "enrichment"
              ? "Automatically enrich new observables with your threat-intel integrations"
              : "Normalize threat-intel enrichment from multiple sources into one Torq reputation"
        }
        actions={
          editable && view === "sync" ? (
            <Button onClick={() => { setEditing(null); setEditorOpen(true); }} disabled={workspaces.length === 0}>
              <Plus /> New rule
            </Button>
          ) : editable && view === "enrichment" ? (
            <Button onClick={() => setNewEnrichmentRule((n) => n + 1)}>
              <Plus /> New enrichment rule
            </Button>
          ) : null
        }
      />
      <Segmented
        className="mb-5"
        value={view}
        onChange={(v) => setParams(v === "sync" ? {} : { view: v }, { replace: true })}
        options={[
          { value: "sync", label: <><GitBranch /> Sync rules</> },
          { value: "enrichment", label: <><Wand2 /> Enrichment rules</> },
          { value: "normalization", label: <><Scale /> Reputation normalization</> },
        ]}
      />

      {view === "normalization" ? (
        <NormalizationPanel />
      ) : view === "enrichment" ? (
        <EnrichmentRulesPanel newRuleSignal={newEnrichmentRule} />
      ) : (
      <>

      <div className="mb-5 grid gap-4 lg:grid-cols-[1fr_340px]">
        <Card className="flex gap-3 p-4 text-sm">
          <Info className="mt-0.5 size-4 shrink-0 text-primary" />
          <div className="space-y-1 text-muted-foreground">
            <p>
              Rules are an <span className="font-medium text-foreground">allow-list</span>. Every workspace feeds the central database,
              but observables are only pushed to a workspace when a rule allows it. With no rules, nothing is pushed.
            </p>
            <p>
              Sources match the workspace where an observable was <span className="font-medium text-foreground">originally</span> seen, so
              copies synced into a workspace never cascade further. Choose <span className="font-medium text-foreground">Central</span> as a source to distribute manually created or edited observables.
            </p>
          </div>
        </Card>
        <Card className="flex items-center gap-4 p-4">
          <div className="grid size-10 shrink-0 place-items-center rounded-xl bg-accent text-accent-foreground">
            <RefreshCcw className="size-5" />
          </div>
          <div className="text-sm">
            <div className="font-medium">Pending on next sync</div>
            {previewQ.data ? (
              <div className="text-muted-foreground tabular">
                {fmt(previewQ.data.total_create)} to create · {fmt(previewQ.data.total_update)} to update
              </div>
            ) : (
              <Skeleton className="mt-1 h-4 w-40" />
            )}
          </div>
        </Card>
      </div>

      {rulesQ.isLoading ? (
        <div className="space-y-3">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-32 rounded-2xl" />)}</div>
      ) : order.length === 0 ? (
        <Card>
          <EmptyState
            icon={<GitBranch />}
            title="No sync rules yet"
            description={workspaces.length === 0 ? "Connect at least one workspace in Settings before creating rules." : "Create a rule to start distributing observables between workspaces."}
            action={editable && workspaces.length > 0 && <Button onClick={() => { setEditing(null); setEditorOpen(true); }}><Plus /> New rule</Button>}
          />
        </Card>
      ) : (
        <Reorder.Group
          axis="y"
          values={order}
          onReorder={(o) => {
            setOrder(o);
            orderRef.current = o;
          }}
          className="space-y-3"
        >
          <AnimatePresence initial={false}>
            {order.map((rule) => (
              <RuleCard
                key={rule.id}
                rule={rule}
                workspaces={workspaces}
                editable={editable}
                onEdit={() => { setEditing(rule); setEditorOpen(true); }}
                onDelete={() => remove(rule)}
                onToggle={(enabled) => toggle.mutate({ id: rule.id, enabled })}
                onDragEnd={persistOrder}
              />
            ))}
          </AnimatePresence>
        </Reorder.Group>
      )}
      </>
      )}

      <RuleEditor open={editorOpen} onOpenChange={setEditorOpen} initial={editing} workspaces={workspaces} />
    </>
  );
}
