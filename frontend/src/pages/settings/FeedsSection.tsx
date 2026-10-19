import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { CheckCircle2, Copy, Download, List, Loader2, Pencil, Plug, Plus, RefreshCw, Rss, Share2, Trash2, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { ReputationBadge } from "@/components/bits";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { useConfirmWithOption } from "@/components/ui/confirm";
import { removalOption, type DeleteImpact } from "@/components/SourceRemoval";
import { Modal } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { MultiSelect } from "@/components/ui/multi-select";
import { Segmented } from "@/components/ui/segmented";
import { Select } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { del, get, patch, post, put } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useFeeds } from "@/lib/feeds";
import { useMeta } from "@/lib/meta";
import type { Feed, FeedInput, TaxiiCollection, TaxiiServerConfig, Workspace } from "@/lib/types";
import { cn, errorMessage, fmt, timeAgo } from "@/lib/utils";

const POLL_OPTIONS = [
  [15, "Every 15 minutes"],
  [30, "Every 30 minutes"],
  [60, "Every hour"],
  [360, "Every 6 hours"],
  [720, "Every 12 hours"],
  [1440, "Every day"],
] as const;

const LIST_TYPES: { value: Feed["list_type"]; label: string; badge: string; placeholder: string }[] = [
  { value: "ip", label: "IP addresses", badge: "IP list", placeholder: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" },
  { value: "url", label: "URLs", badge: "URL list", placeholder: "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt" },
  { value: "domain", label: "Domains", badge: "Domain list", placeholder: "https://example.com/bad-domains.txt" },
  { value: "auto", label: "Auto-detect (mixed)", badge: "Mixed list", placeholder: "https://example.com/iocs.txt" },
];

export const feedKindLabel = (f: Pick<Feed, "kind" | "list_type">) =>
  f.kind === "text_list" ? LIST_TYPES.find((t) => t.value === f.list_type)?.badge ?? "Threat list" : f.kind === "taxii21" ? "TAXII 2.1" : "STIX URL";

const EMPTY: FeedInput = {
  name: "", kind: "taxii21", url: "", collection_id: "", list_type: "auto", auth: "none", username: "", secret: null, header_name: "",
  poll_minutes: 60, initial_lookback_days: 30, max_age_days: 0, default_reputation: "SCORE_MALICIOUS", min_confidence: 0,
  enrich_new: false, enabled: true,
};

function invalidate(qc: ReturnType<typeof useQueryClient>) {
  ["feeds", "dashboard-flows", "rules"].forEach((k) => qc.invalidateQueries({ queryKey: [k] }));
}

function RepSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const meta = useMeta();
  return (
    <Select value={value} onChange={(e) => onChange(e.target.value)}>
      {[...(meta.data?.reputations ?? [])].sort((a, b) => b.severity - a.severity).map((r) => (
        <option key={r.id} value={r.id}>{r.label}</option>
      ))}
    </Select>
  );
}

// ---- Feed dialog ------------------------------------------------------------------------------------------

function FeedDialog({ open, onOpenChange, initial }: { open: boolean; onOpenChange: (o: boolean) => void; initial: Feed | null }) {
  const qc = useQueryClient();
  const [draft, setDraft] = useState<FeedInput>(EMPTY);
  const [collections, setCollections] = useState<TaxiiCollection[] | null>(null);
  const [test, setTest] = useState<{ ok: boolean; message: string } | null>(null);
  useEffect(() => {
    if (!open) return;
    setDraft(initial ? { ...initial, secret: null } : EMPTY);
    setCollections(null);
    setTest(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, initial?.id]);
  const set = <K extends keyof FeedInput>(k: K, v: FeedInput[K]) => {
    setDraft((d) => ({ ...d, [k]: v }));
    setTest(null);
  };
  const probe = () => ({
    kind: draft.kind, url: draft.url, collection_id: draft.collection_id, list_type: draft.list_type, auth: draft.auth, username: draft.username,
    secret: draft.secret, header_name: draft.header_name, feed_id: initial?.id ?? null,
  });

  const loadCollections = useMutation({
    mutationFn: () => post<TaxiiCollection[]>("/feeds/collections", probe()),
    onSuccess: (cols) => {
      setCollections(cols);
      if (cols.length && !cols.some((c) => c.id === draft.collection_id)) set("collection_id", cols.find((c) => c.can_read)?.id ?? cols[0].id);
      if (!cols.length) toast.message("The server lists no collections");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const testM = useMutation({
    mutationFn: () => post<{ ok: boolean; message: string }>("/feeds/test", probe()),
    onSuccess: setTest,
    onError: (e) => setTest({ ok: false, message: errorMessage(e) }),
  });
  const save = useMutation({
    mutationFn: () => (initial ? put(`/feeds/${initial.id}`, draft) : post("/feeds", draft)),
    onSuccess: () => {
      toast.success(initial ? "Feed updated" : "Feed added: first poll started");
      invalidate(qc);
      onOpenChange(false);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  const taxii = draft.kind === "taxii21";
  const textList = draft.kind === "text_list";
  const listType = LIST_TYPES.find((t) => t.value === draft.list_type) ?? LIST_TYPES[3];
  const valid = draft.name.trim() && /^https?:\/\//i.test(draft.url.trim()) && (!taxii || draft.collection_id);
  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={initial ? `Edit ${initial.name}` : "Add threat feed"}
      description="Observables from the feed are added to the central database. They reach workspaces only through sync rules that name the feed."
      className="max-w-2xl"
      footer={
        <>
          <Button variant="outline" className="mr-auto" onClick={() => testM.mutate()} loading={testM.isPending} disabled={!/^https?:\/\//i.test(draft.url.trim())}>
            <Plug /> Test
          </Button>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!valid}>{initial ? "Save feed" : "Add feed"}</Button>
        </>
      }
    >
      <div className="space-y-5">
        <div className="grid gap-4 sm:grid-cols-[1fr_auto]">
          <Field label="Name">
            <Input value={draft.name} onChange={(e) => set("name", e.target.value)} placeholder={textList ? "e.g. Emerging Threats compromised IPs" : "e.g. CISA AIS"} autoFocus maxLength={64} />
          </Field>
          <Field label="Type">
            <Segmented
              value={draft.kind}
              onChange={(v) => set("kind", v)}
              options={[{ value: "taxii21", label: "TAXII 2.1" }, { value: "stix_url", label: "STIX bundle" }, { value: "text_list", label: "Text list" }]}
            />
          </Field>
        </div>
        {textList ? (
          <div className="grid gap-4 sm:grid-cols-[1fr_200px]">
            <Field label="List URL" hint="A plain-text file with one value per line. Comments (#, ;, //) and blank lines are ignored.">
              <Input value={draft.url} onChange={(e) => set("url", e.target.value)} placeholder={listType.placeholder} className="font-mono" />
            </Field>
            <Field label="List contains">
              <Select value={draft.list_type} onChange={(e) => set("list_type", e.target.value as Feed["list_type"])}>
                {LIST_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
              </Select>
            </Field>
          </div>
        ) : (
          <Field label={taxii ? "TAXII server or API root URL" : "STIX bundle URL"} hint={taxii ? "A discovery URL (…/taxii2/) or an API root (…/api1/)." : "A JSON STIX 2.x bundle; the whole file is re-read on each poll (only when it changed)."}>
            <Input value={draft.url} onChange={(e) => set("url", e.target.value)} placeholder={taxii ? "https://taxii.example.com/taxii2/" : "https://feeds.example.com/indicators.json"} className="font-mono" />
          </Field>
        )}

        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Authentication">
            <Select value={draft.auth} onChange={(e) => set("auth", e.target.value as FeedInput["auth"])}>
              <option value="none">None</option>
              <option value="basic">Username & password</option>
              <option value="header">API key header</option>
            </Select>
          </Field>
          {draft.auth === "basic" && (
            <>
              <Field label="Username"><Input value={draft.username} onChange={(e) => set("username", e.target.value)} autoComplete="off" /></Field>
              <Field label="Password">
                <Input type="password" value={draft.secret ?? ""} onChange={(e) => set("secret", e.target.value)} autoComplete="new-password" placeholder={initial?.secret_set ? "Stored: leave blank to keep" : ""} />
              </Field>
            </>
          )}
          {draft.auth === "header" && (
            <>
              <Field label="Header name"><Input value={draft.header_name} onChange={(e) => set("header_name", e.target.value)} placeholder="Authorization" className="font-mono" /></Field>
              <Field label="Header value">
                <Input type="password" value={draft.secret ?? ""} onChange={(e) => set("secret", e.target.value)} autoComplete="new-password" placeholder={initial?.secret_set ? "Stored: leave blank to keep" : "e.g. Bearer abc…"} />
              </Field>
            </>
          )}
        </div>

        {taxii && (
          <Field label="Collection">
            <div className="flex gap-2">
              {collections ? (
                <Select value={draft.collection_id} onChange={(e) => set("collection_id", e.target.value)} className="flex-1">
                  {collections.map((c) => <option key={c.id} value={c.id} disabled={!c.can_read}>{c.title}{c.can_read ? "" : " (no read access)"}</option>)}
                </Select>
              ) : (
                <Input value={draft.collection_id} onChange={(e) => set("collection_id", e.target.value)} placeholder="Collection id" className="flex-1 font-mono" />
              )}
              <Button variant="outline" onClick={() => loadCollections.mutate()} loading={loadCollections.isPending} disabled={!/^https?:\/\//i.test(draft.url.trim())}>
                {!loadCollections.isPending && <Download />} Load collections
              </Button>
            </div>
          </Field>
        )}

        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Poll">
            <Select value={String(draft.poll_minutes)} onChange={(e) => set("poll_minutes", Number(e.target.value))}>
              {POLL_OPTIONS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </Select>
          </Field>
          <Field label={textList ? "Reputation for listed observables" : "Default reputation"} hint={textList ? "Also applied to observables already in Beacon." : "Refined by STIX hints (benign, anomalous, malicious)."}>
            <RepSelect value={draft.default_reputation} onChange={(v) => set("default_reputation", v)} />
          </Field>
          {!textList && (
            <Field label="Minimum confidence" hint="0–100; indicators below are skipped.">
              <Input type="number" min={0} max={100} value={draft.min_confidence} onChange={(e) => set("min_confidence", Math.max(0, Math.min(100, Number(e.target.value))))} />
            </Field>
          )}
          {taxii && (
            <Field label="First poll looks back" hint="Days of history on the first poll.">
              <Input type="number" min={0} max={3650} value={draft.initial_lookback_days} onChange={(e) => set("initial_lookback_days", Number(e.target.value))} />
            </Field>
          )}
          {!textList && (
            <Field label="Retire after (days)" hint="Stop listing indicators not seen for this long. 0 = until revoked/expired.">
              <Input type="number" min={0} max={3650} value={draft.max_age_days} onChange={(e) => set("max_age_days", Number(e.target.value))} />
            </Field>
          )}
        </div>

        <div className="flex flex-wrap gap-6">
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={draft.enrich_new} onCheckedChange={(v) => set("enrich_new", v)} aria-label="Enrich new observables" />
            Run enrichment rules on new observables from this feed
          </label>
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={draft.enabled} onCheckedChange={(v) => set("enabled", v)} aria-label="Enabled" />
            Enabled
          </label>
        </div>
        {textList && (
          <div className="rounded-xl border bg-muted/30 p-3 text-xs text-muted-foreground">
            On each update only the <span className="font-medium text-foreground">changes</span> are applied: values new to the list are added (or, if already in Beacon,
            set to this reputation), values still listed are left alone, and values that drop off the list get back the reputation they had before
            (observables the list created go back to Unknown), unless someone changed them since. Centrally edited observables are never changed.
          </div>
        )}
        <p className="text-xs text-muted-foreground">
          Duplicates are never created: a value that's already in Beacon (from a workspace, another feed or created by hand) is matched by type and normalized value, and the feed is recorded on it.
        </p>
        <AnimatePresence>
          {test && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }}>
              <div className={cn("flex items-start gap-2 rounded-xl border p-3 text-sm", test.ok ? "border-success/30 bg-success/10 text-success" : "border-destructive/30 bg-destructive/10 text-destructive")}>
                {test.ok ? <CheckCircle2 className="mt-0.5 size-4 shrink-0" /> : <XCircle className="mt-0.5 size-4 shrink-0" />}
                <span className="break-words">{test.message}</span>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </Modal>
  );
}

// ---- Feeds list -------------------------------------------------------------------------------------------

function FeedCard({ feed, onEdit }: { feed: Feed; onEdit: () => void }) {
  const qc = useQueryClient();
  const confirmWithOption = useConfirmWithOption();
  const { can } = useAuth();
  const admin = can("admin");
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => patch(`/feeds/${feed.id}/enabled?enabled=${enabled}`),
    onSettled: () => invalidate(qc),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const poll = useMutation({
    mutationFn: () => post<{ started: boolean; message?: string }>(`/feeds/${feed.id}/poll`),
    onSuccess: (r) => (r.started ? toast.success(`Polling ${feed.name}…`) : toast.message(r.message ?? "Already polling")),
    onSettled: () => invalidate(qc),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const st = feed.stats;
  return (
    <Card className={cn("flex flex-col p-5", !feed.enabled && "opacity-75")}>
      <div className="flex items-start gap-3">
        <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-foreground/80 text-background">
          {feed.kind === "text_list" ? <List className="size-5" /> : <Rss className="size-5" />}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-semibold">{feed.name}</h3>
            <Badge tone="outline">{feedKindLabel(feed)}</Badge>
            {feed.polling ? (
              <Badge tone="primary"><Loader2 className="size-3 animate-spin" /> Polling</Badge>
            ) : feed.last_status === "error" ? (
              <Badge tone="danger">Error</Badge>
            ) : feed.last_status === "ok" ? (
              <Badge tone="success">OK</Badge>
            ) : null}
          </div>
          <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground" title={feed.url}>{feed.url}</p>
        </div>
        {admin && <Switch checked={feed.enabled} onCheckedChange={(v) => toggle.mutate(v)} aria-label={`Enable ${feed.name}`} />}
      </div>
      <div className="mt-4 grid grid-cols-3 gap-2 text-center">
        {(feed.kind === "text_list"
          ? [
              ["Listed now", feed.listed],
              ["Added last update", (st.created ?? 0) + (st.linked ?? 0)],
              ["Removed last update", st.deactivated ?? 0],
            ]
          : [
              ["Listed now", feed.listed],
              ["New last poll", st.created ?? 0],
              ["Matched existing", (st.linked ?? 0) + (st.escalated ?? 0)],
            ]
        ).map(([label, v]) => (
          <div key={label as string} className="rounded-xl bg-muted/40 p-2">
            <div className="text-lg font-semibold tabular">{fmt(v as number)}</div>
            <div className="text-[11px] text-muted-foreground">{label}</div>
          </div>
        ))}
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
        <span>Default <ReputationBadge value={feed.default_reputation} /></span>
        <span>· {POLL_OPTIONS.find(([v]) => v === feed.poll_minutes)?.[1].toLowerCase() ?? `every ${feed.poll_minutes} min`}</span>
        <span>· last poll {feed.last_poll_at ? timeAgo(feed.last_poll_at) : "never"}</span>
      </div>
      {feed.last_status === "error" && feed.last_error && <p className="mt-2 line-clamp-2 text-xs text-destructive/80" title={feed.last_error}>{feed.last_error}</p>}
      <div className="mt-auto flex items-center gap-2 pt-4">
        {can("edit") && (
          <Button size="sm" variant="subtle" onClick={() => poll.mutate()} loading={poll.isPending || feed.polling} disabled={!feed.enabled}>
            {!(poll.isPending || feed.polling) && <RefreshCw />} Poll now
          </Button>
        )}
        {admin && (
          <>
            <Button size="sm" variant="ghost" onClick={onEdit}><Pencil /> Edit</Button>
            <div className="flex-1" />
            <Button
              size="icon-sm"
              variant="ghost"
              className="text-destructive hover:bg-destructive/10"
              aria-label={`Remove ${feed.name}`}
              onClick={async () => {
                const impact = await get<DeleteImpact>(`/feeds/${feed.id}/delete-impact`).catch(() => null);
                const choice = await confirmWithOption({
                  title: `Remove ${feed.name}?`,
                  description: "Polling stops and the feed is removed from sync rules (rules left without a source are disabled).",
                  confirmLabel: "Remove", destructive: true,
                  option: removalOption(impact, "feed"),
                });
                if (!choice.confirmed) return;
                try {
                  await del(`/feeds/${feed.id}${choice.option ? "?remove_observables=true" : ""}`);
                  toast.success(choice.option && impact ? `${feed.name} removed with ${fmt(impact.observables)} observable(s)` : `${feed.name} removed`);
                  qc.invalidateQueries({ queryKey: ["observables"] });
                  invalidate(qc);
                } catch (e) {
                  toast.error(errorMessage(e));
                }
              }}
            >
              <Trash2 />
            </Button>
          </>
        )}
      </div>
    </Card>
  );
}

// ---- TAXII server -----------------------------------------------------------------------------------------

function CopyField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="mb-1 text-[11px] font-medium text-muted-foreground">{label}</div>
      <div className="flex items-center gap-1 rounded-lg border bg-muted/30 py-1 pl-2.5 pr-1">
        <code className="min-w-0 flex-1 truncate text-xs">{value}</code>
        <Button size="icon-sm" variant="ghost" aria-label={`Copy ${label}`} onClick={() => navigator.clipboard.writeText(value).then(() => toast.success("Copied"))}>
          <Copy />
        </Button>
      </div>
    </div>
  );
}

function TaxiiServerCard() {
  const qc = useQueryClient();
  const meta = useMeta();
  const { can } = useAuth();
  const admin = can("admin");
  const feeds = useFeeds();
  const ws = useQuery({ queryKey: ["workspaces"], queryFn: () => get<Workspace[]>("/workspaces") });
  const q = useQuery({ queryKey: ["taxii-server"], queryFn: () => get<TaxiiServerConfig>("/feeds/taxii-server") });
  const [draft, setDraft] = useState<TaxiiServerConfig | null>(null);
  useEffect(() => {
    if (q.data) setDraft(q.data);
  }, [q.data]);
  const save = useMutation({
    mutationFn: (body: TaxiiServerConfig) => put<TaxiiServerConfig>("/feeds/taxii-server", body),
    onSuccess: (cfg) => {
      qc.setQueryData(["taxii-server"], cfg);
      toast.success(cfg.enabled ? "TAXII server settings saved" : "TAXII server disabled");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  if (!draft || !q.data) return null;
  const origin = window.location.origin;
  const dirty = JSON.stringify(draft) !== JSON.stringify(q.data);
  const sourceOptions = [
    { value: "central" as number | string, label: "Central (manual & edited)" },
    ...(ws.data ?? []).map((w) => ({ value: w.id as number | string, label: w.name })),
    ...(feeds.data ?? []).map((f) => ({ value: `feed:${f.id}` as number | string, label: f.name, hint: "Feed" })),
  ];
  return (
    <Card>
      <CardHeader
        title={<span className="inline-flex items-center gap-2"><Share2 className="size-4 text-primary" /> Beacon TAXII server {q.data.enabled ? <Badge tone="success">On</Badge> : <Badge tone="outline">Off</Badge>}</span>}
        description="Publish Beacon's observables as a read-only TAXII 2.1 collection of STIX indicators for SIEMs, firewalls and other TIPs."
        action={admin && <Switch checked={draft.enabled} onCheckedChange={(v) => setDraft({ ...draft, enabled: v })} aria-label="Enable TAXII server" />}
      />
      <CardBody className="space-y-4">
        <div className="grid gap-3 md:grid-cols-2">
          <CopyField label="Discovery URL" value={`${origin}${q.data.discovery_path}`} />
          <CopyField label="Collection objects URL" value={`${origin}${q.data.objects_path}`} />
        </div>
        <div className="grid gap-4 md:grid-cols-3">
          <Field label="Publish observables at least">
            <Select value={draft.min_reputation} onChange={(e) => setDraft({ ...draft, min_reputation: e.target.value })} disabled={!admin}>
              {[...(meta.data?.reputations ?? [])].filter((r) => r.severity > 0).sort((a, b) => b.severity - a.severity).map((r) => <option key={r.id} value={r.id}>{r.label}</option>)}
            </Select>
          </Field>
          <Field label="Types" hint="Empty = all types with a STIX pattern.">
            <MultiSelect options={(meta.data?.types ?? []).map((t) => ({ value: t.id, label: t.label }))} value={draft.types} onChange={(v) => setDraft({ ...draft, types: v })} placeholder="All types" />
          </Field>
          <Field label="Sources" hint="Empty = everything in Beacon.">
            <MultiSelect options={sourceOptions} value={draft.sources} onChange={(v) => setDraft({ ...draft, sources: v })} placeholder="All sources" />
          </Field>
        </div>
        <div className="rounded-xl bg-muted/40 p-3 text-xs text-muted-foreground">
          Authenticate with an API key from <span className="font-medium text-foreground">Settings → API</span> (the Viewer role is enough), sent as{" "}
          <code className="rounded bg-muted px-1">Authorization: Bearer tim_…</code> or as HTTP Basic with any username and the key as the password.
          Downgraded and deleted observables are published as revoked to clients that poll with <code className="rounded bg-muted px-1">added_after</code>.
        </div>
        {admin && dirty && (
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => setDraft(q.data!)}>Discard</Button>
            <Button size="sm" onClick={() => save.mutate(draft)} loading={save.isPending}>Save</Button>
          </div>
        )}
      </CardBody>
    </Card>
  );
}

// ---- Section ----------------------------------------------------------------------------------------------

export function FeedsSection() {
  const { can } = useAuth();
  const feeds = useFeeds();
  const [editing, setEditing] = useState<Feed | null>(null);
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-10 space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-base font-semibold"><Rss className="size-4" /> Threat feeds</h3>
          <p className="text-sm text-muted-foreground">Ingest observables from TAXII 2.1 collections, STIX 2.x bundles and plain-text threat lists (IPs, URLs, domains).</p>
        </div>
        {can("admin") && (
          <Button onClick={() => { setEditing(null); setOpen(true); }}><Plus /> Add feed</Button>
        )}
      </div>
      {feeds.data && feeds.data.length === 0 ? (
        <Card className="p-6 text-center text-sm text-muted-foreground">
          No feeds yet. Add a TAXII 2.1 collection (e.g. CISA AIS, MISP, OpenCTI), a STIX bundle URL, or a text list such as OpenPhish or Emerging Threats.
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
          {(feeds.data ?? []).map((f) => <FeedCard key={f.id} feed={f} onEdit={() => { setEditing(f); setOpen(true); }} />)}
        </div>
      )}
      <TaxiiServerCard />
      <FeedDialog open={open} onOpenChange={setOpen} initial={editing} />
    </div>
  );
}
