import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  ArrowRight,
  ArrowUpRight,
  Braces,
  Eye,
  FileText,
  History,
  MinusCircle,
  Pin,
  PinOff,
  PlusCircle,
  RefreshCw,
  Rss,
  Server,
  ShieldAlert,
  Sparkles,
  TrendingDown,
  TrendingUp,
  type LucideIcon,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import { get } from "@/lib/api";
import { severity } from "@/lib/meta";
import type { ObservableEvent } from "@/lib/types";
import { cn, formatDate, timeAgo } from "@/lib/utils";
import { ReputationBadge } from "./bits";
import { EmptyState } from "./ui/empty";
import { Segmented } from "./ui/segmented";
import { Skeleton } from "./ui/skeleton";
import { Tooltip } from "./ui/tooltip";

type Filter = "all" | "reputation" | "workspaces" | "enrichment";

const FILTER_KINDS: Record<Exclude<Filter, "all">, ObservableEvent["kind"][]> = {
  reputation: ["created", "reputation_changed", "workspace_reputation_changed", "description_changed", "pinned", "unpinned"],
  workspaces: ["created", "seen_in_workspace", "pushed_to_workspace", "updated_in_workspace", "removed_from_workspace", "seen_in_feed", "removed_from_feed"],
  enrichment: ["enrichment_added", "enrichment_updated", "enrichment_removed", "intel_enriched"],
};

const STRATEGY_LABEL: Record<string, string> = {
  highest_severity: "highest severity wins",
  most_recent: "most recent wins",
  workspace_priority: "workspace priority",
};

const NORM_STRATEGY_LABEL: Record<string, string> = {
  highest_severity: "Most severe source",
  lowest_severity: "Least severe source",
  most_common: "Most common opinion",
  priority: "Source priority",
};

const Ws = ({ name }: { name: string }) => (
  <span className="rounded-md bg-muted px-1.5 py-0.5 text-[12px] font-medium text-foreground">{name || "a workspace"}</span>
);
/** Actors: usernames, "api:<key>", or "rule:<enrichment rule>" for rule-driven lookups. */
export const actorLabel = (actor: string) => (actor.startsWith("rule:") ? `rule “${actor.slice(5)}”` : actor);
const Who = ({ actor }: { actor: string }) => <span className="font-medium text-foreground">{actorLabel(actor)}</span>;

function RepChange({ from, to }: { from: string | null; to: string | null }) {
  if (!to) return null;
  const delta = severity(to) - severity(from ?? "SCORE_UNKNOWN");
  const Trend = delta > 0 ? TrendingUp : delta < 0 ? TrendingDown : ArrowRight;
  return (
    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
      {from && <ReputationBadge value={from} />}
      {from && (
        <Trend
          className={cn("size-3.5", delta > 0 ? "text-destructive" : delta < 0 ? "text-[var(--rep-2)]" : "text-muted-foreground")}
          aria-label={delta > 0 ? "more severe" : delta < 0 ? "less severe" : "changed"}
        />
      )}
      <ReputationBadge value={to} />
    </div>
  );
}

function TextChange({ from, to }: { from: string | null; to: string | null }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mt-1">
      <button onClick={() => setOpen(!open)} className="text-xs font-medium text-primary hover:underline">
        {open ? "Hide change" : "Show change"}
      </button>
      {open && (
        <div className="mt-1.5 grid gap-1.5 text-xs">
          <div className="whitespace-pre-wrap break-words rounded-lg border border-destructive/20 bg-destructive/5 p-2 line-through decoration-destructive/40">
            {from || <span className="italic text-muted-foreground no-underline">(empty)</span>}
          </div>
          <div className="whitespace-pre-wrap break-words rounded-lg border border-success/20 bg-success/5 p-2">
            {to || <span className="italic text-muted-foreground">(empty)</span>}
          </div>
        </div>
      )}
    </div>
  );
}

interface Rendered {
  icon: LucideIcon;
  tone: string;
  title: ReactNode;
  body?: ReactNode;
}

function render(e: ObservableEvent): Rendered {
  const d = e.detail;
  switch (e.kind) {
    case "created":
      if (d.backfilled)
        return {
          icon: History,
          tone: "bg-muted text-muted-foreground",
          title: <>Present in Beacon{e.workspace_name && <> from <Ws name={e.workspace_name} /></>}</>,
          body: <p className="mt-1 text-xs text-muted-foreground">Recorded when change tracking was enabled; earlier history is not available.</p>,
        };
      if (d.origin === "feed")
        return { icon: Rss, tone: "bg-primary/15 text-primary", title: <>Added from feed <Ws name={String(d.feed_name ?? "")} /></>, body: <RepChange from={null} to={e.new_value} /> };
      return d.origin === "manual"
        ? { icon: PlusCircle, tone: "bg-primary/15 text-primary", title: <>Created manually by <Who actor={e.actor} /></>, body: <RepChange from={null} to={e.new_value} /> }
        : { icon: PlusCircle, tone: "bg-primary/15 text-primary", title: <>First seen in <Ws name={e.workspace_name} /></>, body: <RepChange from={null} to={e.new_value} /> };
    case "seen_in_feed":
      return {
        icon: Rss,
        tone: "bg-sky-500/15 text-sky-600 dark:text-sky-400",
        title: <>Listed by feed <Ws name={String(d.feed_name ?? "")} /></>,
        body: (
          <>
            <RepChange from={null} to={e.new_value} />
            {d.pinned && <p className="mt-1 text-xs text-muted-foreground">Not applied: this observable is centrally edited.</p>}
          </>
        ),
      };
    case "removed_from_feed":
      return {
        icon: Rss,
        tone: "bg-muted text-muted-foreground",
        title: <>No longer listed by feed <Ws name={String(d.feed_name ?? "")} /></>,
        body: d.reason ? <p className="mt-1 text-xs text-muted-foreground">{String(d.reason).replace(/^./, (c) => c.toUpperCase())}</p> : undefined,
      };
    case "seen_in_workspace":
      return { icon: Eye, tone: "bg-sky-500/15 text-sky-600 dark:text-sky-400", title: <>Also observed in <Ws name={e.workspace_name} /></>, body: d.backfilled ? undefined : <RepChange from={null} to={e.new_value} /> };
    case "pushed_to_workspace":
      return { icon: ArrowUpRight, tone: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400", title: <>Synced to <Ws name={e.workspace_name} /></>, body: d.backfilled ? undefined : <RepChange from={null} to={e.new_value} /> };
    case "updated_in_workspace": {
      const ch = (d.changes ?? {}) as Record<string, { old: string; new: string }>;
      return {
        icon: RefreshCw,
        tone: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400",
        title: <>Pushed update to <Ws name={e.workspace_name} /></>,
        body: (
          <>
            {ch.reputation && <RepChange from={ch.reputation.old} to={ch.reputation.new} />}
            {ch.description && (
              <>
                <p className="mt-1 text-xs text-muted-foreground">Description updated</p>
                <TextChange from={ch.description.old} to={ch.description.new} />
              </>
            )}
          </>
        ),
      };
    }
    case "removed_from_workspace":
      return {
        icon: MinusCircle,
        tone: "bg-amber-500/15 text-amber-600 dark:text-amber-400",
        title: <>Removed from <Ws name={e.workspace_name} />{e.actor !== "sync" && <> by <Who actor={e.actor} /></>}</>,
        body: d.reason && <p className="mt-1 text-xs text-muted-foreground">{String(d.reason).replace(/^./, (c) => c.toUpperCase())}</p>,
      };
    case "workspace_reputation_changed":
      return {
        icon: Server,
        tone: "bg-sky-500/15 text-sky-600 dark:text-sky-400",
        title: <><Ws name={e.workspace_name} /> changed its verdict</>,
        body: (
          <>
            <RepChange from={e.old_value} to={e.new_value} />
            {d.pinned && <p className="mt-1 text-xs text-muted-foreground">Not applied to central: this observable is centrally edited.</p>}
          </>
        ),
      };
    case "reputation_changed":
    case "description_changed": {
      const what = e.kind === "reputation_changed" ? "Reputation" : "Description";
      const from = e.workspace_name && <> from <Ws name={e.workspace_name} /></>;
      const title =
        d.cause === "manual" ? <>{what} edited by <Who actor={e.actor} /></>
        : d.cause === "revert" ? <>{what} reverted to the workspace value{from} by <Who actor={e.actor} /></>
        : d.cause === "workspace_change" ? <>{what} updated from a change in <Ws name={e.workspace_name} /></>
        : d.cause === "strategy_change" ? <>{what} re-resolved after <Who actor={e.actor} /> changed the collision strategy</>
        : d.cause === "normalization" ? <>{what} set by threat-intel normalization{e.actor && e.actor !== "sync" && <> (<Who actor={e.actor} />)</>}</>
        : d.cause === "feed" ? <>{what} set by feed <Ws name={String(d.feed_name ?? "")} /></>
        : d.cause === "feed_removed" ? <>{what} restored after leaving feed <Ws name={String(d.feed_name ?? "")} /></>
        : <>{what} changed by collision merge{from}</>;
      const body =
        e.kind === "reputation_changed" ? <RepChange from={e.old_value} to={e.new_value} /> : <TextChange from={e.old_value} to={e.new_value} />;
      const note = d.cause === "normalization"
        ? <p className="mt-1 text-xs text-muted-foreground">{NORM_STRATEGY_LABEL[d.strategy] ?? d.strategy} across {(d.providers ?? []).join(", ") || "enrichment sources"}</p>
        : !d.cause || d.cause === "merge" || d.cause === "strategy_change"
        ? <p className="mt-1 text-xs text-muted-foreground">Strategy: {STRATEGY_LABEL[d.strategy] ?? d.strategy}</p>
        : null;
      return e.kind === "reputation_changed"
        ? { icon: ShieldAlert, tone: "bg-destructive/15 text-destructive", title, body: <>{body}{note}</> }
        : { icon: FileText, tone: "bg-muted text-muted-foreground", title, body: <>{body}{note}</> };
    }
    case "pinned":
      return { icon: Pin, tone: "bg-primary/15 text-primary", title: d.cause === "normalization" ? <>Marked centrally authoritative by threat-intel normalization</> : <>Marked centrally authoritative by <Who actor={e.actor} /></>, body: <p className="mt-1 text-xs text-muted-foreground">Workspace values no longer overwrite this observable.</p> };
    case "unpinned":
      return { icon: PinOff, tone: "bg-muted text-muted-foreground", title: <>Central edits reverted by <Who actor={e.actor} /></> };
    case "enrichment_added":
      return { icon: Braces, tone: "bg-violet-500/15 text-violet-600 dark:text-violet-400", title: <>Enrichment added in <Ws name={e.workspace_name} /></> };
    case "enrichment_updated":
      return {
        icon: Braces,
        tone: "bg-violet-500/15 text-violet-600 dark:text-violet-400",
        title: <>Enrichment refreshed in <Ws name={e.workspace_name} /></>,
        body: e.old_value && <p className="mt-1 text-xs text-muted-foreground">Previously updated {formatDate(e.old_value)}</p>,
      };
    case "intel_enriched": {
      const verdict = String(e.new_value ?? "unknown");
      const tone = verdict === "malicious" ? "bg-destructive/15 text-destructive" : verdict === "suspicious" ? "bg-amber-500/15 text-amber-600 dark:text-amber-400" : "bg-violet-500/15 text-violet-600 dark:text-violet-400";
      return {
        icon: Sparkles,
        tone,
        title: <>Enriched via {String(d.provider_name ?? d.provider)}{e.actor && e.actor !== "sync" && <> by <Who actor={e.actor} /></>}</>,
        body: <p className="mt-1 text-xs text-muted-foreground">{String(d.headline ?? "")}{d.status === "not_found" ? "" : ` · verdict: ${verdict}`}</p>,
      };
    }
    case "enrichment_removed":
      return { icon: Braces, tone: "bg-muted text-muted-foreground", title: <>Enrichment removed in <Ws name={e.workspace_name} /></> };
    default:
      return { icon: History, tone: "bg-muted text-muted-foreground", title: String(e.kind).replace(/_/g, " ") };
  }
}

function dayLabel(iso: string | null) {
  if (!iso) return "Unknown date";
  const d = new Date(iso);
  const today = new Date();
  const yesterday = new Date(Date.now() - 86400000);
  if (d.toDateString() === today.toDateString()) return "Today";
  if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
  return d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric" });
}

export function ObservableTimeline({ id }: { id: number }) {
  const [filter, setFilter] = useState<Filter>("all");
  const q = useQuery({
    queryKey: ["observable-history", id],
    queryFn: () => get<{ items: ObservableEvent[]; total: number }>(`/observables/${id}/history?limit=1000`),
  });

  const all = q.data?.items ?? [];
  const items = filter === "all" ? all : all.filter((e) => FILTER_KINDS[filter].includes(e.kind));
  const groups: { day: string; events: ObservableEvent[] }[] = [];
  for (const e of items) {
    const day = dayLabel(e.ts);
    if (groups.at(-1)?.day !== day) groups.push({ day, events: [] });
    groups.at(-1)!.events.push(e);
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Segmented
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all", label: "All" },
            { value: "reputation", label: "Reputation" },
            { value: "workspaces", label: "Sources" },
            { value: "enrichment", label: "Enrichment" },
          ]}
        />
        {q.data && <span className="text-xs text-muted-foreground tabular">{items.length} of {q.data.total} events</span>}
      </div>

      {q.isLoading ? (
        <div className="space-y-3">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-14" />)}</div>
      ) : items.length === 0 ? (
        <EmptyState icon={<History />} title="No events" description={filter === "all" ? "Nothing has happened to this observable yet." : "No events of this kind."} />
      ) : (
        <div className="space-y-5">
          {groups.map((g) => (
            <section key={g.day}>
              <h5 className="sticky top-0 z-10 -mx-1 mb-2 bg-popover/90 px-1 py-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground backdrop-blur">
                {g.day}
              </h5>
              <ol className="relative ml-3.5 border-l">
                {g.events.map((e, i) => {
                  const r = render(e);
                  const Icon = r.icon;
                  return (
                    <motion.li
                      key={e.id}
                      initial={{ opacity: 0, x: -6 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: Math.min(i * 0.03, 0.3) }}
                      className="relative pb-4 pl-6 last:pb-0"
                    >
                      <span className={cn("absolute -left-3.5 top-0 grid size-7 place-items-center rounded-full ring-4 ring-popover", r.tone)}>
                        <Icon className="size-3.5" />
                      </span>
                      <div className="text-sm leading-6">{r.title}</div>
                      {r.body}
                      <div className="mt-1 flex flex-wrap items-center gap-x-2 text-[11px] text-muted-foreground">
                        <Tooltip content={formatDate(e.ts)}>
                          <span>{new Date(e.ts ?? "").toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })} · {timeAgo(e.ts)}</span>
                        </Tooltip>
                        {e.run_id && <span>· sync run #{e.run_id}</span>}
                        {e.detail.backfilled && e.kind !== "created" && <span>· time approximate</span>}
                        {e.actor === "sync" && !e.run_id && !e.detail.backfilled && <span>· sync</span>}
                      </div>
                    </motion.li>
                  );
                })}
              </ol>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
