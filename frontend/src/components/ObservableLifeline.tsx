import { useQuery } from "@tanstack/react-query";
import { Rss } from "lucide-react";
import { motion } from "framer-motion";
import { useCallback, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import { ReputationBadge } from "@/components/bits";
import { actorLabel } from "@/components/ObservableTimeline";
import { WorkspaceName } from "@/components/RegionFlag";
import { Segmented } from "@/components/ui/segmented";
import { Skeleton } from "@/components/ui/skeleton";
import { get } from "@/lib/api";
import { repColor, repLabel } from "@/lib/meta";
import type { Observable, ObservableEvent } from "@/lib/types";
import { formatDate } from "@/lib/utils";

type Range = "all" | "1y" | "90d" | "30d" | "7d";
const RANGE_MS: Record<Exclude<Range, "all">, number> = { "1y": 365 * 864e5, "90d": 90 * 864e5, "30d": 30 * 864e5, "7d": 7 * 864e5 };

const LABEL_W = 148;
const ROW_H = 30;
const AXIS_H = 26;
const MILESTONE_H = 22;
const PAD_R = 14;

interface Marker {
  t: number;
  shape: "dot" | "diamond";
  color: string;
  title: ReactNode;
  body?: ReactNode;
}
interface Segment {
  from: number;
  to: number;
  rep?: string;
  fill?: string;
  faded?: boolean;
  striped?: boolean;
  title: ReactNode;
  body?: ReactNode;
}
interface Lane {
  key: string;
  label: ReactNode;
  segments: Segment[];
  markers: Marker[];
  band?: boolean;
}

const ts = (iso: string | null | undefined) => (iso ? new Date(iso.endsWith("Z") || iso.includes("+") ? iso : `${iso}Z`).getTime() : NaN);

function ticks(start: number, end: number, width: number) {
  const span = end - start;
  const target = Math.max(2, Math.floor(width / 110));
  const DAY = 864e5;
  const steps: [number, "day" | "month" | "year", Intl.DateTimeFormatOptions][] = [
    [1, "day", { month: "short", day: "numeric" }],
    [2, "day", { month: "short", day: "numeric" }],
    [7, "day", { month: "short", day: "numeric" }],
    [14, "day", { month: "short", day: "numeric" }],
    [1, "month", { month: "short", year: "2-digit" }],
    [3, "month", { month: "short", year: "2-digit" }],
    [6, "month", { month: "short", year: "numeric" }],
    [1, "year", { year: "numeric" }],
  ];
  const approx = (n: number, unit: string) => n * (unit === "day" ? DAY : unit === "month" ? 30.4 * DAY : 365 * DAY);
  const [n, unit, fmt] = steps.find(([n, u]) => span / approx(n, u) <= target) ?? steps[steps.length - 1];
  const out: { t: number; label: string }[] = [];
  const d = new Date(start);
  if (unit === "day") d.setHours(0, 0, 0, 0);
  else if (unit === "month") { d.setHours(0, 0, 0, 0); d.setDate(1); d.setMonth(d.getMonth() - (d.getMonth() % n)); }
  else { d.setHours(0, 0, 0, 0); d.setMonth(0, 1); }
  for (let i = 0; i < 400 && d.getTime() <= end; i++) {
    if (d.getTime() >= start) out.push({ t: d.getTime(), label: d.toLocaleDateString(undefined, fmt) });
    if (unit === "day") d.setDate(d.getDate() + n);
    else if (unit === "month") d.setMonth(d.getMonth() + n);
    else d.setFullYear(d.getFullYear() + n);
  }
  return out;
}

function useWidth<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const ro = useRef<ResizeObserver | null>(null);
  const [w, setW] = useState(0);
  // Callback ref: the element mounts only after the history has loaded.
  const setRef = useCallback((el: T | null) => {
    ro.current?.disconnect();
    ref.current = el;
    if (el) {
      ro.current = new ResizeObserver(([e]) => setW(e.contentRect.width));
      ro.current.observe(el);
    }
  }, []);
  return [ref, setRef, w] as const;
}

/** Build the lanes: central reputation band, then one lane per workspace. */
function buildLanes(o: Observable, events: ObservableEvent[], regionOf: (id: number) => string | undefined, now: number) {
  const asc = [...events].filter((e) => e.ts).sort((a, b) => ts(a.ts) - ts(b.ts) || a.id - b.id);
  const trackedFrom = asc.length ? ts(asc[0].ts) : now;
  const firstSeen = [ts(o.first_observed_at), ts(o.created_at), trackedFrom].filter((x) => !Number.isNaN(x)).reduce((a, b) => Math.min(a, b), now);

  // Central reputation: walk reputation changes forward from the earliest known value.
  const repChanges = asc.filter((e) => e.kind === "reputation_changed");
  const created = asc.find((e) => e.kind === "created");
  const initial = repChanges[0]?.old_value ?? created?.new_value ?? o.reputation;
  const band: Segment[] = [];
  let cur = initial;
  let at = firstSeen;
  if (trackedFrom > firstSeen + 1) {
    band.push({ from: firstSeen, to: trackedFrom, rep: cur, faded: true, title: <>Before change tracking</>, body: <>Earliest recorded reputation <ReputationBadge value={cur} />. Changes before {formatDate(new Date(trackedFrom).toISOString())} weren't tracked.</> });
    at = trackedFrom;
  }
  const centralMarkers: Marker[] = [];
  for (const e of repChanges) {
    const t = ts(e.ts);
    if (t > at) band.push({ from: at, to: t, rep: cur, title: repLabel(cur) });
    cur = e.new_value ?? cur;
    at = Math.max(at, t);
    const cause = e.detail?.cause;
    centralMarkers.push({
      t,
      shape: "dot",
      color: repColor(cur),
      title: <>Reputation {cause === "normalization" ? "set by normalization" : cause === "manual" ? `edited by ${e.actor}` : cause === "workspace_change" ? `updated from ${e.workspace_name}` : "changed"}</>,
      body: <span className="inline-flex items-center gap-1"><ReputationBadge value={e.old_value ?? "SCORE_UNKNOWN"} /> → <ReputationBadge value={e.new_value ?? "SCORE_UNKNOWN"} /></span>,
    });
  }
  band.push({ from: at, to: now, rep: cur, title: repLabel(cur) });
  for (const e of asc.filter((e) => e.kind === "intel_enriched")) {
    centralMarkers.push({ t: ts(e.ts), shape: "diamond", color: "var(--chart-ink)", title: <>Enriched via {String(e.detail?.provider_name ?? e.detail?.provider)}{e.actor?.startsWith("rule:") && <> by {actorLabel(e.actor)}</>}</>, body: e.detail?.headline ? String(e.detail.headline) : undefined });
  }
  const lanes: Lane[] = [{ key: "central", label: <span className="font-medium">Central reputation</span>, segments: band, markers: centralMarkers, band: true }];

  // Workspaces: presence from the first event that ties the observable to the workspace, colored by the
  // workspace's own verdict over time. Synced-in copies are striped.
  for (const l of o.links) {
    const wsEvents = asc.filter((e) => e.workspace_id === l.workspace_id);
    const join = wsEvents.find((e) => ["created", "seen_in_workspace", "pushed_to_workspace"].includes(e.kind));
    const native = l.relation === "origin";
    const how = native ? "Native in workspace" : "Synced in by Beacon";
    // The workspace's verdict changes: edits made in the workspace, and reputation updates Beacon pushed to it.
    const verdictChanges = wsEvents.flatMap((e) => {
      if (e.kind === "workspace_reputation_changed") return [{ t: ts(e.ts), old: e.old_value, new: e.new_value, pushed: false }];
      const ch = e.kind === "updated_in_workspace" ? e.detail?.changes?.reputation : null;
      return ch ? [{ t: ts(e.ts), old: ch.old as string | null, new: ch.new as string | null, pushed: true }] : [];
    });
    let rep = verdictChanges[0]?.old ?? join?.new_value ?? l.remote_reputation ?? "SCORE_UNKNOWN";
    const removed = wsEvents.find((e) => e.kind === "removed_from_workspace");
    const joinedAt = join ? ts(join.ts) : trackedFrom;
    const endAt = removed ? ts(removed.ts) : now;
    const segments: Segment[] = [];
    if ((!join || join.detail?.backfilled) && native && firstSeen < joinedAt) {
      // Present before tracking began: we only know it was there by then.
      segments.push({ from: firstSeen, to: joinedAt, rep, faded: true, title: <>{how} (before tracking)</>, body: <>Present by {formatDate(new Date(joinedAt).toISOString())}; the exact date isn't known.</> });
    }
    let at = joinedAt;
    for (const c of verdictChanges) {
      if (c.t > at) segments.push({ from: at, to: c.t, rep, striped: !native, title: how });
      rep = c.new ?? rep;
      at = Math.max(at, c.t);
    }
    segments.push({ from: at, to: endAt, rep, striped: !native, title: how, body: removed ? <>Removed {formatDate(removed.ts)}</> : undefined });
    const markers: Marker[] = verdictChanges.map((c) => ({
      t: c.t,
      shape: "dot",
      color: repColor(c.new ?? ""),
      title: c.pushed ? <>Beacon pushed a new verdict to {l.workspace_name}</> : <>Verdict changed in {l.workspace_name}</>,
      body: <span className="inline-flex items-center gap-1"><ReputationBadge value={c.old ?? "SCORE_UNKNOWN"} /> → <ReputationBadge value={c.new ?? "SCORE_UNKNOWN"} /></span>,
    }));
    markers.push(...wsEvents.flatMap((e): Marker[] => {
      const t = ts(e.ts);
      if (e.kind === "enrichment_added" || e.kind === "enrichment_updated")
        return [{ t, shape: "diamond", color: "var(--chart-ink)", title: <>Enrichment {e.kind === "enrichment_added" ? "added" : "refreshed"} in {l.workspace_name}</> }];
      return [];
    }));
    lanes.push({ key: `ws:${l.workspace_id}`, label: <WorkspaceName name={l.workspace_name} region={regionOf(l.workspace_id)} className="truncate" />, segments, markers });
  }
  // Feeds: one lane per feed, from first listing until it stopped (or now), colored by the feed's verdict.
  const byFeed = new Map<number, NonNullable<Observable["feeds"]>>();
  for (const f of o.feeds ?? []) byFeed.set(f.feed_id, [...(byFeed.get(f.feed_id) ?? []), f]);
  for (const [feedId, rows] of byFeed) {
    const name = rows[0].feed_name;
    const start = Math.min(...rows.map((r) => ts(r.first_seen_at)).filter((t) => !Number.isNaN(t)));
    const active = rows.some((r) => r.active);
    const end = active ? now : Math.max(...rows.map((r) => ts(r.last_seen_at)).filter((t) => !Number.isNaN(t)));
    const rep = rows.find((r) => r.active)?.reputation ?? rows[0].reputation;
    if (!Number.isFinite(start)) continue;
    const markers: Marker[] = asc
      .filter((e) => (e.kind === "seen_in_feed" || e.kind === "removed_from_feed" || (e.kind === "created" && e.detail?.origin === "feed")) && e.detail?.feed_id === feedId)
      .map((e) => ({
        t: ts(e.ts),
        shape: "dot",
        color: e.kind === "removed_from_feed" ? "var(--chart-axis)" : repColor(e.new_value ?? rep),
        title: e.kind === "removed_from_feed" ? <>No longer listed by {name}</> : <>Listed by {name}</>,
        body: e.kind === "removed_from_feed" ? (e.detail?.reason ? String(e.detail.reason) : undefined) : e.new_value ? <ReputationBadge value={e.new_value} /> : undefined,
      }));
    lanes.push({
      key: `feed:${feedId}`,
      label: <span className="inline-flex min-w-0 items-center gap-1 truncate"><Rss className="size-3 shrink-0 text-muted-foreground" />{name}</span>,
      segments: [{ from: start, to: Math.max(end, start + 1), rep, faded: !active, title: <>Listed by {name}</>, body: active ? undefined : <>Listing ended {formatDate(new Date(end).toISOString())}</> }],
      markers,
    });
  }
  return { lanes, firstSeen, trackedFrom };
}

export function ObservableLifeline({ obs, regionOf }: { obs: Observable; regionOf: (id: number) => string | undefined }) {
  const q = useQuery({
    queryKey: ["observable-history", obs.id],
    queryFn: () => get<{ items: ObservableEvent[]; total: number }>(`/observables/${obs.id}/history?limit=1000`),
  });
  const [range, setRange] = useState<Range>("all");
  const stripeId = `stripes-${useId().replace(/:/g, "")}`;
  const [ref, setRef, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<{ x: number; y: number; content: ReactNode } | null>(null);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(t);
  }, []);

  const built = useMemo(() => (q.data ? buildLanes(obs, q.data.items, regionOf, now) : null), [q.data, obs, regionOf, now]);

  if (!built) return <Skeleton className="h-40 rounded-xl" />;
  const { lanes, firstSeen, trackedFrom } = built;
  const lifetime = now - firstSeen;
  const start = range === "all" ? firstSeen - lifetime * 0.01 : now - RANGE_MS[range];
  const end = now + (now - start) * 0.012;
  const plotW = Math.max(0, width - LABEL_W - PAD_R);
  const x = (t: number) => LABEL_W + ((Math.min(Math.max(t, start), end) - start) / (end - start)) * plotW;
  const inRange = (t: number) => t >= start && t <= end;
  const height = MILESTONE_H + lanes.length * ROW_H + AXIS_H;
  const laneY = (i: number) => MILESTONE_H + i * ROW_H;

  const milestones = [
    { t: ts(obs.first_observed_at), label: "First observed" },
    { t: ts(obs.created_at), label: "Added to Beacon" },
    { t: ts(obs.last_observed_at), label: "Last observed" },
  ].filter((m) => !Number.isNaN(m.t));
  const tip = (e: React.MouseEvent, content: ReactNode) => {
    const box = ref.current!.getBoundingClientRect();
    setHover({ x: e.clientX - box.left, y: e.clientY - box.top, content });
  };
  const ranges: { value: Range; label: string }[] = [
    { value: "all", label: "Lifetime" },
    ...(lifetime > RANGE_MS["1y"] ? [{ value: "1y" as const, label: "1 year" }] : []),
    ...(lifetime > RANGE_MS["90d"] ? [{ value: "90d" as const, label: "90d" }] : []),
    ...(lifetime > RANGE_MS["30d"] ? [{ value: "30d" as const, label: "30d" }] : []),
    { value: "7d", label: "7d" },
  ];
  // Change history only exists since tracking began; offer a zoom when that's a sliver of the lifetime.
  const zoomTo = range === "all" && now - trackedFrom < lifetime * 0.08
    ? ranges.find((r) => r.value !== "all" && RANGE_MS[r.value as Exclude<Range, "all">] >= (now - trackedFrom) * 1.1 && RANGE_MS[r.value as Exclude<Range, "all">] < lifetime)?.value
      ?? null
    : null;
  const ago = (ms: number) => {
    const d = Math.floor(ms / 864e5);
    return d >= 730 ? `${Math.floor(d / 365)} years` : d >= 60 ? `${Math.floor(d / 30.4)} months` : d >= 1 ? `${d} day${d === 1 ? "" : "s"}` : "less than a day";
  };

  return (
    <div className="rounded-xl border p-4">
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <h4 className="text-sm font-semibold">Lifetime</h4>
          <p className="text-xs text-muted-foreground">
            First observed {ago(now - firstSeen)} ago · {obs.links.length} workspace{obs.links.length === 1 ? "" : "s"}
            {lanes.length - 1 > obs.links.length && <> · {lanes.length - 1 - obs.links.length} feed{lanes.length - 2 - obs.links.length === 0 ? "" : "s"}</>}
            {zoomTo && (
              <>
                {" · "}
                <button onClick={() => setRange(zoomTo)} className="font-medium text-primary hover:underline">
                  Zoom to tracked activity ({ago(now - trackedFrom)})
                </button>
              </>
            )}
          </p>
        </div>
        <Segmented value={range} onChange={setRange} options={ranges} className="[&_button]:px-2.5 [&_button]:py-1 [&_button]:text-xs" />
      </div>
      <div ref={setRef} className="relative" onMouseLeave={() => setHover(null)}>
        {width > 0 && (
          <svg width={width} height={height} role="img" aria-label={`Lifetime of ${obs.value} from first observed to now`} className="block overflow-visible">
            <defs>
              <pattern id={stripeId} width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                <rect width="2" height="5" fill="var(--chart-surface)" fillOpacity="0.75" />
              </pattern>
            </defs>
            {/* Grid + axis */}
            {ticks(start, end, plotW).map((tk) => (
              <g key={tk.t}>
                <line x1={x(tk.t)} x2={x(tk.t)} y1={MILESTONE_H} y2={height - AXIS_H} stroke="var(--chart-grid)" />
                <text x={x(tk.t)} y={height - 8} textAnchor="middle" fontSize={11} fill="var(--chart-axis)">{tk.label}</text>
              </g>
            ))}
            <line x1={LABEL_W} x2={LABEL_W + plotW} y1={height - AXIS_H} y2={height - AXIS_H} stroke="var(--chart-axis)" strokeOpacity={0.5} />

            {/* Tracking boundary */}
            {inRange(trackedFrom) && trackedFrom - firstSeen > (end - start) * 0.01 && (
              <g>
                <line x1={x(trackedFrom)} x2={x(trackedFrom)} y1={MILESTONE_H - 4} y2={height - AXIS_H} stroke="var(--chart-axis)" strokeDasharray="3 3" />
              </g>
            )}

            {/* Lanes */}
            {lanes.map((lane, i) => {
              const y = laneY(i);
              const barH = lane.band ? 14 : 8;
              const cy = y + ROW_H / 2;
              return (
                <g key={lane.key}>
                  {i > 0 && <line x1={0} x2={LABEL_W + plotW} y1={y} y2={y} stroke="var(--chart-grid)" strokeOpacity={0.6} />}
                  <foreignObject x={0} y={y} width={LABEL_W - 10} height={ROW_H}>
                    <div className="flex h-full items-center text-xs text-foreground">{lane.label}</div>
                  </foreignObject>
                  {lane.segments
                    .filter((s) => s.to >= start && s.from <= end)
                    .map((s, k) => {
                      const x0 = x(s.from);
                      const w = Math.max(2, x(s.to) - x0 - (lane.band ? 2 : 0));
                      const fill = s.rep ? repColor(s.rep) : s.fill!;
                      const show = (e: React.MouseEvent) =>
                        tip(e, (
                          <>
                            <div className="flex flex-wrap items-center gap-1.5 font-medium">
                              {s.rep && <ReputationBadge value={s.rep} />}
                              {(!s.rep || s.title !== repLabel(s.rep)) && <span>{s.title}</span>}
                            </div>
                            <div className="mt-0.5 text-muted-foreground">
                              {s.body ?? <>{formatDate(new Date(s.from).toISOString())} → {s.to >= now - 1 ? "now" : formatDate(new Date(s.to).toISOString())}</>}
                            </div>
                          </>
                        ));
                      return (
                        <g key={`${k}-${range}`} onMouseMove={show}>
                          <motion.rect
                            x={x0}
                            y={cy - barH / 2}
                            height={barH}
                            rx={lane.band ? 4 : barH / 2}
                            fill={fill}
                            fillOpacity={s.faded ? 0.3 : 1}
                            stroke={s.faded ? fill : "none"}
                            strokeDasharray={s.faded ? "3 2" : undefined}
                            initial={{ width: 0 }}
                            animate={{ width: w }}
                            transition={{ duration: 0.5, delay: k * 0.04, ease: "easeOut" }}
                          />
                          {s.striped && (
                            <motion.rect
                              x={x0}
                              y={cy - barH / 2}
                              height={barH}
                              rx={barH / 2}
                              fill={`url(#${stripeId})`}
                              initial={{ width: 0 }}
                              animate={{ width: w }}
                              transition={{ duration: 0.5, delay: k * 0.04, ease: "easeOut" }}
                            />
                          )}
                          <rect x={x0} y={cy - ROW_H / 2 + 3} width={w} height={ROW_H - 6} fill="transparent" />
                        </g>
                      );
                    })}
                  {lane.markers.filter((m) => inRange(m.t)).map((m, k) => {
                    const mx = x(m.t);
                    const handlers = {
                      onMouseMove: (e: React.MouseEvent) =>
                        tip(e, (
                          <>
                            <div className="font-medium">{m.title}</div>
                            {m.body && <div className="mt-1">{m.body}</div>}
                            <div className="mt-0.5 text-muted-foreground">{formatDate(new Date(m.t).toISOString())}</div>
                          </>
                        )),
                    };
                    return (
                      <g key={k} {...handlers} className="cursor-default">
                        <circle cx={mx} cy={cy} r={10} fill="transparent" />
                        {m.shape === "dot" ? (
                          <circle cx={mx} cy={cy} r={5} fill={m.color} stroke="var(--chart-surface)" strokeWidth={2} />
                        ) : (
                          <rect x={mx - 4.5} y={cy - 4.5} width={9} height={9} transform={`rotate(45 ${mx} ${cy})`} fill={m.color} stroke="var(--chart-surface)" strokeWidth={2} />
                        )}
                      </g>
                    );
                  })}
                </g>
              );
            })}

            {/* Milestones */}
            {milestones.filter((m) => inRange(m.t)).map((m) => (
              <g key={m.label} onMouseMove={(e) => tip(e, <><div className="font-medium">{m.label}</div><div className="text-muted-foreground">{formatDate(new Date(m.t).toISOString())}</div></>)}>
                <line x1={x(m.t)} x2={x(m.t)} y1={6} y2={height - AXIS_H} stroke="var(--chart-ink)" strokeOpacity={0.35} />
                <path d={`M${x(m.t) - 5},4 L${x(m.t) + 5},4 L${x(m.t)},11 Z`} fill="var(--chart-ink)" />
                <rect x={x(m.t) - 8} y={0} width={16} height={MILESTONE_H - 4} fill="transparent" />
              </g>
            ))}
            {/* Now */}
            <g>
              <line x1={x(now)} x2={x(now)} y1={6} y2={height - AXIS_H} className="stroke-primary" strokeWidth={2} />
              <text x={x(now)} y={10} textAnchor="end" dx={-5} fontSize={10} fontWeight={600} className="fill-primary">Now</text>
            </g>
          </svg>
        )}
        {hover && (
          <div
            className="pointer-events-none absolute z-20 max-w-[280px] rounded-lg border bg-popover px-3 py-2 text-xs shadow-lg"
            style={{ left: Math.min(hover.x + 14, Math.max(0, width - 290)), top: hover.y + 14 }}
          >
            {hover.content}
          </div>
        )}
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
        <span>Color = reputation</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-2 w-4 rounded-full bg-muted-foreground/70" /> Native in workspace</span>
        <span className="inline-flex items-center gap-1.5">
          <svg width="16" height="8" aria-hidden><rect width="16" height="8" rx="4" className="fill-muted-foreground/70" /><rect width="16" height="8" rx="4" fill={`url(#${stripeId})`} /></svg>
          Synced in by Beacon
        </span>
        <span className="inline-flex items-center gap-1.5"><span className="h-2 w-4 rounded-full border border-dashed border-muted-foreground/60 bg-muted-foreground/20" /> Before change tracking</span>
        <span className="inline-flex items-center gap-1.5"><span className="size-2 rounded-full bg-muted-foreground/70" /> Reputation change</span>
        <span className="inline-flex items-center gap-1.5"><span className="size-2 rotate-45 bg-[var(--chart-ink)]" /> Enrichment</span>
        <span className="inline-flex items-center gap-1.5"><span className="h-0 w-0 border-x-[5px] border-t-[7px] border-x-transparent border-t-[var(--chart-ink)]" /> Milestone</span>
      </div>
    </div>
  );
}
