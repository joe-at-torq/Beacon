import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { animate, AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { ArrowRight, Database as DatabaseIcon, HelpCircle, List as ListIcon, Rss as RssIcon, Loader2, Maximize2, Network, Pause, Play, Table2, X, ZoomIn, ZoomOut } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { get, qs } from "@/lib/api";
import { usePreferences, useSavePreference } from "@/lib/preferences";
import { useSyncStatus } from "@/lib/sync";
import { repLabel, subTypeLabel, typeLabel, useMeta } from "@/lib/meta";
import type { FlowCentralNode, FlowEdge, FlowFeedNode, FlowGraphData, FlowRule, FlowWorkspaceNode } from "@/lib/types";
import { cn, fmt } from "@/lib/utils";
import { SyncStatusPill } from "./bits";
import { RegionFlag, WorkspaceName } from "./RegionFlag";
import { Card, CardHeader } from "./ui/card";
import { EmptyState } from "./ui/empty";
import { MultiSelect } from "./ui/multi-select";
import { Segmented } from "./ui/segmented";
import { Skeleton } from "./ui/skeleton";
import { Switch } from "./ui/switch";
import { Tooltip } from "./ui/tooltip";

const MIN_HEIGHT = 260;
const PANEL_WIDTH = 288;
const MIN_ZOOM = 0.4;
const MAX_ZOOM = 4;
type View = { k: number; x: number; y: number };
const IDENTITY: View = { k: 1, x: 0, y: 0 };
const CENTRAL = "central";
const CAT_SLOTS = 8;

type Pt = { x: number; y: number };
type Hover =
  | { kind: "edge"; edge: FlowEdge; x: number; y: number }
  | { kind: "node"; id: string; x: number; y: number }
  | { kind: "spoke"; ws: FlowWorkspaceNode; x: number; y: number }
  | { kind: "feed-spoke"; feed: FlowFeedNode; x: number; y: number }
  | null;

type AnyNode = FlowWorkspaceNode | FlowCentralNode | FlowFeedNode;
const FEED_COLOR = "var(--chart-ink)";

// Text halo in the surface color keeps labels legible over lines.
const HALO = { paintOrder: "stroke" as const, stroke: "var(--chart-surface)", strokeWidth: 4, strokeLinejoin: "round" as const };

const isFeed = (n: AnyNode): n is FlowFeedNode => (n as FlowFeedNode).kind === "feed";
const isWs = (n: AnyNode): n is FlowWorkspaceNode => n.id !== CENTRAL && !isFeed(n);
const edgeKey = (e: { source: string; target: string }) => `${e.source}>${e.target}`;
const sub = (a: Pt, b: Pt) => ({ x: a.x - b.x, y: a.y - b.y });
const len = (v: Pt) => Math.hypot(v.x, v.y) || 1;
const unit = (v: Pt) => ({ x: v.x / len(v), y: v.y / len(v) });
const along = (from: Pt, dir: Pt, d: number) => ({ x: from.x + dir.x * d, y: from.y + dir.y * d });
const quad = (p0: Pt, c: Pt, p2: Pt, t: number) => ({
  x: (1 - t) ** 2 * p0.x + 2 * (1 - t) * t * c.x + t ** 2 * p2.x,
  y: (1 - t) ** 2 * p0.y + 2 * (1 - t) * t * c.y + t ** 2 * p2.y,
});

function useSize<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([entry]) =>
      setSize({ width: entry.contentRect.width, height: entry.contentRect.height }),
    );
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, size] as const;
}

function ruleSummary(rule: FlowRule, meta: ReturnType<typeof useMeta>["data"]) {
  const parts: string[] = [];
  if (rule.types.length) parts.push(rule.types.map(typeLabel).join(", "));
  if (rule.sub_types.length) parts.push(rule.sub_types.map((s) => subTypeLabel(s, meta)).join(", ") + " only");
  if (!rule.types.length && !rule.sub_types.length) parts.push("all types");
  if (rule.min_reputation) parts.push(`≥ ${repLabel(rule.min_reputation)}`);
  parts.push(rule.sync_updates ? "creates & updates" : "creates only");
  return parts.join(" · ");
}

/** Expanding, fading ring that marks something actively syncing (static outline with reduced motion). */
function PulseRing({ r, color, strong = false, reduceMotion }: { r: number; color: string; strong?: boolean; reduceMotion: boolean }) {
  if (reduceMotion) return <circle r={r} fill="none" stroke={color} strokeWidth={2.5} strokeOpacity={0.8} />;
  return (
    <>
      {[0, 0.7].map((delay) => (
        <motion.circle
          key={delay}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={strong ? 3 : 2}
          initial={{ scale: 1, opacity: strong ? 0.8 : 0.45 }}
          animate={{ scale: 1.55, opacity: 0 }}
          transition={{ duration: 1.4, delay, repeat: Infinity, ease: "easeOut" }}
        />
      ))}
    </>
  );
}

function Legend() {
  const item = (glyph: ReactNode, label: string) => (
    <span className="inline-flex items-center gap-1.5">
      <svg width="26" height="10" aria-hidden>
        {glyph}
      </svg>
      {label}
    </span>
  );
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-1 border-t px-5 py-3 text-xs text-muted-foreground">
      {item(<line x1="1" y1="5" x2="25" y2="5" stroke="var(--chart-ink)" strokeWidth="4" strokeLinecap="round" />, "Thicker = more observables synced")}
      {item(<line x1="1" y1="5" x2="25" y2="5" stroke="var(--chart-axis)" strokeWidth="1.5" strokeDasharray="3 3" />, "Allowed by a rule, nothing synced yet")}
      {item(
        <>
          <line x1="1" y1="5" x2="25" y2="5" stroke="var(--chart-grid)" strokeWidth="2" />
          <circle cx="9" cy="5" r="2.5" fill="var(--chart-ink)" />
          <circle cx="19" cy="5" r="2.5" fill="var(--chart-ink)" />
        </>,
        "Moving dots = active flow",
      )}
      {item(<line x1="1" y1="5" x2="25" y2="5" stroke="var(--chart-grid)" strokeWidth="1" />, "Faint line = pulled into Beacon")}
      {item(<rect x="8" y="0" width="10" height="10" rx="2.5" fill={FEED_COLOR} />, "Threat feed (STIX/TAXII or list)")}
      <span>Arrow color = source workspace (feeds in ink)</span>
    </div>
  );
}

export function FlowGraph() {
  const meta = useMeta();
  const reduceMotion = useReducedMotion();
  const [types, setTypes] = useState<string[]>([]);
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");
  const [showAllowed, setShowAllowed] = useState(false);
  const [paused, setPaused] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [pinnedRule, setPinnedRule] = useState<number | null>(null);
  const [hoverRule, setHoverRule] = useState<number | null>(null);
  const [hover, setHover] = useState<Hover>(null);
  const [wrapRef, size] = useSize<HTMLDivElement>();
  const width = size.width;
  const height = Math.max(MIN_HEIGHT, size.height);
  const svgRef = useRef<SVGSVGElement>(null);

  // ---- Zoom & pan (persisted per user as zoom + pan relative to the widget size) ----------------
  const prefs = usePreferences();
  const savePref = useSavePreference();
  const [view, setViewState] = useState<View>(IDENTITY);
  const viewRef = useRef(view);
  const restored = useRef(false);
  const drag = useRef<{ x0: number; y0: number; vx: number; vy: number; moved: boolean } | null>(null);
  const [panning, setPanning] = useState(false);
  const setView = (v: View) => {
    viewRef.current = v;
    setViewState(v);
    if (width && height) savePref("flow_view", { k: v.k, px: v.x / width, py: v.y / height });
  };
  useEffect(() => {
    if (restored.current || !prefs.data || !width) return;
    restored.current = true;
    const saved = prefs.data.flow_view as { k?: number; px?: number; py?: number } | undefined;
    if (saved?.k) {
      const v = { k: saved.k, x: (saved.px ?? 0) * width, y: (saved.py ?? 0) * height };
      viewRef.current = v;
      setViewState(v);
    }
  }, [prefs.data, width, height]);
  const zoomAt = (px: number, py: number, factor: number) => {
    const cur = viewRef.current;
    const k = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, cur.k * factor));
    const ratio = k / cur.k;
    setView({ k, x: px - (px - cur.x) * ratio, y: py - (py - cur.y) * ratio });
  };
  // Clicks that end a drag-pan must not select or clear anything.
  const consumeDrag = () => {
    const moved = !!drag.current?.moved;
    drag.current = null;
    return moved;
  };
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    // Ctrl/⌘ + wheel (and trackpad pinch) zooms; plain wheel keeps scrolling the page.
    const onWheel = (e: WheelEvent) => {
      if (!e.ctrlKey && !e.metaKey) return;
      e.preventDefault();
      const r = svg.getBoundingClientRect();
      zoomAt(e.clientX - r.left, e.clientY - r.top, Math.exp(-e.deltaY * 0.0025));
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  });
  useEffect(() => {
    const up = () => {
      if (drag.current && !drag.current.moved) drag.current = null;
      setPanning(false);
    };
    window.addEventListener("pointerup", up);
    return () => window.removeEventListener("pointerup", up);
  }, []);

  const q = useQuery({
    queryKey: ["dashboard-flows", types],
    queryFn: () => get<FlowGraphData>("/dashboard/flows" + qs({ type: types })),
    placeholderData: keepPreviousData,
  });
  const d = q.data;

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    if (paused) svg.pauseAnimations();
    else svg.unpauseAnimations();
  }, [paused, viewMode, d]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setSelected(null);
        setPinnedRule(null);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const wsNodes = useMemo(() => (d?.nodes.filter(isWs) ?? []) as FlowWorkspaceNode[], [d]);
  const feedNodes = useMemo(() => (d?.nodes.filter(isFeed) ?? []) as FlowFeedNode[], [d]);
  const central = d?.nodes.find((n) => n.id === CENTRAL) as FlowCentralNode | undefined;
  const nameOf = (id: string) =>
    id === CENTRAL ? "Beacon central (manual)" : (wsNodes.find((n) => n.id === id) ?? feedNodes.find((n) => n.id === id))?.name ?? id;
  const ruleName = (id: number) => d?.rules.find((r) => r.id === id)?.name ?? `#${id}`;
  const regionOfNode = (id: string) => wsNodes.find((n) => n.id === id)?.region;
  /** Node name for HTML (tooltips, panel, table): flag + name for workspaces. */
  const labelOf = (id: string) =>
    id === CENTRAL ? nameOf(id) : id.startsWith("feed:") ? (
      <span className="inline-flex items-center gap-1"><RssIcon className="size-3 text-muted-foreground" />{nameOf(id)}</span>
    ) : <WorkspaceName name={nameOf(id)} region={regionOfNode(id)} />;

  // Color follows the workspace (by id), never its position or rank.
  const colorOf = useMemo(() => {
    const ids = [...wsNodes].sort((a, b) => a.workspace_id - b.workspace_id).map((n) => n.id);
    return (id: string) => {
      if (id === CENTRAL) return "hsl(var(--primary))";
      if (id.startsWith("feed:")) return FEED_COLOR;
      const i = ids.indexOf(id);
      return i >= 0 && i < CAT_SLOTS ? `var(--cat-${i + 1})` : "var(--chart-axis)";
    };
  }, [wsNodes]);

  // ---- Geometry -----------------------------------------------------------------------------
  const geo = useMemo(() => {
    if (!d || !width) return null;
    // Feeds get their own column on the left, apart from the workspace ring.
    const sideW = feedNodes.length ? Math.min(190, Math.max(130, width * 0.18)) : 0;
    const cx = sideW + (width - sideW) / 2;
    const cy = height / 2;
    const radius = Math.max(70, Math.min((width - sideW) / 2 - 110, height / 2 - 70));
    const maxVol = Math.max(1, ...wsNodes.map((n) => n.native + n.synced_in));
    const pos = new Map<string, Pt & { r: number }>();
    wsNodes.forEach((n, i) => {
      const angle = -Math.PI / 2 + (i * 2 * Math.PI) / Math.max(1, wsNodes.length);
      pos.set(n.id, {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
        r: 18 + 22 * Math.sqrt((n.native + n.synced_in) / maxVol),
      });
    });
    pos.set(CENTRAL, { x: cx, y: cy, r: 24 });
    const maxListed = Math.max(1, ...feedNodes.map((n) => n.listed));
    const step = Math.min(96, (height - 90) / Math.max(1, feedNodes.length));
    const top = cy - (step * (feedNodes.length - 1)) / 2;
    feedNodes.forEach((n, i) => {
      pos.set(n.id, { x: sideW / 2, y: top + i * step, r: 12 + 6 * Math.sqrt(n.listed / maxListed) });
    });
    const feedBox = feedNodes.length
      ? { x: 10, y: top - 46, w: sideW - 20, h: step * (feedNodes.length - 1) + 92 }
      : null;

    const maxCount = Math.max(1, ...d.edges.map((e) => e.count));
    const edges = d.edges.filter((e) => pos.has(e.source) && pos.has(e.target)).map((e) => {
      const s = pos.get(e.source)!;
      const t = pos.get(e.target)!;
      const chord = sub(t, s);
      const dist = len(chord);
      const normal = { x: -chord.y / dist, y: chord.x / dist }; // left of direction -> A→B and B→A bow apart
      const mid = { x: (s.x + t.x) / 2, y: (s.y + t.y) / 2 };
      // Bow further when the straight line would cross the hub.
      const nearHub = len(sub(mid, { x: cx, y: cy })) < 40;
      const bow = dist * (e.source === CENTRAL ? 0.12 : nearHub ? 0.38 : 0.22);
      const ctrl = along(mid, normal, bow);
      const width_ = e.count > 0 ? 1.5 + 5.5 * Math.sqrt(e.count / maxCount) : 1.25;
      const head = 6 + width_ * 1.1; // arrowhead length, proportional to the line
      const p0 = along(s, unit(sub(ctrl, s)), s.r + 3);
      const tip = along(t, unit(sub(ctrl, t)), t.r + 3);
      const dir = unit(sub(tip, ctrl));
      const base = along(tip, dir, -head);
      const perp = { x: -dir.y, y: dir.x };
      const halfW = head * 0.55;
      const arrow = `M${tip.x},${tip.y} L${base.x + perp.x * halfW},${base.y + perp.y * halfW} L${base.x - perp.x * halfW},${base.y - perp.y * halfW} Z`;
      return {
        e,
        id: `flow-${edgeKey(e).replace(/[^a-z0-9]/gi, "-")}`,
        path: `M${p0.x},${p0.y} Q${ctrl.x},${ctrl.y} ${base.x},${base.y}`,
        arrow,
        mid: quad(p0, ctrl, base, 0.5),
        length: dist * 1.1,
        width: width_,
      };
    });
    return { cx, cy, radius, pos, edges, feedBox };
  }, [d, width, height, wsNodes, feedNodes]);

  // ---- Make room for the details panel ---------------------------------------------------------
  // While the panel is open, slide the graph left so it is centered in the space beside the panel
  // (shrinking it a little if the ring would not fit), and slide it back when the panel closes.
  // This is separate from the user's zoom/pan, which stays untouched and persisted as-is.
  const [fit, setFit] = useState({ dx: 0, s: 1 });
  const fitRef = useRef(fit);
  const hasSelection = !!selected && viewMode === "graph" && !!d?.nodes.some((n) => n.id === selected);
  useEffect(() => {
    if (!geo || !width) return;
    let target = { dx: 0, s: 1 };
    if (hasSelection) {
      const panelSpace = Math.min(PANEL_WIDTH + 24, width * 0.6);
      const avail = width - panelSpace;
      const need = (geo.radius + 125) * 2; // ring plus its outside labels
      target = { dx: -panelSpace / 2, s: Math.min(1, Math.max(0.35, avail / need)) };
    }
    const from = fitRef.current;
    if (from.dx === target.dx && from.s === target.s) return;
    if (reduceMotion) {
      fitRef.current = target;
      setFit(target);
      return;
    }
    const controls = animate(0, 1, {
      type: "spring",
      stiffness: 260,
      damping: 32,
      onUpdate: (t) => {
        const next = { dx: from.dx + (target.dx - from.dx) * t, s: from.s + (target.s - from.s) * t };
        fitRef.current = next;
        setFit(next);
      },
    });
    return () => controls.stop();
  }, [hasSelection, geo, width, reduceMotion]);

  // ---- Live sync: show which systems and directions are syncing right now ----------------------
  const syncStatus = useSyncStatus();
  const live = syncStatus.data?.running ? syncStatus.data.live : null;
  const syncing = !!live;
  const syncPhase = syncing ? syncStatus.data!.phase : null;
  const livePull = useMemo(() => new Map((live?.workspaces ?? []).map((w) => [`ws:${w.workspace_id}`, w])), [live]);
  const liveEdges = useMemo(() => new Map((live?.edges ?? []).map((e) => [`${e.source}>${e.target}`, e])), [live]);
  const pushTotals = useMemo(() => {
    const ws = live?.workspaces ?? [];
    return { total: ws.reduce((a, w) => a + w.push_total, 0), done: ws.reduce((a, w) => a + w.push_done + w.push_failed, 0) };
  }, [live]);
  const isPushingEdge = (e: FlowEdge) => syncPhase === "push" && liveEdges.has(edgeKey(e));
  const syncLabel = !syncing
    ? null
    : syncPhase === "pull"
      ? `Pulling from ${livePull.size} workspace${livePull.size === 1 ? "" : "s"} · ${[...livePull.values()].filter((w) => w.pull === "done").length} done`
      : syncPhase === "merge"
        ? "Merging into Beacon central"
        : syncPhase === "push"
          ? `Pushing changes · ${fmt(pushTotals.done)} / ${fmt(pushTotals.total)}`
          : "Starting sync…";

  // ---- Focus / highlighting ------------------------------------------------------------------
  const activeRule = hoverRule ?? pinnedRule;
  const ruleEdges = useMemo(() => {
    const rule = d?.rules.find((r) => r.id === activeRule);
    return rule ? new Set(rule.edges.map(([s, t]) => `${s}>${t}`)) : null;
  }, [d, activeRule]);
  const focusNode = hover?.kind === "node" ? hover.id : selected;

  const edgeVisible = (e: FlowEdge) =>
    e.count > 0 || (showAllowed && e.allowed) || !!ruleEdges?.has(edgeKey(e)) || isPushingEdge(e);
  const edgeActive = (e: FlowEdge) => {
    if (ruleEdges) return ruleEdges.has(edgeKey(e));
    if (focusNode) return e.source === focusNode || e.target === focusNode;
    if (hover?.kind === "edge") return edgeKey(hover.edge) === edgeKey(e);
    return true;
  };
  const nodeActive = (id: string) => {
    if (ruleEdges) return [...ruleEdges].some((k) => k.startsWith(id + ">") || k.endsWith(">" + id));
    if (focusNode) return id === focusNode || d!.edges.some((e) => edgeVisible(e) && ((e.source === focusNode && e.target === id) || (e.target === focusNode && e.source === id)));
    return true;
  };
  const anyFocus = !!(ruleEdges || focusNode || hover?.kind === "edge");
  const visibleEdges = geo?.edges.filter((g) => edgeVisible(g.e)) ?? [];
  const labelAll = visibleEdges.filter((g) => g.e.count > 0).length <= 8;

  const pointer = (evt: React.MouseEvent) => {
    const rect = wrapRef.current!.getBoundingClientRect();
    return { x: evt.clientX - rect.left, y: evt.clientY - rect.top };
  };

  // ---- Render ---------------------------------------------------------------------------------
  const selectedNode = selected ? d?.nodes.find((n) => n.id === selected) : undefined;
  const inbound = selected ? (d?.edges.filter((e) => e.target === selected && (e.count || e.allowed)) ?? []) : [];
  const outbound = selected ? (d?.edges.filter((e) => e.source === selected && (e.count || e.allowed)) ?? []) : [];

  return (
    <Card className="flex h-full flex-col overflow-hidden">
      <CardHeader
        title="Observable flows"
        description={
          syncLabel ? (
            <span className="inline-flex items-center gap-1.5 font-medium text-primary">
              <Loader2 className="size-3.5 animate-spin" /> Syncing · {syncLabel}
            </span>
          ) : d ? (
            `${fmt(d.totals.synced)} observable syncs between workspaces · ${fmt(d.totals.pending)} pending on the next sync`
          ) : (
            "How observables move between workspaces through Beacon"
          )
        }
        action={
          <div className="flex flex-wrap items-center justify-end gap-2">
            <MultiSelect
              options={(meta.data?.types ?? []).map((t) => ({ value: t.id, label: t.label }))}
              value={types}
              onChange={setTypes}
              placeholder="All types"
              className="w-48"
            />
            <Segmented
              value={viewMode}
              onChange={setViewMode}
              options={[
                { value: "graph", label: <Network aria-label="Graph view" /> },
                { value: "table", label: <Table2 aria-label="Table view" /> },
              ]}
              className="[&_button]:px-2 [&_button]:py-1"
            />
          </div>
        }
      />

      {/* Rules in effect */}
      <div className="flex flex-wrap items-center gap-1.5 px-5 pt-4" onMouseLeave={() => setHoverRule(null)}>
        <span className="mr-1 text-xs font-medium text-muted-foreground">Rules</span>
        {d?.rules.length === 0 && (
          <Link to="/rules" className="text-xs text-primary hover:underline">
            No rules yet: create one to start syncing
          </Link>
        )}
        {d?.rules.map((r) => {
          const on = activeRule === r.id;
          return (
            <button
              key={r.id}
              onMouseEnter={() => setHoverRule(r.id)}
              onFocus={() => setHoverRule(r.id)}
              onBlur={() => setHoverRule(null)}
              onClick={() => setPinnedRule(pinnedRule === r.id ? null : r.id)}
              title={ruleSummary(r, meta.data)}
              aria-pressed={pinnedRule === r.id}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 text-xs font-medium transition-all",
                on ? "border-primary/50 bg-accent text-accent-foreground shadow-sm" : "bg-card hover:border-ring/40",
                !r.enabled && "text-muted-foreground opacity-70",
              )}
            >
              <span className={cn("size-1.5 rounded-full", r.enabled ? "bg-success" : "bg-muted-foreground/50")} />
              {r.name}
              {!r.enabled && <span className="text-[10px] uppercase tracking-wide">off</span>}
            </button>
          );
        })}
        {!!d?.rules.length && (
          <Link to="/rules" className="ml-1 inline-flex items-center gap-0.5 text-xs text-primary hover:underline">
            Manage <ArrowRight className="size-3" />
          </Link>
        )}
        <div className="ml-auto flex items-center gap-3">
          {viewMode === "graph" && (
            <>
              <label className="flex items-center gap-2 text-xs text-muted-foreground">
                <Switch checked={showAllowed} onCheckedChange={setShowAllowed} aria-label="Show allowed paths with no traffic" />
                Paths with no traffic
              </label>
              {!reduceMotion && (
                <button
                  onClick={() => setPaused(!paused)}
                  className="grid size-7 place-items-center rounded-md text-muted-foreground hover:bg-muted hover:text-foreground"
                  aria-label={paused ? "Play animation" : "Pause animation"}
                >
                  {paused ? <Play className="size-3.5" /> : <Pause className="size-3.5" />}
                </button>
              )}
            </>
          )}
        </div>
      </div>
      <AnimatePresence initial={false}>
        {activeRule !== null && d && (
          <motion.p initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} className="px-5 pt-1.5 text-xs text-muted-foreground">
            <span className="font-medium text-foreground">{ruleName(activeRule)}</span>: {ruleSummary(d.rules.find((r) => r.id === activeRule)!, meta.data)}
            {!d.rules.find((r) => r.id === activeRule)!.enabled && " · disabled, not applied"}
          </motion.p>
        )}
      </AnimatePresence>

      <div
        ref={wrapRef}
        className={cn("relative mt-2 min-h-[260px] flex-1 overflow-hidden transition-opacity", q.isFetching && q.isPlaceholderData && "opacity-60")}
        onMouseLeave={() => setHover(null)}
      >
        {!d ? (
          <div className="p-5">
            <Skeleton className="h-full min-h-[240px]" />
          </div>
        ) : wsNodes.length === 0 ? (
          <EmptyState icon={<Network />} title="No workspaces connected" description="Connect Torq workspaces in Settings to see how observables flow between them." />
        ) : viewMode === "table" ? (
          <div className="absolute inset-0 overflow-auto px-5 pb-4">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-card text-xs text-muted-foreground">
                <tr className="border-b">
                  <th className="py-2 text-left font-medium">From</th>
                  <th className="py-2 text-left font-medium">To</th>
                  <th className="py-2 text-right font-medium">Synced</th>
                  <th className="py-2 text-right font-medium">Pending</th>
                  <th className="py-2 pl-4 text-left font-medium">Allowed by</th>
                </tr>
              </thead>
              <tbody className="divide-y tabular">
                {[...d.edges]
                  .filter((e) => e.count || e.allowed)
                  .sort((a, b) => b.count - a.count || b.pending_create - a.pending_create)
                  .map((e) => (
                    <tr key={edgeKey(e)}>
                      <td className="py-1.5">{labelOf(e.source)}</td>
                      <td className="py-1.5">{labelOf(e.target)}</td>
                      <td className="py-1.5 text-right">{fmt(e.count)}</td>
                      <td className="py-1.5 text-right">{fmt(e.pending_create + e.pending_update)}</td>
                      <td className="py-1.5 pl-4 text-muted-foreground">{e.rules.length ? e.rules.map(ruleName).join(", ") : "No enabled rule"}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        ) : (
          geo && (
            <svg
              ref={svgRef}
              width={width}
              height={height}
              role="img"
              aria-label="Network of observable flows between workspaces"
              className={cn("absolute inset-0 touch-none select-none", panning ? "cursor-grabbing" : "cursor-grab")}
              onPointerDown={(evt) => {
                if (evt.button !== 0) return;
                drag.current = { x0: evt.clientX, y0: evt.clientY, vx: viewRef.current.x, vy: viewRef.current.y, moved: false };
              }}
              onPointerMove={(evt) => {
                const dr = drag.current;
                if (!dr || evt.buttons !== 1) return;
                const dx = evt.clientX - dr.x0;
                const dy = evt.clientY - dr.y0;
                if (!dr.moved && Math.hypot(dx, dy) < 4) return;
                if (!dr.moved) {
                  dr.moved = true;
                  setPanning(true);
                  setHover(null);
                }
                setView({ ...viewRef.current, x: dr.vx + dx, y: dr.vy + dy });
              }}
              onDoubleClick={(evt) => {
                const r = svgRef.current!.getBoundingClientRect();
                zoomAt(evt.clientX - r.left, evt.clientY - r.top, 1.6);
              }}
              onClick={() => {
                if (consumeDrag()) return;
                setSelected(null);
                setPinnedRule(null);
              }}
            >
              <g transform={geo ? `translate(${geo.cx + fit.dx} ${geo.cy}) scale(${fit.s}) translate(${-geo.cx} ${-geo.cy})` : undefined}>
              <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>

              {/* Spokes: each workspace's native observables pulled into Beacon central */}
              {wsNodes.map((n) => {
                const p = geo.pos.get(n.id)!;
                const pull = syncPhase === "pull" ? livePull.get(n.id)?.pull : undefined;
                const spokeId = `spoke-path-${n.workspace_id}`;
                const spokeColor = pull === "error" ? "hsl(var(--destructive))" : "hsl(var(--primary))";
                return (
                  <g key={`spoke-${n.id}`} opacity={anyFocus && !nodeActive(n.id) && !pull ? 0.15 : 1}>
                    <path id={spokeId} d={`M${p.x},${p.y} L${geo.cx},${geo.cy}`} fill="none" stroke="var(--chart-grid)" strokeWidth={1.5} />
                    {(pull === "running" || pull === "done" || pull === "error") && (
                      <path
                        d={`M${p.x},${p.y} L${geo.cx},${geo.cy}`}
                        fill="none"
                        stroke={spokeColor}
                        strokeWidth={pull === "running" ? 3 : 2}
                        strokeOpacity={pull === "running" ? 0.7 : 0.35}
                        strokeLinecap="round"
                        strokeDasharray={pull === "error" ? "4 4" : undefined}
                      />
                    )}
                    {pull === "running" &&
                      !reduceMotion &&
                      [0, 1, 2, 3].map((i) => (
                        <circle key={i} r={3} fill="hsl(var(--primary))" stroke="var(--chart-surface)" strokeWidth={1}>
                          <animateMotion dur="1.1s" begin={`${i * 0.275}s`} repeatCount="indefinite">
                            <mpath href={`#${spokeId}`} />
                          </animateMotion>
                        </circle>
                      ))}
                    <line
                      x1={p.x}
                      y1={p.y}
                      x2={geo.cx}
                      y2={geo.cy}
                      stroke="transparent"
                      strokeWidth={12}
                      onMouseMove={(evt) => setHover({ kind: "spoke", ws: n, ...pointer(evt) })}
                      onMouseLeave={() => setHover(null)}
                    />
                  </g>
                );
              })}

              {/* Feed column frame */}
              {geo.feedBox && (
                <g pointerEvents="none">
                  <rect x={geo.feedBox.x} y={geo.feedBox.y} width={geo.feedBox.w} height={geo.feedBox.h} rx={12}
                    fill="var(--chart-grid)" fillOpacity={0.18} stroke="var(--chart-grid)" strokeDasharray="4 4" />
                  <text x={geo.feedBox.x + geo.feedBox.w / 2} y={geo.feedBox.y + 16} textAnchor="middle" fontSize={10}
                    fontWeight={600} letterSpacing="0.08em" fill="var(--chart-axis)">THREAT FEEDS</text>
                </g>
              )}

              {/* Feed spokes: indicators each feed lists in Beacon central */}
              {feedNodes.map((n) => {
                const p = geo.pos.get(n.id)!;
                return (
                  <g key={`fspoke-${n.id}`} opacity={anyFocus && !nodeActive(n.id) ? 0.15 : 1}>
                    <path d={`M${p.x},${p.y} L${geo.cx},${geo.cy}`} fill="none" stroke="var(--chart-grid)" strokeWidth={1.5} strokeDasharray="2 3" />
                    <line x1={p.x} y1={p.y} x2={geo.cx} y2={geo.cy} stroke="transparent" strokeWidth={12}
                      onMouseMove={(evt) => setHover({ kind: "feed-spoke", feed: n, ...pointer(evt) })}
                      onMouseLeave={() => setHover(null)} />
                  </g>
                );
              })}

              {/* Flows */}
              {visibleEdges.map((g) => {
                const e = g.e;
                const liveEdge = isPushingEdge(e) ? liveEdges.get(edgeKey(e))! : null;
                const pushingNow = !!liveEdge && liveEdge.done < liveEdge.total;
                const active = syncing && !anyFocus ? pushingNow : edgeActive(e);
                const traffic = e.count > 0 || !!liveEdge;
                const color = traffic ? colorOf(e.source) : "var(--chart-axis)";
                const normalParticles = Math.min(5, Math.max(1, Math.round(Math.log10(e.count + 1) * 1.6) + 1));
                // While syncing, the regular flow animation pauses; only directions being pushed move (faster).
                const particles = reduceMotion ? 0 : syncing ? (pushingNow ? 5 : 0) : e.count > 0 ? normalParticles : 0;
                const dur = syncing ? Math.max(0.9, g.length / 260) : Math.max(2.2, g.length / 85);
                const pending = e.pending_create + e.pending_update;
                const dimmed = syncing && !anyFocus ? !pushingNow && !(liveEdge && liveEdge.done >= liveEdge.total) : anyFocus && !active;
                return (
                  <motion.g key={g.id} initial={{ opacity: 0 }} animate={{ opacity: dimmed ? (syncing ? 0.18 : 0.1) : 1 }} transition={{ duration: 0.3 }}>
                    <path
                      id={g.id}
                      d={g.path}
                      fill="none"
                      stroke={color}
                      strokeLinecap="round"
                      strokeDasharray={traffic ? undefined : "4 4"}
                      strokeOpacity={pushingNow ? 0.85 : traffic ? 0.5 : 0.9}
                      strokeWidth={pushingNow ? Math.max(g.width, 3) : g.width}
                    />
                    <path d={g.arrow} fill={color} fillOpacity={traffic ? 0.85 : 0.9} />
                    {Array.from({ length: particles }).map((_, i) => (
                      <circle key={i} r={Math.min(4, 2 + g.width / 4)} fill={color} stroke="var(--chart-surface)" strokeWidth={1}>
                        <animateMotion dur={`${dur}s`} begin={`${(i * dur) / particles}s`} repeatCount="indefinite" rotate="auto">
                          <mpath href={`#${g.id}`} />
                        </animateMotion>
                      </circle>
                    ))}
                    {liveEdge && pushingNow && (
                      <g transform={`translate(${g.mid.x}, ${g.mid.y})`} pointerEvents="none">
                        <rect x={-26} y={-9} width={52} height={18} rx={9} fill="hsl(var(--primary))" />
                        <text textAnchor="middle" dy={4} fontSize={10} fontWeight={700} fill="#fff" className="tabular">
                          {`${fmt(liveEdge.done)}/${fmt(liveEdge.total)}`}
                        </text>
                      </g>
                    )}
                    {!liveEdge && !syncing && traffic && (labelAll || (anyFocus && active)) && (
                      <text x={g.mid.x} y={g.mid.y - 6} textAnchor="middle" fontSize={11} fontWeight={600} fill="var(--chart-ink)" className="tabular" pointerEvents="none" paintOrder="stroke" stroke="var(--chart-surface)" strokeWidth={3}>
                        {fmt(e.count)}
                      </text>
                    )}
                    {pending > 0 && !syncing && (
                      <g transform={`translate(${g.mid.x}, ${g.mid.y + (traffic ? 9 : 0)})`} pointerEvents="none">
                        <rect x={-18} y={-8} width={36} height={16} rx={8} fill="hsl(var(--primary))" />
                        <text textAnchor="middle" dy={4} fontSize={10} fontWeight={600} fill="hsl(var(--primary-foreground))">
                          +{pending > 999 ? "999+" : pending}
                        </text>
                      </g>
                    )}
                    {/* Generous hit target */}
                    <path
                      d={g.path}
                      fill="none"
                      stroke="transparent"
                      strokeWidth={Math.max(14, g.width + 8)}
                      onMouseMove={(evt) => setHover({ kind: "edge", edge: e, ...pointer(evt) })}
                      onMouseLeave={() => setHover(null)}
                      onClick={(evt) => {
                        evt.stopPropagation();
                        if (consumeDrag()) return;
                        setSelected(e.target);
                      }}
                      className="cursor-pointer"
                    />
                  </motion.g>
                );
              })}

              {/* Hub */}
              {central &&
                (() => {
                  const p = geo.pos.get(CENTRAL)!;
                  const s = 22;
                  return (
                    <g
                      transform={`translate(${p.x}, ${p.y})`}
                      opacity={anyFocus && !nodeActive(CENTRAL) && focusNode !== CENTRAL ? 0.4 : 1}
                      className="cursor-pointer outline-none"
                      tabIndex={0}
                      role="button"
                      aria-label={`Beacon central: ${central.total} observables`}
                      onClick={(evt) => {
                        evt.stopPropagation();
                        if (consumeDrag()) return;
                        setSelected(selected === CENTRAL ? null : CENTRAL);
                      }}
                      onKeyDown={(evt) => evt.key === "Enter" && setSelected(CENTRAL)}
                      onMouseMove={(evt) => setHover({ kind: "node", id: CENTRAL, ...pointer(evt) })}
                      onMouseLeave={() => setHover(null)}
                    >
                      {syncing && <PulseRing r={s * 1.45} color="hsl(var(--primary))" strong={syncPhase === "merge"} reduceMotion={!!reduceMotion} />}
                      <motion.g initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", stiffness: 260, damping: 20 }}>
                        <rect x={-s} y={-s} width={s * 2} height={s * 2} rx={8} transform="rotate(45)" fill="hsl(var(--primary))" stroke="var(--chart-surface)" strokeWidth={3} />
                      </motion.g>
                      <DatabaseIcon x={-9} y={-9} width={18} height={18} color="hsl(var(--primary-foreground))" />
                      <text y={s + 22} textAnchor="middle" fontSize={12} fontWeight={600} fill="var(--chart-ink)" {...HALO}>Beacon central</text>
                      <text y={s + 36} textAnchor="middle" fontSize={11} fill="var(--chart-axis)" className="tabular" {...HALO}>{fmt(central.total)} observables</text>
                    </g>
                  );
                })()}

              {/* Feeds */}
              {feedNodes.map((n, i) => {
                const p = geo.pos.get(n.id)!;
                const isSel = selected === n.id;
                const sz = p.r;
                return (
                  <motion.g
                    key={n.id}
                    initial={{ opacity: 0, scale: 0.6 }}
                    animate={{ opacity: anyFocus && !nodeActive(n.id) ? 0.35 : 1, scale: 1 }}
                    transition={{ delay: 0.1 + i * 0.05, type: "spring", stiffness: 260, damping: 22 }}
                    className="cursor-pointer outline-none"
                    tabIndex={0}
                    role="button"
                    aria-label={`Feed ${n.name}: ${n.listed} observables listed`}
                    onClick={(evt) => {
                      evt.stopPropagation();
                      if (consumeDrag()) return;
                      setSelected(isSel ? null : n.id);
                    }}
                    onKeyDown={(evt) => evt.key === "Enter" && setSelected(n.id)}
                    onMouseMove={(evt) => setHover({ kind: "node", id: n.id, ...pointer(evt) })}
                    onMouseLeave={() => setHover(null)}
                  >
                    {isSel && <rect x={p.x - sz - 6} y={p.y - sz - 6} width={(sz + 6) * 2} height={(sz + 6) * 2} rx={8} fill="none" stroke={FEED_COLOR} strokeWidth={2} strokeDasharray="3 3" />}
                    <rect x={p.x - sz} y={p.y - sz} width={sz * 2} height={sz * 2} rx={sz * 0.35} fill={FEED_COLOR}
                      stroke={n.status === "error" ? "hsl(var(--destructive))" : "var(--chart-surface)"} strokeWidth={n.status === "error" ? 2.5 : 3}
                      opacity={n.enabled ? 1 : 0.45} />
                    {n.feed_kind === "text_list" ? (
                      <ListIcon x={p.x - sz * 0.5} y={p.y - sz * 0.5} width={sz} height={sz} color="var(--chart-surface)" pointerEvents="none" />
                    ) : (
                      <RssIcon x={p.x - sz * 0.5} y={p.y - sz * 0.5} width={sz} height={sz} color="var(--chart-surface)" pointerEvents="none" />
                    )}
                    <text x={p.x} y={p.y + sz + 14} textAnchor="middle" fontSize={11} fontWeight={600} fill="var(--chart-ink)" {...HALO}>
                      {(n.name.length > 20 ? n.name.slice(0, 19) + "…" : n.name) + (n.enabled ? "" : " (off)")}
                    </text>
                    <text x={p.x} y={p.y + sz + 27} textAnchor="middle" fontSize={10} fill="var(--chart-axis)" className="tabular" {...HALO}>
                      {fmt(n.listed)} listed
                    </text>
                  </motion.g>
                );
              })}

              {/* Workspaces */}
              {wsNodes.map((n, i) => {
                const p = geo.pos.get(n.id)!;
                const isSel = selected === n.id;
                // Label sits outside the ring, away from the hub and the arrows.
                const out = unit(sub(p, { x: geo.cx, y: geo.cy }));
                const lx = p.x + out.x * (p.r + 10);
                const ly = p.y + out.y * (p.r + 10);
                const anchor = out.x > 0.35 ? "start" : out.x < -0.35 ? "end" : "middle";
                const [nameDy, statDy] = out.y < -0.35 ? [-16, -2] : out.y > 0.35 ? [12, 26] : [-3, 11];
                return (
                  <motion.g
                    key={n.id}
                    initial={{ opacity: 0, scale: 0.6 }}
                    animate={{ opacity: anyFocus && !nodeActive(n.id) ? 0.35 : 1, scale: 1 }}
                    transition={{ delay: i * 0.05, type: "spring", stiffness: 260, damping: 22 }}
                    className="cursor-pointer outline-none"
                    tabIndex={0}
                    role="button"
                    aria-label={`${n.name}: ${n.native} native, ${n.synced_in} synced in, ${n.synced_out} synced out`}
                    onClick={(evt) => {
                      evt.stopPropagation();
                      if (consumeDrag()) return;
                      setSelected(isSel ? null : n.id);
                    }}
                    onKeyDown={(evt) => evt.key === "Enter" && setSelected(n.id)}
                    onMouseMove={(evt) => setHover({ kind: "node", id: n.id, ...pointer(evt) })}
                    onMouseLeave={() => setHover(null)}
                  >
                    {isSel && <circle cx={p.x} cy={p.y} r={p.r + 6} fill="none" stroke={colorOf(n.id)} strokeWidth={2} strokeDasharray="3 3" />}
                    {syncing &&
                      (() => {
                        const lw = livePull.get(n.id);
                        if (!lw) return null;
                        const pushing = syncPhase === "push" && lw.push_total > lw.push_done + lw.push_failed;
                        const failed = lw.pull === "error" || lw.push_failed > 0;
                        const done = syncPhase === "pull" ? lw.pull === "done" : syncPhase === "push" ? lw.push_total > 0 && !pushing : false;
                        // Status text goes on the opposite side of the node from its name label.
                        const statusY = out.y > 0.35 ? -p.r - 9 : p.r + 17;
                        return (
                          <g transform={`translate(${p.x}, ${p.y})`} pointerEvents="none">
                            {(lw.pull === "running" && syncPhase === "pull") || pushing ? (
                              <PulseRing r={p.r + 4} color={pushing ? colorOf(n.id) : "hsl(var(--primary))"} strong reduceMotion={!!reduceMotion} />
                            ) : null}
                            {failed && <circle r={p.r + 5} fill="none" stroke="hsl(var(--destructive))" strokeWidth={2.5} />}
                            {(done || failed) && (
                              <g transform={`translate(${p.r * 0.72}, ${-p.r * 0.72})`}>
                                <circle r={8} fill={failed ? "hsl(var(--destructive))" : "hsl(var(--success))"} stroke="var(--chart-surface)" strokeWidth={2} />
                                <text textAnchor="middle" dy={3.5} fontSize={10} fontWeight={800} fill="#fff">{failed ? "!" : "✓"}</text>
                              </g>
                            )}
                            {syncPhase === "pull" && lw.pull === "running" && (
                              <text y={statusY} textAnchor="middle" fontSize={10} fontWeight={600} fill="hsl(var(--primary))" className="tabular" {...HALO}>
                                {fmt(lw.pulled)} pulled
                              </text>
                            )}
                            {pushing && (
                              <text y={statusY} textAnchor="middle" fontSize={10} fontWeight={600} fill="var(--chart-ink)" className="tabular" {...HALO}>
                                receiving {fmt(lw.push_done)}/{fmt(lw.push_total)}
                              </text>
                            )}
                          </g>
                        );
                      })()}
                    <circle cx={p.x} cy={p.y} r={p.r} fill={colorOf(n.id)} stroke="var(--chart-surface)" strokeWidth={3} opacity={n.enabled ? 1 : 0.45} />
                    <text x={p.x} y={p.y + 4} textAnchor="middle" fontSize={11} fontWeight={700} fill="#fff" pointerEvents="none" className="tabular">
                      {n.native + n.synced_in >= 1000 ? `${((n.native + n.synced_in) / 1000).toFixed(1)}k` : n.native + n.synced_in}
                    </text>
                    {(() => {
                      // Flag sits between the node and the name (centered pair for top/bottom labels).
                      const label = n.name + (n.enabled ? "" : " (disabled)");
                      const fw = 15, gap = 5;
                      const est = label.length * 7.1; // approx. text width at 12px semibold
                      const flagX = anchor === "start" ? lx : anchor === "end" ? lx - fw : lx - (fw + gap + est) / 2;
                      const nameX = anchor === "start" ? lx + fw + gap : anchor === "end" ? lx - fw - gap : flagX + fw + gap + est / 2;
                      return (
                        <>
                          <RegionFlag region={n.region} height={10} x={flagX} y={ly + nameDy - 9} />
                          <text x={nameX} y={ly + nameDy} textAnchor={anchor} fontSize={12} fontWeight={600} fill="var(--chart-ink)" pointerEvents="none" {...HALO}>
                            {label}
                          </text>
                        </>
                      );
                    })()}
                    <text x={lx} y={ly + statDy} textAnchor={anchor} fontSize={11} fill="var(--chart-axis)" pointerEvents="none" className="tabular" {...HALO}>
                      {fmt(n.native)} native · {fmt(n.synced_in)} in{n.pending_in ? ` · +${fmt(n.pending_in)}` : ""}
                    </text>
                  </motion.g>
                );
              })}
              </g>
              </g>
            </svg>
          )
        )}

        {/* Zoom controls (top-left: the ring layout leaves that corner free) */}
        {d && wsNodes.length > 0 && viewMode === "graph" && (
          <div className="absolute left-3 top-2 z-10 flex items-center gap-0.5 rounded-xl border bg-popover/90 p-0.5 shadow-sm backdrop-blur">
            <Tooltip content="Zoom out">
              <button onClick={() => zoomAt(width / 2, height / 2, 1 / 1.25)} className="grid size-7 place-items-center rounded-lg text-muted-foreground hover:bg-muted hover:text-foreground" aria-label="Zoom out">
                <ZoomOut className="size-4" />
              </button>
            </Tooltip>
            <span className="w-10 text-center text-[11px] tabular text-muted-foreground">{Math.round(view.k * 100)}%</span>
            <Tooltip content="Zoom in">
              <button onClick={() => zoomAt(width / 2, height / 2, 1.25)} className="grid size-7 place-items-center rounded-lg text-muted-foreground hover:bg-muted hover:text-foreground" aria-label="Zoom in">
                <ZoomIn className="size-4" />
              </button>
            </Tooltip>
            <Tooltip content="Reset zoom and position">
              <button
                onClick={() => setView(IDENTITY)}
                disabled={view.k === 1 && view.x === 0 && view.y === 0}
                className="grid size-7 place-items-center rounded-lg text-muted-foreground hover:bg-muted hover:text-foreground disabled:opacity-40"
                aria-label="Fit to view"
              >
                <Maximize2 className="size-3.5" />
              </button>
            </Tooltip>
            <Tooltip content="⌘/Ctrl + scroll or pinch to zoom · drag to pan · double-click to zoom in">
              <span className="grid size-7 cursor-help place-items-center rounded-lg text-muted-foreground" aria-label="Zoom help">
                <HelpCircle className="size-3.5" />
              </span>
            </Tooltip>
          </div>
        )}

        {/* Tooltip */}
        {hover && d && viewMode === "graph" && (
          <div
            className="pointer-events-none absolute z-20 max-w-xs rounded-lg border bg-popover px-3 py-2 text-xs shadow-xl"
            style={{ left: Math.min(hover.x + 14, Math.max(0, width - 270)), top: Math.max(0, hover.y - 10) }}
          >
            {hover.kind === "edge" && (
              <>
                <div className="flex items-center gap-1.5 font-medium">
                  {labelOf(hover.edge.source)} <ArrowRight className="size-3 shrink-0" /> {labelOf(hover.edge.target)}
                </div>
                <div className="mt-1.5 space-y-0.5">
                  <div className="flex justify-between gap-6">
                    <span className="text-muted-foreground">Synced</span>
                    <span className="font-semibold tabular">{fmt(hover.edge.count)}</span>
                  </div>
                  {hover.edge.pending_create + hover.edge.pending_update > 0 && (
                    <div className="flex justify-between gap-6">
                      <span className="text-muted-foreground">Pending next sync</span>
                      <span className="font-semibold tabular">
                        +{fmt(hover.edge.pending_create)} new · {fmt(hover.edge.pending_update)} updates
                      </span>
                    </div>
                  )}
                </div>
                <div className="mt-1.5 text-muted-foreground">
                  {hover.edge.rules.length ? <>Allowed by {hover.edge.rules.map(ruleName).join(", ")}</> : "No enabled rule allows this direction"}
                </div>
                {hover.edge.count > 0 && (
                  <div className="mt-1 text-[11px] text-muted-foreground">
                    Observables native to {nameOf(hover.edge.source)} that Beacon synced into {nameOf(hover.edge.target)}.
                  </div>
                )}
              </>
            )}
            {hover.kind === "spoke" && (
              <>
                <div className="font-medium">
                  <span className="inline-flex items-center gap-1.5">
                    <WorkspaceName name={hover.ws.name} region={hover.ws.region} /> → Beacon central
                  </span>
                </div>
                <div className="mt-1 text-muted-foreground">
                  <span className="font-semibold text-foreground tabular">{fmt(hover.ws.native)}</span> native observables pulled into the central database
                </div>
              </>
            )}
            {hover.kind === "feed-spoke" && (
              <>
                <div className="font-medium">{hover.feed.name} → Beacon central</div>
                <div className="mt-1 text-muted-foreground">
                  <span className="font-semibold text-foreground tabular">{fmt(hover.feed.listed)}</span> observables currently listed by this feed
                </div>
              </>
            )}
            {hover.kind === "node" &&
              (() => {
                const n = d.nodes.find((x) => x.id === hover.id)!;
                if (isFeed(n))
                  return (
                    <>
                      <div className="flex items-center justify-between gap-3 font-medium">
                        <span className="inline-flex items-center gap-1.5"><RssIcon className="size-3.5" /> {n.name}</span>
                        <SyncStatusPill status={n.status} />
                      </div>
                      <div className="mt-1.5 space-y-0.5 tabular">
                        {[["Listed", n.listed], ["Synced out", n.synced_out], ["Pending out", n.pending_out]].map(([label, v]) => (
                          <div key={label as string} className="flex justify-between gap-6">
                            <span className="text-muted-foreground">{label}</span>
                            <span className="font-semibold">{fmt(v as number)}</span>
                          </div>
                        ))}
                      </div>
                      <div className="mt-1.5 text-[11px] text-muted-foreground">{n.feed_kind === "text_list" ? "Threat list" : "STIX/TAXII feed"} · pushed only by rules that name it</div>
                    </>
                  );
                if (!isWs(n))
                  return (
                    <>
                      <div className="font-medium">Beacon central database</div>
                      <div className="mt-1 space-y-0.5 tabular">
                        <div className="flex justify-between gap-6"><span className="text-muted-foreground">Observables</span><span className="font-semibold">{fmt(n.total)}</span></div>
                        <div className="flex justify-between gap-6"><span className="text-muted-foreground">Created manually</span><span className="font-semibold">{fmt(n.manual)}</span></div>
                      </div>
                    </>
                  );
                return (
                  <>
                    <div className="flex items-center justify-between gap-3 font-medium">
                      <WorkspaceName name={n.name} region={n.region} />
                      <SyncStatusPill status={n.status} />
                    </div>
                    <div className="mt-1.5 space-y-0.5 tabular">
                      {[
                        ["Native", n.native],
                        ["Synced in", n.synced_in],
                        ["Synced out (to others)", n.synced_out],
                        ["Pending in", n.pending_in],
                      ].map(([label, v]) => (
                        <div key={label as string} className="flex justify-between gap-6">
                          <span className="text-muted-foreground">{label}</span>
                          <span className="font-semibold">{fmt(v as number)}</span>
                        </div>
                      ))}
                    </div>
                    <div className="mt-1.5 text-[11px] text-muted-foreground">Click for details</div>
                  </>
                );
              })()}
          </div>
        )}

        {/* Detail panel for the selected node */}
        <AnimatePresence>
          {selectedNode && viewMode === "graph" && (
            <motion.aside
              initial={{ opacity: 0, x: 24 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 24 }}
              transition={{ type: "spring", stiffness: 380, damping: 34 }}
              style={{ width: PANEL_WIDTH }}
              className="absolute bottom-2 right-3 top-2 z-10 overflow-y-auto rounded-xl border bg-popover/95 p-4 shadow-xl backdrop-blur"
              onClick={(evt) => evt.stopPropagation()}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="size-3 rounded-full" style={{ background: colorOf(selectedNode.id) }} />
                  <h4 className="text-sm font-semibold">
                    {isWs(selectedNode) ? (
                      <WorkspaceName name={selectedNode.name} region={selectedNode.region} />
                    ) : isFeed(selectedNode) ? (
                      <span className="inline-flex items-center gap-1.5"><RssIcon className="size-3.5" /> {selectedNode.name}</span>
                    ) : "Beacon central"}
                  </h4>
                </div>
                <button onClick={() => setSelected(null)} className="rounded p-0.5 text-muted-foreground hover:bg-muted" aria-label="Close details">
                  <X className="size-4" />
                </button>
              </div>
              {isWs(selectedNode) ? (
                <dl className="mt-3 grid grid-cols-2 gap-2 text-xs tabular">
                  {[
                    ["Native", selectedNode.native],
                    ["Synced in", selectedNode.synced_in],
                    ["Synced out", selectedNode.synced_out],
                    ["Pending in", selectedNode.pending_in],
                  ].map(([label, v]) => (
                    <div key={label as string} className="rounded-lg bg-muted/50 p-2">
                      <dt className="text-muted-foreground">{label}</dt>
                      <dd className="text-base font-semibold">{fmt(v as number)}</dd>
                    </div>
                  ))}
                </dl>
              ) : isFeed(selectedNode) ? (
                <>
                  <dl className="mt-3 grid grid-cols-3 gap-2 text-xs tabular">
                    {[["Listed", selectedNode.listed], ["Synced out", selectedNode.synced_out], ["Pending", selectedNode.pending_out]].map(([label, v]) => (
                      <div key={label as string} className="rounded-lg bg-muted/50 p-2">
                        <dt className="text-muted-foreground">{label}</dt>
                        <dd className="text-base font-semibold">{fmt(v as number)}</dd>
                      </div>
                    ))}
                  </dl>
                  <p className="mt-2 text-xs text-muted-foreground">Observables from this feed reach workspaces only through sync rules that name the feed as a source.</p>
                  <Link to={`/database?source=feed:${selectedNode.feed_id}`} className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline">
                    View its observables <ArrowRight className="size-3" />
                  </Link>
                </>
              ) : (
                <>
                  <p className="mt-2 text-xs text-muted-foreground">
                    {fmt((selectedNode as FlowCentralNode).total)} observables · {fmt((selectedNode as FlowCentralNode).manual)} created manually
                  </p>
                  <Link to="/database?source=central" className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline">
                    View centrally created or edited observables <ArrowRight className="size-3" />
                  </Link>
                </>
              )}
              {[
                ["Receives from", inbound, "source"] as const,
                ["Sends to", outbound, "target"] as const,
              ].map(([title, list, side]) => (
                <div key={title} className="mt-4">
                  <h5 className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">{title}</h5>
                  {list.length === 0 ? (
                    <p className="text-xs text-muted-foreground">Nothing yet.</p>
                  ) : (
                    <ul className="space-y-1.5">
                      {[...list].sort((a, b) => b.count - a.count).map((e) => (
                        <li key={edgeKey(e)} className="rounded-lg border p-2 text-xs">
                          <div className="flex items-center justify-between gap-2">
                            <span className="flex items-center gap-1.5 font-medium">
                              <span className="size-2 shrink-0 rounded-full" style={{ background: colorOf(e[side]) }} />
                              {labelOf(e[side])}
                            </span>
                            <span className="font-semibold tabular">{fmt(e.count)}</span>
                          </div>
                          <div className="mt-0.5 text-muted-foreground">
                            {e.rules.length ? e.rules.map(ruleName).join(", ") : "No enabled rule"}
                            {e.pending_create + e.pending_update > 0 && ` · +${fmt(e.pending_create + e.pending_update)} pending`}
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              ))}
              {isWs(selectedNode) && (
                <Link
                  to={`/database?workspace=${selectedNode.workspace_id}`}
                  className="mt-4 inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline"
                >
                  View observables <ArrowRight className="size-3" />
                </Link>
              )}
            </motion.aside>
          )}
        </AnimatePresence>
      </div>

      <Legend />
    </Card>
  );
}
