import { useQuery } from "@tanstack/react-query";
import { animate, motion } from "framer-motion";
import {
  Activity,
  AlertOctagon,
  ArrowRight,
  Boxes,
  CheckCircle2,
  Clock,
  GitBranch,
  LayoutGrid,
  Server,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import { useEffect, useRef, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  ResponsiveContainer,
  Tooltip as RTooltip,
  XAxis,
  YAxis,
} from "recharts";
import { PageHeader, SyncStatusPill } from "@/components/bits";
import { DashboardGrid, useDashboardLayout, type Widget, type WidgetSpec } from "@/components/DashboardGrid";
import { EnrichmentChart } from "@/components/EnrichmentChart";
import { FlowGraph } from "@/components/FlowGraph";
import { WorkspaceName } from "@/components/RegionFlag";
import { Button } from "@/components/ui/button";
import { ObservedChart } from "@/components/ObservedChart";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { get } from "@/lib/api";
import type { Dashboard as DashboardData, SyncRun } from "@/lib/types";
import { cn, fmt, timeAgo } from "@/lib/utils";

const axisTick = { fill: "var(--chart-axis)", fontSize: 11 };

function CountUp({ value }: { value: number }) {
  const ref = useRef<HTMLSpanElement>(null);
  const prev = useRef(0);
  useEffect(() => {
    const controls = animate(prev.current, value, {
      duration: 0.9,
      ease: [0.22, 1, 0.36, 1],
      onUpdate: (v) => {
        if (ref.current) ref.current.textContent = Math.round(v).toLocaleString();
      },
    });
    prev.current = value;
    return () => controls.stop();
  }, [value]);
  return <span ref={ref}>0</span>;
}

function StatTile({
  label,
  value,
  sub,
  icon,
  accent,
  index,
}: {
  label: string;
  value: number;
  sub?: ReactNode;
  icon: ReactNode;
  accent: string;
  index: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05, type: "spring", stiffness: 300, damping: 28 }}
      whileHover={{ y: -2 }}
      className="h-full"
    >
      <Card className="relative h-full overflow-hidden p-5">
        <div className={cn("absolute -right-6 -top-6 size-24 rounded-full opacity-[0.08] blur-xl", accent)} />
        <div className="flex items-center justify-between">
          <span className="text-xs font-medium text-muted-foreground">{label}</span>
          <span className="text-muted-foreground [&_svg]:size-4">{icon}</span>
        </div>
        <div className="mt-3 text-3xl font-semibold tracking-tight">
          <CountUp value={value} />
        </div>
        {sub && <div className="mt-1 text-xs text-muted-foreground">{sub}</div>}
      </Card>
    </motion.div>
  );
}

function ChartTooltip({ active, payload, label, render }: any) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border bg-popover px-3 py-2 text-xs shadow-xl">
      {render ? render(payload[0].payload, label) : null}
    </div>
  );
}

function GrowthChart({ data }: { data: DashboardData["growth"] }) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 10, right: 12, left: 0, bottom: 0 }}>
        <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
        <XAxis
          dataKey="date"
          tick={axisTick}
          tickLine={false}
          axisLine={{ stroke: "var(--chart-grid)" }}
          tickFormatter={(d: string) => new Date(d + "T00:00:00").toLocaleDateString(undefined, { month: "short", day: "numeric" })}
          minTickGap={28}
        />
        <YAxis tick={axisTick} tickLine={false} axisLine={false} width={48} allowDecimals={false} tickFormatter={fmt} />
        <RTooltip
          cursor={{ stroke: "var(--chart-axis)", strokeWidth: 1 }}
          content={
            <ChartTooltip
              render={(p: any) => (
                <>
                  <div className="font-medium">
                    {new Date(p.date + "T00:00:00").toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" })}
                  </div>
                  <div className="mt-1 text-muted-foreground">
                    Total <span className="font-semibold text-foreground tabular">{fmt(p.total)}</span>
                  </div>
                  <div className="text-muted-foreground">
                    Added <span className="font-semibold text-foreground tabular">+{fmt(p.added)}</span>
                  </div>
                </>
              )}
            />
          }
        />
        <Area
          type="monotone"
          dataKey="total"
          stroke="var(--series-1)"
          strokeWidth={2}
          fill="var(--series-1)"
          fillOpacity={0.1}
          activeDot={{ r: 4, stroke: "var(--chart-surface)", strokeWidth: 2, fill: "var(--series-1)" }}
          animationDuration={900}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function TypeChart({ data }: { data: DashboardData["by_type"] }) {
  const sorted = [...data].sort((a, b) => b.count - a.count);
  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={sorted} layout="vertical" margin={{ top: 4, right: 48, left: 0, bottom: 4 }} barCategoryGap={8}>
        <XAxis type="number" hide />
        <YAxis type="category" dataKey="label" tick={axisTick} tickLine={false} axisLine={false} width={96} />
        <RTooltip
          cursor={{ fill: "var(--chart-grid)", opacity: 0.4 }}
          content={<ChartTooltip render={(p: any) => <><div className="font-medium">{p.label}</div><div className="text-muted-foreground tabular">{fmt(p.count)} observables</div></>} />}
        />
        <Bar dataKey="count" fill="var(--series-1)" radius={[0, 4, 4, 0]} maxBarSize={20} animationDuration={800}>
          <LabelList dataKey="count" position="right" formatter={fmt} style={{ fill: "var(--chart-ink)", fontSize: 11 }} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

function ReputationChart({ data }: { data: DashboardData["by_reputation"] }) {
  // Ordered safe → unknown → malicious so the diverging scale reads left to right.
  const ordered = [...data].sort((a, b) => {
    const rank = (s: number) => (s === 0 ? 4.5 : s);
    return rank(a.severity) - rank(b.severity);
  });
  return (
    <div className="flex h-full flex-col">
      <div className="min-h-0 flex-1">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={ordered} margin={{ top: 18, right: 8, left: 0, bottom: 0 }} barCategoryGap={2}>
          <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
          <XAxis dataKey="label" tick={{ ...axisTick, fontSize: 10 }} tickLine={false} axisLine={{ stroke: "var(--chart-grid)" }} interval={0} angle={-30} textAnchor="end" height={64} />
          <YAxis tick={axisTick} tickLine={false} axisLine={false} width={40} allowDecimals={false} tickFormatter={fmt} />
          <RTooltip
            cursor={{ fill: "var(--chart-grid)", opacity: 0.4 }}
            content={
              <ChartTooltip
                render={(p: any) => (
                  <>
                    <div className="flex items-center gap-1.5 font-medium">
                      <span className="size-2 rounded-full" style={{ background: `var(--rep-${p.severity})` }} />
                      {p.label}
                    </div>
                    <div className="text-muted-foreground tabular">{fmt(p.count)} observables</div>
                  </>
                )}
              />
            }
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={24} animationDuration={800}>
            {ordered.map((d) => (
              <Cell key={d.id} fill={`var(--rep-${d.severity})`} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
      </div>
      <div className="mt-1 flex items-center justify-center gap-2 text-[11px] text-muted-foreground">
        <span>Safe</span>
        <span className="flex h-1.5 w-40 overflow-hidden rounded-full">
          {[1, 2, 3, 4].map((s) => <span key={s} className="flex-1" style={{ background: `var(--rep-${s})` }} />)}
          <span className="flex-1" style={{ background: "var(--rep-0)" }} />
          {[5, 6, 7, 8, 9, 10].map((s) => <span key={s} className="flex-1" style={{ background: `var(--rep-${s})` }} />)}
        </span>
        <span>Malicious</span>
      </div>
    </div>
  );
}

function RunRow({ run }: { run: SyncRun }) {
  const Icon = run.status === "ok" ? CheckCircle2 : run.status === "running" ? Clock : XCircle;
  return (
    <div className="flex items-center gap-3 py-2.5">
      <Icon
        className={cn(
          "size-4 shrink-0",
          run.status === "ok" ? "text-success" : run.status === "running" ? "text-primary" : "text-destructive",
        )}
      />
      <div className="min-w-0 flex-1">
        <div className="truncate text-sm">
          <span className="capitalize">{run.trigger}</span> sync
          {run.status === "partial" && <span className="text-destructive"> · partial</span>}
          {run.status === "error" && <span className="text-destructive"> · failed</span>}
        </div>
        <div className="text-xs text-muted-foreground tabular">
          {fmt(run.pulled)} pulled · +{fmt(run.created_central)} new · {fmt(run.pushed_created)} pushed · {fmt(run.conflicts)} conflicts
        </div>
      </div>
      <span className="shrink-0 text-xs text-muted-foreground">{timeAgo(run.started_at)}</span>
    </div>
  );
}

const ACTION_LABELS: Record<string, string> = {
  login: "signed in",
  create_observable: "created observable",
  update_observable: "edited observable",
  delete_observable: "deleted observable",
  create_rule: "created rule",
  update_rule: "updated rule",
  delete_rule: "deleted rule",
  create_workspace: "connected workspace",
  update_workspace: "updated workspace",
  delete_workspace: "removed workspace",
  update_settings: "changed settings",
};

// Default placement on a 12-column grid (row = 32px). Users can move/resize; layouts persist per user.
const WIDGET_SPECS: WidgetSpec[] = [
  { id: "kpi-observables", x: 0, y: 0, w: 3, h: 3, minW: 2, minH: 3 },
  { id: "kpi-malicious", x: 3, y: 0, w: 3, h: 3, minW: 2, minH: 3 },
  { id: "kpi-workspaces", x: 6, y: 0, w: 3, h: 3, minW: 2, minH: 3 },
  { id: "kpi-rules", x: 9, y: 0, w: 3, h: 3, minW: 2, minH: 3 },
  { id: "flows", x: 0, y: 3, w: 12, h: 14, minW: 5, minH: 9 },
  { id: "growth", x: 0, y: 17, w: 8, h: 8, minW: 3, minH: 5 },
  { id: "by-type", x: 8, y: 17, w: 4, h: 8, minW: 3, minH: 5 },
  { id: "observed", x: 0, y: 25, w: 12, h: 9, minW: 4, minH: 6 },
  { id: "reputation", x: 0, y: 34, w: 8, h: 9, minW: 3, minH: 6 },
  { id: "health", x: 8, y: 34, w: 4, h: 9, minW: 3, minH: 4 },
  { id: "runs", x: 0, y: 43, w: 6, h: 9, minW: 3, minH: 4 },
  { id: "activity", x: 6, y: 43, w: 6, h: 9, minW: 3, minH: 4 },
  { id: "enrichment", x: 0, y: 52, w: 12, h: 11, minW: 4, minH: 8 },
];

const widgetCard = "flex h-full flex-col overflow-hidden";
const widgetBody = "min-h-0 flex-1 pt-3";

export default function Dashboard() {
  const q = useQuery({ queryKey: ["dashboard"], queryFn: () => get<DashboardData>("/dashboard"), refetchInterval: 30000 });
  const d = q.data;
  const layout = useDashboardLayout(WIDGET_SPECS);

  if (q.isLoading || !d) {
    return (
      <>
        <PageHeader title="Dashboard" description="Overview of your central observable database" />
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          {[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-32 rounded-2xl" />)}
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-3">
          <Skeleton className="h-80 rounded-2xl lg:col-span-2" />
          <Skeleton className="h-80 rounded-2xl" />
        </div>
      </>
    );
  }

  const noWorkspaces = d.totals.workspaces === 0;

  const nodes: Record<string, ReactNode> = {
    "kpi-observables": <StatTile index={0} label="Observables" value={d.totals.observables} icon={<Boxes />} accent="bg-primary" sub={`${fmt(d.totals.pinned)} centrally edited`} />,
    "kpi-malicious": <StatTile index={1} label="Malicious" value={d.totals.malicious} icon={<ShieldAlert />} accent="bg-red-500" sub={`${fmt(d.totals.suspicious)} more need caution`} />,
    "kpi-workspaces": (
      <StatTile index={2} label="Workspaces" value={d.totals.workspaces} icon={<Server />} accent="bg-sky-500" sub={`${d.totals.workspaces_healthy} of ${d.totals.workspaces} healthy`} />
    ),
    "kpi-rules": <StatTile index={3} label="Active rules" value={d.totals.rules_active} icon={<GitBranch />} accent="bg-emerald-500" sub="Directional sync policies" />,
    flows: <FlowGraph />,
    growth: (
      <Card className={widgetCard}>
        <CardHeader title="Central database size" description="Total observables over the last 30 days" />
        <CardBody className={widgetBody}>
          <GrowthChart data={d.growth} />
        </CardBody>
      </Card>
    ),
    "by-type": (
      <Card className={widgetCard}>
        <CardHeader title="Observables by type" description="Count of observables per type" />
        <CardBody className={widgetBody}>
          {d.by_type.length ? <TypeChart data={d.by_type} /> : <EmptyState icon={<Boxes />} title="No observables yet" />}
        </CardBody>
      </Card>
    ),
    observed: <ObservedChart />,
    enrichment: <EnrichmentChart />,
    reputation: (
      <Card className={widgetCard}>
        <CardHeader title="Reputation distribution" description="Observables per verdict, from safe to malicious" />
        <CardBody className={widgetBody}>
          <ReputationChart data={d.by_reputation} />
        </CardBody>
      </Card>
    ),
    health: (
      <Card className={widgetCard}>
        <CardHeader
          title="Workspace health"
          description="Status of the last sync"
          action={<Link to="/settings/workspaces" className="text-xs font-medium text-primary hover:underline">Manage</Link>}
        />
        <CardBody className={cn(widgetBody, "overflow-y-auto")}>
          {d.workspaces.length === 0 ? (
            <EmptyState icon={<Server />} title="No workspaces" description="Connect a Torq workspace in Settings." />
          ) : (
            <div className="divide-y">
              {d.workspaces.map((ws, i) => (
                <motion.div key={ws.id} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.04 }} className="flex items-center gap-3 py-3">
                  <div className={cn("grid size-9 place-items-center rounded-xl bg-muted", !ws.enabled && "opacity-50")}>
                    <Server className="size-4 text-muted-foreground" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium">
                      <WorkspaceName name={ws.name} region={ws.region}>
                        {!ws.enabled && <span className="text-xs font-normal text-muted-foreground">(disabled)</span>}
                      </WorkspaceName>
                    </div>
                    <div className="text-xs text-muted-foreground tabular">
                      {fmt(ws.origin_count)} native · {fmt(ws.pushed_count)} synced in
                    </div>
                  </div>
                  <SyncStatusPill status={ws.status} error={ws.last_error} />
                </motion.div>
              ))}
            </div>
          )}
        </CardBody>
      </Card>
    ),
    runs: (
      <Card className={widgetCard}>
        <CardHeader title="Recent sync runs" action={<Link to="/settings/sync" className="text-xs font-medium text-primary hover:underline">View all</Link>} />
        <CardBody className={cn(widgetBody, "overflow-y-auto pt-2")}>
          {d.recent_runs.length === 0 ? <EmptyState icon={<Activity />} title="No syncs yet" /> : <div className="divide-y">{d.recent_runs.map((r) => <RunRow key={r.id} run={r} />)}</div>}
        </CardBody>
      </Card>
    ),
    activity: (
      <Card className={widgetCard}>
        <CardHeader title="Recent activity" />
        <CardBody className={cn(widgetBody, "overflow-y-auto pt-2")}>
          {d.recent_activity.length === 0 ? (
            <EmptyState icon={<AlertOctagon />} title="No activity" />
          ) : (
            <ol className="relative space-y-3 border-l pl-4">
              {d.recent_activity.map((e) => (
                <li key={e.id} className="relative">
                  <span className="absolute -left-[21px] top-1.5 size-2 rounded-full bg-primary ring-4 ring-card" />
                  <div className="text-sm">
                    <span className="font-medium">{e.username}</span>{" "}
                    <span className="text-muted-foreground">{ACTION_LABELS[e.action] ?? e.action.replace(/_/g, " ")}</span>
                    {e.detail && <span className="ml-1 break-all text-foreground/80">{e.detail}</span>}
                  </div>
                  <div className="text-xs text-muted-foreground">{timeAgo(e.ts)}</div>
                </li>
              ))}
            </ol>
          )}
        </CardBody>
      </Card>
    ),
  };
  const widgets: Widget[] = WIDGET_SPECS.map((spec) => ({ ...spec, node: nodes[spec.id] }));

  return (
    <>
      <PageHeader
        title="Dashboard"
        description="Overview of your central observable database · drag widgets by their top edge and resize from the corner"
        actions={
          layout.customized && (
            <Button variant="outline" size="sm" onClick={layout.reset}>
              <LayoutGrid /> Reset layout
            </Button>
          )
        }
      />

      {noWorkspaces && (
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mb-4">
          <Card className="flex flex-wrap items-center justify-between gap-4 border-primary/30 bg-gradient-to-r from-primary/10 to-transparent p-5">
            <div>
              <div className="font-medium">Connect your first Torq workspace</div>
              <div className="text-sm text-muted-foreground">Add a service account API key to start collecting observables.</div>
            </div>
            <Link to="/settings/workspaces" className="inline-flex items-center gap-1.5 text-sm font-medium text-primary hover:underline">
              Add workspace <ArrowRight className="size-4" />
            </Link>
          </Card>
        </motion.div>
      )}

      {layout.ready ? <DashboardGrid widgets={widgets} layout={layout} /> : <Skeleton className="h-96 rounded-2xl" />}
    </>
  );
}
