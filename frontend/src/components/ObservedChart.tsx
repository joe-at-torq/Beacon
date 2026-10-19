import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { BarChart3, Table2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Area, CartesianGrid, ComposedChart, LabelList, Line, ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis } from "recharts";
import { get } from "@/lib/api";
import type { ObservedRange, ObservedSeries } from "@/lib/types";
import { cn, fmt } from "@/lib/utils";
import { Card, CardBody, CardHeader } from "./ui/card";
import { Segmented } from "./ui/segmented";
import { Skeleton } from "./ui/skeleton";

const RANGES: { value: ObservedRange; label: string }[] = [
  { value: "all", label: "All" },
  { value: "12m", label: "12M" },
  { value: "9m", label: "9M" },
  { value: "6m", label: "6M" },
  { value: "3m", label: "3M" },
  { value: "30d", label: "30D" },
  { value: "14d", label: "14D" },
  { value: "7d", label: "7D" },
];

type SeriesDef = { key: "first_observed" | "cumulative"; label: string; color: string };
const ALL_SERIES: SeriesDef[] = [{ key: "first_observed", label: "First observed", color: "var(--series-1)" }];
const CUMULATIVE: SeriesDef[] = [{ key: "cumulative", label: "Total observables (by first observed)", color: "var(--series-1)" }];

const axisTick = { fill: "var(--chart-axis)", fontSize: 11 };

function fmtDay(iso: string, withYear = false) {
  return new Date(iso + "T00:00:00").toLocaleDateString(undefined, { month: "short", day: "numeric", ...(withYear ? { year: "numeric" } : {}) });
}

function periodLabel(p: { start: string; end: string }, bucket: ObservedSeries["bucket"]) {
  if (bucket === "day") return new Date(p.start + "T00:00:00").toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric", year: "numeric" });
  if (bucket === "month") return new Date(p.start + "T00:00:00").toLocaleDateString(undefined, { month: "long", year: "numeric" });
  return `${fmtDay(p.start)} – ${fmtDay(p.end, true)}`;
}

function tickLabel(iso: string, bucket: ObservedSeries["bucket"]) {
  const d = new Date(iso + "T00:00:00");
  if (bucket === "day") return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  return `${d.toLocaleDateString(undefined, { month: "short" })} '${String(d.getFullYear()).slice(2)}`;
}

function TooltipBody({ active, payload, bucket, series }: any) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="min-w-44 rounded-lg border bg-popover px-3 py-2 text-xs shadow-xl">
      <div className="mb-1.5 font-medium">{periodLabel(p, bucket)}</div>
      {(series as typeof ALL_SERIES).map((s) => (
        <div key={s.key} className="flex items-center gap-2 py-0.5">
          <span className="h-0.5 w-3 rounded-full" style={{ background: s.color }} />
          <span className="text-muted-foreground">{s.label}</span>
          <span className="ml-auto font-semibold tabular text-foreground">{fmt(p[s.key])}</span>
        </div>
      ))}
    </div>
  );
}

/** Direct label at the end of a line: the last point's value. */
function EndLabel(count: number) {
  return ({ x, y, value, index }: any) =>
    index === count - 1 ? (
      <text x={x + 6} y={y} dy={4} fontSize={11} fill="var(--chart-ink)" className="tabular">
        {fmt(value)}
      </text>
    ) : null;
}

export function ObservedChart() {
  const [range, setRange] = useState<ObservedRange>("12m");
  const [view, setView] = useState<"chart" | "table">("chart");
  const [mode, setMode] = useState<"period" | "cumulative">("period");
  const q = useQuery({
    queryKey: ["dashboard-observed", range],
    queryFn: () => get<ObservedSeries>(`/dashboard/observed?range=${range}`),
    placeholderData: keepPreviousData,
  });
  const d = q.data;
  const bucketWord = d ? { day: "day", week: "week", month: "month" }[d.bucket] : "";
  const SERIES = mode === "cumulative" ? CUMULATIVE : ALL_SERIES;
  const points = useMemo(() => {
    if (!d) return [];
    let running = d.first_observed_before;
    return d.points.map((p) => ({ ...p, cumulative: (running += p.first_observed) }));
  }, [d]);
  // Weekly buckets: one tick per month (its first week) so month labels never repeat.
  const monthTicks = useMemo(() => {
    if (!d || d.bucket !== "week") return undefined;
    return d.points.filter((p, i) => i === 0 || p.start.slice(0, 7) !== d.points[i - 1].start.slice(0, 7)).map((p) => p.start);
  }, [d]);

  return (
    <Card className="flex h-full flex-col overflow-hidden">
      <CardHeader
        title="Observables over time"
        description={
          !d
            ? "Observables by when Torq first observed them"
            : mode === "cumulative"
              ? `${fmt(d.first_observed_before + d.totals.first_observed)} observables in total, +${fmt(d.totals.first_observed)} in this period`
              : `${fmt(d.totals.first_observed)} observables first observed in this period, per ${bucketWord}`
        }
        action={
          <div className="flex flex-wrap items-center justify-end gap-2">
            <Segmented
              value={mode}
              onChange={setMode}
              options={[
                { value: "period", label: "Per period" },
                { value: "cumulative", label: "Cumulative" },
              ]}
              className="[&_button]:px-2 [&_button]:py-1 [&_button]:text-xs"
            />
            <Segmented value={range} onChange={setRange} options={RANGES} className="[&_button]:px-2 [&_button]:py-1 [&_button]:text-xs" />
            <Segmented
              value={view}
              onChange={setView}
              options={[
                { value: "chart", label: <BarChart3 aria-label="Chart view" /> },
                { value: "table", label: <Table2 aria-label="Table view" /> },
              ]}
              className="[&_button]:px-2 [&_button]:py-1"
            />
          </div>
        }
      />
      <CardBody className="flex min-h-0 flex-1 flex-col pt-3">
        {!!d?.undated && (
          <div className="mb-2 text-right text-xs text-muted-foreground">{fmt(d.undated)} without timestamps not shown</div>
        )}
        {!d ? (
          <Skeleton className="min-h-0 flex-1" />
        ) : view === "table" ? (
          <div className="min-h-0 flex-1 overflow-auto rounded-xl border">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-muted text-xs text-muted-foreground">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Period</th>
                  {[...ALL_SERIES, ...CUMULATIVE].map((s) => (
                    <th key={s.key} className="px-3 py-2 text-right font-medium">{s.key === "cumulative" ? "Running total" : s.label}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y tabular">
                {[...points].reverse().map((p) => (
                  <tr key={p.start}>
                    <td className="px-3 py-1.5">{periodLabel(p, d.bucket)}</td>
                    <td className="px-3 py-1.5 text-right">{fmt(p.first_observed)}</td>
                    <td className="px-3 py-1.5 text-right">{fmt(p.cumulative)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className={cn("min-h-0 flex-1 transition-opacity", q.isFetching && q.isPlaceholderData && "opacity-60")}>
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={points} margin={{ top: 10, right: 36, left: 0, bottom: 0 }}>
                <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
                <XAxis
                  dataKey="start"
                  tick={axisTick}
                  tickLine={false}
                  axisLine={{ stroke: "var(--chart-grid)" }}
                  tickFormatter={(v: string) => tickLabel(v, d.bucket)}
                  ticks={monthTicks}
                  interval={monthTicks ? "preserveStartEnd" : undefined}
                  minTickGap={32}
                />
                <YAxis tick={axisTick} tickLine={false} axisLine={false} width={44} allowDecimals={false} tickFormatter={fmt} />
                <RTooltip cursor={{ stroke: "var(--chart-axis)", strokeWidth: 1 }} content={<TooltipBody bucket={d.bucket} series={SERIES} />} />
                <Area
                  type="linear"
                  dataKey={SERIES[0].key}
                  stroke="none"
                  fill="var(--series-1)"
                  fillOpacity={0.1}
                  isAnimationActive={false}
                  activeDot={false}
                />
                {SERIES.map((s) => (
                  <Line
                    key={s.key}
                    type="linear"
                    dataKey={s.key}
                    name={s.label}
                    stroke={s.color}
                    strokeWidth={2}
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    dot={false}
                    activeDot={{ r: 4, stroke: "var(--chart-surface)", strokeWidth: 2, fill: s.color }}
                    animationDuration={700}
                  >
                    <LabelList dataKey={s.key} content={EndLabel(points.length)} />
                  </Line>
                ))}
              </ComposedChart>
            </ResponsiveContainer>
          </div>
        )}
      </CardBody>
    </Card>
  );
}
