import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { AlertTriangle, BarChart3, Sparkles, Table2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis } from "recharts";
import { get } from "@/lib/api";
import { useProviders } from "@/lib/integrations";
import { ProviderLogo } from "@/pages/settings/IntegrationsTab";
import type { EnrichmentSeries, ObservedRange } from "@/lib/types";
import { cn, fmt } from "@/lib/utils";
import { Card, CardBody, CardHeader } from "./ui/card";
import { EmptyState } from "./ui/empty";
import { Segmented } from "./ui/segmented";
import { Skeleton } from "./ui/skeleton";

const RANGES: { value: ObservedRange; label: string }[] = [
  { value: "all", label: "All" },
  { value: "12m", label: "12M" },
  { value: "3m", label: "3M" },
  { value: "30d", label: "30D" },
  { value: "7d", label: "7D" },
];

const axisTick = { fill: "var(--chart-axis)", fontSize: 11 };

function periodLabel(p: { start: string; end: string }, bucket: EnrichmentSeries["bucket"]) {
  const d = (iso: string, o: Intl.DateTimeFormatOptions) => new Date(iso + "T00:00:00").toLocaleDateString(undefined, o);
  if (bucket === "day") return d(p.start, { weekday: "short", month: "short", day: "numeric", year: "numeric" });
  if (bucket === "month") return d(p.start, { month: "long", year: "numeric" });
  return `${d(p.start, { month: "short", day: "numeric" })} – ${d(p.end, { month: "short", day: "numeric", year: "numeric" })}`;
}

function tickLabel(iso: string, bucket: EnrichmentSeries["bucket"]) {
  const d = new Date(iso + "T00:00:00");
  if (bucket === "day") return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  return `${d.toLocaleDateString(undefined, { month: "short" })} '${String(d.getFullYear()).slice(2)}`;
}

type Series = { id: string; name: string; color: string };

function TooltipBody({ active, payload, bucket, series }: { active?: boolean; payload?: any[]; bucket: EnrichmentSeries["bucket"]; series: Series[] }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="min-w-48 rounded-lg border bg-popover px-3 py-2 text-xs shadow-xl">
      <div className="mb-1.5 font-medium">{periodLabel(p, bucket)}</div>
      {[...series].reverse().map((s) =>
        p[s.id] ? (
          <div key={s.id} className="flex items-center gap-2 py-0.5">
            <span className="size-2 rounded-sm" style={{ background: s.color }} />
            <span className="text-muted-foreground">{s.name}</span>
            <span className="ml-auto font-semibold tabular text-foreground">{fmt(p[s.id])}</span>
          </div>
        ) : null,
      )}
      <div className="mt-1 flex border-t pt-1 font-medium">
        <span>Total</span>
        <span className="ml-auto tabular">{fmt(p.total)}</span>
      </div>
    </div>
  );
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="min-w-0 rounded-xl bg-muted/40 px-3 py-2">
      <div className="truncate text-[11px] text-muted-foreground">{label}</div>
      <div className="text-lg font-semibold tabular leading-tight">{value}</div>
      {sub && <div className="truncate text-[11px] text-muted-foreground">{sub}</div>}
    </div>
  );
}

const pct = (n: number, d: number) => (d ? `${Math.round((n / d) * 100)}%` : "–");

/** Threat-intel lookups done by the platform, stacked by integration. */
export function EnrichmentChart() {
  const [range, setRange] = useState<ObservedRange>("30d");
  const [view, setView] = useState<"chart" | "table">("chart");
  const providers = useProviders();
  const q = useQuery({
    queryKey: ["dashboard-enrichment", range],
    queryFn: () => get<EnrichmentSeries>(`/dashboard/enrichment?range=${range}`),
    placeholderData: keepPreviousData,
    refetchInterval: 30000,
  });
  const d = q.data;

  // Two series (validated pair). Integrations are shown as a labelled ranked list: seven provider colors can't all
  // stay distinguishable when any two may end up adjacent in a stack.
  const series: Series[] = [
    { id: "automatic", name: "By enrichment rules", color: "var(--series-1)" },
    { id: "manual", name: "Manual", color: "var(--series-2)" },
  ];
  const logo = (id: string) => {
    const p = providers.data?.find((x) => x.id === id);
    return { id, name: p?.name ?? id, color: p?.color ?? "var(--chart-axis)", monogram: p?.monogram };
  };
  const points = d?.points ?? [];
  const monthTicks = useMemo(() => {
    if (!d || d.bucket !== "week") return undefined;
    return d.points.filter((p, i) => i === 0 || p.start.slice(0, 7) !== d.points[i - 1].start.slice(0, 7)).map((p) => p.start);
  }, [d]);
  const t = d?.totals;
  const max = Math.max(1, ...(d?.providers.map((p) => p.lookups) ?? [1]));

  return (
    <Card className="flex h-full flex-col overflow-hidden">
      <CardHeader
        title="Threat-intel enrichment"
        description={
          !d || !t
            ? "Lookups done by your threat-intel integrations"
            : `${fmt(t.lookups)} lookup${t.lookups === 1 ? "" : "s"} in this period, ${pct(t.automatic, t.lookups)} automatic by enrichment rules`
        }
        action={
          <div className="flex flex-wrap items-center justify-end gap-2">
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
      <CardBody className="flex min-h-0 flex-1 flex-col gap-3 pt-3">
        {!d || !t ? (
          <Skeleton className="min-h-0 flex-1" />
        ) : (
          <>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Stat label="Lookups" value={fmt(t.lookups)} sub={`${fmt(t.manual)} manual`} />
              <Stat label="Automatic (rules)" value={pct(t.automatic, t.lookups)} sub={`${fmt(t.automatic)} lookups`} />
              <Stat label="Observables enriched" value={fmt(t.observables)} sub="in this period" />
              <Stat
                label="Database coverage"
                value={pct(d.coverage.enriched, d.coverage.observables)}
                sub={`${fmt(d.coverage.enriched)} of ${fmt(d.coverage.observables)} have intel`}
              />
            </div>
            {t.lookups === 0 ? (
              <div className="grid min-h-0 flex-1 place-items-center">
                <EmptyState
                  icon={<Sparkles />}
                  title="No threat-intel lookups in this period"
                  description={
                    <>
                      Enrich observables from the Database, or set up{" "}
                      <Link to="/rules?view=enrichment" className="text-primary hover:underline">enrichment rules</Link> to do it automatically.
                    </>
                  }
                />
              </div>
            ) : view === "table" ? (
              <div className="min-h-0 flex-1 overflow-auto rounded-xl border">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-muted text-xs text-muted-foreground">
                    <tr>
                      <th className="px-3 py-2 text-left font-medium">Period</th>
                      <th className="px-3 py-2 text-right font-medium">By rules</th>
                      <th className="px-3 py-2 text-right font-medium">Manual</th>
                      {d.providers.map((p) => <th key={p.provider} className="px-3 py-2 text-right font-medium">{p.name}</th>)}
                      <th className="px-3 py-2 text-right font-medium">Total</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y tabular">
                    {[...points].reverse().filter((p) => p.total > 0).map((p) => (
                      <tr key={p.start}>
                        <td className="px-3 py-1.5">{periodLabel(p, d.bucket)}</td>
                        <td className="px-3 py-1.5 text-right">{fmt(p.automatic)}</td>
                        <td className="px-3 py-1.5 text-right">{fmt(p.manual)}</td>
                        {d.providers.map((x) => <td key={x.provider} className="px-3 py-1.5 text-right">{fmt(p.providers[x.provider] ?? 0)}</td>)}
                        <td className="px-3 py-1.5 text-right font-medium">{fmt(p.total)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="flex min-h-0 flex-1 flex-col gap-4 md:flex-row">
                <div className="flex min-h-[160px] min-w-0 flex-1 flex-col">
                  {/* Legend with totals: identity never rests on color alone. */}
                  <div className="mb-1 flex flex-wrap gap-x-4 gap-y-1 text-xs">
                    {series.map((s) => (
                      <span key={s.id} className="inline-flex items-center gap-1.5">
                        <span className="size-2.5 rounded-sm" style={{ background: s.color }} />
                        <span className="text-muted-foreground">{s.name}</span>
                        <span className="font-semibold tabular">{fmt(s.id === "automatic" ? t.automatic : t.manual)}</span>
                      </span>
                    ))}
                  </div>
                  <div className={cn("min-h-0 flex-1 transition-opacity", q.isFetching && q.isPlaceholderData && "opacity-60")}>
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={points} margin={{ top: 6, right: 8, left: 0, bottom: 0 }} barCategoryGap="22%">
                        <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
                        <XAxis
                          dataKey="start"
                          tick={axisTick}
                          tickLine={false}
                          axisLine={{ stroke: "var(--chart-grid)" }}
                          tickFormatter={(v: string) => tickLabel(v, d.bucket)}
                          ticks={monthTicks}
                          interval={monthTicks ? "preserveStartEnd" : undefined}
                          minTickGap={28}
                        />
                        <YAxis tick={axisTick} tickLine={false} axisLine={false} width={40} allowDecimals={false} tickFormatter={fmt} />
                        <RTooltip cursor={{ fill: "var(--chart-grid)", fillOpacity: 0.5 }} content={<TooltipBody bucket={d.bucket} series={series} />} />
                        {series.map((s, i) => (
                          <Bar
                            key={s.id}
                            dataKey={s.id}
                            name={s.name}
                            stackId="lookups"
                            fill={s.color}
                            stroke="var(--chart-surface)"
                            strokeWidth={2}
                            maxBarSize={28}
                            radius={i === series.length - 1 ? [4, 4, 0, 0] : 0}
                            animationDuration={600}
                          />
                        ))}
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
                <div className="flex shrink-0 flex-col md:w-60">
                  <div className="mb-2 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">By integration</div>
                  <ul className="flex min-h-0 flex-col gap-2.5 overflow-y-auto text-xs">
                    {d.providers.map((p) => (
                      <li key={p.provider} className="flex items-center gap-2">
                        <ProviderLogo provider={logo(p.provider)} size={22} />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="truncate font-medium">{p.name}</span>
                            <span className="ml-auto shrink-0 tabular text-muted-foreground">{fmt(p.lookups)} · {pct(p.lookups, t.lookups)}</span>
                          </div>
                          <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-muted">
                            <div className="h-full rounded-full bg-foreground/55" style={{ width: `${(p.lookups / max) * 100}%` }} />
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                  {d.failing_now > 0 && (
                    <div className="mt-auto flex items-center gap-1.5 pt-3 text-[11px] text-muted-foreground">
                      <AlertTriangle className="size-3.5 text-destructive" /> {fmt(d.failing_now)} lookup result{d.failing_now === 1 ? "" : "s"} currently failed
                    </div>
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </CardBody>
    </Card>
  );
}
