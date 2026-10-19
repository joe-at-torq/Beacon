import { AlertTriangle, ChevronsDownUp, ChevronsUpDown, Copy, ExternalLink, Sparkles } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { useProviders } from "@/lib/integrations";
import type { IntelEnrichment, IntelProvider, ObservableLink } from "@/lib/types";
import { cn, fmt, formatDate } from "@/lib/utils";
import { ReputationBadge } from "./bits";
import { JsonTree } from "./JsonTree";
import { RegionFlag } from "./RegionFlag";
import { Button } from "./ui/button";
import { Segmented } from "./ui/segmented";

const VERDICT_STYLE: Record<string, { label: string; className: string }> = {
  malicious: { label: "Malicious", className: "bg-destructive/10 text-destructive border-destructive/30" },
  suspicious: { label: "Suspicious", className: "bg-warning/15 text-amber-700 dark:text-amber-300 border-warning/40" },
  harmless: { label: "Harmless", className: "bg-success/10 text-success border-success/30" },
  unknown: { label: "No verdict", className: "bg-muted text-muted-foreground border-border" },
};

function JsonViewer({ data, label, resetKey }: { data: unknown; label: React.ReactNode; resetKey: string }) {
  const [depth, setDepth] = useState(1);
  const [version, setVersion] = useState(0);
  const setAll = (d: number) => {
    setDepth(d);
    setVersion((v) => v + 1);
  };
  return (
    <div className="rounded-xl border bg-muted/20">
      <div className="flex flex-wrap items-center gap-1 border-b px-3 py-1.5 text-xs text-muted-foreground">
        <span className="mr-auto">{label}</span>
        <Button size="sm" variant="ghost" onClick={() => setAll(99)}>
          <ChevronsUpDown /> Expand all
        </Button>
        <Button size="sm" variant="ghost" onClick={() => setAll(1)}>
          <ChevronsDownUp /> Collapse
        </Button>
        <Button size="sm" variant="ghost" onClick={() => navigator.clipboard.writeText(JSON.stringify(data, null, 2)).then(() => toast.success("JSON copied"))}>
          <Copy /> Copy JSON
        </Button>
      </div>
      <div className="max-h-[420px] overflow-auto p-2">
        <JsonTree data={data} defaultDepth={depth} resetKey={`${resetKey}-${version}`} />
      </div>
    </div>
  );
}

/** Readable fact values: thousands separators and local dates for ISO timestamps. */
function factValue(v: string | number | boolean) {
  if (typeof v === "number") return fmt(v);
  if (typeof v === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(v)) return formatDate(v);
  return String(v);
}

function StatBar({ stats }: { stats: Record<string, unknown> }) {
  const parts = [
    { key: "malicious", label: "Malicious", color: "var(--rep-10)" },
    { key: "suspicious", label: "Suspicious", color: "var(--rep-7)" },
    { key: "harmless", label: "Harmless", color: "var(--rep-2)" },
    { key: "undetected", label: "Undetected", color: "var(--rep-0)" },
  ].map((p) => ({ ...p, value: Number(stats[p.key] ?? 0) }));
  const total = parts.reduce((a, p) => a + p.value, 0);
  if (!total) return null;
  return (
    <div>
      <div className="flex h-2 gap-0.5 overflow-hidden rounded-full">
        {parts.filter((p) => p.value).map((p) => (
          <span key={p.key} style={{ width: `${(p.value / total) * 100}%`, background: p.color }} title={`${p.label}: ${p.value}`} />
        ))}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-muted-foreground tabular">
        {parts.map((p) => (
          <span key={p.key} className="inline-flex items-center gap-1">
            <span className="size-2 rounded-full" style={{ background: p.color }} />
            {p.label} <span className="font-semibold text-foreground">{fmt(p.value)}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

function IntelCard({
  item,
  provider,
  currentReputation,
  onApplyReputation,
}: {
  item: IntelEnrichment;
  provider: IntelProvider | undefined;
  currentReputation?: string;
  onApplyReputation?: (rep: string) => void;
}) {
  const s = item.summary;
  const name = provider?.name ?? item.provider;
  if (item.status === "error") {
    return (
      <div className="flex items-start gap-2 rounded-xl border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
        <AlertTriangle className="mt-0.5 size-4 shrink-0" />
        <div>
          <div className="font-medium">{name} lookup failed</div>
          <div className="mt-0.5 break-words text-xs">{item.error}</div>
          <div className="mt-1 text-[11px] text-muted-foreground">{formatDate(item.fetched_at)} · {item.fetched_by}</div>
        </div>
      </div>
    );
  }
  const verdict = VERDICT_STYLE[s.verdict ?? "unknown"] ?? VERDICT_STYLE.unknown;
  const stats = (s.stats ?? {}) as Record<string, unknown>;
  const topPulses = (stats.top_pulses as string[] | undefined) ?? [];
  const families = (stats.malware_families as string[] | undefined) ?? [];
  const canApply = !!s.suggested_reputation && !!onApplyReputation && s.suggested_reputation !== currentReputation;
  return (
    <div className="space-y-3 rounded-xl border p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className={cn("rounded-md border px-2 py-0.5 text-xs font-semibold", verdict.className)}>{verdict.label}</span>
        <span className="text-sm font-medium">{s.headline}</span>
        {s.link && (
          <a href={s.link} target="_blank" rel="noreferrer noopener" className="ml-auto inline-flex items-center gap-1 text-xs font-medium text-primary hover:underline">
            Open in {name} <ExternalLink className="size-3" />
          </a>
        )}
      </div>
      <StatBar stats={stats} />
      {"pulses" in stats && (
        <div className="grid gap-2 text-xs sm:grid-cols-2">
          {topPulses.length > 0 && (
            <div>
              <div className="mb-1 font-medium text-muted-foreground">Top pulses</div>
              <ul className="list-inside list-disc space-y-0.5">{topPulses.map((p) => <li key={p} className="truncate">{p}</li>)}</ul>
            </div>
          )}
          {families.length > 0 && (
            <div>
              <div className="mb-1 font-medium text-muted-foreground">Malware families</div>
              <div className="flex flex-wrap gap-1">{families.map((f) => <span key={f} className="rounded bg-destructive/10 px-1.5 py-0.5 text-destructive">{f}</span>)}</div>
            </div>
          )}
        </div>
      )}
      {!!s.facts?.length && (
        <dl className="grid grid-cols-2 gap-x-4 gap-y-2 rounded-lg bg-muted/30 p-3 text-xs sm:grid-cols-3">
          {s.facts.map((f) => (
            <div key={f.label} className="min-w-0">
              <dt className="text-muted-foreground">{f.label}</dt>
              <dd className="truncate font-medium" title={String(f.value)}>{factValue(f.value)}</dd>
            </div>
          ))}
        </dl>
      )}
      {!s.facts?.length && stats.reputation !== undefined && stats.reputation !== null && (
        <div className="text-xs text-muted-foreground">
          {name} reputation score: <span className="font-semibold text-foreground tabular">{String(stats.reputation)}</span>
        </div>
      )}
      {!!s.tags?.length && (
        <div className="flex flex-wrap gap-1">{s.tags.map((t) => <span key={t} className="rounded-md bg-muted px-1.5 py-0.5 text-[11px]">{t}</span>)}</div>
      )}
      <div className="flex flex-wrap items-center gap-2 border-t pt-3 text-[11px] text-muted-foreground">
        <span>Enriched {formatDate(item.fetched_at)} by {item.fetched_by}</span>
        {s.suggested_reputation && (
          <span className="ml-auto inline-flex items-center gap-1.5">
            Suggested <ReputationBadge value={s.suggested_reputation} />
            {canApply && (
              <Button size="sm" variant="subtle" onClick={() => onApplyReputation!(s.suggested_reputation!)}>
                Apply
              </Button>
            )}
          </span>
        )}
      </div>
    </div>
  );
}

/** Enrichment for an observable: Torq workspace enrichment plus Beacon threat-intel lookups, one tab per source. */
export function EnrichmentPanel({
  links,
  intel = [],
  raw = {},
  currentReputation,
  onApplyReputation,
  regionOf,
  preferSource,
}: {
  links: ObservableLink[];
  intel?: IntelEnrichment[];
  raw?: Record<string, unknown>;
  currentReputation?: string;
  onApplyReputation?: (rep: string) => void;
  regionOf?: (workspaceId: number) => string | undefined;
  preferSource?: string;
}) {
  const providers = useProviders();
  const wsSources = links.filter((l) => l.has_enrichment && l.enrichment).map((l) => ({ key: `ws:${l.workspace_id}`, link: l }));
  // Same order as the providers in Settings → Integrations.
  const order = (id: string) => {
    const i = providers.data?.findIndex((p) => p.id === id) ?? -1;
    return i < 0 ? 99 : i;
  };
  const intelSources = [...intel].sort((a, b) => order(a.provider) - order(b.provider)).map((i) => ({ key: `intel:${i.provider}`, item: i }));
  const keys = [...intelSources.map((s) => s.key), ...wsSources.map((s) => s.key)];
  const [active, setActive] = useState(preferSource && keys.includes(preferSource) ? preferSource : keys[0] ?? "");
  useEffect(() => {
    if (preferSource && keys.includes(preferSource)) setActive(preferSource);
    else if (!keys.includes(active) && keys.length) setActive(keys[0]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [preferSource, keys.join("|")]);

  if (!keys.length) return <p className="text-sm text-muted-foreground">No enrichment yet.</p>;

  const pName = (id: string) => providers.data?.find((p) => p.id === id)?.name ?? id;
  const ws = wsSources.find((s) => s.key === active);
  const it = intelSources.find((s) => s.key === active);
  const wsData = ws?.link.enrichment as Record<string, unknown> | undefined;
  const aiSummary = wsData && typeof wsData.ai_summary === "string" ? wsData.ai_summary : null;

  return (
    <div className="space-y-3">
      {keys.length > 1 && (
        <Segmented
          value={active}
          onChange={setActive}
          className="flex-wrap"
          options={[
            ...intelSources.map((s) => ({ value: s.key, label: <><Sparkles className="text-primary" /> {pName(s.item.provider)}</> })),
            ...wsSources.map((s) => ({
              value: s.key,
              label: (
                <>
                  <RegionFlag region={regionOf?.(s.link.workspace_id)} height={10} /> {s.link.workspace_name}
                </>
              ),
            })),
          ]}
        />
      )}

      {it && (
        <>
          <IntelCard item={it.item} provider={providers.data?.find((p) => p.id === it.item.provider)} currentReputation={currentReputation} onApplyReputation={onApplyReputation} />
          {raw[it.item.provider] !== undefined && (
            <JsonViewer data={raw[it.item.provider]} label={`${pName(it.item.provider)} raw API response`} resetKey={active} />
          )}
        </>
      )}

      {ws && wsData && (
        <>
          {aiSummary && (
            <div className="flex gap-2 rounded-xl border border-primary/20 bg-primary/5 p-3 text-sm">
              <Sparkles className="mt-0.5 size-4 shrink-0 text-primary" />
              <p>{aiSummary}</p>
            </div>
          )}
          <JsonViewer
            data={wsData}
            resetKey={active}
            label={
              <>
                {ws.link.workspace_name} (Torq workspace)
                {ws.link.enrichment_updated_at && <> · updated {formatDate(ws.link.enrichment_updated_at)}</>}
              </>
            }
          />
        </>
      )}
    </div>
  );
}
