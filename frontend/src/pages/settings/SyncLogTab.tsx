import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { Activity, AlertTriangle, ChevronLeft, ChevronRight } from "lucide-react";
import { Fragment, useState } from "react";
import { ApiCallList } from "@/components/ApiCallList";
import { Badge } from "@/components/ui/badge";
import { WorkspaceName } from "@/components/RegionFlag";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { get, qs } from "@/lib/api";
import type { ApiCall, Page, SyncRun, Workspace } from "@/lib/types";
import { cn, fmt, formatDate } from "@/lib/utils";

const STATUS_TONE = { ok: "success", partial: "warning", error: "danger", running: "primary" } as const;
const STATUS_LABEL = { ok: "Success", partial: "Partial", error: "Failed", running: "Running" } as const;
const CALLS_PAGE = 50;

function duration(run: SyncRun) {
  if (!run.started_at || !run.finished_at) return "—";
  const s = (new Date(run.finished_at).getTime() - new Date(run.started_at).getTime()) / 1000;
  return s < 60 ? `${s.toFixed(1)}s` : `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

function RunDetails({ run }: { run: SyncRun }) {
  const [failedOnly, setFailedOnly] = useState(run.api_errors > 0);
  const [page, setPage] = useState(1);
  const q = useQuery({
    queryKey: ["sync-run-calls", run.id, failedOnly, page],
    queryFn: () => get<Page<ApiCall>>(`/sync/runs/${run.id}/calls` + qs({ failed_only: failedOnly || undefined, page, page_size: CALLS_PAGE })),
    placeholderData: keepPreviousData,
  });
  const total = q.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / CALLS_PAGE));

  return (
    <div className="space-y-4 bg-muted/20 px-6 py-4">
      {run.errors.length > 0 && (
        <div>
          <h4 className="mb-1.5 flex items-center gap-1.5 text-xs font-semibold text-destructive">
            <AlertTriangle className="size-3.5" /> Errors
          </h4>
          <ul className="space-y-1 rounded-lg border border-destructive/20 bg-destructive/5 p-3 font-mono text-xs text-destructive">
            {run.errors.map((e, i) => (
              <li key={i} className="break-all">{e}</li>
            ))}
          </ul>
        </div>
      )}
      <div>
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h4 className="text-xs font-semibold">
            Torq API calls{" "}
            <span className="font-normal text-muted-foreground">
              {fmt(run.api_calls)} total · {fmt(run.api_errors)} failed
            </span>
          </h4>
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <Switch
              checked={failedOnly}
              onCheckedChange={(v) => {
                setFailedOnly(v);
                setPage(1);
              }}
              aria-label="Failed calls only"
            />
            Failed calls only
          </label>
        </div>
        {q.isLoading ? (
          <Skeleton className="h-24" />
        ) : (
          <div className={cn("transition-opacity", q.isFetching && "opacity-60")}>
            <ApiCallList calls={q.data?.items ?? []} offset={(page - 1) * CALLS_PAGE} />
          </div>
        )}
        {pages > 1 && (
          <div className="mt-2 flex items-center justify-end gap-2 text-xs text-muted-foreground">
            <span className="tabular">Page {page} of {pages}</span>
            <Button variant="outline" size="icon-sm" disabled={page <= 1} onClick={() => setPage(page - 1)} aria-label="Previous page">
              <ChevronLeft />
            </Button>
            <Button variant="outline" size="icon-sm" disabled={page >= pages} onClick={() => setPage(page + 1)} aria-label="Next page">
              <ChevronRight />
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function SyncLogTab() {
  const q = useQuery({ queryKey: ["sync-runs"], queryFn: () => get<SyncRun[]>("/sync/runs?limit=100"), refetchInterval: 10000 });
  const ws = useQuery({ queryKey: ["workspaces"], queryFn: () => get<Workspace[]>("/workspaces") });
  const [open, setOpen] = useState<number | null>(null);
  const wsName = (id: number | null) => (id === null ? "All workspaces" : ws.data?.find((w) => w.id === id)?.name ?? `#${id}`);

  if (q.isLoading) return <Skeleton className="h-64 rounded-2xl" />;
  if (!q.data?.length) return <Card><EmptyState icon={<Activity />} title="No sync runs yet" description="Runs appear here after the first manual or scheduled sync." /></Card>;

  return (
    <Card className="overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[900px] text-sm">
          <thead className="border-b bg-muted/40 text-xs text-muted-foreground">
            <tr>
              <th className="w-8" />
              <th className="px-3 py-3 text-left font-medium">Started</th>
              <th className="px-3 py-3 text-left font-medium">Scope</th>
              <th className="px-3 py-3 text-left font-medium">Status</th>
              <th className="px-3 py-3 text-right font-medium">Pulled</th>
              <th className="px-3 py-3 text-right font-medium">New</th>
              <th className="px-3 py-3 text-right font-medium">Merged</th>
              <th className="px-3 py-3 text-right font-medium">Conflicts</th>
              <th className="px-3 py-3 text-right font-medium">Pushed</th>
              <th className="px-3 py-3 text-right font-medium">Updated</th>
              <th className="px-3 py-3 text-right font-medium">API calls</th>
              <th className="px-3 py-3 text-right font-medium">Duration</th>
            </tr>
          </thead>
          <tbody className="divide-y tabular">
            {q.data.map((r) => (
              <Fragment key={r.id}>
                <tr className="cursor-pointer transition-colors hover:bg-muted/40" onClick={() => setOpen(open === r.id ? null : r.id)}>
                  <td className="pl-3">
                    <ChevronRight className={cn("size-4 text-muted-foreground transition-transform", open === r.id && "rotate-90")} />
                  </td>
                  <td className="px-3 py-2.5">
                    <div>{formatDate(r.started_at)}</div>
                    <div className="text-xs capitalize text-muted-foreground">
                      {r.trigger}
                      {r.triggered_by && (r.trigger === "manual" || r.trigger === "priority") ? ` · ${r.triggered_by}` : ""}
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-muted-foreground">
                    {r.workspace_id === null ? wsName(null) : <WorkspaceName name={wsName(r.workspace_id)} region={ws.data?.find((w) => w.id === r.workspace_id)?.region} />}
                  </td>
                  <td className="px-3 py-2.5">
                    <Badge tone={STATUS_TONE[r.status]}>{STATUS_LABEL[r.status]}</Badge>
                  </td>
                  <td className="px-3 py-2.5 text-right">{fmt(r.pulled)}</td>
                  <td className="px-3 py-2.5 text-right">{fmt(r.created_central)}</td>
                  <td className="px-3 py-2.5 text-right">{fmt(r.updated_central)}</td>
                  <td className="px-3 py-2.5 text-right">{fmt(r.conflicts)}</td>
                  <td className="px-3 py-2.5 text-right">{fmt(r.pushed_created)}</td>
                  <td className="px-3 py-2.5 text-right">{fmt(r.pushed_updated)}</td>
                  <td className="px-3 py-2.5 text-right">
                    {fmt(r.api_calls)}
                    {r.api_errors > 0 && <span className="ml-1 text-destructive">({fmt(r.api_errors)} failed)</span>}
                  </td>
                  <td className="px-3 py-2.5 text-right text-muted-foreground">{duration(r)}</td>
                </tr>
                <AnimatePresence>
                  {open === r.id && (
                    <tr>
                      <td colSpan={12} className="p-0">
                        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                          <RunDetails run={r} />
                        </motion.div>
                      </td>
                    </tr>
                  )}
                </AnimatePresence>
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
