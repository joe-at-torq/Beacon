import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef } from "react";
import { toast } from "sonner";
import { get, post } from "./api";
import type { SyncStatus } from "./types";
import { errorMessage } from "./utils";

export function useSyncStatus() {
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["sync-status"],
    queryFn: () => get<SyncStatus>("/sync/status"),
    refetchInterval: (query) => (query.state.data?.running ? 1500 : 15000),
  });
  const wasRunning = useRef(false);
  const lastRunId = useRef<number | null | undefined>(undefined);
  useEffect(() => {
    if (!q.data) return;
    const running = q.data.running;
    const run = q.data.last_run;
    // Refresh data whenever a new run has finished, including scheduled runs that started and ended
    // between two polls.
    const newRun = lastRunId.current !== undefined && (run?.id ?? null) !== lastRunId.current;
    lastRunId.current = run?.id ?? null;
    if (newRun || (wasRunning.current && !running)) {
      ["dashboard", "dashboard-observed", "dashboard-flows", "observables", "observable", "observable-history", "workspaces", "sync-runs", "rule-preview"].forEach((k) =>
        qc.invalidateQueries({ queryKey: [k] }),
      );
    }
    if (wasRunning.current && !running) {
      if (run) {
        const summary = `Pulled ${run.pulled}, +${run.created_central} new, ${run.pushed_created} pushed, ${run.pushed_updated} updated`;
        if (run.status === "ok") toast.success("Sync complete", { description: summary });
        else toast.error(run.status === "partial" ? "Sync finished with errors" : "Sync failed", {
          description: run.errors[0] ?? summary,
        });
      }
    }
    wasRunning.current = running;
  }, [q.data, qc]);
  return q;
}

export function useStartSync() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (workspaceId?: number) => post(workspaceId ? `/workspaces/${workspaceId}/sync` : "/sync/run"),
    onSuccess: () => {
      toast("Sync started");
      qc.invalidateQueries({ queryKey: ["sync-status"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
}
