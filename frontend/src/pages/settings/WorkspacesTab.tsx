import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { CheckCircle2, KeyRound, Pencil, Plug, Plus, RefreshCw, Server, Trash2, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { ApiCallList } from "@/components/ApiCallList";
import { SyncStatusPill } from "@/components/bits";
import { REGIONS, RegionFlag, type Region } from "@/components/RegionFlag";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useConfirmWithOption } from "@/components/ui/confirm";
import { removalOption, type DeleteImpact } from "@/components/SourceRemoval";
import { Modal } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty";
import { Field, Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { del, get, patch, post } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useStartSync, useSyncStatus } from "@/lib/sync";
import type { ApiCall, Workspace } from "@/lib/types";
import { cn, errorMessage, fmt } from "@/lib/utils";

interface FormState {
  name: string;
  region: Region;
  client_id: string;
  client_secret: string;
  priority: number;
  enabled: boolean;
}

const EMPTY: FormState = { name: "", region: "us", client_id: "", client_secret: "", priority: 100, enabled: true };

function WorkspaceDialog({ open, onOpenChange, initial }: { open: boolean; onOpenChange: (o: boolean) => void; initial: Workspace | null }) {
  const qc = useQueryClient();
  const [form, setForm] = useState<FormState>(EMPTY);
  const [test, setTest] = useState<{ ok: boolean; message: string; calls?: ApiCall[] } | null>(null);
  useEffect(() => {
    if (open) {
      setForm(
        initial
          ? {
              name: initial.name,
              region: initial.region,
              client_id: initial.client_id,
              client_secret: "",
              priority: initial.priority,
              enabled: initial.enabled,
            }
          : EMPTY,
      );
      setTest(null);
    }
  }, [open, initial]);
  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => {
    setForm((f) => ({ ...f, [k]: v }));
    setTest(null);
  };

  const testM = useMutation({
    mutationFn: () =>
      post<{ ok: boolean; message: string; calls: ApiCall[] }>("/workspaces/test", {
        workspace_id: initial?.id,
        region: form.region,
        client_id: form.client_id,
        client_secret: form.client_secret,
      }),
    onSuccess: setTest,
    onError: (e) => setTest({ ok: false, message: errorMessage(e) }),
  });

  const save = useMutation({
    mutationFn: () => {
      const body: Partial<FormState> = { ...form };
      if (initial && !body.client_secret) delete body.client_secret;
      return initial ? patch(`/workspaces/${initial.id}`, body) : post("/workspaces", body);
    },
    onSuccess: () => {
      toast.success(initial ? "Workspace updated" : "Workspace connected");
      qc.invalidateQueries({ queryKey: ["workspaces"] });
      qc.invalidateQueries({ queryKey: ["dashboard"] });
      onOpenChange(false);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  const canSubmit = form.name.trim() && form.client_id.trim() && (initial || form.client_secret.trim());

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={initial ? `Edit ${initial.name}` : "Connect a Torq workspace"}
      description="Use a Torq service account API key (client ID & secret) created in the workspace's API Keys settings."
      footer={
        <>
          <Button variant="outline" className="mr-auto" onClick={() => testM.mutate()} loading={testM.isPending} disabled={!form.client_id || (!initial && !form.client_secret)}>
            <Plug /> Test connection
          </Button>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!canSubmit}>
            {initial ? "Save" : "Connect"}
          </Button>
        </>
      }
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Display name" className="sm:col-span-2">
          <Input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="e.g. Production SOC" autoFocus />
        </Field>
        <Field label="Region" className="sm:col-span-2" hint="The Torq deployment the workspace lives in (its URL domain).">
          <div className="grid grid-cols-3 gap-2" role="radiogroup" aria-label="Region">
            {(Object.keys(REGIONS) as Region[]).map((r) => (
              <button
                key={r}
                type="button"
                role="radio"
                aria-checked={form.region === r}
                onClick={() => set("region", r)}
                className={cn(
                  "flex items-center gap-2 rounded-lg border px-3 py-2 text-left text-sm transition-all",
                  form.region === r ? "border-primary/60 bg-accent ring-1 ring-primary/40" : "bg-card hover:border-ring/40",
                )}
              >
                <RegionFlag region={r} height={14} />
                <span className="min-w-0">
                  <span className="block font-medium">{REGIONS[r].label}</span>
                  <span className="block truncate font-mono text-[10px] text-muted-foreground">{REGIONS[r].api}</span>
                </span>
              </button>
            ))}
          </div>
        </Field>
        <Field label="Priority" hint="Lower wins under the workspace-priority collision strategy.">
          <Input type="number" value={form.priority} onChange={(e) => set("priority", Number(e.target.value))} />
        </Field>
        <Field label="Client ID" className="sm:col-span-2">
          <Input value={form.client_id} onChange={(e) => set("client_id", e.target.value)} className="font-mono" autoComplete="off" />
        </Field>
        <Field label="Client secret" className="sm:col-span-2" hint={initial ? "Leave blank to keep the stored secret." : "Stored encrypted at rest."}>
          <Input
            type="password"
            value={form.client_secret}
            onChange={(e) => set("client_secret", e.target.value)}
            placeholder={initial ? "••••••••••••" : ""}
            className="font-mono"
            autoComplete="new-password"
          />
        </Field>
        <label className="flex items-center gap-3 text-sm sm:col-span-2">
          <Switch checked={form.enabled} onCheckedChange={(v) => set("enabled", v)} aria-label="Enabled" />
          Include this workspace in synchronization
        </label>
        <AnimatePresence>
          {test && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="sm:col-span-2"
            >
              <div
                className={cn(
                  "flex items-start gap-2 rounded-xl border p-3 text-sm",
                  test.ok ? "border-success/30 bg-success/10 text-success" : "border-destructive/30 bg-destructive/10 text-destructive",
                )}
              >
                {test.ok ? <CheckCircle2 className="mt-0.5 size-4 shrink-0" /> : <XCircle className="mt-0.5 size-4 shrink-0" />}
                <span className="break-all">{test.message}</span>
              </div>
              {!!test.calls?.length && (
                <details className="group mt-3" open={!test.ok}>
                  <summary className="cursor-pointer select-none text-xs font-medium text-muted-foreground hover:text-foreground">
                    API calls ({test.calls.length})
                  </summary>
                  <div className="mt-2">
                    <ApiCallList calls={test.calls} />
                  </div>
                </details>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </Modal>
  );
}

export default function WorkspacesTab() {
  const qc = useQueryClient();
  const { can } = useAuth();
  const confirmWithOption = useConfirmWithOption();
  const admin = can("admin");
  const q = useQuery({ queryKey: ["workspaces"], queryFn: () => get<Workspace[]>("/workspaces") });
  const sync = useStartSync();
  const status = useSyncStatus();
  const [dialog, setDialog] = useState<{ open: boolean; ws: Workspace | null }>({ open: false, ws: null });

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => patch(`/workspaces/${id}`, { enabled }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["workspaces"] }),
    onError: (e) => toast.error(errorMessage(e)),
  });

  const remove = async (ws: Workspace) => {
    const impact = await get<DeleteImpact>(`/workspaces/${ws.id}/delete-impact`).catch(() => null);
    const choice = await confirmWithOption({
      title: `Disconnect ${ws.name}?`,
      description: "Beacon stops syncing with this workspace. Rules referencing it are updated (and disabled if left empty).",
      confirmLabel: "Disconnect",
      destructive: true,
      option: removalOption(impact, "workspace"),
    });
    if (!choice.confirmed) return;
    try {
      await del(`/workspaces/${ws.id}${choice.option ? "?remove_observables=true" : ""}`);
      toast.success(choice.option && impact ? `Workspace disconnected and ${fmt(impact.observables)} observable(s) deleted` : "Workspace disconnected");
      ["workspaces", "rules", "dashboard", "observables"].forEach((k) => qc.invalidateQueries({ queryKey: [k] }));
    } catch (e) {
      toast.error(errorMessage(e));
    }
  };

  return (
    <>
      <div className="mb-4 flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {q.data ? `${q.data.length} connected workspace${q.data.length === 1 ? "" : "s"}` : "Loading…"}
        </p>
        {admin && (
          <Button onClick={() => setDialog({ open: true, ws: null })}>
            <Plus /> Add workspace
          </Button>
        )}
      </div>

      {q.isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">{[0, 1, 2].map((i) => <Skeleton key={i} className="h-48 rounded-2xl" />)}</div>
      ) : (q.data ?? []).length === 0 ? (
        <Card>
          <EmptyState
            icon={<Server />}
            title="No workspaces connected"
            description="Create a service API key in each Torq workspace, then add it here."
            action={admin && <Button onClick={() => setDialog({ open: true, ws: null })}><Plus /> Add workspace</Button>}
          />
        </Card>
      ) : (
        <motion.div layout className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <AnimatePresence>
            {q.data!.map((ws, i) => (
              <motion.div
                key={ws.id}
                layout
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0, transition: { delay: i * 0.04 } }}
                exit={{ opacity: 0, scale: 0.95 }}
              >
                <Card className={cn("flex h-full flex-col p-5 transition-all hover:shadow-glow/0 hover:-translate-y-0.5", !ws.enabled && "opacity-70")}>
                  <div className="flex items-start gap-3">
                    <div className="grid size-10 shrink-0 place-items-center rounded-xl bg-gradient-to-br from-primary/15 to-primary/5 text-primary">
                      <Server className="size-5" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <h3 className="flex min-w-0 items-center gap-1.5 font-semibold">
                          <RegionFlag region={ws.region} height={13} />
                          <span className="truncate">{ws.name}</span>
                        </h3>
                        <Badge tone="outline" title={REGIONS[ws.region]?.api}>
                          {ws.region.toUpperCase()}
                        </Badge>
                      </div>
                      <div className="mt-0.5 flex items-center gap-1 truncate font-mono text-xs text-muted-foreground">
                        <KeyRound className="size-3 shrink-0" />
                        {ws.client_id.length > 14 ? `${ws.client_id.slice(0, 6)}…${ws.client_id.slice(-4)}` : ws.client_id}
                      </div>
                    </div>
                    <Switch checked={ws.enabled} onCheckedChange={(enabled) => toggle.mutate({ id: ws.id, enabled })} disabled={!admin} aria-label="Enabled" />
                  </div>

                  <div className="mt-4 grid grid-cols-3 gap-2 rounded-xl bg-muted/40 p-3 text-center">
                    <div>
                      <div className="text-lg font-semibold tabular">{fmt(ws.origin_count)}</div>
                      <div className="text-[11px] text-muted-foreground">Native</div>
                    </div>
                    <div>
                      <div className="text-lg font-semibold tabular">{fmt(ws.pushed_count)}</div>
                      <div className="text-[11px] text-muted-foreground">Synced in</div>
                    </div>
                    <div>
                      <div className="text-lg font-semibold tabular">{ws.priority}</div>
                      <div className="text-[11px] text-muted-foreground">Priority</div>
                    </div>
                  </div>

                  <div className="mt-4 flex items-center justify-between gap-2">
                    <SyncStatusPill status={ws.last_sync_status} at={ws.last_sync_at} error={ws.last_error} />
                  </div>
                  {ws.last_error && <p className="mt-2 line-clamp-2 break-all text-xs text-destructive/80">{ws.last_error}</p>}

                  <div className="mt-auto flex items-center gap-1 pt-4">
                    {can("edit") && (
                      <Button
                        size="sm"
                        variant="subtle"
                        onClick={() => sync.mutate(ws.id)}
                        disabled={!ws.enabled || status.data?.running}
                        title="Pull from this workspace and push allowed observables into it"
                      >
                        <RefreshCw className={cn(status.data?.running && "animate-spin")} /> Sync
                      </Button>
                    )}
                    <div className="flex-1" />
                    {admin && (
                      <>
                        <Button size="icon-sm" variant="ghost" onClick={() => setDialog({ open: true, ws })} aria-label="Edit">
                          <Pencil />
                        </Button>
                        <Button size="icon-sm" variant="ghost" className="text-destructive hover:bg-destructive/10" onClick={() => remove(ws)} aria-label="Delete">
                          <Trash2 />
                        </Button>
                      </>
                    )}
                  </div>
                </Card>
              </motion.div>
            ))}
          </AnimatePresence>
        </motion.div>
      )}

      <WorkspaceDialog open={dialog.open} onOpenChange={(open) => setDialog((d) => ({ ...d, open }))} initial={dialog.ws} />
    </>
  );
}
