import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, BookOpen, Check, Copy, Download, ExternalLink, FileJson, KeyRound, Plus, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { useConfirm } from "@/components/ui/confirm";
import { Modal } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty";
import { Field, Input } from "@/components/ui/input";
import { Segmented } from "@/components/ui/segmented";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { del, get, post } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { cn, errorMessage, formatDate, timeAgo } from "@/lib/utils";

interface ApiKeyRow {
  id: number;
  name: string;
  prefix: string;
  role: "viewer" | "analyst" | "admin";
  created_by: string;
  created_at: string | null;
  last_used_at: string | null;
  expires_at: string | null;
  status: "active" | "expired" | "revoked";
}

const ROLE_HELP: Record<ApiKeyRow["role"], string> = {
  viewer: "Read only: list, query and get observables, rules, sync runs",
  analyst: "Viewer + create/update/delete observables and trigger syncs",
  admin: "Analyst + create/update/delete sync rules",
};

function useCopy() {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = (text: string, id = text) =>
    navigator.clipboard.writeText(text).then(() => {
      setCopied(id);
      setTimeout(() => setCopied((c) => (c === id ? null : c)), 1500);
    });
  return { copied, copy };
}

async function download(path: string, filename: string) {
  try {
    const res = await fetch(path, { credentials: "same-origin" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const blob = new Blob([JSON.stringify(await res.json(), null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
    toast.success(`Downloaded ${filename}`);
  } catch (e) {
    toast.error(`Download failed: ${errorMessage(e)}`);
  }
}

function CreateKeyDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [role, setRole] = useState<ApiKeyRow["role"]>("viewer");
  const [expiry, setExpiry] = useState("90");
  const [created, setCreated] = useState<string | null>(null);
  const { copied, copy } = useCopy();
  useEffect(() => {
    if (open) {
      setName("");
      setRole("viewer");
      setExpiry("90");
      setCreated(null);
    }
  }, [open]);

  const create = useMutation({
    mutationFn: () =>
      post<ApiKeyRow & { key: string }>("/api-keys", { name, role, expires_in_days: expiry === "never" ? null : Number(expiry) }),
    onSuccess: (r) => {
      setCreated(r.key);
      qc.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={created ? "Copy your new API key" : "Create API key"}
      description={created ? undefined : "Keys authenticate requests to the Beacon API as Authorization: Bearer <key>."}
      className="max-w-md"
      footer={
        created ? (
          <Button onClick={() => onOpenChange(false)}>Done</Button>
        ) : (
          <>
            <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button onClick={() => create.mutate()} loading={create.isPending} disabled={!name.trim()}>
              Create key
            </Button>
          </>
        )
      }
    >
      {created ? (
        <div className="space-y-3">
          <div className="flex items-start gap-2 rounded-xl border border-warning/40 bg-warning/10 p-3 text-sm text-amber-800 dark:text-amber-200">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            This is the only time the key is shown. Store it somewhere safe now.
          </div>
          <div className="flex items-center gap-2 rounded-xl border bg-muted/40 p-2">
            <code className="min-w-0 flex-1 break-all px-1 font-mono text-xs">{created}</code>
            <Button size="sm" variant="outline" onClick={() => copy(created, "new-key")}>
              {copied === "new-key" ? <Check /> : <Copy />} {copied === "new-key" ? "Copied" : "Copy"}
            </Button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <Field label="Name" hint="Where it's used, e.g. “SOAR playbook” or “Splunk lookup”.">
            <Input value={name} onChange={(e) => setName(e.target.value)} autoFocus />
          </Field>
          <Field label="Role" hint={ROLE_HELP[role]}>
            <Segmented
              value={role}
              onChange={setRole}
              options={[
                { value: "viewer", label: "Viewer" },
                { value: "analyst", label: "Analyst" },
                { value: "admin", label: "Admin" },
              ]}
            />
          </Field>
          <Field label="Expires">
            <Select value={expiry} onChange={(e) => setExpiry(e.target.value)}>
              <option value="30">In 30 days</option>
              <option value="90">In 90 days</option>
              <option value="365">In 1 year</option>
              <option value="never">Never</option>
            </Select>
          </Field>
        </div>
      )}
    </Modal>
  );
}

function CodeSnippet({ title, code }: { title: string; code: string }) {
  const { copied, copy } = useCopy();
  return (
    <div className="overflow-hidden rounded-xl border">
      <div className="flex items-center justify-between border-b bg-muted/40 px-3 py-1.5 text-xs font-medium">
        {title}
        <button onClick={() => copy(code)} className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-muted-foreground hover:bg-muted hover:text-foreground">
          {copied === code ? <Check className="size-3.5" /> : <Copy className="size-3.5" />} {copied === code ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto p-3 font-mono text-[11.5px] leading-relaxed">{code}</pre>
    </div>
  );
}

export default function ApiTab() {
  const { can } = useAuth();
  const admin = can("admin");
  const confirm = useConfirm();
  const qc = useQueryClient();
  const [createOpen, setCreateOpen] = useState(false);
  const { copied, copy } = useCopy();
  const base = `${window.location.origin}/api/v1`;
  const keys = useQuery({ queryKey: ["api-keys"], queryFn: () => get<ApiKeyRow[]>("/api-keys"), enabled: admin });

  const revoke = async (k: ApiKeyRow) => {
    if (!(await confirm({ title: `Revoke “${k.name}”?`, description: "Requests using this key will be rejected immediately.", confirmLabel: "Revoke", destructive: true }))) return;
    try {
      await del(`/api-keys/${k.id}`);
      toast.success("Key revoked");
      qc.invalidateQueries({ queryKey: ["api-keys"] });
    } catch (e) {
      toast.error(errorMessage(e));
    }
  };

  const snippets = [
    {
      title: "Query malicious IPs observed this year",
      code: `curl -s -X POST "${base}/observables/query" \\\n  -H "Authorization: Bearer $BEACON_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '{"types":["TYPE_ID_IP_ADDRESS"],"min_severity":8,"last_observed":{"from":"${new Date().getFullYear()}-01-01T00:00:00Z"},"page_size":100}'`,
    },
    {
      title: "Add an observable",
      code: `curl -s -X POST "${base}/observables" \\\n  -H "Authorization: Bearer $BEACON_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '{"type":"TYPE_ID_URL","value":"https://phish.example/login","reputation":"SCORE_MALICIOUS"}'`,
    },
    {
      title: "Trigger a sync and check its result",
      code: `RUN=$(curl -s -X POST "${base}/sync" -H "Authorization: Bearer $BEACON_API_KEY" | jq .run_id)\ncurl -s "${base}/sync/runs/$RUN" -H "Authorization: Bearer $BEACON_API_KEY"`,
    },
  ];

  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_420px]">
      <div className="space-y-4">
        <Card>
          <CardHeader title="Documentation" description="Interactive reference and client collections for the Beacon REST API (v1)" />
          <CardBody className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-3">
              <a
                href="/api/v1/docs"
                target="_blank"
                rel="noreferrer"
                className="group flex flex-col gap-2 rounded-xl border p-4 transition-all hover:-translate-y-0.5 hover:border-primary/40 hover:shadow-soft"
              >
                <span className="grid size-9 place-items-center rounded-lg bg-[#85EA2D]/20 text-[#3b7d0b] dark:text-[#85EA2D]">
                  <BookOpen className="size-4" />
                </span>
                <span className="text-sm font-medium">Swagger UI <ExternalLink className="ml-0.5 inline size-3 opacity-60" /></span>
                <span className="text-xs text-muted-foreground">Browse endpoints and try requests with your key or session.</span>
              </a>
              <button
                onClick={() => download("/api/v1/postman.json", "Beacon API.postman_collection.json")}
                className="group flex flex-col gap-2 rounded-xl border p-4 text-left transition-all hover:-translate-y-0.5 hover:border-primary/40 hover:shadow-soft"
              >
                <span className="grid size-9 place-items-center rounded-lg bg-[#FF6C37]/15 text-[#FF6C37]">
                  <Download className="size-4" />
                </span>
                <span className="text-sm font-medium">Postman collection</span>
                <span className="text-xs text-muted-foreground">v2.1 · set the <code>apiKey</code> variable after importing.</span>
              </button>
              <button
                onClick={() => download("/api/v1/openapi.json", "beacon-openapi.json")}
                className="group flex flex-col gap-2 rounded-xl border p-4 text-left transition-all hover:-translate-y-0.5 hover:border-primary/40 hover:shadow-soft"
              >
                <span className="grid size-9 place-items-center rounded-lg bg-accent text-accent-foreground">
                  <FileJson className="size-4" />
                </span>
                <span className="text-sm font-medium">OpenAPI spec</span>
                <span className="text-xs text-muted-foreground">OpenAPI 3.1 JSON for code generators and gateways.</span>
              </button>
            </div>
            <Field label="Base URL">
              <div className="flex items-center gap-2">
                <code className="flex h-9 min-w-0 flex-1 items-center truncate rounded-lg border bg-muted/40 px-3 font-mono text-sm">{base}</code>
                <Button variant="outline" size="icon" onClick={() => copy(base, "base")} aria-label="Copy base URL">
                  {copied === "base" ? <Check /> : <Copy />}
                </Button>
              </div>
            </Field>
            <div className="grid gap-2 text-xs text-muted-foreground sm:grid-cols-2">
              <div><span className="font-medium text-foreground">Sync</span> · POST /sync, GET /sync/status, GET /sync/runs</div>
              <div><span className="font-medium text-foreground">Rules</span> · GET/POST /rules, GET/PUT/PATCH/DELETE /rules/{"{id}"}</div>
              <div><span className="font-medium text-foreground">Query</span> · POST /observables/query, GET /observables/lookup</div>
              <div><span className="font-medium text-foreground">Observables</span> · GET/POST /observables, GET/PATCH/DELETE /observables/{"{id}"}</div>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            title="API keys"
            description="Each key has a role and can be revoked at any time. Only a hash of the key is stored."
            action={
              admin && (
                <Button size="sm" onClick={() => setCreateOpen(true)}>
                  <Plus /> Create key
                </Button>
              )
            }
          />
          <CardBody className="pt-3">
            {!admin ? (
              <p className="text-sm text-muted-foreground">Ask an admin to create an API key for you.</p>
            ) : keys.isLoading ? (
              <Skeleton className="h-24" />
            ) : !keys.data?.length ? (
              <EmptyState icon={<KeyRound />} title="No API keys yet" description="Create a key to call the API from scripts, SOAR or SIEM tools." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-xs text-muted-foreground">
                    <tr className="border-b">
                      <th className="py-2 text-left font-medium">Name</th>
                      <th className="py-2 text-left font-medium">Key</th>
                      <th className="py-2 text-left font-medium">Role</th>
                      <th className="py-2 text-left font-medium">Last used</th>
                      <th className="py-2 text-left font-medium">Expires</th>
                      <th className="py-2" />
                    </tr>
                  </thead>
                  <tbody className="divide-y">
                    <AnimatePresence initial={false}>
                      {keys.data.map((k) => (
                        <motion.tr key={k.id} layout initial={{ opacity: 0 }} animate={{ opacity: 1 }} className={cn(k.status !== "active" && "opacity-60")}>
                          <td className="py-2.5">
                            <div className="font-medium">{k.name}</div>
                            <div className="text-[11px] text-muted-foreground">by {k.created_by} · {formatDate(k.created_at, false)}</div>
                          </td>
                          <td className="py-2.5 font-mono text-xs">{k.prefix}…</td>
                          <td className="py-2.5">
                            <Badge tone={k.role === "admin" ? "warning" : k.role === "analyst" ? "primary" : "neutral"} className="capitalize">{k.role}</Badge>
                          </td>
                          <td className="py-2.5 text-xs text-muted-foreground">{k.last_used_at ? timeAgo(k.last_used_at) : "Never"}</td>
                          <td className="py-2.5 text-xs">
                            {k.status === "revoked" ? (
                              <Badge tone="danger">Revoked</Badge>
                            ) : k.status === "expired" ? (
                              <Badge tone="danger">Expired</Badge>
                            ) : (
                              <span className="text-muted-foreground">{k.expires_at ? formatDate(k.expires_at, false) : "Never"}</span>
                            )}
                          </td>
                          <td className="py-2.5 text-right">
                            {k.status !== "revoked" && (
                              <Button size="icon-sm" variant="ghost" className="text-destructive hover:bg-destructive/10" onClick={() => revoke(k)} aria-label={`Revoke ${k.name}`}>
                                <Trash2 />
                              </Button>
                            )}
                          </td>
                        </motion.tr>
                      ))}
                    </AnimatePresence>
                  </tbody>
                </table>
              </div>
            )}
          </CardBody>
        </Card>
      </div>

      <Card className="h-fit">
        <CardHeader title="Quick start" description="Export your key, then try these requests" />
        <CardBody className="space-y-3">
          <CodeSnippet title="Set your key" code={`export BEACON_API_KEY="bcn_…"`} />
          {snippets.map((s) => <CodeSnippet key={s.title} title={s.title} code={s.code} />)}
          <p className="text-xs text-muted-foreground">
            Using a self-signed certificate? Add <code>-k</code> to curl, or install your own certificate in the container.
          </p>
        </CardBody>
      </Card>

      <CreateKeyDialog open={createOpen} onOpenChange={setCreateOpen} />
    </div>
  );
}
