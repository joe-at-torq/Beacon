import { useMutation, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { CheckCircle2, ExternalLink, KeyRound, Plug, Trash2, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useConfirmWithOption } from "@/components/ui/confirm";
import { Modal } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { del, get, patch, post } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useIntegrations, useProviders } from "@/lib/integrations";
import { FeedsSection } from "./FeedsSection";
import { typeLabel } from "@/lib/meta";
import type { Integration, IntelProvider } from "@/lib/types";
import { cn, errorMessage, fmt, timeAgo } from "@/lib/utils";

/** Brand-colored monogram (no external images: the app runs under a strict CSP). */
export function ProviderLogo({ provider, size = 40 }: { provider: Pick<IntelProvider, "id" | "name" | "color" | "monogram">; size?: number }) {
  const initials = provider.monogram || provider.name.split(/\s+/).map((w) => w[0]).join("").slice(0, 2);
  return (
    <span
      className="grid shrink-0 place-items-center rounded-xl font-bold text-white shadow-sm"
      style={{ width: size, height: size, background: provider.color, fontSize: size * (initials.length > 2 ? 0.28 : 0.36) }}
      aria-hidden
    >
      {initials}
    </span>
  );
}

function invalidate(qc: ReturnType<typeof useQueryClient>) {
  ["integrations", "intel-capabilities"].forEach((k) => qc.invalidateQueries({ queryKey: [k] }));
}

function ConnectDialog({
  provider,
  integration,
  open,
  onOpenChange,
}: {
  provider: IntelProvider;
  integration: Integration | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const qc = useQueryClient();
  const [key, setKey] = useState("");
  const [test, setTest] = useState<{ ok: boolean; message: string } | null>(null);
  useEffect(() => {
    if (open) {
      setKey("");
      setTest(null);
    }
  }, [open]);

  const testM = useMutation({
    mutationFn: () => post<{ ok: boolean; message: string }>("/integrations/test", { provider: provider.id, api_key: key }),
    onSuccess: setTest,
    onError: (e) => setTest({ ok: false, message: errorMessage(e) }),
  });
  const save = useMutation({
    mutationFn: () =>
      integration ? patch(`/integrations/${integration.id}`, { api_key: key }) : post("/integrations", { provider: provider.id, api_key: key }),
    onSuccess: () => {
      toast.success(integration ? `${provider.name} key updated` : `${provider.name} connected`);
      invalidate(qc);
      onOpenChange(false);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={
        <span className="inline-flex items-center gap-2.5">
          <ProviderLogo provider={provider} size={28} /> {integration ? `Update ${provider.name} key` : `Connect ${provider.name}`}
        </span>
      }
      description={provider.description}
      className="max-w-md"
      footer={
        <>
          <Button variant="outline" className="mr-auto" onClick={() => testM.mutate()} loading={testM.isPending} disabled={key.trim().length < 8}>
            <Plug /> Test
          </Button>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => save.mutate()} loading={save.isPending} disabled={key.trim().length < 8}>
            {integration ? "Save key" : "Connect"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <Field
          label="API key"
          hint={
            <>
              {provider.key_help}{" "}
              <a href={provider.docs_url} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-0.5 text-primary hover:underline">
                Docs <ExternalLink className="size-3" />
              </a>
            </>
          }
        >
          <Input type="password" value={key} onChange={(e) => { setKey(e.target.value); setTest(null); }} className="font-mono" autoComplete="off" autoFocus placeholder={integration ? `Current key ${integration.key_hint}` : ""} />
        </Field>
        <p className="text-xs text-muted-foreground">Stored encrypted. Lookups send only the observable value to {provider.name}.</p>
        <AnimatePresence>
          {test && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }}>
              <div className={cn("flex items-start gap-2 rounded-xl border p-3 text-sm", test.ok ? "border-success/30 bg-success/10 text-success" : "border-destructive/30 bg-destructive/10 text-destructive")}>
                {test.ok ? <CheckCircle2 className="mt-0.5 size-4 shrink-0" /> : <XCircle className="mt-0.5 size-4 shrink-0" />}
                <span className="break-words">{test.message}</span>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </Modal>
  );
}

export default function IntegrationsTab() {
  const qc = useQueryClient();
  const { can } = useAuth();
  const admin = can("admin");
  const confirmWithOption = useConfirmWithOption();
  const providers = useProviders();
  const integrations = useIntegrations();
  const [dialog, setDialog] = useState<{ provider: IntelProvider; integration: Integration | null } | null>(null);

  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) => patch(`/integrations/${id}`, { enabled }),
    onSettled: () => invalidate(qc),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const testStored = useMutation({
    mutationFn: (provider: string) => post<{ ok: boolean; message: string }>("/integrations/test", { provider }),
    onSuccess: (r) => (r.ok ? toast.success(r.message) : toast.error(r.message)),
    onSettled: () => invalidate(qc),
  });

  if (providers.isLoading || integrations.isLoading) {
    return <div className="grid gap-4 md:grid-cols-2">{[0, 1].map((i) => <Skeleton key={i} className="h-56 rounded-2xl" />)}</div>;
  }

  return (
    <>
      <p className="mb-4 text-sm text-muted-foreground">
        Connect threat-intelligence providers to enrich observables on demand from the Database. Results and the raw API responses are stored with each observable.
      </p>
      <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
        {(providers.data ?? []).map((p, i) => {
          const integ = integrations.data?.find((x) => x.provider === p.id) ?? null;
          return (
            <motion.div key={p.id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0, transition: { delay: i * 0.05 } }}>
              <Card className={cn("flex h-full flex-col p-5", integ && !integ.enabled && "opacity-75")}>
                <div className="flex items-start gap-3">
                  <ProviderLogo provider={p} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold">{p.name}</h3>
                      {integ ? (
                        <Badge tone={integ.enabled ? "success" : "neutral"}>{integ.enabled ? "Active" : "Disabled"}</Badge>
                      ) : (
                        <Badge tone="outline">Not connected</Badge>
                      )}
                    </div>
                    <p className="mt-0.5 text-sm text-muted-foreground">{p.description}</p>
                  </div>
                  {integ && (
                    <Switch checked={integ.enabled} onCheckedChange={(enabled) => toggle.mutate({ id: integ.id, enabled })} disabled={!admin} aria-label={`Enable ${p.name}`} />
                  )}
                </div>
                <div className="mt-4">
                  <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">Enriches</div>
                  <div className="flex flex-wrap gap-1">
                    {p.types.map((t) => <Badge key={t} tone="primary">{typeLabel(t)}</Badge>)}
                  </div>
                </div>
                {integ && (
                  <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
                    <span className="inline-flex items-center gap-1 font-mono"><KeyRound className="size-3" /> {integ.key_hint}</span>
                    {integ.last_status === "ok" && <span className="inline-flex items-center gap-1 text-success"><CheckCircle2 className="size-3.5" /> Tested {timeAgo(integ.last_test_at)}</span>}
                    {integ.last_status === "error" && <span className="inline-flex items-center gap-1 text-destructive" title={integ.last_error ?? ""}><XCircle className="size-3.5" /> Test failed {timeAgo(integ.last_test_at)}</span>}
                  </div>
                )}
                {integ?.last_status === "error" && integ.last_error && <p className="mt-2 line-clamp-2 text-xs text-destructive/80">{integ.last_error}</p>}
                <div className="mt-auto flex items-center gap-2 pt-5">
                  {admin && !integ && (
                    <Button onClick={() => setDialog({ provider: p, integration: null })}>
                      <Plug /> Connect
                    </Button>
                  )}
                  {admin && integ && (
                    <>
                      <Button variant="subtle" size="sm" onClick={() => testStored.mutate(p.id)} loading={testStored.isPending && testStored.variables === p.id}>
                        <Plug /> Test
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => setDialog({ provider: p, integration: integ })}>
                        <KeyRound /> Update key
                      </Button>
                      <div className="flex-1" />
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        className="text-destructive hover:bg-destructive/10"
                        aria-label={`Remove ${p.name}`}
                        onClick={async () => {
                          const impact = await get<{ enrichments: number }>(`/integrations/${integ.id}/delete-impact`).catch(() => null);
                          const n = impact?.enrichments ?? 0;
                          const choice = await confirmWithOption({
                            title: `Remove ${p.name}?`,
                            description: "New lookups stop and its queued lookups are cancelled. Lookup providers don't add observables, so the observables themselves are kept.",
                            confirmLabel: "Remove",
                            destructive: true,
                            option: n
                              ? { label: `Also delete ${fmt(n)} stored ${p.name} enrichment result${n === 1 ? "" : "s"}`, hint: "Removes the results and raw responses saved on observables. Their history still records that the lookups happened." }
                              : { label: "", disabledReason: `There are no stored ${p.name} enrichment results.` },
                          });
                          if (!choice.confirmed) return;
                          try {
                            await del(`/integrations/${integ.id}${choice.option ? "?remove_enrichment=true" : ""}`);
                            toast.success(choice.option ? `${p.name} removed with ${fmt(n)} enrichment result(s)` : `${p.name} removed`);
                            ["observables", "observable"].forEach((k) => qc.invalidateQueries({ queryKey: [k] }));
                            invalidate(qc);
                          } catch (e) {
                            toast.error(errorMessage(e));
                          }
                        }}
                      >
                        <Trash2 />
                      </Button>
                    </>
                  )}
                  {!admin && !integ && <span className="text-xs text-muted-foreground">An admin can connect this provider.</span>}
                </div>
              </Card>
            </motion.div>
          );
        })}
      </div>
      {dialog && <ConnectDialog provider={dialog.provider} integration={dialog.integration} open={!!dialog} onOpenChange={(o) => !o && setDialog(null)} />}
      <FeedsSection />
    </>
  );
}
