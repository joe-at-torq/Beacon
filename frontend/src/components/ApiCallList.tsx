import { AnimatePresence, motion } from "framer-motion";
import { ChevronRight, Copy, TerminalSquare } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import type { ApiCall } from "@/lib/types";
import { cn, formatDate } from "@/lib/utils";
import { Button } from "./ui/button";

const failed = (c: ApiCall) => !!c.error || (c.status_code ?? 0) >= 400;

function statusTone(c: ApiCall) {
  if (c.error || c.status_code === null) return "bg-destructive/10 text-destructive";
  if (c.status_code >= 500 || c.status_code === 429) return "bg-warning/15 text-amber-700 dark:text-amber-300";
  if (c.status_code >= 400) return "bg-destructive/10 text-destructive";
  return "bg-success/10 text-success";
}

const shellQuote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;

/** Reproduce the call as a curl command; credentials are replaced with shell variables. */
export function toCurl(c: ApiCall) {
  const parts = [`curl -X ${c.method} ${shellQuote(c.url)}`];
  for (const [k, v] of Object.entries(c.request_headers)) {
    const key = k.toLowerCase();
    if (["user-agent", "accept-encoding", "connection"].includes(key)) continue;
    if (key === "authorization") {
      if (v.startsWith("Basic")) parts.push(`-u "$TORQ_CLIENT_ID:$TORQ_CLIENT_SECRET"`);
      else parts.push(`-H "Authorization: Bearer $TORQ_TOKEN"`);
      continue;
    }
    parts.push(`-H ${shellQuote(`${k}: ${v}`)}`);
  }
  if (c.request_body) {
    let body = c.request_body;
    try {
      body = JSON.stringify(JSON.parse(body));
    } catch {
      /* form-encoded or plain text */
    }
    parts.push(`--data ${shellQuote(body)}`);
  }
  return parts.join(" \\\n  ");
}

function copy(text: string, label: string) {
  navigator.clipboard.writeText(text).then(() => toast.success(`${label} copied`));
}

function CodeBlock({ title, children, action }: { title: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="mb-1 flex items-center justify-between text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        {title}
        {action}
      </div>
      <pre className="max-h-80 overflow-auto rounded-lg border bg-muted/40 p-3 font-mono text-[11.5px] leading-relaxed text-foreground/90 whitespace-pre-wrap break-all">
        {children}
      </pre>
    </div>
  );
}

function Headers({ headers }: { headers: Record<string, string> }) {
  const entries = Object.entries(headers);
  if (!entries.length) return <span className="text-muted-foreground">(none)</span>;
  return (
    <>
      {entries.map(([k, v]) => (
        <div key={k}>
          <span className="text-primary">{k}</span>: {v}
        </div>
      ))}
    </>
  );
}

function CallRow({ call, index }: { call: ApiCall; index: number }) {
  const [open, setOpen] = useState(false);
  const url = new URL(call.url);
  return (
    <div className={cn("rounded-xl border bg-card transition-colors", failed(call) && "border-destructive/30")}>
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-3 px-3 py-2 text-left text-xs hover:bg-muted/40">
        <ChevronRight className={cn("size-3.5 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")} />
        <span className="w-6 shrink-0 text-right tabular text-muted-foreground">{index}</span>
        <span className="w-12 shrink-0 font-mono font-semibold">{call.method}</span>
        <span className={cn("shrink-0 rounded-md px-1.5 py-0.5 font-mono font-semibold tabular", statusTone(call))}>
          {call.status_code ?? "ERR"}
        </span>
        <span className="min-w-0 flex-1 truncate font-mono">
          <span className="text-muted-foreground">{url.host}</span>
          {url.pathname}
        </span>
        {call.attempt > 1 && <span className="shrink-0 text-muted-foreground">attempt {call.attempt}</span>}
        {call.workspace_name && <span className="hidden shrink-0 text-muted-foreground sm:inline">{call.workspace_name}</span>}
        <span className="w-14 shrink-0 text-right tabular text-muted-foreground">{call.duration_ms} ms</span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <div className="space-y-3 border-t p-3">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="font-mono break-all">
                  {call.method} {call.url}
                </span>
                <span className="text-muted-foreground">· {formatDate(call.ts)}</span>
                <div className="ml-auto flex gap-1">
                  <Button size="sm" variant="outline" onClick={() => copy(toCurl(call), "cURL command")}>
                    <TerminalSquare /> Copy as cURL
                  </Button>
                  {call.response_body && (
                    <Button size="sm" variant="ghost" onClick={() => copy(call.response_body, "Response")}>
                      <Copy /> Copy response
                    </Button>
                  )}
                </div>
              </div>
              {call.error && (
                <div className="rounded-lg border border-destructive/30 bg-destructive/10 p-2.5 font-mono text-xs text-destructive break-all">
                  {call.error}
                </div>
              )}
              <div className="grid gap-3 lg:grid-cols-2">
                <div className="space-y-3">
                  <CodeBlock title="Request headers">
                    <Headers headers={call.request_headers} />
                  </CodeBlock>
                  <CodeBlock title="Request body">{call.request_body || <span className="text-muted-foreground">(empty)</span>}</CodeBlock>
                </div>
                <div className="space-y-3">
                  <CodeBlock title={`Response headers${call.status_code ? ` · ${call.status_code}` : ""}`}>
                    <Headers headers={call.response_headers} />
                  </CodeBlock>
                  <CodeBlock title="Response body">{call.response_body || <span className="text-muted-foreground">(empty)</span>}</CodeBlock>
                </div>
              </div>
              <p className="text-[11px] text-muted-foreground">
                Credentials and tokens are redacted. The cURL command uses $TORQ_CLIENT_ID, $TORQ_CLIENT_SECRET and $TORQ_TOKEN.
              </p>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export function ApiCallList({ calls, offset = 0 }: { calls: ApiCall[]; offset?: number }) {
  if (!calls.length) return <p className="py-3 text-center text-xs text-muted-foreground">No API calls recorded.</p>;
  return (
    <div className="space-y-1.5">
      {calls.map((c, i) => (
        <CallRow key={c.id ?? i} call={c} index={offset + i + 1} />
      ))}
    </div>
  );
}
