import { ChevronRight } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

type Json = string | number | boolean | null | Json[] | { [k: string]: Json };

const isContainer = (v: unknown): v is Json[] | Record<string, Json> => v !== null && typeof v === "object";

function summary(v: Json[] | Record<string, Json>) {
  if (Array.isArray(v)) return `[${v.length} item${v.length === 1 ? "" : "s"}]`;
  const n = Object.keys(v).length;
  return `{${n} key${n === 1 ? "" : "s"}}`;
}

function Primitive({ value }: { value: Json }) {
  if (value === null) return <span className="text-muted-foreground">null</span>;
  if (typeof value === "boolean") return <span className="text-[#c03535] dark:text-[#ec7b74]">{String(value)}</span>;
  if (typeof value === "number") return <span className="text-[#1c5cab] dark:text-[#86b6ef]">{value}</span>;
  const s = String(value);
  if (/^https?:\/\/\S+$/.test(s)) {
    return (
      <a href={s} target="_blank" rel="noreferrer noopener" className="break-all text-primary underline-offset-2 hover:underline">
        "{s}"
      </a>
    );
  }
  return <span className="whitespace-pre-wrap break-words text-[#0f7a52] dark:text-[#5fd4a0]">"{s}"</span>;
}

function Node({ name, value, depth, defaultDepth }: { name?: string; value: Json; depth: number; defaultDepth: number }) {
  const container = isContainer(value);
  const empty = container && (Array.isArray(value) ? value.length === 0 : Object.keys(value).length === 0);
  const [open, setOpen] = useState(depth < defaultDepth);
  const label = name !== undefined && <span className="text-foreground/80">{name}: </span>;

  if (!container || empty) {
    return (
      <div className="py-px pl-5">
        {label}
        {container ? <span className="text-muted-foreground">{Array.isArray(value) ? "[]" : "{}"}</span> : <Primitive value={value} />}
      </div>
    );
  }
  const entries = Array.isArray(value) ? value.map((v, i) => [String(i), v] as const) : Object.entries(value);
  return (
    <div>
      <button type="button" onClick={() => setOpen(!open)} className="group flex w-full items-start gap-1 rounded py-px text-left hover:bg-muted/60">
        <ChevronRight className={cn("mt-[3px] size-3.5 shrink-0 text-muted-foreground transition-transform", open && "rotate-90")} />
        <span>
          {label}
          {!open && <span className="text-muted-foreground">{summary(value)}</span>}
          {open && <span className="text-muted-foreground">{Array.isArray(value) ? "[" : "{"}</span>}
        </span>
      </button>
      {open && (
        <div className="ml-[7px] border-l border-border pl-2">
          {entries.map(([k, v]) => (
            <Node key={k} name={Array.isArray(value) ? undefined : k} value={v} depth={depth + 1} defaultDepth={defaultDepth} />
          ))}
        </div>
      )}
    </div>
  );
}

/** Collapsible JSON viewer. Change `resetKey` to re-apply `defaultDepth` (e.g. expand/collapse all). */
export function JsonTree({ data, defaultDepth = 1, resetKey }: { data: unknown; defaultDepth?: number; resetKey?: string | number }) {
  return (
    <div key={resetKey} className="font-mono text-[12px] leading-relaxed">
      <Node value={data as Json} depth={0} defaultDepth={defaultDepth} />
    </div>
  );
}
