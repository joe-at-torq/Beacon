import * as RP from "@radix-ui/react-popover";
import { AnimatePresence, motion } from "framer-motion";
import { Check, ChevronDown, Search, X } from "lucide-react";
import { useMemo, useState } from "react";
import { cn } from "@/lib/utils";

export interface Option<T extends string | number> {
  value: T;
  label: string;
  hint?: string;
}

export function MultiSelect<T extends string | number>({
  options,
  value,
  onChange,
  placeholder = "Any",
  emptyLabel,
  className,
  searchable = true,
}: {
  options: Option<T>[];
  value: T[];
  onChange: (v: T[]) => void;
  placeholder?: string;
  emptyLabel?: string;
  className?: string;
  searchable?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const filtered = useMemo(
    () => options.filter((o) => o.label.toLowerCase().includes(q.toLowerCase())),
    [options, q],
  );
  const selected = options.filter((o) => value.includes(o.value));
  const toggle = (v: T) => onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]);

  return (
    <RP.Root open={open} onOpenChange={setOpen}>
      <RP.Trigger asChild>
        <button
          type="button"
          className={cn(
            "flex min-h-9 w-full items-center gap-1.5 rounded-lg border border-input bg-card px-2 py-1 text-left text-sm shadow-sm",
            "transition-all duration-200 hover:border-ring/50 focus:outline-none focus:ring-2 focus:ring-ring/40",
            className,
          )}
        >
          <div className="flex min-w-0 flex-1 flex-wrap gap-1">
            {selected.length === 0 && <span className="truncate whitespace-nowrap px-1 text-muted-foreground">{placeholder}</span>}
            <AnimatePresence initial={false}>
              {selected.map((o) => (
                <motion.span
                  key={String(o.value)}
                  layout
                  initial={{ opacity: 0, scale: 0.85 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.85 }}
                  className="inline-flex items-center gap-1 rounded-md bg-accent px-1.5 py-0.5 text-xs font-medium text-accent-foreground"
                >
                  {o.label}
                  <span
                    role="button"
                    tabIndex={-1}
                    onPointerDown={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      toggle(o.value);
                    }}
                    className="rounded opacity-60 hover:opacity-100"
                  >
                    <X className="size-3" />
                  </span>
                </motion.span>
              ))}
            </AnimatePresence>
          </div>
          <ChevronDown className={cn("size-4 shrink-0 text-muted-foreground transition-transform", open && "rotate-180")} />
        </button>
      </RP.Trigger>
      <RP.Portal>
        <RP.Content
          align="start"
          sideOffset={6}
          className="z-[70] w-[var(--radix-popover-trigger-width)] min-w-56 overflow-hidden rounded-xl border bg-popover p-1 shadow-xl"
        >
          <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.15 }}>
            {searchable && options.length > 6 && (
              <div className="relative mb-1">
                <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <input
                  autoFocus
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Search…"
                  className="h-8 w-full rounded-lg bg-muted/60 pl-8 pr-2 text-sm outline-none"
                />
              </div>
            )}
            <div className="max-h-64 overflow-y-auto">
              {filtered.length === 0 && (
                <div className="px-3 py-6 text-center text-xs text-muted-foreground">{emptyLabel ?? "No options"}</div>
              )}
              {filtered.map((o) => {
                const on = value.includes(o.value);
                return (
                  <button
                    type="button"
                    key={String(o.value)}
                    onClick={() => toggle(o.value)}
                    className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-sm transition-colors hover:bg-muted"
                  >
                    <span
                      className={cn(
                        "grid size-4 shrink-0 place-items-center rounded border transition-all",
                        on ? "border-primary bg-primary text-primary-foreground" : "border-input",
                      )}
                    >
                      {on && <Check className="size-3" strokeWidth={3} />}
                    </span>
                    <span className="flex-1 truncate">{o.label}</span>
                    {o.hint && <span className="text-xs text-muted-foreground">{o.hint}</span>}
                  </button>
                );
              })}
            </div>
            {value.length > 0 && (
              <button
                type="button"
                onClick={() => onChange([])}
                className="mt-1 w-full rounded-lg border-t px-2 py-1.5 text-left text-xs text-muted-foreground hover:bg-muted"
              >
                Clear selection
              </button>
            )}
          </motion.div>
        </RP.Content>
      </RP.Portal>
    </RP.Root>
  );
}
