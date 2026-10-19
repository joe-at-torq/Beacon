import { CheckCircle2, CircleDashed, Pin, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import { motion } from "framer-motion";
import { repColor, repLabel, typeLabel } from "@/lib/meta";
import { cn, timeAgo } from "@/lib/utils";
import { Badge } from "./ui/badge";
import { Tooltip } from "./ui/tooltip";

export function ReputationBadge({ value, className }: { value: string; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border bg-card px-1.5 py-0.5 text-[11px] font-medium",
        className,
      )}
    >
      <span className="size-2 rounded-full" style={{ background: repColor(value) }} />
      {repLabel(value)}
    </span>
  );
}

export function TypeBadge({ value }: { value: string }) {
  return <Badge tone="primary">{typeLabel(value)}</Badge>;
}

export function PinnedMark() {
  return (
    <Tooltip content="Edited centrally — authoritative over workspace values">
      <Pin className="size-3.5 text-primary" />
    </Tooltip>
  );
}

export function SyncStatusPill({ status, at, error }: { status: "ok" | "error" | null; at?: string | null; error?: string | null }) {
  const pill =
    status === "ok" ? (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-success">
        <CheckCircle2 className="size-3.5" /> Healthy
      </span>
    ) : status === "error" ? (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-destructive">
        <XCircle className="size-3.5" /> Error
      </span>
    ) : (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground">
        <CircleDashed className="size-3.5" /> Never synced
      </span>
    );
  return (
    <span className="inline-flex items-center gap-2">
      {error ? <Tooltip content={error}>{pill}</Tooltip> : pill}
      {at && <span className="text-xs text-muted-foreground">{timeAgo(at)}</span>}
    </span>
  );
}

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <motion.h1
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-2xl font-semibold tracking-tight"
        >
          {title}
        </motion.h1>
        {description && <p className="mt-1 text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
