import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Clock, Flame, ListOrdered, Monitor, Moon, Sun } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Field, Input } from "@/components/ui/input";
import { Segmented } from "@/components/ui/segmented";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { get, put } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { useTheme, type ThemePref } from "@/lib/theme";
import type { Settings } from "@/lib/types";
import { cn, errorMessage } from "@/lib/utils";

const STRATEGIES: { value: Settings["collision_strategy"]; title: string; description: string; icon: ReactNode }[] = [
  {
    value: "highest_severity",
    title: "Highest severity wins",
    description: "The most malicious verdict from any workspace becomes the central reputation. Safest default for threat intel.",
    icon: <Flame />,
  },
  {
    value: "most_recent",
    title: "Most recent wins",
    description: "The copy that was updated most recently in its workspace wins.",
    icon: <Clock />,
  },
  {
    value: "workspace_priority",
    title: "Workspace priority",
    description: "The workspace with the lowest priority number is authoritative.",
    icon: <ListOrdered />,
  },
];

function RadioCard({ selected, onClick, disabled, title, description, icon }: { selected: boolean; onClick: () => void; disabled?: boolean; title: string; description: string; icon: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={cn(
        "relative flex w-full items-start gap-3 rounded-2xl border p-4 text-left transition-all duration-200",
        selected ? "border-primary/50 bg-accent/60" : "hover:border-ring/40 hover:bg-muted/40",
        disabled && "cursor-not-allowed opacity-70",
      )}
    >
      {selected && (
        <motion.span layoutId="strategy-ring" className="absolute inset-0 rounded-2xl ring-2 ring-primary" transition={{ type: "spring", stiffness: 500, damping: 40 }} />
      )}
      <span className={cn("grid size-9 shrink-0 place-items-center rounded-xl [&_svg]:size-4", selected ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground")}>
        {icon}
      </span>
      <span>
        <span className="block text-sm font-medium">{title}</span>
        <span className="mt-0.5 block text-xs text-muted-foreground">{description}</span>
      </span>
    </button>
  );
}

export default function GeneralTab() {
  const qc = useQueryClient();
  const { can } = useAuth();
  const admin = can("admin");
  const { pref, setPref } = useTheme();
  const q = useQuery({ queryKey: ["settings"], queryFn: () => get<Settings>("/settings") });
  const [form, setForm] = useState<Settings | null>(null);
  useEffect(() => {
    if (q.data) setForm(q.data);
  }, [q.data]);
  const dirty = !!form && !!q.data && JSON.stringify(form) !== JSON.stringify(q.data);

  const save = useMutation({
    mutationFn: () => put<Settings>("/settings", form),
    onSuccess: (s) => {
      qc.setQueryData(["settings"], s);
      qc.invalidateQueries({ queryKey: ["sync-status"] });
      toast.success("Settings saved");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_380px]">
      <Card>
        <CardHeader
          title="Collision handling"
          description="Used when the same observable is found in several workspaces with different values. Changing it re-resolves existing observables."
        />
        <CardBody className="space-y-5">
          {!form ? (
            <Skeleton className="h-48" />
          ) : (
            <>
              <div className="grid gap-3">
                {STRATEGIES.map((s) => (
                  <RadioCard
                    key={s.value}
                    {...s}
                    selected={form.collision_strategy === s.value}
                    disabled={!admin}
                    onClick={() => setForm({ ...form, collision_strategy: s.value })}
                  />
                ))}
              </div>
              <Field label="Descriptions" hint="Combine descriptions from every workspace, or keep only the winning copy's.">
                <Segmented
                  value={form.description_merge}
                  onChange={(v) => admin && setForm({ ...form, description_merge: v })}
                  options={[
                    { value: "winner", label: "Use winner's" },
                    { value: "concat", label: "Merge all" },
                  ]}
                />
              </Field>
              <p className="text-xs text-muted-foreground">
                A reputation or description changed later in any workspace always updates the central value, and sync rules
                carry it to other workspaces. Observables edited in Beacon stay authoritative and are not overwritten.
              </p>
            </>
          )}
        </CardBody>
      </Card>

      <div className="space-y-4">
        <Card>
          <CardHeader title="Scheduled sync" />
          <CardBody className="space-y-4">
            {!form ? (
              <Skeleton className="h-24" />
            ) : (
              <>
                <label className="flex items-center justify-between gap-3 text-sm">
                  <span>
                    <span className="block font-medium">Automatic synchronization</span>
                    <span className="block text-xs text-muted-foreground">Pull and push on a fixed interval</span>
                  </span>
                  <Switch checked={form.sync_enabled} onCheckedChange={(v) => setForm({ ...form, sync_enabled: v })} disabled={!admin} aria-label="Automatic sync" />
                </label>
                <Field label="Interval (minutes)">
                  <Input
                    type="number"
                    min={1}
                    max={1440}
                    value={form.sync_interval_minutes}
                    disabled={!admin || !form.sync_enabled}
                    onChange={(e) => setForm({ ...form, sync_interval_minutes: Number(e.target.value) })}
                  />
                </Field>
              </>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Appearance" description="Saved in this browser" />
          <CardBody>
            <Segmented<ThemePref>
              value={pref}
              onChange={setPref}
              options={[
                { value: "light", label: <><Sun /> Light</> },
                { value: "dark", label: <><Moon /> Dark</> },
                { value: "system", label: <><Monitor /> System</> },
              ]}
            />
          </CardBody>
        </Card>

        {admin && (
          <motion.div animate={{ opacity: dirty ? 1 : 0.6 }} className="flex justify-end gap-2">
            <Button variant="ghost" disabled={!dirty} onClick={() => q.data && setForm(q.data)}>
              Discard
            </Button>
            <Button disabled={!dirty} loading={save.isPending} onClick={() => save.mutate()}>
              Save settings
            </Button>
          </motion.div>
        )}
      </div>
    </div>
  );
}
