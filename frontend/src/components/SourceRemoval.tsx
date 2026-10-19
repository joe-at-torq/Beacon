import { fmt } from "@/lib/utils";

export interface DeleteImpact {
  observables: number;
  with_copies: number;
}

/** The "also remove its observables" choice for deleting a workspace or feed. */
export function removalOption(impact: DeleteImpact | null, kind: "workspace" | "feed") {
  if (!impact) return { label: "Also delete observables that came only from this " + kind, hint: "Couldn't count them right now." };
  if (impact.observables === 0)
    return {
      label: "",
      disabledReason: `No observables came only from this ${kind}: everything it provided is also in another source, so nothing would be deleted.`,
    };
  const n = fmt(impact.observables);
  return {
    label: `Also delete ${n} observable${impact.observables === 1 ? "" : "s"} that came only from this ${kind}`,
    hint: (
      <>
        Observables also seen in another workspace, listed by another feed, or created or edited in Beacon are kept.
        {impact.with_copies > 0 && (
          <> {fmt(impact.with_copies)} of them were synced to other workspaces; Torq&apos;s API can&apos;t delete those copies, so they&apos;re blocked from being imported again.</>
        )}
      </>
    ),
  };
}
