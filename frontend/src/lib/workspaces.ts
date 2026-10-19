import { useQuery } from "@tanstack/react-query";
import { useCallback } from "react";
import { get } from "./api";
import type { Workspace } from "./types";

export function useWorkspacesQuery() {
  return useQuery({ queryKey: ["workspaces"], queryFn: () => get<Workspace[]>("/workspaces") });
}

/** Region lookup by workspace id (for places that only know the id/name, e.g. observable links). */
export function useRegionOf() {
  const q = useWorkspacesQuery();
  return useCallback((id: number | null | undefined) => q.data?.find((w) => w.id === id)?.region, [q.data]);
}
