import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback } from "react";
import { get, patch } from "./api";

export type Preferences = Record<string, unknown>;

export function usePreferences() {
  return useQuery({ queryKey: ["preferences"], queryFn: () => get<Preferences>("/auth/preferences"), staleTime: Infinity });
}

const timers = new Map<string, ReturnType<typeof setTimeout>>();

/** Save one preference key (debounced per key, optimistic in the local cache). Pass null to clear it. */
export function useSavePreference() {
  const qc = useQueryClient();
  return useCallback(
    (key: string, value: unknown, delay = 600) => {
      qc.setQueryData<Preferences>(["preferences"], (prev) => {
        const next = { ...(prev ?? {}) };
        if (value === null) delete next[key];
        else next[key] = value;
        return next;
      });
      clearTimeout(timers.get(key));
      timers.set(
        key,
        setTimeout(() => {
          timers.delete(key);
          patch("/auth/preferences", { [key]: value }).catch(() => undefined);
        }, delay),
      );
    },
    [qc],
  );
}
