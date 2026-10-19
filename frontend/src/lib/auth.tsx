import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, type ReactNode } from "react";
import { ApiError, get, onUnauthorized, post } from "./api";
import type { User } from "./types";

interface AuthCtx {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<User>;
  logout: () => Promise<void>;
  refresh: () => Promise<unknown>;
  can: (action: "admin" | "edit") => boolean;
}

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const me = useQuery({
    queryKey: ["me"],
    queryFn: async () => {
      try {
        return await get<User>("/auth/me");
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null;
        throw e;
      }
    },
    staleTime: 60_000,
    retry: false,
  });

  useEffect(
    () =>
      onUnauthorized(() => {
        if (qc.getQueryData(["me"])) qc.setQueryData(["me"], null);
      }),
    [qc],
  );

  const user = me.data ?? null;
  const value: AuthCtx = {
    user,
    loading: me.isLoading,
    login: async (username, password) => {
      const u = await post<User>("/auth/login", { username, password });
      qc.setQueryData(["me"], u);
      return u;
    },
    logout: async () => {
      await post("/auth/logout").catch(() => undefined);
      qc.clear();
      qc.setQueryData(["me"], null);
    },
    refresh: () => me.refetch(),
    can: (action) => {
      if (!user) return false;
      if (action === "admin") return user.role === "admin";
      return user.role === "admin" || user.role === "analyst";
    },
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}
