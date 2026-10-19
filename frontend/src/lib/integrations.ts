import { useQuery } from "@tanstack/react-query";
import { get } from "./api";
import type { Integration, IntelProvider } from "./types";

export const useProviders = () =>
  useQuery({ queryKey: ["intel-providers"], queryFn: () => get<IntelProvider[]>("/integrations/providers"), staleTime: Infinity });

export const useIntegrations = () => useQuery({ queryKey: ["integrations"], queryFn: () => get<Integration[]>("/integrations") });

/** Observable type -> enabled providers that can enrich it. */
export const useCapabilities = () =>
  useQuery({ queryKey: ["intel-capabilities"], queryFn: () => get<Record<string, string[]>>("/integrations/capabilities") });

export const providerName = (providers: IntelProvider[] | undefined, id: string) => providers?.find((p) => p.id === id)?.name ?? id;
