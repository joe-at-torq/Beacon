import { useQuery } from "@tanstack/react-query";
import { get } from "./api";
import type { Meta } from "./types";

export function useMeta() {
  return useQuery({ queryKey: ["meta"], queryFn: () => get<Meta>("/meta"), staleTime: Infinity });
}

const FALLBACK_TYPES: Record<string, string> = {
  TYPE_ID_HOSTNAME: "Hostname",
  TYPE_ID_IP_ADDRESS: "IP address",
  TYPE_ID_MAC_ADDRESS: "MAC address",
  TYPE_ID_USER_NAME: "Username",
  TYPE_ID_EMAIL_ADDRESS: "Email address",
  TYPE_ID_URL: "URL",
  TYPE_ID_FILE_NAME: "File name",
  TYPE_ID_FILE_HASH: "File hash",
  TYPE_ID_PROCESS_NAME: "Process name",
  TYPE_ID_RESOURCE_UID: "Resource UID",
  TYPE_ID_OTHER: "Other",
  TYPE_ID_UNKNOWN: "Unknown",
};

export const REPUTATION_SEVERITY: Record<string, number> = {
  SCORE_UNKNOWN: 0,
  SCORE_OTHER: 0,
  SCORE_VERY_SAFE: 1,
  SCORE_SAFE: 2,
  SCORE_PROBABLY_SAFE: 3,
  SCORE_LEANS_SAFE: 4,
  SCORE_MAY_NOT_BE_SAFE: 5,
  SCORE_EXERCISE_CAUTION: 6,
  SCORE_SUSPICIOUS_OR_RISKY: 7,
  SCORE_POSSIBLY_MALICIOUS: 8,
  SCORE_PROBABLY_MALICIOUS: 9,
  SCORE_MALICIOUS: 10,
};

const REP_LABELS: Record<string, string> = {
  SCORE_UNKNOWN: "Unknown",
  SCORE_OTHER: "Other",
  SCORE_VERY_SAFE: "Very safe",
  SCORE_SAFE: "Safe",
  SCORE_PROBABLY_SAFE: "Probably safe",
  SCORE_LEANS_SAFE: "Leans safe",
  SCORE_MAY_NOT_BE_SAFE: "May not be safe",
  SCORE_EXERCISE_CAUTION: "Exercise caution",
  SCORE_SUSPICIOUS_OR_RISKY: "Suspicious",
  SCORE_POSSIBLY_MALICIOUS: "Possibly malicious",
  SCORE_PROBABLY_MALICIOUS: "Probably malicious",
  SCORE_MALICIOUS: "Malicious",
};

export const typeLabel = (id: string) => FALLBACK_TYPES[id] ?? id.replace(/^TYPE_ID_/, "");
export const repLabel = (id: string) => REP_LABELS[id] ?? id;
export const subTypeLabel = (id: string, meta?: Meta) =>
  meta?.sub_types.find((s) => s.id === id)?.label ?? id.replace(/^SUB_TYPE_ID_/, "").replace(/_/g, " ");
export const repColor = (id: string) => `var(--rep-${REPUTATION_SEVERITY[id] ?? 0})`;
export const severity = (id: string) => REPUTATION_SEVERITY[id] ?? 0;
