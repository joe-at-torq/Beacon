import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(iso: string | null | undefined, withTime = true) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    ...(withTime ? { hour: "2-digit", minute: "2-digit" } : {}),
  });
}

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
export function timeAgo(iso: string | null | undefined) {
  if (!iso) return "never";
  const diff = (new Date(iso).getTime() - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return diff < 0 ? "just now" : "in a moment";
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ["minute", 60],
    ["hour", 3600],
    ["day", 86400],
    ["week", 604800],
    ["month", 2629800],
    ["year", 31557600],
  ];
  let unit: Intl.RelativeTimeFormatUnit = "minute";
  let value = diff / 60;
  for (const [u, secs] of units) {
    if (abs >= secs) {
      unit = u;
      value = diff / secs;
    }
  }
  return rtf.format(Math.round(value), unit);
}

export const fmt = (n: number) => n.toLocaleString();

export function errorMessage(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}
