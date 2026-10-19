import { useQuery } from "@tanstack/react-query";
import { get } from "./api";
import type { Feed } from "./types";

/** STIX/TAXII feeds (polls quickly while one is being polled). */
export function useFeeds() {
  return useQuery({
    queryKey: ["feeds"],
    queryFn: () => get<Feed[]>("/feeds"),
    refetchInterval: (q) => (q.state.data?.some((f) => f.polling) ? 3000 : 30000),
  });
}

export const isFeedSource = (id: number | string): id is string => typeof id === "string" && id.startsWith("feed:");
export const feedIdOf = (id: string) => Number(id.slice(5));
