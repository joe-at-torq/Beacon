import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export type Region = "us" | "eu" | "jp";

export const REGIONS: Record<Region, { label: string; country: string; api: string }> = {
  us: { label: "US", country: "United States", api: "api.torq.io" },
  eu: { label: "EU", country: "European Union", api: "api.eu.torq.io" },
  jp: { label: "JP", country: "Japan", api: "api.jp.torq.io" },
};

// 12 stars on a circle for the EU flag (viewBox 30x20).
const EU_STARS = Array.from({ length: 12 }, (_, i) => {
  const a = (i * Math.PI) / 6;
  return { x: 15 + 6 * Math.sin(a), y: 10 - 6 * Math.cos(a) };
});

function Flag({ region }: { region: Region }) {
  switch (region) {
    case "eu":
      return (
        <>
          <rect width="30" height="20" fill="#003399" />
          {EU_STARS.map((s, i) => (
            <circle key={i} cx={s.x} cy={s.y} r="1.05" fill="#FFCC00" />
          ))}
        </>
      );
    case "jp":
      return (
        <>
          <rect width="30" height="20" fill="#fff" />
          <circle cx="15" cy="10" r="6" fill="#BC002D" />
        </>
      );
    default:
      return (
        <>
          <rect width="30" height="20" fill="#B22234" />
          {[1, 3, 5, 7, 9, 11].map((i) => (
            <rect key={i} y={(i * 20) / 13} width="30" height={20 / 13} fill="#fff" />
          ))}
          <rect width="13" height={(20 * 7) / 13} fill="#3C3B6E" />
          {[0, 1, 2].map((r) => [0, 1, 2, 3].map((c) => <circle key={`${r}${c}`} cx={2 + c * 3} cy={2 + r * 3.4} r="0.7" fill="#fff" />))}
        </>
      );
  }
}

/** Small country/region flag for a Torq deployment region. Works in HTML and inside an SVG (via x/y). */
export function RegionFlag({
  region,
  height = 11,
  x,
  y,
  className,
}: {
  region: string | null | undefined;
  height?: number;
  x?: number;
  y?: number;
  className?: string;
}) {
  const r = (region && region in REGIONS ? region : "us") as Region;
  const width = (height * 3) / 2;
  return (
    <svg
      x={x}
      y={y}
      width={width}
      height={height}
      viewBox="0 0 30 20"
      role="img"
      aria-label={`${REGIONS[r].country} region`}
      className={cn("inline-block shrink-0 overflow-hidden rounded-[2px] align-[-1px]", className)}
    >
      <title>{`${REGIONS[r].country} (${REGIONS[r].label})`}</title>
      <Flag region={r} />
      <rect x="0.75" y="0.75" width="28.5" height="18.5" fill="none" stroke="rgb(0 0 0 / 0.35)" strokeWidth="1.5" rx="1.5" />
    </svg>
  );
}

/** Workspace name with its region flag in front. */
export function WorkspaceName({ name, region, className, children }: { name: string; region?: string | null; className?: string; children?: ReactNode }) {
  return (
    <span className={cn("inline-flex min-w-0 items-center gap-1.5", className)}>
      <RegionFlag region={region} />
      <span className="truncate">{name}</span>
      {children}
    </span>
  );
}
