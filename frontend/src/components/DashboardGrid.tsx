import { GripHorizontal } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Responsive, type Layout, type Layouts } from "react-grid-layout";
import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";
import { usePreferences, useSavePreference } from "@/lib/preferences";
import { cn } from "@/lib/utils";
import { Tooltip } from "./ui/tooltip";


export const BREAKPOINTS = { lg: 1100, md: 700, sm: 0 } as const;
export const COLS = { lg: 12, md: 6, sm: 1 } as const;
const PREF_KEY = "dashboard_layout";

export interface WidgetSpec {
  id: string;
  /** Default placement on the 12-column (lg) grid. */
  x: number;
  y: number;
  w: number;
  h: number;
  minW?: number;
  minH?: number;
}

export interface Widget extends WidgetSpec {
  node: ReactNode;
}

type Bp = keyof typeof COLS;
const strip = (l: Layout) => ({ i: l.i, x: l.x, y: l.y, w: l.w, h: l.h });

/** Saved layouts merged with defaults: unknown widgets are dropped, new widgets get their default spot. */
function mergeLayouts(saved: Layouts | undefined, widgets: WidgetSpec[]): Layouts {
  const byId = new Map(widgets.map((w) => [w.id, w]));
  const withLimits = (l: Layout, bp: Bp): Layout => {
    const w = byId.get(l.i)!;
    const cols = COLS[bp];
    const minW = Math.min(w.minW ?? 1, cols);
    return { ...l, w: Math.min(Math.max(l.w, minW), cols), minW, minH: w.minH ?? 1 };
  };
  const defaults: Layout[] = widgets.map((w) => ({ i: w.id, x: w.x, y: w.y, w: w.w, h: w.h }));
  const result: Layouts = { lg: defaults.map((l) => withLimits(l, "lg")) };
  for (const bp of Object.keys(COLS) as Bp[]) {
    const items = (saved?.[bp] ?? []).filter((l) => byId.has(l.i));
    if (!items.length) {
      if (bp !== "lg") delete result[bp]; // let the grid derive it from the larger breakpoint
      continue;
    }
    const present = new Set(items.map((l) => l.i));
    const missing = defaults.filter((l) => !present.has(l.i)).map((l) => ({ ...l, y: Infinity }));
    result[bp] = [...items, ...missing].map((l) => withLimits(l, bp));
  }
  return result;
}

export function useDashboardLayout(widgets: WidgetSpec[]) {
  const prefs = usePreferences();
  const save = useSavePreference();
  const saved = prefs.data?.[PREF_KEY] as Layouts | undefined;
  // Depend on the widget specs, not their (re-created every render) React nodes.
  const specKey = widgets.map((w) => `${w.id}:${w.x},${w.y},${w.w},${w.h},${w.minW},${w.minH}`).join("|");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const merged = useMemo(() => mergeLayouts(saved, widgets), [saved, specKey]);
  return {
    ready: prefs.isFetched,
    layouts: merged,
    customized: !!saved,
    save: (layouts: Layouts) => {
      const compact: Layouts = {};
      for (const [bp, items] of Object.entries(layouts)) compact[bp] = items.map(strip);
      save(PREF_KEY, compact, 300);
    },
    reset: () => save(PREF_KEY, null, 0),
  };
}

export function DashboardGrid({ widgets, layout }: { widgets: Widget[]; layout: ReturnType<typeof useDashboardLayout> }) {
  const [layouts, setLayouts] = useState<Layouts>(layout.layouts);
  const latest = useRef<Layouts>(layout.layouts);
  const [mounted, setMounted] = useState(false);
  // Measure the container ourselves: the grid's built-in width provider only measures once at mount,
  // which can happen mid page-transition (width 0) and leave the dashboard in the 1-column layout.
  const wrapRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => setWidth(Math.round(entry.contentRect.width)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // External changes (initial load, reset) replace the local layout.
  useEffect(() => {
    latest.current = layout.layouts;
    setLayouts(layout.layouts);
  }, [layout.layouts]);
  useEffect(() => {
    if (!width || mounted) return;
    const t = setTimeout(() => setMounted(true), 300);
    return () => clearTimeout(t);
  }, [width, mounted]);

  // Only persist what the user did (drag/resize), not the grid's own initial compaction.
  const persist = useCallback(() => setTimeout(() => layout.save(latest.current), 0), [layout]);

  return (
    <div ref={wrapRef} className="-mx-2">
    {width > 0 && (
    <Responsive
      width={width}
      className={cn("beacon-grid", !mounted && "beacon-grid-static")}
      layouts={layouts}
      breakpoints={BREAKPOINTS}
      cols={COLS}
      rowHeight={32}
      margin={[16, 16]}
      containerPadding={[8, 0]}
      draggableHandle=".widget-drag-handle"
      resizeHandles={["se"]}
      onLayoutChange={(_current, all) => {
        latest.current = all;
        setLayouts(all);
      }}
      onDragStop={persist}
      onResizeStop={persist}
    >
      {widgets.map((w) => (
        <div key={w.id} className="group/widget relative">
          <Tooltip content="Drag to move · resize from the corner">
            <button
              className="widget-drag-handle absolute left-1/2 top-1 z-20 -translate-x-1/2 cursor-grab rounded-md px-2 py-0.5 text-muted-foreground opacity-0 transition-opacity hover:bg-muted hover:text-foreground focus-visible:opacity-100 active:cursor-grabbing group-hover/widget:opacity-100"
              aria-label="Move widget"
            >
              <GripHorizontal className="size-4" />
            </button>
          </Tooltip>
          <div className="h-full">{w.node}</div>
        </div>
      ))}
    </Responsive>
    )}
    </div>
  );
}
