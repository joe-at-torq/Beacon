import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";

export type ThemePref = "light" | "dark" | "system";
const KEY = "tim-theme";

interface ThemeCtx {
  pref: ThemePref;
  resolved: "light" | "dark";
  setPref: (p: ThemePref) => void;
  toggle: () => void;
}

const Ctx = createContext<ThemeCtx | null>(null);
const media = () => window.matchMedia("(prefers-color-scheme: dark)");

function apply(resolved: "light" | "dark", animate: boolean) {
  const root = document.documentElement;
  if (animate) {
    root.classList.add("theme-transition");
    window.setTimeout(() => root.classList.remove("theme-transition"), 400);
  }
  root.classList.toggle("dark", resolved === "dark");
  root.dataset.theme = resolved;
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [pref, setPrefState] = useState<ThemePref>(() => (localStorage.getItem(KEY) as ThemePref) || "dark");
  const [systemDark, setSystemDark] = useState(() => media().matches);
  const resolved = pref === "system" ? (systemDark ? "dark" : "light") : pref;

  useEffect(() => {
    const m = media();
    const fn = (e: MediaQueryListEvent) => setSystemDark(e.matches);
    m.addEventListener("change", fn);
    return () => m.removeEventListener("change", fn);
  }, []);

  useEffect(() => apply(resolved, true), [resolved]);

  const setPref = useCallback((p: ThemePref) => {
    localStorage.setItem(KEY, p);
    setPrefState(p);
  }, []);
  const toggle = useCallback(() => setPref(resolved === "dark" ? "light" : "dark"), [resolved, setPref]);

  return <Ctx.Provider value={{ pref, resolved, setPref, toggle }}>{children}</Ctx.Provider>;
}

export function useTheme() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useTheme outside ThemeProvider");
  return ctx;
}
