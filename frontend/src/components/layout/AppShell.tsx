import * as DM from "@radix-ui/react-dropdown-menu";
import { AnimatePresence, motion, PresenceContext, useIsPresent } from "framer-motion";
import {
  ChevronsLeft,
  Database,
  GitBranch,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu,
  RefreshCw,
  Settings,
} from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { NavLink, useLocation, useOutlet } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import { useTheme } from "@/lib/theme";
import { useStartSync, useSyncStatus } from "@/lib/sync";
import { cn, timeAgo } from "@/lib/utils";
import { Button } from "../ui/button";
import { Tooltip } from "../ui/tooltip";
import { ChangePasswordDialog } from "./ChangePasswordDialog";
import { ThemeToggle } from "./ThemeToggle";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/database", label: "Database", icon: Database },
  { to: "/rules", label: "Rules", icon: GitBranch },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Logo({ compact = false }: { compact?: boolean }) {
  const { resolved } = useTheme();
  if (compact)
    return <img src={`/brand/beacon-lighthouse-${resolved}.png`} alt="Beacon" className="h-9 w-auto max-w-none select-none" draggable={false} />;
  return (
    <motion.img
      key={resolved}
      src={`/brand/beacon-text-${resolved}.png`}
      alt="Beacon"
      className="h-7 w-auto select-none"
      draggable={false}
      initial={{ opacity: 0, x: -6 }}
      animate={{ opacity: 1, x: 0 }}
    />
  );
}

/** Lighthouse artwork filling the bottom third of the nav; the tower is centered, the beam fades off the edge. */
function SidebarLighthouse() {
  const { resolved } = useTheme();
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 12, transition: { duration: 0.12 } }}
      transition={{ duration: 0.35, ease: "easeOut" }}
      className="pointer-events-none relative -mx-3 mt-auto h-[33%] min-h-0 shrink overflow-hidden [mask-image:linear-gradient(to_right,black_72%,transparent)]"
      aria-hidden
    >
      <img
        src={`/brand/beacon-lighthouse-${resolved}.png`}
        alt=""
        className="absolute bottom-0 left-1/2 h-full w-auto max-w-none -translate-x-1/2 select-none object-contain"
        draggable={false}
      />
    </motion.div>
  );
}

function SidebarContent({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const location = useLocation();
  const isActive = (to: string) => (to === "/" ? location.pathname === "/" : location.pathname.startsWith(to));
  return (
    <nav className="flex flex-col gap-1">
      {NAV.map(({ to, label, icon: Icon }) => {
        const active = isActive(to);
        const link = (
          <NavLink
            key={to}
            to={to}
            onClick={onNavigate}
            className={cn(
              "group relative flex h-10 items-center gap-3 rounded-xl px-3 text-sm font-medium transition-colors",
              active ? "text-foreground" : "text-muted-foreground hover:text-foreground",
            )}
          >
            {active && (
              <motion.span
                layoutId="nav-active"
                className="absolute inset-0 rounded-xl bg-card shadow-sm ring-1 ring-border"
                transition={{ type: "spring", stiffness: 450, damping: 36 }}
              />
            )}
            <Icon
              className={cn(
                "relative z-10 size-[18px] shrink-0 transition-transform group-hover:scale-110",
                active && "text-primary",
              )}
            />
            {!collapsed && <span className="relative z-10 truncate">{label}</span>}
          </NavLink>
        );
        return collapsed ? (
          <Tooltip key={to} content={label} side="right">
            {link}
          </Tooltip>
        ) : (
          link
        );
      })}
    </nav>
  );
}

function SyncIndicator() {
  const status = useSyncStatus();
  const start = useStartSync();
  const { can } = useAuth();
  const running = !!status.data?.running;
  const last = status.data?.last_run;
  return (
    <div className="flex items-center gap-3">
      <div className="hidden text-right text-xs leading-tight sm:block">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div
            key={running ? "running" : "idle"}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
          >
            {running ? (
              <>
                <div className="font-medium text-primary">Syncing · {status.data?.phase}</div>
                <div className="text-muted-foreground">{status.data?.detail || "Working…"}</div>
              </>
            ) : (
              <>
                <div className="font-medium">Last sync {timeAgo(last?.finished_at)}</div>
                <div className="text-muted-foreground">
                  {status.data?.next_run_at ? `Next ${timeAgo(status.data.next_run_at)}` : "Scheduler off"}
                </div>
              </>
            )}
          </motion.div>
        </AnimatePresence>
      </div>
      {can("edit") && (
        <Button size="sm" variant={running ? "subtle" : "primary"} onClick={() => start.mutate(undefined)} disabled={running} loading={start.isPending}>
          {!start.isPending && <RefreshCw className={cn(running && "animate-spin")} />}
          {running ? "Syncing" : "Sync now"}
        </Button>
      )}
    </div>
  );
}

function UserMenu({ onChangePassword }: { onChangePassword: () => void }) {
  const { user, logout } = useAuth();
  if (!user) return null;
  return (
    <DM.Root>
      <DM.Trigger asChild>
        <button className="flex items-center gap-2 rounded-xl p-1 pr-2 transition-colors hover:bg-muted">
          <span className="grid size-8 place-items-center rounded-lg bg-gradient-to-br from-primary/80 to-primary text-xs font-semibold uppercase text-primary-foreground">
            {user.username.slice(0, 2)}
          </span>
          <span className="hidden text-left text-xs leading-tight md:block">
            <span className="block font-medium">{user.username}</span>
            <span className="block capitalize text-muted-foreground">{user.role}</span>
          </span>
        </button>
      </DM.Trigger>
      <DM.Portal>
        <DM.Content align="end" sideOffset={8} className="z-50 min-w-48 rounded-xl border bg-popover p-1 shadow-xl">
          <motion.div initial={{ opacity: 0, scale: 0.96, y: -4 }} animate={{ opacity: 1, scale: 1, y: 0 }} transition={{ duration: 0.14 }}>
            <DM.Item
              onSelect={onChangePassword}
              className="flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 text-sm outline-none data-[highlighted]:bg-muted"
            >
              <KeyRound className="size-4" /> Change password
            </DM.Item>
            <DM.Separator className="my-1 h-px bg-border" />
            <DM.Item
              onSelect={() => logout()}
              className="flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 text-sm text-destructive outline-none data-[highlighted]:bg-destructive/10"
            >
              <LogOut className="size-4" /> Sign out
            </DM.Item>
          </motion.div>
        </DM.Content>
      </DM.Portal>
    </DM.Root>
  );
}

/**
 * Page content for the route transition. While a page is leaving it keeps showing its *own* content
 * (not the next route's), and nothing inside a page can hold up the transition: animated descendants
 * are detached from the exit animation, which otherwise could stall and leave an invisible page.
 */
function PageContent({ children }: { children: ReactNode }) {
  const isPresent = useIsPresent();
  const frozen = useRef(children);
  if (isPresent) frozen.current = children;
  return <PresenceContext.Provider value={null}>{frozen.current}</PresenceContext.Provider>;
}

export function AppShell() {
  const location = useLocation();
  const outlet = useOutlet();
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("tim-sidebar") === "collapsed");
  const [mobileOpen, setMobileOpen] = useState(false);
  const [pwOpen, setPwOpen] = useState(false);

  useEffect(() => localStorage.setItem("tim-sidebar", collapsed ? "collapsed" : "open"), [collapsed]);

  return (
    <div className="flex h-full">
      {/* Desktop sidebar */}
      <motion.aside
        animate={{ width: collapsed ? 76 : 240 }}
        transition={{ type: "spring", stiffness: 380, damping: 38 }}
        className="relative hidden shrink-0 flex-col border-r bg-muted/40 px-3 py-4 lg:flex"
      >
        <div className="mb-6 flex h-10 items-center px-2">
          <Logo compact={collapsed} />
        </div>
        <SidebarContent collapsed={collapsed} />
        <AnimatePresence initial={false}>{!collapsed && <SidebarLighthouse key="lighthouse" />}</AnimatePresence>
        <div className={cn(collapsed && "mt-auto")}>
          <button
            onClick={() => setCollapsed((c) => !c)}
            className="flex h-9 w-full items-center gap-3 rounded-xl px-3 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            <motion.span animate={{ rotate: collapsed ? 180 : 0 }}>
              <ChevronsLeft className="size-4" />
            </motion.span>
            {!collapsed && "Collapse"}
          </button>
        </div>
      </motion.aside>

      {/* Mobile sidebar */}
      <AnimatePresence>
        {mobileOpen && (
          <>
            <motion.div
              className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm lg:hidden"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setMobileOpen(false)}
            />
            <motion.aside
              className="fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r bg-background px-3 py-4 lg:hidden"
              initial={{ x: "-100%" }}
              animate={{ x: 0 }}
              exit={{ x: "-100%" }}
              transition={{ type: "spring", stiffness: 380, damping: 36 }}
            >
              <div className="mb-6 px-2">
                <Logo />
              </div>
              <SidebarContent collapsed={false} onNavigate={() => setMobileOpen(false)} />
              <SidebarLighthouse />
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 shrink-0 items-center gap-3 border-b bg-background/75 px-4 backdrop-blur-xl sm:px-6">
          <Button variant="ghost" size="icon" className="lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open menu">
            <Menu />
          </Button>
          <div className="lg:hidden">
            <Logo compact />
          </div>
          <div className="flex-1" />
          <SyncIndicator />
          <div className="mx-1 h-6 w-px bg-border" />
          <ThemeToggle />
          <UserMenu onChangePassword={() => setPwOpen(true)} />
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={location.pathname.split("/")[1] || "home"}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0, transition: { duration: 0.22, ease: [0.22, 1, 0.36, 1] } }}
              exit={{ opacity: 0, y: -6, transition: { duration: 0.12, ease: "easeIn" } }}
              className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8"
            >
              <PageContent>{outlet}</PageContent>
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <ChangePasswordDialog open={pwOpen} onOpenChange={setPwOpen} />
    </div>
  );
}
