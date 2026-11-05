import { Activity, Code2, Puzzle, Server, SlidersHorizontal, Users } from "lucide-react";
import { createPortal } from "react-dom";
import { useNavigate, useParams } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import { PageHeader } from "@/components/bits";
import { Segmented } from "@/components/ui/segmented";
import { useAuth } from "@/lib/auth";
import ApiTab from "./ApiTab";
import GeneralTab from "./GeneralTab";
import IntegrationsTab from "./IntegrationsTab";
import SyncLogTab from "./SyncLogTab";
import UsersTab from "./UsersTab";
import WorkspacesTab from "./WorkspacesTab";

type Tab = "workspaces" | "integrations" | "api" | "users" | "general" | "sync";

export default function SettingsPage() {
  const { tab = "workspaces" } = useParams();
  const navigate = useNavigate();
  const { can } = useAuth();
  const tabs: { value: Tab; label: React.ReactNode }[] = [
    { value: "workspaces", label: <><Server /> Workspaces</> },
    { value: "integrations", label: <><Puzzle /> Integrations</> },
    { value: "api", label: <><Code2 /> API</> },
    ...(can("admin") ? [{ value: "users" as Tab, label: <><Users /> Users</> }] : []),
    { value: "general", label: <><SlidersHorizontal /> General</> },
    { value: "sync", label: <><Activity /> Sync log</> },
  ];
  const current = (tabs.some((t) => t.value === tab) ? tab : "workspaces") as Tab;

  return (
    <>
      <PageHeader title="Settings" description="Manage connected workspaces, users and synchronization behavior" />
      <Segmented value={current} onChange={(t) => navigate(`/settings/${t}`)} options={tabs} className="mb-6" />
      <AnimatePresence mode="wait">
        <motion.div
          key={current}
          initial={{ opacity: 0, x: 12 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -12 }}
          transition={{ duration: 0.2, ease: "easeOut" }}
        >
          {current === "workspaces" && <WorkspacesTab />}
          {current === "integrations" && <IntegrationsTab />}
          {current === "api" && <ApiTab />}
          {current === "users" && <UsersTab />}
          {current === "general" && <GeneralTab />}
          {current === "sync" && <SyncLogTab />}
        </motion.div>
      </AnimatePresence>
      {/* Portaled: the animated page wrappers use transforms, which would break position: fixed. */}
      {createPortal(
        <span className="pointer-events-none fixed bottom-3 right-4 z-10 select-none text-[11px] tabular-nums text-muted-foreground">
          v{__APP_VERSION__}
        </span>,
        document.body,
      )}
    </>
  );
}
