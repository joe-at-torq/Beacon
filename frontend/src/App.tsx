import { AnimatePresence, motion } from "framer-motion";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell, Logo } from "./components/layout/AppShell";
import { ChangePasswordDialog } from "./components/layout/ChangePasswordDialog";
import { useAuth } from "./lib/auth";
import Dashboard from "./pages/Dashboard";
import DatabasePage from "./pages/Database";
import Login, { AuthBackdrop } from "./pages/Login";
import RulesPage from "./pages/Rules";
import SettingsPage from "./pages/settings/Settings";

function Splash() {
  return (
    <div className="grid h-full place-items-center">
      <motion.div animate={{ scale: [1, 1.06, 1], opacity: [0.7, 1, 0.7] }} transition={{ repeat: Infinity, duration: 1.6 }}>
        <Logo compact />
      </motion.div>
    </div>
  );
}

export default function App() {
  const { user, loading } = useAuth();
  if (loading) return <Splash />;

  return (
    <AnimatePresence mode="wait">
      {!user ? (
        <motion.div key="login" className="h-full" exit={{ opacity: 0 }}>
          <Routes>
            <Route path="*" element={<Login />} />
          </Routes>
        </motion.div>
      ) : user.must_change_password ? (
        <motion.div key="pw" className="h-full" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <AuthBackdrop />
          <ChangePasswordDialog open forced onOpenChange={() => undefined} />
        </motion.div>
      ) : (
        <motion.div key="app" className="h-full" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<Dashboard />} />
              <Route path="database" element={<DatabasePage />} />
              <Route path="rules" element={<RulesPage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="settings/:tab" element={<SettingsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
