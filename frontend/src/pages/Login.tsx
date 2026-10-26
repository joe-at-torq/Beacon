import { AnimatePresence, motion } from "framer-motion";
import { Lock, User as UserIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/input";
import { useAuth } from "@/lib/auth";
import { useTheme } from "@/lib/theme";
import { errorMessage } from "@/lib/utils";

export function AuthBackdrop() {
  return (
    <div className="pointer-events-none fixed inset-0 -z-0 overflow-hidden">
      <div className="bg-grid absolute inset-0 [mask-image:radial-gradient(ellipse_at_center,black_20%,transparent_70%)]" />
      <motion.div
        className="absolute -left-40 -top-40 size-[520px] rounded-full bg-[#7c5cff]/25 blur-3xl"
        animate={{ x: [0, 60, 0], y: [0, 40, 0] }}
        transition={{ duration: 18, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.div
        className="absolute -bottom-48 -right-32 size-[560px] rounded-full bg-[#2a78d6]/20 blur-3xl"
        animate={{ x: [0, -50, 0], y: [0, -30, 0] }}
        transition={{ duration: 22, repeat: Infinity, ease: "easeInOut" }}
      />
    </div>
  );
}

export default function Login() {
  const { login } = useAuth();
  const { resolved } = useTheme();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [shake, setShake] = useState(0);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await login(username, password);
    } catch (err) {
      toast.error(errorMessage(err));
      setShake((s) => s + 1);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative grid h-full place-items-center overflow-hidden px-4">
      <AuthBackdrop />
      <div className="absolute right-4 top-4 z-10">
        <ThemeToggle />
      </div>
      <motion.div
        key={shake}
        initial={shake ? { x: 0 } : { opacity: 0, y: 16, scale: 0.98 }}
        animate={shake ? { x: [0, -10, 10, -6, 6, 0] } : { opacity: 1, y: 0, scale: 1 }}
        transition={shake ? { duration: 0.4 } : { type: "spring", stiffness: 260, damping: 26 }}
        className="glass relative z-10 w-full max-w-md rounded-3xl p-8 shadow-2xl"
      >
        <div className="mb-6 flex flex-col items-center text-center">
          <AnimatePresence mode="wait" initial={false}>
            <motion.img
              key={resolved}
              src={resolved === "dark" ? "/brand/beacon-dark.png" : "/brand/beacon-light.png"}
              alt="Beacon"
              className="-mx-8 h-[22rem] max-h-[42vh] w-auto max-w-[calc(100%+4rem)] select-none object-contain"
              draggable={false}
              initial={{ opacity: 0, scale: 0.96 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.96 }}
              transition={{ duration: 0.25 }}
            />
          </AnimatePresence>
        </div>
        <form onSubmit={submit} className="space-y-4">
          <Field label="Username">
            <Input icon={<UserIcon />} value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
          </Field>
          <Field label="Password">
            <Input icon={<Lock />} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
          </Field>
          <Button type="submit" size="lg" className="mt-2 w-full" loading={busy}>
            Sign in
          </Button>
        </form>
      </motion.div>
    </div>
  );
}
