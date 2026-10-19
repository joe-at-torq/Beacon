import { useState } from "react";
import { toast } from "sonner";
import { ShieldCheck } from "lucide-react";
import { post } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { errorMessage } from "@/lib/utils";
import { Button } from "../ui/button";
import { Modal } from "../ui/dialog";
import { Field, Input } from "../ui/input";

export function ChangePasswordDialog({ open, onOpenChange, forced = false }: { open: boolean; onOpenChange: (o: boolean) => void; forced?: boolean }) {
  const { refresh } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const mismatch = confirm.length > 0 && next !== confirm;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (next !== confirm) return;
    setBusy(true);
    try {
      await post("/auth/change-password", { current_password: current, new_password: next });
      toast.success("Password updated");
      setCurrent("");
      setNext("");
      setConfirm("");
      await refresh();
      onOpenChange(false);
    } catch (err) {
      toast.error(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onOpenChange={(o) => !forced && onOpenChange(o)}
      title={
        <span className="inline-flex items-center gap-2">
          <ShieldCheck className="size-5 text-primary" /> {forced ? "Set a new password" : "Change password"}
        </span>
      }
      description={forced ? "You're using the default credentials. Choose a new password to continue." : undefined}
      className="max-w-md"
    >
      <form onSubmit={submit} className="space-y-4">
        <Field label="Current password">
          <Input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required autoFocus />
        </Field>
        <Field label="New password" hint="At least 8 characters.">
          <Input type="password" autoComplete="new-password" minLength={8} value={next} onChange={(e) => setNext(e.target.value)} required />
        </Field>
        <Field label="Confirm new password" hint={mismatch ? <span className="text-destructive">Passwords don't match</span> : undefined}>
          <Input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
        </Field>
        <div className="flex justify-end gap-2 pt-2">
          {!forced && (
            <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
          )}
          <Button type="submit" loading={busy} disabled={mismatch || next.length < 8}>
            Update password
          </Button>
        </div>
      </form>
    </Modal>
  );
}
