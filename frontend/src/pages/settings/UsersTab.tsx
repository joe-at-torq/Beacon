import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { KeyRound, Plus, Trash2, UserRound } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useConfirm } from "@/components/ui/confirm";
import { Modal } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { del, get, patch, post } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Role, User } from "@/lib/types";
import { errorMessage, timeAgo } from "@/lib/utils";

const ROLE_INFO: Record<Role, string> = {
  admin: "Full access, including users, workspaces, rules and settings",
  analyst: "View everything, edit the database and trigger syncs",
  viewer: "Read-only access",
};

function UserDialog({ open, onOpenChange, user }: { open: boolean; onOpenChange: (o: boolean) => void; user: User | null }) {
  const qc = useQueryClient();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [mustChange, setMustChange] = useState(true);
  useEffect(() => {
    if (open) {
      setUsername(user?.username ?? "");
      setPassword("");
      setRole(user?.role ?? "viewer");
      setMustChange(true);
    }
  }, [open, user]);

  const save = useMutation({
    mutationFn: () =>
      user
        ? patch(`/users/${user.id}`, { password, must_change_password: mustChange })
        : post("/users", { username, password, role, must_change_password: mustChange }),
    onSuccess: () => {
      toast.success(user ? "Password reset" : "User created");
      qc.invalidateQueries({ queryKey: ["users"] });
      onOpenChange(false);
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title={user ? `Reset password for ${user.username}` : "Add user"}
      className="max-w-md"
      footer={
        <>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => save.mutate()} loading={save.isPending} disabled={password.length < 8 || (!user && !username.trim())}>
            {user ? "Reset password" : "Create user"}
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        {!user && (
          <>
            <Field label="Username">
              <Input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="off" />
            </Field>
            <Field label="Role" hint={ROLE_INFO[role]}>
              <Select value={role} onChange={(e) => setRole(e.target.value as Role)}>
                <option value="viewer">Viewer</option>
                <option value="analyst">Analyst</option>
                <option value="admin">Admin</option>
              </Select>
            </Field>
          </>
        )}
        <Field label={user ? "New password" : "Password"} hint="At least 8 characters.">
          <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" autoFocus={!!user} />
        </Field>
        <label className="flex items-center gap-3 text-sm">
          <Switch checked={mustChange} onCheckedChange={setMustChange} aria-label="Require change" />
          Require password change at next sign-in
        </label>
      </div>
    </Modal>
  );
}

export default function UsersTab() {
  const qc = useQueryClient();
  const { user: me } = useAuth();
  const confirm = useConfirm();
  const q = useQuery({ queryKey: ["users"], queryFn: () => get<User[]>("/users") });
  const [dialog, setDialog] = useState<{ open: boolean; user: User | null }>({ open: false, user: null });

  const setRole = useMutation({
    mutationFn: ({ id, role }: { id: number; role: Role }) => patch(`/users/${id}`, { role }),
    onSuccess: () => toast.success("Role updated"),
    onError: (e) => toast.error(errorMessage(e)),
    onSettled: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });

  const remove = async (u: User) => {
    if (!(await confirm({ title: `Delete ${u.username}?`, confirmLabel: "Delete", destructive: true }))) return;
    try {
      await del(`/users/${u.id}`);
      toast.success("User deleted");
      qc.invalidateQueries({ queryKey: ["users"] });
    } catch (e) {
      toast.error(errorMessage(e));
    }
  };

  return (
    <>
      <div className="mb-4 flex items-center justify-between">
        <p className="text-sm text-muted-foreground">Local accounts that can sign in to Beacon</p>
        <Button onClick={() => setDialog({ open: true, user: null })}>
          <Plus /> Add user
        </Button>
      </div>
      <Card className="overflow-hidden">
        <table className="w-full text-sm">
          <thead className="border-b bg-muted/40 text-xs text-muted-foreground">
            <tr>
              <th className="px-4 py-3 text-left font-medium">User</th>
              <th className="px-4 py-3 text-left font-medium">Role</th>
              <th className="hidden px-4 py-3 text-left font-medium md:table-cell">Last sign-in</th>
              <th className="px-4 py-3 text-right font-medium">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {q.isLoading && (
              <tr>
                <td colSpan={4} className="p-4">
                  <Skeleton className="h-8" />
                </td>
              </tr>
            )}
            <AnimatePresence initial={false}>
              {(q.data ?? []).map((u) => (
                <motion.tr key={u.id} layout initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-3">
                      <span className="grid size-8 place-items-center rounded-lg bg-muted text-muted-foreground">
                        <UserRound className="size-4" />
                      </span>
                      <div>
                        <div className="font-medium">
                          {u.username} {u.id === me?.id && <span className="text-xs font-normal text-muted-foreground">(you)</span>}
                        </div>
                        {u.must_change_password && <Badge tone="warning">Password change pending</Badge>}
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <Select
                      value={u.role}
                      onChange={(e) => setRole.mutate({ id: u.id, role: e.target.value as Role })}
                      disabled={u.id === me?.id}
                      className="w-32"
                    >
                      <option value="viewer">Viewer</option>
                      <option value="analyst">Analyst</option>
                      <option value="admin">Admin</option>
                    </Select>
                  </td>
                  <td className="hidden px-4 py-3 text-xs text-muted-foreground md:table-cell">{timeAgo(u.last_login)}</td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-1">
                      <Button size="sm" variant="ghost" onClick={() => setDialog({ open: true, user: u })}>
                        <KeyRound /> Reset password
                      </Button>
                      <Button
                        size="icon-sm"
                        variant="ghost"
                        className="text-destructive hover:bg-destructive/10"
                        disabled={u.id === me?.id}
                        onClick={() => remove(u)}
                        aria-label="Delete user"
                      >
                        <Trash2 />
                      </Button>
                    </div>
                  </td>
                </motion.tr>
              ))}
            </AnimatePresence>
          </tbody>
        </table>
      </Card>
      <UserDialog open={dialog.open} onOpenChange={(open) => setDialog((d) => ({ ...d, open }))} user={dialog.user} />
    </>
  );
}
