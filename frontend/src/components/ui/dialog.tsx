import * as RD from "@radix-ui/react-dialog";
import { AnimatePresence, motion, PresenceContext } from "framer-motion";
import { X } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/**
 * Detach dialog contents from the dialog's exit animation. Without this, animated descendants (e.g. shared
 * layout highlights) can keep the exit from ever completing, leaving an invisible overlay over the page.
 */
function IsolatePresence({ children }: { children: ReactNode }) {
  return <PresenceContext.Provider value={null}>{children}</PresenceContext.Provider>;
}

// Once closed (while the exit animation plays), never intercept clicks.
const CLOSED_PASSTHROUGH = "data-[state=closed]:pointer-events-none";

export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  className,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  className?: string;
}) {
  return (
    <RD.Root open={open} onOpenChange={onOpenChange}>
      <AnimatePresence>
        {open && (
          <RD.Portal forceMount>
            <RD.Overlay asChild forceMount>
              <motion.div
                className={cn("fixed inset-0 z-50 bg-black/40 backdrop-blur-sm", CLOSED_PASSTHROUGH)}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0, transition: { duration: 0.14 } }}
                transition={{ duration: 0.2 }}
              />
            </RD.Overlay>
            <div className="pointer-events-none fixed inset-0 z-50 grid place-items-center p-4">
              <RD.Content asChild forceMount>
                <motion.div
                  className={cn(
                    "pointer-events-auto relative flex max-h-[90vh] w-full max-w-lg flex-col rounded-2xl border bg-popover text-popover-foreground shadow-2xl",
                    CLOSED_PASSTHROUGH,
                    className,
                  )}
                  initial={{ opacity: 0, scale: 0.96, y: 12 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.97, y: 8, transition: { duration: 0.14, ease: "easeIn" } }}
                  transition={{ type: "spring", stiffness: 380, damping: 30 }}
                >
                  <div className="flex items-start justify-between gap-4 px-6 pt-5">
                    <div>
                      <RD.Title className="text-base font-semibold tracking-tight">{title}</RD.Title>
                      {description ? (
                        <RD.Description className="mt-1 text-sm text-muted-foreground">{description}</RD.Description>
                      ) : (
                        <RD.Description className="sr-only">{typeof title === "string" ? title : "Dialog"}</RD.Description>
                      )}
                    </div>
                    <RD.Close className="-mr-2 rounded-lg p-1.5 text-muted-foreground transition hover:bg-muted hover:text-foreground">
                      <X className="size-4" />
                    </RD.Close>
                  </div>
                  <IsolatePresence>
                    <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">{children}</div>
                    {footer && <div className="flex justify-end gap-2 border-t bg-muted/30 px-6 py-3.5 rounded-b-2xl">{footer}</div>}
                  </IsolatePresence>
                </motion.div>
              </RD.Content>
            </div>
          </RD.Portal>
        )}
      </AnimatePresence>
    </RD.Root>
  );
}

export function Sheet({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  className,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  className?: string;
}) {
  return (
    <RD.Root open={open} onOpenChange={onOpenChange}>
      <AnimatePresence>
        {open && (
          <RD.Portal forceMount>
            <RD.Overlay asChild forceMount>
              <motion.div
                className={cn("fixed inset-0 z-50 bg-black/30 backdrop-blur-[2px]", CLOSED_PASSTHROUGH)}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0, transition: { duration: 0.2 } }}
              />
            </RD.Overlay>
            <RD.Content asChild forceMount onOpenAutoFocus={(e) => e.preventDefault()}>
              <motion.aside
                className={cn("fixed inset-y-0 right-0 z-50 flex w-full max-w-xl flex-col border-l bg-popover shadow-2xl", className, CLOSED_PASSTHROUGH)}
                initial={{ x: "100%" }}
                animate={{ x: 0 }}
                exit={{ x: "100%", transition: { duration: 0.2, ease: [0.4, 0, 1, 1] } }}
                transition={{ type: "spring", stiffness: 320, damping: 34 }}
              >
                <div className="flex items-start justify-between gap-4 border-b px-6 py-5">
                  <div className="min-w-0">
                    <RD.Title className="truncate text-base font-semibold tracking-tight">{title}</RD.Title>
                    <RD.Description className={description ? "mt-1 text-sm text-muted-foreground" : "sr-only"}>
                      {description ?? "Details"}
                    </RD.Description>
                  </div>
                  <RD.Close className="-mr-2 rounded-lg p-1.5 text-muted-foreground transition hover:bg-muted hover:text-foreground">
                    <X className="size-4" />
                  </RD.Close>
                </div>
                <IsolatePresence>
                  <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">{children}</div>
                  {footer && <div className="flex justify-end gap-2 border-t px-6 py-4">{footer}</div>}
                </IsolatePresence>
              </motion.aside>
            </RD.Content>
          </RD.Portal>
        )}
      </AnimatePresence>
    </RD.Root>
  );
}
