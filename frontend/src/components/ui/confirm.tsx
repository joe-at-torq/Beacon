import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import { Button } from "./button";
import { Modal } from "./dialog";

interface ConfirmOptions {
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  destructive?: boolean;
}

interface ConfirmOption {
  /** Checkbox label, e.g. "Also delete its 1,234 observables" */
  label: ReactNode;
  hint?: ReactNode;
  defaultChecked?: boolean;
  /** Shown instead of the checkbox when there's nothing to choose (e.g. nothing to delete). */
  disabledReason?: ReactNode;
}

type Result = { confirmed: boolean; option: boolean };
type Request = ConfirmOptions & { option?: ConfirmOption };

const Ctx = createContext<(o: Request) => Promise<Result>>(() => Promise.resolve({ confirmed: false, option: false }));

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [opts, setOpts] = useState<Request | null>(null);
  const [checked, setChecked] = useState(false);
  const resolver = useRef<(v: Result) => void>();

  const ask = useCallback((o: Request) => {
    setOpts(o);
    setChecked(!!o.option?.defaultChecked && !o.option.disabledReason);
    return new Promise<Result>((resolve) => {
      resolver.current = resolve;
    });
  }, []);

  const close = (confirmed: boolean) => {
    resolver.current?.({ confirmed, option: confirmed && checked });
    resolver.current = undefined;
    setOpts(null);
  };

  const option = opts?.option;
  return (
    <Ctx.Provider value={ask}>
      {children}
      <Modal
        open={!!opts}
        onOpenChange={(o) => !o && close(false)}
        title={opts?.title ?? ""}
        description={opts?.description}
        className="max-w-md"
        footer={
          <>
            <Button variant="ghost" onClick={() => close(false)}>
              Cancel
            </Button>
            <Button variant={opts?.destructive ? "destructive" : "primary"} onClick={() => close(true)} autoFocus>
              {opts?.confirmLabel ?? "Confirm"}
            </Button>
          </>
        }
      >
        {option &&
          (option.disabledReason ? (
            <p className="rounded-xl bg-muted/50 p-3 text-xs text-muted-foreground">{option.disabledReason}</p>
          ) : (
            <label className="flex cursor-pointer items-start gap-3 rounded-xl border p-3 text-sm transition-colors hover:bg-muted/40">
              <input
                type="checkbox"
                className="mt-0.5 size-4 shrink-0 accent-[hsl(var(--destructive))]"
                checked={checked}
                onChange={(e) => setChecked(e.target.checked)}
              />
              <span>
                <span className="font-medium">{option.label}</span>
                {option.hint && <span className="mt-0.5 block text-xs text-muted-foreground">{option.hint}</span>}
              </span>
            </label>
          ))}
      </Modal>
    </Ctx.Provider>
  );
}

/** Yes/no confirmation. */
export const useConfirm = () => {
  const ask = useContext(Ctx);
  return useCallback((o: ConfirmOptions) => ask(o).then((r) => r.confirmed), [ask]);
};

/** Confirmation with an optional extra choice (a checkbox), e.g. "also delete its observables". */
export const useConfirmWithOption = () => useContext(Ctx);
