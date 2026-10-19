import * as RT from "@radix-ui/react-tooltip";
import type { ReactNode } from "react";

export const TooltipProvider = RT.Provider;

export function Tooltip({ content, children, side = "top" }: { content: ReactNode; children: ReactNode; side?: "top" | "bottom" | "left" | "right" }) {
  return (
    <RT.Root delayDuration={250}>
      <RT.Trigger asChild>{children}</RT.Trigger>
      <RT.Portal>
        <RT.Content
          side={side}
          sideOffset={6}
          className="z-[60] max-w-xs rounded-md bg-foreground px-2 py-1 text-xs text-background shadow-lg"
        >
          {content}
        </RT.Content>
      </RT.Portal>
    </RT.Root>
  );
}
