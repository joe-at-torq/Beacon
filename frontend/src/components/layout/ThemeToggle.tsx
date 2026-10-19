import { AnimatePresence, motion } from "framer-motion";
import { Moon, Sun } from "lucide-react";
import { useTheme } from "@/lib/theme";
import { Tooltip } from "../ui/tooltip";

export function ThemeToggle() {
  const { resolved, toggle } = useTheme();
  const dark = resolved === "dark";
  return (
    <Tooltip content={dark ? "Switch to light mode" : "Switch to dark mode"}>
      <button
        onClick={toggle}
        aria-label="Toggle theme"
        className="relative grid size-9 place-items-center overflow-hidden rounded-lg text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
      >
        <AnimatePresence mode="wait" initial={false}>
          <motion.span
            key={dark ? "moon" : "sun"}
            initial={{ y: -18, rotate: -90, opacity: 0 }}
            animate={{ y: 0, rotate: 0, opacity: 1 }}
            exit={{ y: 18, rotate: 90, opacity: 0 }}
            transition={{ duration: 0.25, ease: "easeOut" }}
          >
            {dark ? <Moon className="size-[18px]" /> : <Sun className="size-[18px]" />}
          </motion.span>
        </AnimatePresence>
      </button>
    </Tooltip>
  );
}
