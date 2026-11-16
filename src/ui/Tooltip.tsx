import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import type { ReactNode } from "react";

/** Wrap the app once. Tooltips describe icon-only controls; never carry state. */
export function TooltipProvider({ children }: { children: ReactNode }) {
  return (
    <TooltipPrimitive.Provider delayDuration={450} skipDelayDuration={80}>
      {children}
    </TooltipPrimitive.Provider>
  );
}

export function Tip({
  label,
  keys,
  side = "bottom",
  children,
}: {
  label: string;
  keys?: string;
  side?: "top" | "bottom" | "left" | "right";
  children: ReactNode;
}) {
  return (
    <TooltipPrimitive.Root>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content className="tip" side={side} sideOffset={6}>
          {label}
          {keys ? <span className="tip-key">{keys}</span> : null}
          <TooltipPrimitive.Arrow className="tip-arrow" />
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}
