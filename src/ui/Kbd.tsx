import type { ReactNode } from "react";

/** A literal keyboard chord. Rendered with mono digits and a hairline border. */
export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="kbd">{children}</kbd>;
}

export function KbdGroup({ keys }: { keys: string[] }) {
  return (
    <span className="kbd-group">
      {keys.map((key) => (
        <Kbd key={key}>{key}</Kbd>
      ))}
    </span>
  );
}
