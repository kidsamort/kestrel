import { Clock3 } from "lucide-react";
import { clock } from "../../lib/format";
import { Tip } from "../../ui/Tooltip";
import { autolockWarning } from "./logic";

/**
 * Autolock countdown portalled into the window toolbar. The warning window comes
 * from `autolockWarning`, the same rule the shell uses for its warning state.
 */
export default function AutolockBadge({
  remainingSeconds,
  autolockSeconds,
}: {
  remainingSeconds: number;
  autolockSeconds: number;
}) {
  const { warning } = autolockWarning(remainingSeconds, autolockSeconds);
  return (
    <Tip
      label={remainingSeconds > 0 ? "Locks after inactivity" : "Vault locked"}
      keys={`${clock(remainingSeconds)} left · ${Math.round(
        autolockSeconds / 60,
      )} min idle`}
    >
      <span
        className={`autolock ${warning ? "is-warning" : ""}`}
        role="timer"
        aria-live={warning ? "polite" : "off"}
        aria-label={`Vault locks in ${clock(remainingSeconds)}`}
      >
        <Clock3 size={13} strokeWidth={1.6} aria-hidden />
        <span className="autolock-time">{clock(remainingSeconds)}</span>
      </span>
    </Tip>
  );
}
