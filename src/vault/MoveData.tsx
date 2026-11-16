/**
 * Settings → “Move data”: import and export.
 *
 * Props:
 * - `onError?: (message: string) => void` — called with the human-readable
 *   reason whenever a preview, import or export fails, so the host screen can
 *   surface it in a toast. Both flows also render the reason inline.
 *
 * This component is only the card: the two flows own their own state and the
 * stylesheet is imported here because neither flow may render outside the card.
 */
import { ArrowRightLeft } from "lucide-react";
import ExportFlow from "./movedata/ExportFlow";
import ImportFlow from "./movedata/ImportFlow";
import "../styles/portability.css";

export interface MoveDataProps {
  onError?: (message: string) => void;
  /** Fires after an import wrote items, so the shell can refresh its lists. */
  onChanged?: () => void;
}

export default function MoveData({ onError, onChanged }: MoveDataProps) {
  return (
    <section className="card mv-card" aria-labelledby="move-data-title">
      <div className="card-head">
        <h2 className="card-title" id="move-data-title">
          <ArrowRightLeft size={15} aria-hidden /> Move data
        </h2>
      </div>
      <p className="card-copy">
        Bring items in from JSON, CSV or a 1Password <code>.1pux</code> export,
        or take a copy out. Imports never merge: every row becomes a new item,
        even when a title already exists.
      </p>

      <ImportFlow onError={onError} onChanged={onChanged} />
      <ExportFlow onError={onError} />
    </section>
  );
}
