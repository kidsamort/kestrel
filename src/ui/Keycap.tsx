/**
 * A chord drawn as keys.
 *
 * `Ctrl+Shift+Space` is a string; on screen it should look like three keys,
 * because that is what the person is being asked to press. The component takes
 * the same string the backend reports (`quick_status.shortcut`,
 * `autofill_status.shortcut`) and splits it on `+`, so the label never drifts
 * from the chord that is actually registered.
 */

export function Keycap({
  chord,
  size = "normal",
}: {
  /** `Ctrl+Shift+Space`; anything without `+` is one key. */
  chord: string;
  size?: "normal" | "small";
}) {
  const keys = chord
    .split("+")
    .map((key) => key.trim())
    .filter(Boolean);
  if (keys.length === 0) return null;
  return (
    <span className={`keycap-chord${size === "small" ? " is-small" : ""}`}>
      {keys.map((key, index) => (
        <kbd className="keycap" key={`${key}-${index}`}>
          {key}
        </kbd>
      ))}
    </span>
  );
}
