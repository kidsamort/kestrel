/**
 * The chord control: the keys themselves, and the field that records a new one.
 *
 * A chord is shown as keys — `Ctrl` `Shift` `Space` — because that is what the
 * person is being asked to press. The same element records a replacement: click
 * it and the next combination you press becomes the chord. There is no separate
 * text field, so nothing can disagree with what is registered.
 *
 * Rules that keep the result usable:
 *
 * - a chord needs at least one modifier plus one real key; `Shift` alone is not
 *   a shortcut, and neither is `A`;
 * - `Escape` cancels the capture and keeps the previous chord;
 * - the backend releases the old chord before binding the new one, so a failed
 *   rebind leaves the previous value, not an empty one.
 */
import { useEffect, useRef, useState } from "react";

const MODIFIER_KEYS: Record<string, true> = {
  Control: true,
  Shift: true,
  Alt: true,
  Meta: true,
};

/** Order the backend and the OS both read: Ctrl, Shift, Alt, then the key. */
const ORDER = ["Ctrl", "Shift", "Alt", "Meta"];

function modifierName(key: string): string | null {
  switch (key) {
    case "Control":
      return "Ctrl";
    case "Shift":
      return "Shift";
    case "Alt":
      return "Alt";
    case "Meta":
      return "Meta";
    default:
      return null;
  }
}

/** A single printable key as the backend spells it. */
function keyName(event: KeyboardEvent): string | null {
  if (event.code.startsWith("Key")) return event.code.slice(3);
  if (event.code.startsWith("Digit")) return event.code.slice(5);
  if (/^F\d{1,2}$/.test(event.key)) return event.key;
  if (event.key === " ") return "Space";
  if (event.key.length === 1) return event.key.toUpperCase();
  if (event.code.startsWith("Arrow")) return event.code;
  return null;
}

/** Build a chord from the modifiers held down and the key pressed. */
export function chordFrom(event: KeyboardEvent): string | null {
  const pressed = [
    event.ctrlKey ? "Ctrl" : null,
    event.shiftKey ? "Shift" : null,
    event.altKey ? "Alt" : null,
    event.metaKey ? "Meta" : null,
  ].filter((part): part is string => part !== null);
  const key = keyName(event);
  if (!key || pressed.length === 0) return null;
  return [...ORDER.filter((name) => pressed.includes(name)), key].join("+");
}

/** The keys of one chord, as the boxes a keyboard would have. */
function Keys({ chord }: { chord: string }) {
  const keys = chord
    .split("+")
    .map((key) => key.trim())
    .filter(Boolean);
  return (
    <span className="keycap-chord">
      {keys.map((key, index) => (
        <kbd className="keycap" key={`${key}-${index}`}>
          {key}
        </kbd>
      ))}
    </span>
  );
}

export function ChordInput({
  value,
  onChange,
  label,
  disabled,
}: {
  value: string;
  onChange: (chord: string) => void;
  /** Accessible name; the visible label is rendered by the caller. */
  label: string;
  disabled?: boolean;
}) {
  const [capturing, setCapturing] = useState(false);
  const [draft, setDraft] = useState(value);
  const ref = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!capturing) setDraft(value);
  }, [value, capturing]);

  useEffect(() => {
    if (!capturing) return;
    const onKeyDown = (event: KeyboardEvent) => {
      event.preventDefault();
      event.stopPropagation();
      if (event.key === "Escape") {
        setCapturing(false);
        setDraft(value);
        return;
      }
      if (MODIFIER_KEYS[event.key] === true) {
        // Show the modifier while it is held, but never commit it alone.
        setDraft(modifierName(event.key) ?? "");
        return;
      }
      const chord = chordFrom(event);
      if (!chord) return;
      setDraft(chord);
      setCapturing(false);
      if (chord !== value) onChange(chord);
    };
    const onKeyUp = (event: KeyboardEvent) => {
      if (
        MODIFIER_KEYS[event.key] === true &&
        draft === (modifierName(event.key) ?? "")
      ) {
        setDraft("");
      }
    };
    window.addEventListener("keydown", onKeyDown, true);
    window.addEventListener("keyup", onKeyUp, true);
    return () => {
      window.removeEventListener("keydown", onKeyDown, true);
      window.removeEventListener("keyup", onKeyUp, true);
    };
  }, [capturing, value, draft, onChange]);

  return (
    <button
      ref={ref}
      type="button"
      className={`chord-input${capturing ? " is-capturing" : ""}`}
      aria-label={`${label}: ${value}. Click and press a new combination.`}
      aria-live="polite"
      title={capturing ? "Press a combination, Escape to cancel" : "Click to change"}
      disabled={disabled}
      onClick={() => setCapturing((on) => !on)}
      onBlur={() => setCapturing(false)}
    >
      {capturing ? (
        draft ? (
          <Keys chord={draft} />
        ) : (
          <span className="chord-input-hint">Press a combination…</span>
        )
      ) : (
        <Keys chord={value} />
      )}
    </button>
  );
}
