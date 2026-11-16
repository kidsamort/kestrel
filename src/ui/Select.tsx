/**
 * A select whose list we draw ourselves.
 *
 * The native `<select>` popup is rendered by the operating system, so no CSS
 * reaches it: it arrives in the system font, with the system highlight, on top
 * of an app that has its own palette. This is a button plus a listbox, styled
 * with the app's tokens, and it keeps the behaviour a select is expected to
 * have — arrow keys, Home/End, Enter, Escape, type-ahead on the first letter,
 * and a click outside that closes it.
 *
 * It is a listbox, not a menu: `role="listbox"` with `aria-activedescendant`,
 * so a screen reader announces "listbox, 3 of 6" rather than a row of buttons.
 */
import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from "react";
import { Check, ChevronDown } from "lucide-react";

export interface SelectOption {
  value: string;
  label: string;
  /** Shown under the label inside the list; never inside the button. */
  hint?: string;
}

export default function Select({
  value,
  options,
  onChange,
  label,
  disabled,
  className,
  /** Width of the list; defaults to the button's width. */
  listWidth,
}: {
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  /** Accessible name. The visible label, if any, is the caller's. */
  label: string;
  disabled?: boolean;
  className?: string;
  listWidth?: number;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLDivElement>(null);

  const selected = useMemo(
    () => Math.max(0, options.findIndex((option) => option.value === value)),
    [options, value],
  );
  const current = options[selected] ?? options[0];

  // Opening starts on the chosen row, not at the top: that is what a select does.
  useEffect(() => {
    if (open) setActive(selected);
  }, [open, selected]);

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    // Capture, so a click on another control does not fire its handler first.
    document.addEventListener("mousedown", close, true);
    return () => document.removeEventListener("mousedown", close, true);
  }, [open]);

  // Keep the active row in view when the list is longer than its box.
  useEffect(() => {
    if (!open) return;
    const row = list.current?.querySelector<HTMLElement>(`[data-index="${active}"]`);
    // Not every environment implements it (jsdom does not), and a list that
    // cannot scroll itself is not a reason to throw.
    row?.scrollIntoView?.({ block: "nearest" });
  }, [open, active]);

  function choose(index: number) {
    const option = options[index];
    if (!option) return;
    onChange(option.value);
    setOpen(false);
    button.current?.focus();
  }

  function onKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    if (disabled) return;
    if (!open) {
      if (["ArrowDown", "ArrowUp", "Enter", " "].includes(event.key)) {
        event.preventDefault();
        setOpen(true);
      }
      return;
    }
    switch (event.key) {
      case "ArrowDown":
        event.preventDefault();
        setActive((index) => Math.min(options.length - 1, index + 1));
        break;
      case "ArrowUp":
        event.preventDefault();
        setActive((index) => Math.max(0, index - 1));
        break;
      case "Home":
        event.preventDefault();
        setActive(0);
        break;
      case "End":
        event.preventDefault();
        setActive(options.length - 1);
        break;
      case "Enter":
      case " ":
        event.preventDefault();
        choose(active);
        break;
      case "Escape":
        event.preventDefault();
        setOpen(false);
        break;
      case "Tab":
        setOpen(false);
        break;
      default: {
        // Type-ahead: the first letter of a row jumps to it.
        if (event.key.length !== 1) return;
        const needle = event.key.toLowerCase();
        const found = options.findIndex((option) =>
          option.label.toLowerCase().startsWith(needle),
        );
        if (found >= 0) setActive(found);
      }
    }
  }

  return (
    <div className={`select ${className ?? ""}`} ref={root}>
      <button
        ref={button}
        type="button"
        className="select-button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={label}
        disabled={disabled}
        onClick={() => setOpen((value) => !value)}
        onKeyDown={onKeyDown}
      >
        <span className="select-value">{current?.label ?? ""}</span>
        <ChevronDown size={14} strokeWidth={1.6} aria-hidden className="select-chevron" />
      </button>

      {open ? (
        <div
          ref={list}
          className="select-list"
          role="listbox"
          aria-label={label}
          aria-activedescendant={`${id}-${active}`}
          style={listWidth ? { width: listWidth } : undefined}
        >
          {options.map((option, index) => (
            <div
              key={option.value}
              id={`${id}-${index}`}
              data-index={index}
              role="option"
              aria-selected={index === selected}
              className={`select-option${index === active ? " is-active" : ""}`}
              onMouseEnter={() => setActive(index)}
              // `mousedown` keeps focus on the button, so the list does not
              // close before the click lands.
              onMouseDown={(event) => {
                event.preventDefault();
                choose(index);
              }}
            >
              <span className="select-option-label">{option.label}</span>
              {option.hint ? (
                <span className="select-option-hint">{option.hint}</span>
              ) : null}
              {index === selected ? (
                <Check size={13} strokeWidth={2} aria-hidden className="select-check" />
              ) : null}
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}
