import { useEffect, useRef, useState } from "react";
import { Check, RefreshCw } from "lucide-react";
import { api, errorText } from "../api";
import type { CopyApi } from "../lib/copy";
import { entropyFor, optionsAreValid } from "../lib/generator";
import { DEFAULT_GENERATE, type GenerateOptions } from "../types";
import { Button } from "../ui/Button";
import { Switch } from "../ui/Switch";
import { Tip } from "../ui/Tooltip";

/* ------------------------------------------------------------- generator */

const SEPARATORS = ["-", ".", "_", " ", ""];

export function GeneratorPanel({
  variant,
  initial,
  onUse,
  onCopy,
}: {
  variant: "standalone" | "dialog";
  initial?: GenerateOptions;
  onUse?: (value: string) => void;
  onCopy?: CopyApi["copyText"];
}) {
  const [options, setOptions] = useState<GenerateOptions>(initial ?? DEFAULT_GENERATE);
  const [value, setValue] = useState("");
  const [nonce, setNonce] = useState(0);
  const [failed, setFailed] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const request = useRef(0);
  const valid = optionsAreValid(options);
  const bits = entropyFor(options);

  useEffect(() => {
    if (!valid) {
      setValue("");
      return;
    }
    const token = ++request.current;
    const timer = window.setTimeout(() => {
      api
        .generate(options)
        .then((generated) => {
          if (token !== request.current) return;
          setValue(generated);
          setFailed(null);
        })
        .catch((error) => {
          if (token === request.current) setFailed(errorText(error));
        });
    }, 60);
    return () => window.clearTimeout(timer);
  }, [options, nonce, valid]);

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.altKey && event.key.toLowerCase() === "r") {
        event.preventDefault();
        setNonce((n) => n + 1);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const update = <K extends keyof GenerateOptions>(
    key: K,
    next: GenerateOptions[K],
  ) => setOptions((current) => ({ ...current, [key]: next }));

  const level = bits >= 90 ? 4 : bits >= 70 ? 3 : bits >= 50 ? 2 : bits > 0 ? 1 : 0;

  return (
    <div className={`generator generator-${variant}`}>
      <div className="gen-output">
        <div className="gen-value" aria-live="polite" aria-label="Generated value">
          {value || "…"}
        </div>
        <div className="gen-output-actions">
          <Tip label="Generate another" keys="Alt R">
            <button
              type="button"
              className="icon-btn"
              aria-label="Generate another"
              onClick={() => setNonce((n) => n + 1)}
            >
              <RefreshCw size={15} strokeWidth={1.6} aria-hidden />
            </button>
          </Tip>
          {variant === "dialog" ? (
            <Button
              variant="primary"
              size="sm"
              leading={<Check size={13} aria-hidden />}
              disabled={!value}
              onClick={() => onUse?.(value)}
            >
              Use password
            </Button>
          ) : (
            <Button
              variant="primary"
              size="sm"
              disabled={!value}
              leading={copied ? <Check size={13} aria-hidden /> : undefined}
              onClick={() => {
                if (!value || !onCopy) return;
                onCopy(value, "generated password");
                setCopied(true);
                window.setTimeout(() => setCopied(false), 1400);
              }}
            >
              {copied ? "Copied" : "Copy password"}
            </Button>
          )}
        </div>
      </div>

      <div className="gen-meter">
        <div className="strength-bars" aria-hidden="true">
          {[1, 2, 3, 4].map((step) => (
            <span
              key={step}
              className={
                level >= step
                  ? `strength-bar on level-${level}`
                  : "strength-bar"
              }
            />
          ))}
        </div>
        <span className="strength-label">
          ≈{bits} bits of entropy · {options.passphrase ? options.words : options.length}{" "}
          {options.passphrase ? "words" : "characters"}
        </span>
      </div>

      {failed ? (
        <p className="form-error" role="alert">
          {failed}
        </p>
      ) : null}

      <div className="gen-mode" role="group" aria-label="Generator mode">
        <button
          type="button"
          className={`seg ${!options.passphrase ? "is-on" : ""}`}
          aria-pressed={!options.passphrase}
          onClick={() => update("passphrase", false)}
        >
          Password
        </button>
        <button
          type="button"
          className={`seg ${options.passphrase ? "is-on" : ""}`}
          aria-pressed={options.passphrase}
          onClick={() => update("passphrase", true)}
        >
          Passphrase
        </button>
      </div>

      {options.passphrase ? (
        <div className="gen-options">
          <SliderRow
            label="Words"
            value={options.words}
            min={3}
            max={12}
            onChange={(words) => update("words", words)}
          />
          <div className="gen-row">
            <span className="gen-label">Separator</span>
            <div className="seg-row" role="group" aria-label="Word separator">
              {SEPARATORS.map((separator) => (
                <button
                  key={separator || "none"}
                  type="button"
                  className={`seg seg-tight ${
                    options.separator === separator ? "is-on" : ""
                  }`}
                  aria-pressed={options.separator === separator}
                  onClick={() => update("separator", separator)}
                >
                  {separator === " " ? "space" : separator || "none"}
                </button>
              ))}
            </div>
          </div>
          <p className="gen-note">
            The core draws from a fixed 72-word list; each word is worth about
            6.2 bits.
          </p>
        </div>
      ) : (
        <div className="gen-options">
          <SliderRow
            label="Length"
            value={options.length}
            min={8}
            max={64}
            onChange={(length) => update("length", length)}
          />
          <ToggleRow
            label="Lowercase"
            checked={options.lowercase}
            onChange={(v) => update("lowercase", v)}
          />
          <ToggleRow
            label="Uppercase"
            checked={options.uppercase}
            onChange={(v) => update("uppercase", v)}
          />
          <ToggleRow
            label="Digits"
            checked={options.digits}
            onChange={(v) => update("digits", v)}
          />
          <ToggleRow
            label="Symbols"
            checked={options.symbols}
            onChange={(v) => update("symbols", v)}
          />
          <ToggleRow
            label="Avoid ambiguous characters"
            hint="No I, l, 1, O, 0 or o."
            checked={options.avoidAmbiguous}
            onChange={(v) => update("avoidAmbiguous", v)}
          />
          {!valid ? (
            <p className="gen-note is-warn">
              Pick at least one character set. The core would fall back to
              lowercase, which is not what you asked for.
            </p>
          ) : null}
        </div>
      )}
    </div>
  );
}

function SliderRow({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (value: number) => void;
}) {
  return (
    <label className="gen-row">
      <span className="gen-label">{label}</span>
      <input
        className="range"
        type="range"
        min={min}
        max={max}
        value={value}
        aria-label={label}
        onChange={(event) => onChange(Number(event.target.value))}
      />
      <span className="gen-value-small" aria-hidden>
        {value}
      </span>
    </label>
  );
}

function ToggleRow({
  label,
  hint,
  checked,
  onChange,
}: {
  label: string;
  hint?: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div className="gen-row">
      <span className="gen-label">
        {label}
        {hint ? <span className="gen-hint">{hint}</span> : null}
      </span>
      <Switch label={label} checked={checked} onCheckedChange={onChange} />
    </div>
  );
}
