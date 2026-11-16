/**
 * Settings → Appearance. Both controls are pure preferences: they only ask the
 * parent to persist, and the parent applies them to the document root.
 */
import { Check, Monitor, Moon, Sun } from "lucide-react";
import type { AccentId, ThemeChoice } from "../../lib/theme";
import { useSettingsStatus } from "../../lib/settings-status";
import { ACCENTS } from "../../lib/theme";

const THEMES = [
  ["system", Monitor, "System"],
  ["light", Sun, "Light"],
  ["dark", Moon, "Dark"],
] as const;

export default function AppearanceCard({
  theme,
  accent,
  onTheme,
  onAccent,
}: {
  theme: ThemeChoice;
  accent: AccentId;
  onTheme: (theme: ThemeChoice) => void;
  onAccent: (accent: AccentId) => void;
}) {
  // Only words here: the rail draws the accent chip itself, from the prop it
  // already owns. Rollup strips any other key from these literals.
  useSettingsStatus("appearance", {
    tone: "value",
    label: `${theme === "system" ? "System" : theme === "dark" ? "Dark" : "Light"} · ${
      ACCENTS.find((preset) => preset.id === accent)?.name ?? accent
    }`,
  });

  return (
    <section className="card" aria-labelledby="appearance-title">
      <div className="card-head">
        <h2 className="card-title" id="appearance-title">
          <Sun size={15} aria-hidden /> Appearance
        </h2>
      </div>
      <div className="setting-row">
        <div className="setting-label">
          <span>Theme</span>
          <span className="setting-hint">Light, dark, or follow the system.</span>
        </div>
        <div className="seg-row" role="group" aria-label="Theme">
          {THEMES.map(([value, Icon, label]) => (
            <button
              key={value}
              type="button"
              className={`seg ${theme === value ? "is-on" : ""}`}
              aria-pressed={theme === value}
              onClick={() => onTheme(value)}
            >
              <Icon size={13} aria-hidden /> {label}
            </button>
          ))}
        </div>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Accent</span>
          <span className="setting-hint">
            A system colour, not a semantic one: errors, success and warnings
            keep their own colours.
          </span>
        </div>
        <div className="swatches" role="group" aria-label="Accent colour">
          {ACCENTS.map((preset) => (
            <button
              key={preset.id}
              type="button"
              className={`swatch swatch-${preset.id}`}
              aria-pressed={accent === preset.id}
              aria-label={preset.name}
              title={preset.name}
              onClick={() => onAccent(preset.id)}
            >
              <span className="swatch-dot" aria-hidden />
              <Check size={11} strokeWidth={3.4} aria-hidden className="swatch-check" />
            </button>
          ))}
        </div>
      </div>
    </section>
  );
}
