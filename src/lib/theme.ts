export type ThemeChoice = "system" | "light" | "dark";

export type AccentId = "blue" | "teal" | "green" | "amber" | "rose" | "violet";

export const ACCENTS: { id: AccentId; name: string }[] = [
  { id: "blue", name: "Blue" },
  { id: "teal", name: "Teal" },
  { id: "green", name: "Green" },
  { id: "amber", name: "Amber" },
  { id: "rose", name: "Rose" },
  { id: "violet", name: "Violet" },
];

const THEME_KEY = "kestrel.theme";
const ACCENT_KEY = "kestrel.accent";

/** True for values the CSS knows about; guards stale/forged localStorage. */
export function isAccent(value: string): value is AccentId {
  return ACCENTS.some((accent) => accent.id === value);
}

export function storedTheme(): ThemeChoice {
  const raw = window.localStorage.getItem(THEME_KEY);
  return raw === "light" || raw === "dark" || raw === "system" ? raw : "system";
}

export function storedAccent(): AccentId {
  const raw = window.localStorage.getItem(ACCENT_KEY);
  return raw && isAccent(raw) ? raw : "blue";
}

export function resolveTheme(choice: ThemeChoice): "light" | "dark" {
  if (choice === "system") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  }
  return choice;
}

export function applyTheme(choice: ThemeChoice): void {
  document.documentElement.dataset.theme = resolveTheme(choice);
}

export function persistTheme(choice: ThemeChoice): void {
  window.localStorage.setItem(THEME_KEY, choice);
  applyTheme(choice);
}

/** Applied before React mounts, so the first paint already has the accent. */
export function applyAccent(accent: AccentId): void {
  document.documentElement.dataset.accent = accent;
}

export function persistAccent(accent: AccentId): void {
  window.localStorage.setItem(ACCENT_KEY, accent);
  applyAccent(accent);
}
