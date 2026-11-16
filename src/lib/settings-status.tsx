/**
 * What each settings section is doing, shown in the rail.
 *
 * Every card already fetches its own status — the autofill watcher's `enabled`,
 * the passkey plugin's registration, the sync account's presence — but that
 * knowledge died inside the card. The rail is the map of the page, so it is the
 * right place to say "this one is off" or "this one needs attention" before
 * anyone scrolls to find out.
 *
 * Cards report; the rail renders. A card that reports nothing simply has no dot,
 * which is honest: there is no status to show.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import type { SettingsSection } from "./settings-jump";

/**
 * `on` and `off` are a switch, `attention` is a degraded state the user can
 * still live with, `danger` is a switch that is off and should be on, and
 * `value` is a fact that is none of those — a timeout, a version, a theme.
 */
export type SectionTone = "on" | "off" | "attention" | "danger" | "value";

export interface SectionStatus {
  tone: SectionTone;
  /** Shown as the dot's tooltip, and as text when the tone is not a switch. */
  label?: string;
}

type Report = (section: SettingsSection, status: SectionStatus | null) => void;

const Ctx = createContext<Report>(() => {});

export function SettingsStatusProvider({ children }: { children: ReactNode }) {
  const [statuses, setStatuses] = useState<
    Partial<Record<SettingsSection, SectionStatus | null>>
  >({});

  const report = useCallback<Report>((section, status) => {
    setStatuses((current) => {
      const previous = current[section];
      if (
        previous === status ||
        (previous &&
          status &&
          previous.tone === status.tone &&
          previous.label === status.label)
      ) {
        return current;
      }
      return { ...current, [section]: status };
    });
  }, []);

  // The rail reads this through the same context value it reports into, so the
  // provider carries both halves.
  return (
    <Ctx.Provider value={report}>
      <StatusReader.Provider value={statuses}>{children}</StatusReader.Provider>
    </Ctx.Provider>
  );
}

const StatusReader = createContext<
  Partial<Record<SettingsSection, SectionStatus | null>>
>({});

/** Read every reported status; used by the rail. */
export function useSectionStatuses() {
  return useContext(StatusReader);
}

/**
 * Report this card's status. Call it with `null` while the card is still
 * loading, and with the real value once it knows.
 */
export function useSettingsStatus(
  section: SettingsSection,
  status: SectionStatus | null,
) {
  const report = useContext(Ctx);
  const tone = status?.tone;
  const label = status?.label;
  useEffect(() => {
    report(section, tone ? { tone, label } : null);
    // Unmounting clears the dot: a card that is not on screen cannot claim a
    // state the next mount has not confirmed yet.
    return () => report(section, null);
  }, [report, section, tone, label]);
}

/** The status to render for one section, memoised so the rail is stable. */
export function useSectionStatus(section: SettingsSection): SectionStatus | null {
  const statuses = useContext(StatusReader);
  return useMemo(() => statuses[section] ?? null, [statuses, section]);
}
