import { useEffect, useRef, useState } from "react";
import { api, errorText } from "../api";
import { consumeSyncView, SYNC_VIEW_EVENT } from "../lib/api-sync";
import {
  consumeSettingsSection,
  settingsAnchor,
  SETTINGS_JUMP_EVENT,
  type SettingsSection,
} from "../lib/settings-jump";
import {
  SettingsStatusProvider,
  useSectionStatuses,
  type SectionStatus,
} from "../lib/settings-status";
import type { AccentId, ThemeChoice } from "../lib/theme";
import type { AppMeta, VaultState } from "../types";
import { useNotify } from "../ui/Toast";
import AboutCard from "./settings/AboutCard";
import AgentCard from "./settings/AgentCard";
import AppearanceCard from "./settings/AppearanceCard";
import AutofillCard from "./settings/AutofillCard";
import BrowserCard from "./settings/BrowserCard";
import QuickAccessCard from "./settings/QuickAccessCard";
import AccountCard from "./settings/AccountCard";
import SyncCard from "./settings/SyncCard";
import ConflictReview from "./ConflictReview";
import RecoveryCard from "./settings/RecoveryCard";
import RotationCard from "./settings/RotationCard";
import SdkCard from "./settings/SdkCard";
import SecurityCard from "./settings/SecurityCard";
import McpCard from "./settings/McpCard";
import PasskeysCard from "./settings/PasskeysCard";
import MoveData from "./MoveData";

/**
 * The rail. Fifteen cards in one column is a wall; this is the map of it.
 * `id` is also the anchor the command palette scrolls to.
 */
const SECTIONS: { id: SettingsSection; label: string; group: string }[] = [
  { id: "security", label: "Security", group: "Security" },
  { id: "rotation", label: "Change password", group: "Security" },
  { id: "recovery", label: "Recovery code", group: "Security" },
  { id: "agent", label: "SSH agent", group: "Access" },
  { id: "sdk", label: "SDK", group: "Access" },
  { id: "mcp", label: "MCP server", group: "Access" },
  { id: "passkeys", label: "Passkeys", group: "Access" },
  { id: "account", label: "Account", group: "Sync" },
  { id: "sync", label: "Sync", group: "Sync" },
  { id: "quick-access", label: "Quick access", group: "System" },
  { id: "autofill", label: "Autofill", group: "System" },
  { id: "browser", label: "Browser", group: "System" },
  { id: "data", label: "Move data", group: "Data" },
  { id: "appearance", label: "Appearance", group: "App" },
  { id: "about", label: "About", group: "App" },
];

/** One dot per section: on, off, or something to fix. */
function RailStatus({ status }: { status: SectionStatus | null }) {
  if (!status) return null;
  return (
    <span
      className={`settings-rail-status is-${status.tone}`}
      title={status.label}
      aria-label={status.label}
    >
      {status.tone === "attention" && status.label ? (
        <span className="settings-rail-status-text">{status.label}</span>
      ) : status.tone === "danger" && status.label ? (
        <span className="settings-rail-danger-text">{status.label}</span>
      ) : status.tone === "value" && status.label ? (
        <span className="settings-rail-value">{status.label}</span>
      ) : (
        <span className="settings-rail-dot" aria-hidden />
      )}
    </span>
  );
}

interface SettingsProps {
  state: VaultState;
  theme: ThemeChoice;
  accent: AccentId;
  onTheme: (theme: ThemeChoice) => void;
  onAccent: (accent: AccentId) => void;
  onState: (state: VaultState) => void;
  /** Called after an import so the vault list and its counts re-read. */
  onChanged?: () => void;
  onLock: () => void;
}

/**
 * The page is two components because the rail *reads* the statuses its cards
 * *report*: the reader has to sit under the provider, and the provider has to
 * sit above the cards.
 */
export default function Settings(props: SettingsProps) {
  return (
    <SettingsStatusProvider>
      <SettingsBody {...props} />
    </SettingsStatusProvider>
  );
}

function SettingsBody({
  state,
  theme,
  accent,
  onTheme,
  onAccent,
  onState,
  onLock,
  onChanged,
}: SettingsProps) {
  const notify = useNotify();
  const [meta, setMeta] = useState<AppMeta | null>(null);
  const [metaError, setMetaError] = useState<string | null>(null);
  const [screen, setScreen] = useState<"settings" | "conflicts">("settings");
  const [active, setActive] = useState<SettingsSection>("security");
  const statuses = useSectionStatuses();

  /**
   * True while a click's smooth scroll is still moving. The spy stays quiet
   * until the scroll settles, so the section the person asked for keeps the
   * highlight instead of being overwritten by whatever passes under the top
   * edge — the last sections can never reach that edge at all.
   */
  const settling = useRef(false);

  /** Scroll the panel to one section. The anchor is a zero-height span. */
  function goTo(section: SettingsSection) {
    setActive(section);
    settling.current = true;
    document
      .getElementById(settingsAnchor(section))
      ?.scrollIntoView({ block: "start", behavior: "smooth" });
  }

  // The rail highlights whatever is under the top of the viewport, so the page
  // and the rail never disagree about where you are.
  useEffect(() => {
    const scroller = document.querySelector<HTMLElement>(".panel-scroll");
    if (!scroller) return;
    let timer = 0;

    const measure = () => {
      // At the bottom the last sections can never reach the top edge, so the
      // page says which one it is showing instead of guessing.
      if (scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - 4) {
        setActive(SECTIONS[SECTIONS.length - 1].id);
        return;
      }
      const top = scroller.getBoundingClientRect().top + 24;
      let current: SettingsSection = SECTIONS[0].id;
      for (const section of SECTIONS) {
        const anchor = document.getElementById(settingsAnchor(section.id));
        if (anchor && anchor.getBoundingClientRect().top <= top) {
          current = section.id;
        }
      }
      setActive((previous) => (previous === current ? previous : current));
    };

    const onScroll = () => {
      if (timer) clearTimeout(timer);
      // Scrolling has stopped (or never started): the click's choice stands.
      timer = window.setTimeout(() => {
        timer = 0;
        if (settling.current) {
          settling.current = false;
          return;
        }
        measure();
      }, 140);
    };

    scroller.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      scroller.removeEventListener("scroll", onScroll);
      if (timer) clearTimeout(timer);
    };
  }, []);

  // The window bar renders outside the shell's panel state, so the sync pill
  // asks the shell to open Settings and leaves this one-shot scroll request for
  // the page. One frame after mount the anchors exist.
  useEffect(() => {
    const reveal = () => {
      // Consumed so it cannot replay on a later mount; only the panel switch is
      // the shell's job.
      consumeSyncView();
      setScreen("settings");
      requestAnimationFrame(() => goTo("sync"));
    };
    if (consumeSyncView()) reveal();
    window.addEventListener(SYNC_VIEW_EVENT, reveal);
    return () => window.removeEventListener(SYNC_VIEW_EVENT, reveal);
  }, []);

  // The About card names the build and the vault file; both come from the core.
  useEffect(() => {
    let live = true;
    api
      .meta()
      .then((value) => {
        if (live) setMeta(value);
      })
      .catch((error) => {
        if (live) setMetaError(errorText(error));
      });
    return () => {
      live = false;
    };
  }, []);

  // A jump asked for before this page mounted, or while it was showing the
  // conflict screen. One frame after render the anchors are in the DOM.
  useEffect(() => {
    const take = () => {
      const section = consumeSettingsSection();
      if (!section) return;
      setScreen("settings");
      requestAnimationFrame(() => goTo(section));
    };
    take();
    window.addEventListener(SETTINGS_JUMP_EVENT, take);
    return () => window.removeEventListener(SETTINGS_JUMP_EVENT, take);
  }, [screen]);

  if (screen === "conflicts") {
    return <ConflictReview onClose={() => setScreen("settings")} />;
  }

  return (
    <section className="panel-page is-settings" aria-label="Settings">
      <div className="panel-scroll">
        <div className="settings-layout">
          <nav className="settings-rail" aria-label="Settings sections">
            {SECTIONS.map((section, index) => {
              const first = index === 0 || SECTIONS[index - 1].group !== section.group;
              return (
                <div key={section.id} className="settings-rail-item">
                  {first ? (
                    <span className="settings-rail-group">{section.group}</span>
                  ) : null}
                  <button
                    type="button"
                    className={`settings-rail-link${
                      active === section.id ? " is-active" : ""
                    }`}
                    aria-current={active === section.id ? "true" : undefined}
                    onClick={() => goTo(section.id)}
                  >
                    {section.id === "appearance" ? (
                      <span
                        className="settings-rail-swatch"
                        style={{ background: "var(--accent)" }}
                        title={`Accent: ${accent}`}
                        aria-hidden
                      />
                    ) : null}
                    <span className="settings-rail-label">{section.label}</span>
                    <RailStatus status={statuses[section.id] ?? null} />
                  </button>
                </div>
              );
            })}
          </nav>

          <div className="panel-column">
            <header className="settings-head">
              <span className="eyebrow">Kestrel · this device</span>
              <h1 className="panel-title">Settings</h1>
              <p className="panel-sub">
                Every setting here is enforced by the Rust core. This page
                changes what the core exposes; it cannot weaken it.
              </p>
            </header>

            <header className="settings-group-head">
              <h2 className="settings-group">Security</h2>
              <p className="settings-group-sub">
                How the vault locks itself, what the clipboard keeps, and the two
                ways back in — the master password and a printed recovery code.
              </p>
            </header>
            <span id={settingsAnchor("security")} className="settings-anchor" />
            <SecurityCard state={state} onState={onState} onLock={onLock} />
            <span id={settingsAnchor("rotation")} className="settings-anchor" />
            <RotationCard onState={onState} />
            <span id={settingsAnchor("recovery")} className="settings-anchor" />
            <RecoveryCard />
            <header className="settings-group-head">
              <h2 className="settings-group">Access</h2>
              <p className="settings-group-sub">Tools that read this vault from outside the app: a shell, an editor, a browser, a website. Each one is off until you turn it on.</p>
            </header>
            <span id={settingsAnchor("agent")} className="settings-anchor" />
            <AgentCard state={state} />
            <span id={settingsAnchor("sdk")} className="settings-anchor" />
            <SdkCard state={state} />
            <span id={settingsAnchor("mcp")} className="settings-anchor" />
            <McpCard state={state} />
            <span id={settingsAnchor("passkeys")} className="settings-anchor" />
            <PasskeysCard />
            <header className="settings-group-head">
              <h2 className="settings-group">Sync</h2>
              <p className="settings-group-sub">Where this vault's sealed bytes go, and which devices hold a copy. The server stores ciphertext it cannot read.</p>
            </header>
            <span id={settingsAnchor("account")} className="settings-anchor" />
            <AccountCard />
            <span id={settingsAnchor("sync")} className="settings-anchor" />
            <SyncCard onReviewConflicts={() => setScreen("conflicts")} />
            <header className="settings-group-head">
              <h2 className="settings-group">System</h2>
              <p className="settings-group-sub">How Kestrel behaves in Windows: the quick window, filling into other apps, and the browser bridge.</p>
            </header>
            <span id={settingsAnchor("quick-access")} className="settings-anchor" />
            <QuickAccessCard />
            <span id={settingsAnchor("autofill")} className="settings-anchor" />
            <AutofillCard />
            <span id={settingsAnchor("browser")} className="settings-anchor" />
            <BrowserCard state={state} />
            <header className="settings-group-head">
              <h2 className="settings-group">Data</h2>
              <p className="settings-group-sub">Move items in and out of the vault. Import and export run in the core and leave no plaintext behind.</p>
            </header>
            <span id={settingsAnchor("data")} className="settings-anchor" />
            <MoveData
              onChanged={onChanged}
              onError={(message) =>
                notify("Move data", { detail: message, tone: "danger" })
              }
            />
            <header className="settings-group-head">
              <h2 className="settings-group">App</h2>
              <p className="settings-group-sub">How Kestrel looks, and which build you are running.</p>
            </header>
            <span id={settingsAnchor("appearance")} className="settings-anchor" />
            <AppearanceCard
              theme={theme}
              accent={accent}
              onTheme={onTheme}
              onAccent={onAccent}
            />
            <span id={settingsAnchor("about")} className="settings-anchor" />
            <AboutCard state={state} meta={meta} metaError={metaError} />
          </div>
        </div>
      </div>
    </section>
  );
}
