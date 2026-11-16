import { useCallback, useEffect, useRef, type KeyboardEvent } from "react";
import { quick } from "./lib/api-quick";
import { durationLabel } from "./lib/format";
import { QuickFooter } from "./quick/Footer";
import { QuickHeader } from "./quick/Header";
import { QuickLocked } from "./quick/Locked";
import { QuickResults } from "./quick/Results";
import { useQuickCopy } from "./quick/useQuickCopy";
import { useQuickSearch } from "./quick/useQuickSearch";
import { useQuickSession } from "./quick/useQuickSession";
import { useQuickUnlock } from "./quick/useQuickUnlock";
import "./styles/quick.css";

/**
 * The 420 px quick-access surface (`index.html?window=quick`).
 *
 * No props: the window is self-contained and reads everything through the
 * shared `VaultState`. While locked it offers only the master password; once
 * unlocked it searches, opens items in the main window, and copies credentials
 * through the core (the password value never enters this renderer).
 *
 * This file is the composition and the keyboard map; the surfaces live in
 * `./quick/`.
 */
export default function QuickAccess() {
  const session = useQuickSession({
    onShow: handleShown,
    onLocked: handleLocked,
  });
  const search = useQuickSearch(session.unlocked);
  const copy = useQuickCopy();
  const unlock = useQuickUnlock({ setVault: session.setVault });
  const searchRef = useRef<HTMLInputElement>(null);

  // Every appearance starts clean.
  function handleShown() {
    search.reset();
    unlock.reset();
    unlock.reloadHello();
    copy.reset();
  }

  // The watchdog can lock while the palette is open.
  function handleLocked() {
    search.clear();
    copy.reset();
  }

  // Focus follows the lock state: password when locked, search when open.
  useEffect(() => {
    if (!session.vault) return;
    if (session.vault.locked) unlock.passwordRef.current?.focus();
    else searchRef.current?.focus();
  }, [session.vault, unlock.passwordRef]);

  const openItem = useCallback((id: string | null) => {
    void quick.focusMain(id).catch(() => undefined);
  }, []);

  function onBodyKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const target = event.target as HTMLElement;
    // Let a focused copy button receive its own Enter/Space activation.
    if (target.closest("button[data-copy]")) return;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      search.move(1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      search.move(-1);
    } else if (event.key === "Enter") {
      const item = search.items[search.active];
      if (!item) return;
      event.preventDefault();
      openItem(item.id);
    }
  }

  const clipboard = session.vault
    ? durationLabel(session.vault.clipboardClearSeconds)
    : "30 seconds";

  return (
    <div className="qa">
      <div className="qa-drag" data-tauri-drag-region aria-hidden="true" />

      {session.bootError || !session.unlocked ? (
        <QuickLocked
          bootError={session.bootError}
          vault={session.vault}
          password={unlock.password}
          unlocking={unlock.unlocking}
          unlockError={unlock.unlockError}
          passwordRef={unlock.passwordRef}
          onPasswordChange={(value) => {
            unlock.setPassword(value);
            unlock.setUnlockError(null);
          }}
          onSubmit={unlock.submit}
          onOpenMain={() => openItem(null)}
          hello={unlock.hello}
          helloBusy={unlock.helloBusy}
          onHelloUnlock={() => void unlock.unlockWithHello()}
        />
      ) : (
        <div className="qa-body" onKeyDown={onBodyKeyDown}>
          <QuickHeader
            searchRef={searchRef}
            query={search.query}
            hasResults={search.items.length > 0}
            onQueryChange={search.setQuery}
          />

          <QuickResults
            items={search.items}
            active={search.active}
            query={search.query}
            searching={search.searching}
            searchError={search.searchError}
            copied={copy.copied}
            onActivate={search.setActive}
            onSelect={openItem}
            onCopy={copy.copyField}
          />

          <QuickFooter
            vaultName={session.vault?.vaultName ?? null}
            copyError={copy.copyError}
            copied={copy.copied}
            status={session.status}
            clipboard={clipboard}
          />
        </div>
      )}
    </div>
  );
}
