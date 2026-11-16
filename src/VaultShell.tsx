import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import type { VaultState } from "./types";
import { useCopy } from "./lib/copy";
import { ALL_FILTER } from "./lib/navigation";
import type { AccentId, ThemeChoice } from "./lib/theme";
import { useNotify } from "./ui/Toast";
import { Dialog } from "./ui/Overlay";
import { Button } from "./ui/Button";
import Sidebar from "./vault/Sidebar";
import ItemList from "./vault/ItemList";
import ItemDetail from "./vault/ItemDetail";
import ItemEditor from "./vault/ItemEditor";
import CommandPalette from "./vault/CommandPalette";
import NewItemWizard from "./vault/NewItemWizard";
import Settings from "./vault/Settings";
import TrashView from "./vault/TrashView";
import Audit from "./vault/Audit";
import HistoryRail from "./vault/HistoryRail";
import VaultSwitcher from "./vault/VaultSwitcher";
import GeneratorView from "./vault/GeneratorView";
import AutolockBadge from "./vault/shell/AutolockBadge";
import PasskeyApproval from "./vault/PasskeyApproval";
import TitlebarSearch from "./vault/shell/TitlebarSearch";
import { PANEL_LABEL } from "./vault/shell/logic";
import { useSelection } from "./vault/shell/useSelection";
import { useShellPanels } from "./vault/shell/useShellPanels";
import { useTitlebarSlots } from "./vault/shell/useTitlebarSlots";
import { useVaultData } from "./vault/shell/useVaultData";
import type { ShellSession } from "./vault/shell/session";

export default function VaultShell({
  remainingSeconds,
  state,
  onState,
  onLock,
  theme,
  accent,
  onTheme,
  onAccent,
}: {
  remainingSeconds: number;
  state: VaultState;
  onState: (state: VaultState) => void;
  onLock: () => void;
  theme: ThemeChoice;
  accent: AccentId;
  onTheme: (theme: ThemeChoice) => void;
  onAccent: (accent: AccentId) => void;
}) {
  const notify = useNotify();
  const copy = useCopy(state.clipboardClearSeconds);

  // The navigation hooks ask the selection session whether a draft may be
  // discarded; the session object is filled in below, after it exists. Every
  // reader runs from an event handler, never during render.
  const shellSession = useRef<ShellSession | null>(null);
  const panels = useShellPanels({ session: shellSession, notify });
  const data = useVaultData({
    filter: panels.filter,
    debouncedQuery: panels.debouncedQuery,
    sort: panels.sort,
    notify,
    filterCheckPending: panels.filterCheckPending,
  });
  const selection = useSelection({
    panel: panels.panel, version: data.version, summaries: data.summaries,
    filterCheckPending: panels.filterCheckPending, notify, refresh: data.refresh,
    setPanel: panels.setPanel, setFilter: panels.setFilter, setQuery: panels.setQuery,
    onLock,
  });
  const { searchSlot, metaSlot, vaultSlot } = useTitlebarSlots();

  const {
    filter, panel, query, sort, compact, wizardOpen, paletteOpen, setPaletteOpen,
    searchRef, setQuery, setSort, applyFilter, openPanel, searchTag, setWizardOpen,
  } = panels;
  const {
    sorted, allItems, loading, counts, refresh,
  } = data;
  const {
    selectedId, item, itemLoading, editing, focusField, historyOpen,
    pendingAction, setPendingAction, setDirty, setItem, setHistoryOpen, guard,
    guardedLock, editSelected, openItem, openCreated, createItem, fixFinding,
    finishEditing, requestCancel, deleteCurrent, toggleFavorite, vaultChanged,
    openAndEdit, setFavorite, trashById,
  } = selection;

  useEffect(() => {
    shellSession.current = selection.session;
  }, [selection.session]);

  const showEditor = panel === "vault" && editing && item !== null;
  const generatedLabel = PANEL_LABEL[panel];

  return (
    <div className="shell">
      <PasskeyApproval />
      <div className="shell-body">
        <a className="skip-link" href="#main-pane">
          Skip to content
        </a>
        <Sidebar
          filter={filter}
          panel={panel}
          counts={counts}
          compact={compact}
          onFilter={applyFilter}
          onPanel={openPanel}
          onLock={guardedLock}
        />

        <div className="shell-main" id="main-pane">
          {panel === "vault" ? (
            <div className="vault-panes">
              <ItemList
                filter={filter}
                items={sorted}
                query={query}
                sort={sort}
                selectedId={selectedId}
                loading={loading}
                onSelect={openItem}
                onQuery={setQuery}
                onSort={setSort}
                onNew={createItem}
                onNewWizard={() => guard(() => setWizardOpen(true))}
                onClearFilter={() => applyFilter(ALL_FILTER)}
                onRowAction={(action, row) => {
                  if (action === "open") openItem(row.id);
                  else if (action === "edit") openAndEdit(row.id);
                  else if (action === "favorite") setFavorite(row.id, !row.favorite);
                  else trashById(row.id);
                }}
              />
              {showEditor && item ? (
                <ItemEditor
                  key={item.id}
                  item={item}
                  focusFieldId={focusField ?? undefined}
                  onCancel={requestCancel}
                  onSaved={finishEditing}
                  onDirtyChange={setDirty}
                />
              ) : (
                <ItemDetail
                  item={item}
                  loading={itemLoading}
                  copiedKey={copy.copiedKey}
                  onCopyField={copy.copyField}
                  onCopyText={copy.copyText}
                  onEdit={editSelected}
                  onFavorite={toggleFavorite}
                  onDelete={deleteCurrent}
                  onSearchTag={searchTag}
                  onHistory={() => setHistoryOpen(true)}
                />
              )}
              {historyOpen && item && !showEditor ? (
                <HistoryRail
                  item={item}
                  onRestored={(restored) => {
                    setItem(restored);
                    refresh();
                  }}
                  onClose={() => setHistoryOpen(false)}
                />
              ) : null}
            </div>
          ) : (
            <div className="single-pane" aria-label={generatedLabel ?? undefined}>
              {panel === "trash" ? (
                <TrashView
                  onChanged={refresh}
                  onError={(message) => notify("Trash", { detail: message, tone: "danger" })}
                />
              ) : panel === "audit" ? (
                <Audit
                  onFix={fixFinding}
                  onError={(message) =>
                    notify("Security audit", { detail: message, tone: "danger" })
                  }
                />
              ) : panel === "generator" ? (
                <GeneratorView onCopy={copy.copyText} />
              ) : (
                <Settings
                  onChanged={refresh}
                  state={state}
                  theme={theme}
                  accent={accent}
                  onTheme={onTheme}
                  onAccent={onAccent}
                  onState={onState}
                  onLock={guardedLock}
                />
              )}
            </div>
          )}
        </div>

        {searchSlot && panel === "vault"
          ? createPortal(
              <TitlebarSearch query={query} inputRef={searchRef} onQuery={setQuery} />,
              searchSlot,
            )
          : null}

        <NewItemWizard
          open={wizardOpen}
          onOpenChange={setWizardOpen}
          onCreated={(created) => openCreated(created, false)}
        />
      </div>

      {vaultSlot
        ? createPortal(
            <VaultSwitcher
              state={state}
              onState={onState}
              onChanged={vaultChanged}
              guard={guard}
            />,
            vaultSlot,
          )
        : null}

      {metaSlot
        ? createPortal(
            <AutolockBadge remainingSeconds={remainingSeconds} autolockSeconds={state.autolockSeconds} />,
            metaSlot,
          )
        : null}

      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        items={allItems}
        onSelectItem={(id) => {
          setPaletteOpen(false);
          openItem(id);
        }}
        onFilter={(next) => {
          setPaletteOpen(false);
          applyFilter(next);
        }}
        onPanel={(next) => {
          setPaletteOpen(false);
          openPanel(next);
        }}
        onNew={(category) => {
          setPaletteOpen(false);
          createItem(category);
        }}
        onLock={() => {
          setPaletteOpen(false);
          guardedLock();
        }}
      />

      <Dialog
        open={pendingAction !== null}
        onOpenChange={(open) => {
          if (!open) setPendingAction(null);
        }}
        alert
        title="Discard unsaved changes?"
        description={
          item
            ? `“${item.title}” has edits that have not been saved yet. They exist only in this window.`
            : "Edits in the editor have not been saved yet."
        }
        footer={
          <>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setPendingAction(null)}
            >
              Keep editing
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={() => {
                const action = pendingAction;
                setPendingAction(null);
                action?.();
              }}
            >
              Discard changes
            </Button>
          </>
        }
      />
    </div>
  );
}
