import { useCallback, useEffect, useState } from "react";
import { Check, ChevronDown, FolderPlus, Settings2, Vault } from "lucide-react";
import { errorText } from "../api";
import { vaults, type VaultSummary } from "../lib/api-vaults";
import type { VaultState } from "../types";
import { Button } from "../ui/Button";
import { TextField } from "../ui/Input";
import {
  Dialog,
  Menu,
  MenuContent,
  MenuItem,
  MenuLabel,
  MenuSeparator,
  MenuTrigger,
} from "../ui/Overlay";
import { useNotify } from "../ui/Toast";
import { Tip } from "../ui/Tooltip";

/**
 * Vault switcher for the toolbar: the active vault's name, a menu of the other
 * vaults with their counts, and the two doors that change the set (create and
 * rename). It renders into the `#titlebar-vault` slot; the shell owns the
 * unsaved-edit guard and the list refresh.
 */
export default function VaultSwitcher({
  state,
  onState,
  onChanged,
  guard,
}: {
  state: VaultState;
  onState: (next: VaultState) => void;
  /** Called after the active vault or its name changed, so lists re-read. */
  onChanged: () => void;
  /** Runs the change through the shell's "discard unsaved edits?" guard. */
  guard: (action: () => void) => void;
}) {
  const notify = useNotify();
  const [list, setList] = useState<VaultSummary[]>([]);
  const [newOpen, setNewOpen] = useState(false);
  const [manageOpen, setManageOpen] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");

  const load = useCallback(() => {
    vaults
      .list()
      .then(setList)
      .catch(() => undefined);
  }, []);

  useEffect(load, [load, state.vaultUuid, state.vaultCount]);

  const active = list.find((v) => v.uuid === state.vaultUuid) ?? null;
  const activeName = active?.name || state.vaultName || "Vault";

  function switchTo(uuid: string) {
    if (uuid === state.vaultUuid) return;
    guard(() => {
      setBusy(true);
      vaults
        .switch(uuid)
        .then((next) => {
          onState(next);
          onChanged();
          const label = list.find((v) => v.uuid === uuid)?.name ?? "vault";
          notify(`Switched to ${label}`, { tone: "neutral" });
        })
        .catch((err) =>
          notify("Could not switch vaults", {
            detail: errorText(err),
            tone: "danger",
          }),
        )
        .finally(() => setBusy(false));
    });
  }

  function createVault() {
    const trimmed = name.trim();
    if (!trimmed) return;
    setBusy(true);
    setError(null);
    vaults
      .create(trimmed)
      .then((created) =>
        vaults.switch(created.uuid).then((next) => {
          onState(next);
          onChanged();
          setNewOpen(false);
          setName("");
          notify(`Created ${created.name}`, { tone: "neutral" });
        }),
      )
      .catch((err) => setError(errorText(err)))
      .finally(() => setBusy(false));
  }

  function rename(uuid: string) {
    const trimmed = renameValue.trim();
    if (!trimmed) return;
    setBusy(true);
    vaults
      .rename(uuid, trimmed)
      .then(() => {
        setRenaming(null);
        load();
        onChanged();
        notify("Vault renamed", { tone: "neutral" });
      })
      .catch((err) => setError(errorText(err)))
      .finally(() => setBusy(false));
  }

  return (
    <>
      <Menu
        // Counts change as items are added, so the list is re-read whenever the
        // menu opens instead of trusting the copy loaded at mount.
        onOpenChange={(open) => {
          if (open) load();
        }}
      >
        <MenuTrigger asChild>
          <button
            type="button"
            className="vault-switch"
            aria-label={`Active vault: ${activeName}. Switch vault`}
            onMouseDown={(event) => event.stopPropagation()}
            disabled={busy}
          >
            <Vault size={12} strokeWidth={1.7} aria-hidden />
            <span className="vault-switch-name">{activeName}</span>
            <ChevronDown size={12} strokeWidth={1.7} aria-hidden />
          </button>
        </MenuTrigger>
        <MenuContent width={248} align="start">
          <MenuLabel>Vaults are separate keys</MenuLabel>
          {list.map((vault) => (
            <MenuItem
              key={vault.uuid}
              icon={
                vault.uuid === state.vaultUuid ? (
                  <Check size={13} aria-hidden />
                ) : (
                  <Vault size={13} aria-hidden />
                )
              }
              onSelect={() => switchTo(vault.uuid)}
            >
              <span className="vault-row">
                <span className="vault-row-name">{vault.name}</span>
                <span className="vault-row-count">{vault.itemCount}</span>
              </span>
            </MenuItem>
          ))}
          <MenuSeparator />
          <MenuItem
            icon={<FolderPlus size={13} aria-hidden />}
            onSelect={() => {
              setError(null);
              setNewOpen(true);
            }}
          >
            New vault…
          </MenuItem>
          <MenuItem
            icon={<Settings2 size={13} aria-hidden />}
            onSelect={() => {
              setError(null);
              setManageOpen(true);
            }}
          >
            Manage vaults…
          </MenuItem>
        </MenuContent>
      </Menu>

      <Dialog
        open={newOpen}
        onOpenChange={(open) => {
          setNewOpen(open);
          if (!open) {
            setName("");
            setError(null);
          }
        }}
        title="New vault"
        description="Vaults are separate keys, not folders. The same master password opens all of them, and items never move between vaults on their own."
        footer={
          <>
            <Button variant="ghost" size="sm" onClick={() => setNewOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              disabled={busy || name.trim().length === 0}
              onClick={createVault}
            >
              {busy ? "Creating…" : "Create vault"}
            </Button>
          </>
        }
      >
        <TextField
          label="Vault name"
          placeholder="Work"
          value={name}
          maxLength={48}
          autoFocus
          error={error}
          hint="You start inside the new vault once it exists."
          onChange={(event) => setName(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") createVault();
          }}
        />
      </Dialog>

      <Dialog
        open={manageOpen}
        onOpenChange={(open) => {
          setManageOpen(open);
          if (open) load();
          if (!open) {
            setRenaming(null);
            setError(null);
          }
        }}
        title="Manage vaults"
        description="Every vault has its own key. Renaming changes the label only; the ciphertext and its key stay where they are."
        width={480}
        footer={
          <Button variant="ghost" size="sm" onClick={() => setManageOpen(false)}>
            Done
          </Button>
        }
      >
        <div className="vault-manage">
          {list.map((vault) => (
            <div className="vault-manage-row" key={vault.uuid}>
              {renaming === vault.uuid ? (
                <TextField
                  label={`Rename ${vault.name}`}
                  quietLabel
                  value={renameValue}
                  maxLength={48}
                  autoFocus
                  onChange={(event) => setRenameValue(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") rename(vault.uuid);
                    if (event.key === "Escape") setRenaming(null);
                  }}
                />
              ) : (
                <span className="vault-manage-name">
                  {vault.name}
                  {vault.uuid === state.vaultUuid ? (
                    <Tip label="This session is scoped to it">
                      <span className="vault-manage-active">active</span>
                    </Tip>
                  ) : null}
                </span>
              )}
              <span className="vault-manage-count">
                {vault.itemCount} {vault.itemCount === 1 ? "item" : "items"}
              </span>
              {renaming === vault.uuid ? (
                <Button
                  variant="primary"
                  size="sm"
                  disabled={busy || renameValue.trim().length === 0}
                  onClick={() => rename(vault.uuid)}
                >
                  Save
                </Button>
              ) : (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setRenaming(vault.uuid);
                    setRenameValue(vault.name);
                    setError(null);
                  }}
                >
                  Rename
                </Button>
              )}
            </div>
          ))}
          {error ? (
            <p className="field-error" role="alert">
              {error}
            </p>
          ) : null}
        </div>
      </Dialog>
    </>
  );
}
