/**
 * Settings → About: build identity from the core plus the static keymap. `meta`
 * is owned by the parent because it describes the running core for the whole
 * page, while the keyboard list is inert markup.
 */
import type { AppMeta, VaultState } from "../../types";
import { useSettingsStatus } from "../../lib/settings-status";

const KEYMAP: [string, string, string][] = [
  ["Ctrl", "K", "Command palette"],
  ["Ctrl", "F", "Search"],
  ["Ctrl", "N", "New login"],
  ["Ctrl", "E", "Edit open item"],
  ["Ctrl", "G", "Generator"],
  ["Ctrl", "L", "Lock vault"],
  ["↑", "↓", "Move between items"],
  ["Esc", "", "Close a dialog or clear search"],
];

export default function AboutCard({
  state,
  meta,
  metaError,
}: {
  state: VaultState;
  meta: AppMeta | null;
  metaError: string | null;
}) {
  useSettingsStatus("about", {
    tone: metaError ? "attention" : "value",
    label: metaError ? "Version unknown" : (meta?.version ?? "…"),
  });

  return (
    <section className="card" aria-labelledby="about-title">
      <div className="card-head">
        <h2 className="card-title" id="about-title">
          About
        </h2>
      </div>
      <dl className="about-list">
        <div>
          <dt>Application</dt>
          <dd>
            {meta ? `${meta.name} ${meta.version}` : metaError ?? "Reading…"}
          </dd>
        </div>
        <div>
          <dt>Vault format</dt>
          <dd className="mono">{meta ? `v${meta.vaultFormat}` : "—"}</dd>
        </div>
        <div>
          <dt>Items</dt>
          <dd className="mono">{state.itemCount}</dd>
        </div>
        <div>
          <dt>Vault file</dt>
          <dd className="mono about-path">{meta ? meta.vaultPath : "—"}</dd>
        </div>
        <div>
          <dt>Device</dt>
          <dd className="mono">{meta ? meta.deviceName : "—"}</dd>
        </div>
        <div>
          <dt>Renderer</dt>
          <dd>No keys, no network, no navigation</dd>
        </div>
      </dl>
      <div className="keymap">
        <h3 className="edit-subhead">Keyboard</h3>
        <ul>
          {KEYMAP.map(([first, second, label]) => (
            <li key={label}>
              <kbd className="kbd">{first}</kbd>
              {second ? <kbd className="kbd">{second}</kbd> : null}
              <span>{label}</span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
