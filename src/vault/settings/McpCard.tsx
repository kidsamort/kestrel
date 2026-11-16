/**
 * Settings → Developer. The MCP card pairs an external MCP client (an editor or
 * an agent host) with a named list of fields, and shows what that client read.
 *
 * Two rules are visible in the layout:
 *
 * * The checklist is the confirmation. There is no modal and no per-request
 *   approval: what the person ticks here is the whole allowlist, and it is
 *   stored in the vault before a token exists.
 * * No value is ever rendered. The checklist shows item titles and field names;
 *   the audit shows who read which field and when. Both come from commands that
 *   cannot return a value.
 */
import { useEffect, useMemo, useState } from "react";
import { Check, Copy, Server } from "lucide-react";
import { errorText } from "../../api";
import { useSettingsStatus } from "../../lib/settings-status";
import {
  clientConfig,
  mcp,
  type McpAuditRow,
  type McpGrantInput,
  type McpItem,
  type McpStatus,
} from "../../lib/api-mcp";
import { relativeTime } from "../../lib/format";
import type { VaultState } from "../../types";
import "../../styles/mcp.css";

export default function McpCard({ state }: { state: VaultState }) {
  const [status, setStatus] = useState<McpStatus | null>(null);
  useSettingsStatus(
    "mcp",
    status
      ? {
          tone: status.running && status.binaryPresent ? "on" : "attention",
          label:
            status.running && status.binaryPresent
              ? "Ready"
              : !status.binaryPresent
                ? "Binary missing"
                : "Pipe stopped",
        }
      : null,
  );
  const [items, setItems] = useState<McpItem[]>([]);
  const [audit, setAudit] = useState<McpAuditRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [client, setClient] = useState("");
  const [selected, setSelected] = useState<McpGrantInput[]>([]);
  const [expanded, setExpanded] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [pairing, setPairing] = useState(false);

  /** Present only between a pairing and "Done": it is never re-readable. */
  const [token, setToken] = useState<string | null>(null);
  /** The client the visible token was minted for, so Revoke can clear it. */
  const [tokenClient, setTokenClient] = useState<string | null>(null);
  const [copied, setCopied] = useState<"token" | "config" | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);

  // Re-read on every session change: a lock revokes the tokens in the app, and
  // a token from a previous session must not look valid here.
  useEffect(() => {
    let live = true;
    Promise.all([mcp.status(), mcp.inventory(), mcp.audit()])
      .then(([nextStatus, nextItems, nextAudit]) => {
        if (!live) return;
        setStatus(nextStatus);
        setItems(nextItems);
        setAudit(nextAudit);
        setError(null);
      })
      .catch((reason) => {
        if (live) setError(errorText(reason));
      });
    if (state.locked) {
      setToken(null);
      setTokenClient(null);
      setCopied(null);
      setSelected([]);
    }
    return () => {
      live = false;
    };
  }, [state.locked, state.vaultUuid]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return items;
    return items.filter((item) => item.title.toLowerCase().includes(needle));
  }, [items, query]);

  const selectedKeys = useMemo(
    () => new Set(selected.map((grant) => `${grant.itemId}/${grant.fieldId}`)),
    [selected],
  );

  const snippet = clientConfig(status?.binary ?? "kestrel-mcp.exe", token);
  const paired = status?.clients ?? [];
  const binary = status?.binaryPresent ?? false;
  const endState = error
    ? "Unavailable"
    : !status
      ? "Checking…"
      : binary
        ? status.running
          ? "Ready"
          : "Binary found · pipe down"
        : "Binary not found";

  function toggleField(itemId: string, fieldId: string) {
    setSelected((current) => {
      const exists = current.some(
        (grant) => grant.itemId === itemId && grant.fieldId === fieldId,
      );
      return exists
        ? current.filter(
            (grant) => !(grant.itemId === itemId && grant.fieldId === fieldId),
          )
        : [...current, { itemId, fieldId }];
    });
  }

  function toggleItem(itemId: string) {
    setExpanded((current) =>
      current.includes(itemId)
        ? current.filter((id) => id !== itemId)
        : [...current, itemId],
    );
  }

  function fieldsSelected(item: McpItem): number {
    return item.fields.filter((field) =>
      selectedKeys.has(`${item.id}/${field.id}`),
    ).length;
  }

  async function pair() {
    setPairing(true);
    setError(null);
    try {
      const fresh = await mcp.pair(client.trim(), selected);
      setToken(fresh.token);
      setTokenClient(fresh.client);
      setCopied(null);
      setCopyError(null);
      // Re-read rather than assume: the token is the only thing this card
      // could not derive from the response.
      setStatus(await mcp.status());
      setAudit(await mcp.audit());
      setSelected([]);
    } catch (reason) {
      setError(errorText(reason));
    } finally {
      setPairing(false);
    }
  }

  async function revoke(name: string) {
    setError(null);
    try {
      await mcp.revoke(name);
      if (token && name === tokenClient) {
        setToken(null);
        setTokenClient(null);
      }
      setStatus(await mcp.status());
      setAudit(await mcp.audit());
    } catch (reason) {
      setError(errorText(reason));
    }
  }

  async function copy(which: "token" | "config", text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(which);
      setCopyError(null);
    } catch (reason) {
      setCopyError(errorText(reason));
    }
  }

  return (
    <section className="card" aria-labelledby="mcp-title">
      <div className="card-head">
        <h2 className="card-title" id="mcp-title">
          <Server size={15} aria-hidden /> MCP server
        </h2>
        <span
          className={`mcp-state ${binary ? "is-on" : "is-off"}`}
          aria-live="polite"
        >
          {endState}
        </span>
      </div>

      <p className="card-copy">
        An MCP client — an editor or an agent host — reaches the vault through{" "}
        <code>kestrel-mcp.exe</code>, a separate process with no vault code in
        it. It speaks MCP over stdio and asks Kestrel over the same user-only
        pipe as the CLI. It may list item and field names, and read a value only
        for a field you tick below: that list is fixed when you pair, and every
        granted read is recorded. A value is printed to the MCP client and never
        to this window.
      </p>

      <div className="setting-row">
        <div className="setting-label">
          <span>Binary</span>
          <span className="setting-hint">
            {binary
              ? "Found next to Kestrel."
              : "Not found. Build or install it next to Kestrel; the card reports the path it looked at."}
          </span>
        </div>
        <code className="mcp-path">{status?.binary ?? "…"}</code>
      </div>

      <div className="setting-row">
        <div className="setting-label">
          <span>Pipe</span>
          <span className="setting-hint">
            {status?.running
              ? "Serving this Windows account only. Locking the vault revokes this client's token."
              : "Kestrel could not create the pipe; no client can pair."}
          </span>
        </div>
        <code className="mcp-path">{status?.pipe ?? String.raw`\\.\pipe\kestrel-sdk`}</code>
      </div>

      <div className="mcp-snippet">
        <div className="mcp-snippet-head">
          <span className="mcp-snippet-title">Client configuration</span>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => copy("config", snippet)}
          >
            {copied === "config" ? (
              <>
                <Check size={13} aria-hidden /> Copied
              </>
            ) : (
              <>
                <Copy size={13} aria-hidden /> Copy
              </>
            )}
          </button>
        </div>
        <pre className="mcp-code">
          <code>{snippet}</code>
        </pre>
        <p className="setting-hint">
          {token
            ? "The token is in this snippet only until you press Done. Paste it into the client's environment and restart the client."
            : "Until you pair below the snippet shows a placeholder, so a copied configuration cannot contain a token by accident."}
        </p>
      </div>

      {token ? (
        <div className="mcp-token" role="group" aria-label="MCP token">
          <div className="mcp-token-head">
            <span className="setting-label">
              <span>Token</span>
              <span className="setting-hint">
                Shown once. Kestrel keeps only its hash; pairing this client
                again replaces it.
              </span>
            </span>
            <div className="mcp-actions">
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => copy("token", token)}
              >
                {copied === "token" ? (
                  <>
                    <Check size={13} aria-hidden /> Copied
                  </>
                ) : (
                  <>
                    <Copy size={13} aria-hidden /> Copy
                  </>
                )}
              </button>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => {
                  setToken(null);
                  setTokenClient(null);
                  setCopied(null);
                }}
              >
                Done
              </button>
            </div>
          </div>
          <code className="mcp-token-value">{token}</code>
        </div>
      ) : null}

      {copyError ? (
        <p className="mcp-error" role="alert">
          {copyError}
        </p>
      ) : null}

      <div className="mcp-pairing">
        <span className="mcp-snippet-title">Pair a client</span>

        <div className="mcp-field">
          <label className="mcp-label" htmlFor="mcp-client">
            Client name
          </label>
          <input
            id="mcp-client"
            className="mcp-input"
            type="text"
            value={client}
            maxLength={64}
            placeholder="Claude Desktop"
            onChange={(event) => setClient(event.target.value)}
            disabled={state.locked}
          />
          <span className="setting-hint">
            The name the audit list will show. Letters, digits, spaces, dot, dash
            and underscore.
          </span>
        </div>

        <div className="mcp-field">
          <div className="mcp-checklist-head">
            <span className="mcp-label">
              Fields this client may read
              <span className="mcp-count">
                {selected.length} selected
              </span>
            </span>
            <input
              className="mcp-input mcp-search"
              type="search"
              value={query}
              placeholder="Filter items"
              onChange={(event) => setQuery(event.target.value)}
              disabled={state.locked}
              aria-label="Filter items"
            />
          </div>

          <div className="mcp-checklist" role="group" aria-label="Field checklist">
            {filtered.length === 0 ? (
              <p className="setting-hint mcp-empty">
                {items.length === 0
                  ? "The vault has no items to grant yet."
                  : "No item matches that filter."}
              </p>
            ) : (
              filtered.map((item) => {
                const count = fieldsSelected(item);
                const open = expanded.includes(item.id);
                return (
                  <div className="mcp-item" key={item.id}>
                    <button
                      type="button"
                      className="mcp-item-head"
                      aria-expanded={open}
                      onClick={() => toggleItem(item.id)}
                      disabled={state.locked || item.fields.length === 0}
                    >
                      <span className="mcp-item-title">{item.title}</span>
                      <span className="mcp-item-meta">
                        {item.fields.length === 0
                          ? "no fields"
                          : count > 0
                            ? `${count} of ${item.fields.length} granted`
                            : `${item.fields.length} field${item.fields.length === 1 ? "" : "s"}`}
                      </span>
                    </button>
                    {open ? (
                      <div className="mcp-fields">
                        {item.fields.map((field) => {
                          const key = `${item.id}/${field.id}`;
                          return (
                            <label className="mcp-check" key={field.id}>
                              <input
                                type="checkbox"
                                checked={selectedKeys.has(key)}
                                onChange={() => toggleField(item.id, field.id)}
                                disabled={state.locked}
                              />
                              <span className="mcp-check-label">
                                {field.label}
                              </span>
                              <span className="mcp-check-kind">{field.kind}</span>
                            </label>
                          );
                        })}
                      </div>
                    ) : null}
                  </div>
                );
              })
            )}
          </div>
          <span className="setting-hint">
            Ticking a field is the approval: there is no confirmation dialog and
            no per-request prompt. Grant only what the client needs — a granted
            field is readable by that client whenever the vault is unlocked.
          </span>
        </div>

        <div className="mcp-submit">
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={pair}
            disabled={
              pairing ||
              state.locked ||
              !status?.running ||
              client.trim().length === 0 ||
              selected.length === 0
            }
          >
            {pairing ? "Pairing…" : "Pair this client"}
          </button>
          {state.locked ? (
            <span className="setting-hint">Unlock the vault to pair.</span>
          ) : selected.length === 0 ? (
            <span className="setting-hint">Tick at least one field.</span>
          ) : null}
        </div>
      </div>

      <div className="mcp-paired">
        <span className="mcp-snippet-title">Paired clients</span>
        {paired.length === 0 ? (
          <p className="setting-hint">
            No MCP client holds a token. Pairing one here is the only way in.
          </p>
        ) : (
          paired.map((info) => (
            <div className="setting-row" key={info.client}>
              <div className="setting-label">
                <span>{info.client}</span>
                <span className="setting-hint">
                  {info.grants} field{info.grants === 1 ? "" : "s"} granted. The
                  token dies when the vault locks.
                </span>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => revoke(info.client)}
              >
                Revoke
              </button>
            </div>
          ))
        )}
      </div>

      <div className="mcp-audit-block">
        <span className="mcp-snippet-title">Audit</span>
        {audit.length === 0 ? (
          <p className="setting-hint">
            Nothing read yet. Every granted read appears here with the client,
            the item, the field and the time — never the value.
          </p>
        ) : (
          <ul className="mcp-audit" aria-label="MCP reads">
            {audit.map((row, index) => (
              <li
                className="mcp-audit-row"
                key={`${row.client}-${row.itemId}-${row.field}-${row.at}-${index}`}
              >
                <span className="mcp-audit-client">{row.client}</span>
                <span className="mcp-audit-target">
                  {row.itemTitle ?? "deleted item"}
                  <span className="mcp-audit-field">
                    {row.fieldLabel ?? row.field}
                  </span>
                </span>
                <span className="mcp-audit-when">
                  {relativeTime(row.at)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {error ? (
        <p className="mcp-error" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}
