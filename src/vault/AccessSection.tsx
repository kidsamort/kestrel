/**
 * Item editor → Access. Who may read which field of this item.
 *
 * Two facts shape the layout:
 *
 * * The token is the principal. Only a live CLI or MCP token is listed, so a
 *   grant left behind by a revoked token is never shown as access.
 * * A token's pairing is a ceiling. The item editor can narrow it by unticking
 *   a field, but a field the token was not minted for is shown disabled and
 *   cannot be granted here — re-pairing is the only way to widen it. No
 *   wildcard grant exists, and an unrestricted CLI token is described as such
 *   instead of being drawn as "everything ticked".
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Eye, KeyRound, ShieldAlert } from "lucide-react";
import { errorText } from "../api";
import {
  access,
  type ItemAccessPrincipal,
  type ItemAudit,
  type ItemAuditRead,
  type ItemGrantInput,
} from "../lib/api-access";
import type { Item } from "../types";
import "../styles/access.css";

/** `HH:MM` in the viewer's locale, from unix seconds. */
function clockTime(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function AccessSection({
  item,
  disabled,
}: {
  /** The saved item. The access editor never writes into the draft. */
  item: Item;
  /** True while the editor has unsaved field changes. */
  disabled: boolean;
}) {
  const [principals, setPrincipals] = useState<ItemAccessPrincipal[]>([]);
  const [audit, setAudit] = useState<ItemAudit>({ reads: [], truncated: false });
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [openAudit, setOpenAudit] = useState(false);

  const reload = useCallback(() => {
    // A draft has no row yet: asking the core for its grants would answer
    // "no longer in the vault", which is true and useless. The panel already
    // tells the person to save first.
    if (disabled) {
      setLoading(false);
      return () => {};
    }
    let live = true;
    setLoading(true);
    Promise.all([access.itemGrants(item.id), access.itemAudit(item.id)])
      .then(([nextPrincipals, nextAudit]) => {
        if (!live) return;
        setPrincipals(nextPrincipals);
        setAudit(nextAudit);
        setError(null);
      })
      .catch((reason) => {
        if (live) setError(errorText(reason));
      })
      .finally(() => {
        if (live) setLoading(false);
      });
    return () => {
      live = false;
    };
  }, [item.id, disabled]);

  useEffect(() => reload(), [reload, item.updatedAt]);

  /** Every grant currently ticked, across all live principals. */
  const currentGrants = useMemo<ItemGrantInput[]>(
    () =>
      principals.flatMap((principal) =>
        principal.grantedFields.map((field) => ({
          kind: principal.kind,
          client: principal.client,
          field,
        })),
      ),
    [principals],
  );

  function toggle(principal: ItemAccessPrincipal, fieldId: string) {
    if (saving || disabled || principal.unrestricted) return;
    const had = principal.grantedFields.includes(fieldId);
    const next = principals.map((candidate) =>
      candidate.kind === principal.kind && candidate.client === principal.client
        ? {
            ...candidate,
            grantedFields: had
              ? candidate.grantedFields.filter((field) => field !== fieldId)
              : [...candidate.grantedFields, fieldId],
          }
        : candidate,
    );
    const payload: ItemGrantInput[] = next.flatMap((candidate) =>
      candidate.grantedFields.map((field) => ({
        kind: candidate.kind,
        client: candidate.client,
        field,
      })),
    );
    const previous = currentGrants;
    setPrincipals(next);
    setSaving(true);
    setError(null);
    access
      .setItemGrants(item.id, payload)
      .catch((reason) => {
        // The server is the authority: a refused save puts the checkbox back
        // where it was instead of leaving a tick that does nothing.
        setPrincipals((current) =>
          current.map((candidate) => {
            const old = previous
              .filter(
                (grant) =>
                  grant.kind === candidate.kind &&
                  grant.client === candidate.client,
              )
              .map((grant) => grant.field);
            return { ...candidate, grantedFields: old };
          }),
        );
        setError(errorText(reason));
      })
      .finally(() => setSaving(false));
  }

  const readCount = audit.reads.length;
  const lastRead = audit.reads[0]?.at;

  return (
    <section className="side-panel access-panel" aria-label="Access">
      <h2 className="block-title">
        <KeyRound size={13} aria-hidden /> Access
      </h2>
      <p className="access-copy">
        Who may read this item's fields. Only clients you have paired a token
        with appear here, and nothing is granted until you tick it.
      </p>

      {disabled ? (
        <p className="access-note">
          Save the item before changing field access, so a grant cannot name a
          field that is about to change.
        </p>
      ) : null}

      {error ? (
        <p className="access-error" role="alert">
          {error}
        </p>
      ) : null}

      {loading ? (
        <p className="access-empty">Checking paired clients…</p>
      ) : principals.length === 0 ? (
        <p className="access-empty">
          No one has access yet. Pair an MCP client or a CLI token in Settings →
          Developer to grant this item's fields.
        </p>
      ) : (
        <div className="access-list">
          {principals.map((principal) => {
            const key = `${principal.kind}/${principal.client}`;
            const scope = new Set(principal.scopeFields);
            const granted = new Set(principal.grantedFields);
            const outside = item.fields.filter(
              (field) => !scope.has(field.id),
            ).length;
            return (
              <div className="access-principal" key={key}>
                <div className="access-principal-head">
                  <span className={`access-kind is-${principal.kind}`}>
                    {principal.kind === "mcp" ? "MCP" : "CLI"}
                  </span>
                  <span className="access-client">
                    {principal.client || "Unrestricted pairing"}
                  </span>
                  <span className="access-meta">
                    {principal.unrestricted
                      ? "every field"
                      : `${principal.grantedFields.length} of ${principal.scopeFields.length}`}
                  </span>
                </div>

                {principal.unrestricted ? (
                  <p className="access-warning">
                    <ShieldAlert size={13} aria-hidden /> This token has no
                    allowlist: it reads every field while the vault is
                    unlocked. Grants cannot narrow it. Pair a scoped CLI to
                    choose fields.
                  </p>
                ) : item.fields.length === 0 ? (
                  <p className="access-note">This item has no fields yet.</p>
                ) : (
                  <div className="access-fields">
                    {item.fields.map((field) => {
                      const inScope = scope.has(field.id);
                      return (
                        <label
                          className={`access-check${
                            inScope ? "" : " is-outside"
                          }`}
                          key={field.id}
                          title={
                            inScope
                              ? undefined
                              : `“${field.label || "Untitled field"}” was not part of ${principal.client}’s pairing. Pair the client again with it ticked.`
                          }
                        >
                          <input
                            type="checkbox"
                            checked={granted.has(field.id)}
                            disabled={!inScope || disabled || saving}
                            onChange={() => toggle(principal, field.id)}
                          />
                          <span className="access-check-label">
                            {field.label || "Untitled field"}
                          </span>
                          <span className="access-check-kind">
                            {field.kind}
                          </span>
                        </label>
                      );
                    })}
                  </div>
                )}

                <div className="access-principal-foot">
                  <span>
                    Paired {clockTime(principal.createdAt)}
                    {principal.expiresAt
                      ? ` · expires ${new Date(
                          principal.expiresAt * 1000,
                        ).toLocaleDateString(undefined, {
                          day: "numeric",
                          month: "short",
                          year:
                            new Date(principal.expiresAt * 1000).getFullYear() ===
                            new Date().getFullYear()
                              ? undefined
                              : "numeric",
                        })}`
                      : ""}
                    {principal.oneShot ? " · one-shot" : ""}
                  </span>
                  {outside > 0 && !principal.unrestricted ? (
                    <span className="access-hint">
                      {outside} field{outside === 1 ? "" : "s"} outside this
                      token's pairing
                    </span>
                  ) : null}
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="access-audit">
        <span className="access-audit-line">
          <Eye size={13} aria-hidden />{" "}
          {readCount === 0
            ? "No reads recorded."
            : `read ${readCount}${audit.truncated ? "+" : ""}× · last ${
                lastRead ? clockTime(lastRead) : "—"
              }`}
        </span>
        {readCount > 0 ? (
          <button
            type="button"
            className="access-audit-toggle"
            aria-expanded={openAudit}
            onClick={() => setOpenAudit((open) => !open)}
          >
            {openAudit ? "Hide reads" : "Show all"}
          </button>
        ) : null}
      </div>

      {openAudit && audit.reads.length > 0 ? (
        <>
          {audit.truncated ? (
            <p className="access-note">
              Showing the most recent {audit.reads.length} reads; older reads
              are not kept in this list.
            </p>
          ) : null}
          <ul className="access-audit-list">
            {audit.reads.map((read: ItemAuditRead, index) => (
              <li
                className="access-audit-row"
                key={`${read.principal}/${read.field}/${read.at}/${index}`}
              >
                <span className="access-audit-principal">
                  {read.principal.startsWith("cli:")
                    ? `CLI · ${read.principal.slice(4)}`
                    : read.principal.startsWith("browser:")
                      ? `Browser · ${read.principal.slice(8)}`
                      : read.principal}
                </span>
                <span className="access-audit-field">
                  {item.fields.find((field) => field.id === read.field)?.label ||
                    read.field}
                </span>
                <time dateTime={new Date(read.at * 1000).toISOString()}>
                  {clockTime(read.at)}
                </time>
              </li>
            ))}
          </ul>
        </>
      ) : null}

      {saving ? <p className="access-note">Saving access…</p> : null}

      {principals.some(
        (principal) => principal.expiresAt !== null || principal.oneShot,
      ) ? (
        <p className="access-note">
          A deadline or one-shot grant set when the token was paired is not
          carried over by a change here: this item's grants are rewritten
          without one.
        </p>
      ) : null}
    </section>
  );
}
