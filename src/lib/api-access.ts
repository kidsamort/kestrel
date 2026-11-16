/**
 * Per-item access and CLI token inventory — mirrors the `item_*` and `cli_*`
 * commands in `src-tauri/src/commands.rs`.
 *
 * A principal is an MCP client or a CLI token. The token is the authority for
 * "who exists"; the vault's `grants` rows are the authority for "who may read
 * this field". No shape here can carry a field value.
 */
import { invoke } from "@tauri-apps/api/core";

/** The two kinds a grant may name. */
export type PrincipalKind = "mcp" | "cli";

/** One principal with a live token, and its access to one item. */
export interface ItemAccessPrincipal {
  kind: PrincipalKind;
  /**
   * The name the token's grants and audit rows are recorded under. Empty only
   * for the legacy unrestricted CLI pairing, which has no name.
   */
  client: string;
  /** The token has no allowlist and already reads every field. */
  unrestricted: boolean;
  /** Fields of this item the token was minted for — its ceiling. */
  scopeFields: string[];
  /** Fields of this item the vault currently lets it read. */
  grantedFields: string[];
  /** Unix seconds when this session minted the token. */
  createdAt: number;
  /** Earliest deadline among this item's grants, when one is set. */
  expiresAt: number | null;
  oneShot: boolean;
}

/** One ticked field, posted to `item_set_grants`. */
export interface ItemGrantInput {
  kind: PrincipalKind;
  client: string;
  field: string;
}

/** One recorded read of an item. The value is never part of this shape. */
export interface ItemAuditRead {
  /** As stored: an MCP client name, `cli:<client>` or `browser:<origin>`. */
  principal: string;
  field: string;
  at: number;
}

/** Recent reads of one item, newest first. */
export interface ItemAudit {
  reads: ItemAuditRead[];
  /** The store's recent-history cap was reached; the count is a lower bound. */
  truncated: boolean;
}

/** One CLI token. `client` is null for the legacy unrestricted pairing. */
export interface CliToken {
  client: string | null;
  unrestricted: boolean;
  /** Persisted field grants the token currently holds. */
  grants: number;
  createdAt: number;
  expiresAt: number | null;
  oneShot: boolean;
}

export const access = {
  /** Only principals with a live token, with their scope and current grants. */
  itemGrants: (itemId: string) =>
    invoke<ItemAccessPrincipal[]>("item_grants", { itemId }),
  /** Replace this item's whole grant set with exactly `grants`. */
  setItemGrants: (itemId: string, grants: ItemGrantInput[]) =>
    invoke<void>("item_set_grants", { itemId, grants }),
  /** Recent reads of one item. */
  itemAudit: (itemId: string) => invoke<ItemAudit>("item_audit", { itemId }),
  /** CLI tokens alive in this session, with their persisted grant counts. */
  cliTokens: () => invoke<CliToken[]>("cli_tokens"),
  /** Revoke a token and drop the grants recorded under its name. */
  revokeCli: (client: string | null) =>
    invoke<void>("cli_revoke", { client }),
};
