/**
 * MCP bridge — mirrors `src-tauri/src/sdk/mod.rs` (`mcp_*` commands).
 *
 * The MCP server is a separate executable that talks to the app over the same
 * user-only named pipe as the CLI. This module can pair a client, read the
 * checklist and read the audit list. It cannot read a secret: no command in the
 * `mcp_*` surface returns a field value, and the one op that does
 * (`items.reveal`) is answered on the pipe, to the MCP process's own stdout.
 */
import { invoke } from "@tauri-apps/api/core";

/** One paired MCP client. `grants` counts the fields its token allows. */
export interface McpClientInfo {
  client: string;
  grants: number;
}

/** Snapshot for the card. Everything here is non-secret. */
export interface McpStatus {
  /** `\\.\pipe\kestrel-sdk`, shared with the CLI. */
  pipe: string;
  /** Where Kestrel looks for `kestrel-mcp.exe` (next to its own executable). */
  binary: string;
  /** The file exists at `binary`. */
  binaryPresent: boolean;
  /** The pipe is serving clients. MCP has no listener of its own. */
  running: boolean;
  unlocked: boolean;
  clients: McpClientInfo[];
}

/** One field in the checklist: id, label and kind, never a value. */
export interface McpField {
  id: string;
  label: string;
  kind: string;
}

/** One item in the checklist. */
export interface McpItem {
  id: string;
  title: string;
  fields: McpField[];
}

/** A ticked checkbox, posted to `mcp_pair`. */
export interface McpGrantInput {
  itemId: string;
  fieldId: string;
}

/** Returned by `mcp_pair`; the token is readable only in this response. */
export interface McpPairing {
  client: string;
  pipe: string;
  token: string;
}

/** One recorded read. The value that was read is not part of this shape. */
export interface McpAuditRow {
  client: string;
  itemId: string;
  /** `null` once the item has been deleted. */
  itemTitle: string | null;
  field: string;
  /** `null` once the field no longer exists. */
  fieldLabel: string | null;
  /** Unix seconds. */
  at: number;
}

export const mcp = {
  status: () => invoke<McpStatus>("mcp_status"),
  /** The checklist: item ids, titles and field names. No values. */
  inventory: () => invoke<McpItem[]>("mcp_inventory"),
  /** Record the ticked fields and mint a token for `client`. */
  pair: (client: string, grants: McpGrantInput[]) =>
    invoke<McpPairing>("mcp_pair", { client, grants }),
  /** Recent reads, newest first. */
  audit: (limit = 50) => invoke<McpAuditRow[]>("mcp_audit", { limit }),
  /** Drop the client's token and its grants. */
  revoke: (client: string) => invoke<void>("mcp_revoke", { client }),
};

/**
 * The MCP client configuration to paste into an editor. `token` is `null`
 * before pairing, in which case the snippet shows a placeholder rather than a
 * stale or invented value.
 */
export function clientConfig(binary: string, token: string | null): string {
  return JSON.stringify(
    {
      mcpServers: {
        kestrel: {
          command: binary,
          env: { KESTREL_TOKEN: token ?? "<token from Pair>" },
        },
      },
    },
    null,
    2,
  );
}
