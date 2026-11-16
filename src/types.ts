/**
 * Contract types — mirror `src-tauri/core/src/model.rs` and `session.rs`.
 * Field and command names are frozen by the Rust core; do not rename.
 */

export type Category =
  | "login"
  | "password"
  | "creditCard"
  | "identity"
  | "secureNote"
  | "document"
  | "sshKey"
  | "server"
  | "database"
  | "bankAccount"
  | "cryptoWallet"
  | "driverLicense"
  | "passport"
  | "membership"
  | "medicalRecord"
  | "softwareLicense"
  | "apiCredential"
  | "wirelessRouter";

export interface Field {
  id: string;
  label: string;
  kind: string;
  value: string;
  sensitive: boolean;
}

export interface Item {
  id: string;
  title: string;
  category: Category;
  fields: Field[];
  notes: string;
  urls: string[];
  tags: string[];
  favorite: boolean;
  totpSecret?: string;
  createdAt: number;
  updatedAt: number;
}

export interface ItemSummary {
  id: string;
  title: string;
  category: Category;
  username: string;
  url: string;
  tags: string[];
  favorite: boolean;
  hasTotp: boolean;
  updatedAt: number;
}

export interface VaultState {
  initialized: boolean;
  locked: boolean;
  itemCount: number;
  autolockSeconds: number;
  clipboardClearSeconds: number;
  /** The vault this session is scoped to; empty while locked. */
  vaultUuid: string;
  vaultName: string;
  /** How many vaults the account has. */
  vaultCount: number;
  /** Unix ms at which the core will lock an unlocked session; null when locked. */
  lockAt: number | null;
}

/**
 * Windows Hello enrolment for the vault, as the core reports it. Nothing here
 * is secret: the wrapped key material never leaves the Rust process.
 */
export interface HelloStatus {
  /** This build and this machine can use Hello at all. */
  available: boolean;
  /** A wrapped key exists for this vault. */
  enrolled: boolean;
  /** Empty while not enrolled, else the mechanism id (`tpm-key`). */
  mechanism: string;
  /** Empty while not enrolled, else the mechanism's human name. */
  label: string;
  /** Unix ms of the enrolment, null while not enrolled. */
  createdAt: number | null;
  /** Why the feature is unavailable, when the core knows. */
  detail: string | null;
}

export interface Totp {
  code: string;
  secondsRemaining: number;
  /** Seconds per cycle, as declared by the otpauth secret (default 30). */
  period: number;
}

/** One window of a filtered list plus the total that filter matches. */
export interface Page {
  items: ItemSummary[];
  total: number;
}

/** Vault-wide counters, one grouped query in the core. */
export interface Counts {
  /** Live items in the vault. */
  total: number;
  /** Live items flagged favourite. */
  favorites: number;
  /** Rows in the trash. */
  trash: number;
  /** Live items per category label; categories with no live item are absent. */
  categories: Record<string, number>;
}

export interface GenerateOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
  passphrase: boolean;
  words: number;
  separator: string;
}

export interface AppMeta {
  name: string;
  version: string;
  vaultFormat: number;
  /** Absolute path of the SQLite vault file backing this install. */
  vaultPath: string;
  /** Machine name reported to the About screen, or "unknown". */
  deviceName: string;
}

export const DEFAULT_GENERATE: GenerateOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
  passphrase: false,
  words: 4,
  separator: "-",
};

export const CATEGORIES: { id: Category; label: string }[] = [
  { id: "login", label: "Logins" },
  { id: "password", label: "Passwords" },
  { id: "creditCard", label: "Credit Cards" },
  { id: "identity", label: "Identities" },
  { id: "secureNote", label: "Notes" },
  { id: "document", label: "Documents" },
  { id: "sshKey", label: "SSH Keys" },
  { id: "server", label: "Servers" },
  { id: "database", label: "Databases" },
  { id: "bankAccount", label: "Bank Accounts" },
  { id: "cryptoWallet", label: "Wallets" },
  { id: "driverLicense", label: "Driver Licenses" },
  { id: "passport", label: "Passports" },
  { id: "membership", label: "Memberships" },
  { id: "medicalRecord", label: "Medical" },
  { id: "softwareLicense", label: "Licenses" },
  { id: "apiCredential", label: "API Credentials" },
  { id: "wirelessRouter", label: "Routers" },
];

export const CATEGORY_LABEL: Record<string, string> = Object.fromEntries(
  CATEGORIES.map((c) => [c.id, c.label]),
);

export function isCategory(value: string): value is Category {
  return CATEGORIES.some((c) => c.id === value);
}
