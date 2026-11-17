import type { Category, Field, Item, ItemSummary } from "../types";

/** All 18 categories, each with a real line glyph and its singular noun. */
export interface CategoryMeta {
  id: Category;
  label: string;
  noun: string;
  /** lucide-react export name; see ui/CategoryGlyph.tsx */
  glyph: string;
  /** What the detail pane shows when a category has no notes. */
  blurb: string;
}

export const CATEGORY_META: CategoryMeta[] = [
  {
    id: "login",
    label: "Logins",
    noun: "Login",
    glyph: "KeyRound",
    blurb: "Username, password and the sites that pair with them.",
  },
  {
    id: "password",
    label: "Passwords",
    noun: "Password",
    glyph: "LockKeyhole",
    blurb: "A password that belongs to no site in particular.",
  },
  {
    id: "creditCard",
    label: "Credit Cards",
    noun: "Credit Card",
    glyph: "CreditCard",
    blurb: "Card number, expiry and verification code.",
  },
  {
    id: "identity",
    label: "Identities",
    noun: "Identity",
    glyph: "UserRound",
    blurb: "Name, date of birth and national ID.",
  },
  {
    id: "secureNote",
    label: "Notes",
    noun: "Note",
    glyph: "NotebookPen",
    blurb: "Free-form text, encrypted like everything else.",
  },
  {
    id: "document",
    label: "Documents",
    noun: "Document",
    glyph: "FileText",
    blurb: "A document or record, kept as text.",
  },
  {
    id: "sshKey",
    label: "SSH Keys",
    noun: "SSH Key",
    glyph: "KeySquare",
    blurb: "Private key, public key and fingerprint.",
  },
  {
    id: "server",
    label: "Servers",
    noun: "Server",
    glyph: "Server",
    blurb: "Hostname and the account that reaches it.",
  },
  {
    id: "database",
    label: "Databases",
    noun: "Database",
    glyph: "Database",
    blurb: "Host, port, database name and credentials.",
  },
  {
    id: "bankAccount",
    label: "Bank Accounts",
    noun: "Bank Account",
    glyph: "Landmark",
    blurb: "Account and routing numbers.",
  },
  {
    id: "cryptoWallet",
    label: "Wallets",
    noun: "Wallet",
    glyph: "Wallet",
    blurb: "Address, network, derivation path, recovery phrase and spending password.",
  },
  {
    id: "driverLicense",
    label: "Driver Licenses",
    noun: "Driver License",
    glyph: "Car",
    blurb: "License number, class and expiry.",
  },
  {
    id: "passport",
    label: "Passports",
    noun: "Passport",
    glyph: "IdCard",
    blurb: "Passport number, issuing country and expiry.",
  },
  {
    id: "membership",
    label: "Memberships",
    noun: "Membership",
    glyph: "Ticket",
    blurb: "Member number and the name on it.",
  },
  {
    id: "medicalRecord",
    label: "Medical",
    noun: "Medical Record",
    glyph: "HeartPulse",
    blurb: "Patient, condition and medication.",
  },
  {
    id: "softwareLicense",
    label: "Licenses",
    noun: "License",
    glyph: "BadgeCheck",
    blurb: "License key, registered owner and version.",
  },
  {
    id: "apiCredential",
    label: "API Credentials",
    noun: "API Credential",
    glyph: "Key",
    blurb: "Provider, base URL, client id, secret, token and expiry.",
  },
  {
    id: "wirelessRouter",
    label: "Routers",
    noun: "Router",
    glyph: "Router",
    blurb: "Router name, network name and wireless password.",
  },
];

export const META_BY_ID: Record<string, CategoryMeta> = Object.fromEntries(
  CATEGORY_META.map((m) => [m.id, m]),
);

export function metaFor(category: string): CategoryMeta {
  return META_BY_ID[category] ?? CATEGORY_META[0];
}

/** Field kinds the core emits, grouped by how they must be rendered. */
const SECRET_KINDS: Record<string, true> = {
  password: true,
  apiSecret: true,
  sshPrivateKey: true,
  cvv: true,
  pin: true,
  creditCardNumber: true,
  // A mnemonic is the wallet. Mask it even if a foreign import lost the
  // `sensitive` flag.
  seedPhrase: true,
};

const MULTILINE_KINDS: Record<string, true> = {
  sshPrivateKey: true,
  sshPublicKey: true,
  seedPhrase: true,
};

/** Kinds the editor's picker offers, in menu order. */
export const FIELD_KINDS: { id: string; label: string }[] = [
  { id: "text", label: "Text" },
  { id: "username", label: "Username" },
  { id: "url", label: "URL" },
  { id: "host", label: "IP / host" },
  { id: "port", label: "Port" },
  { id: "password", label: "Password" },
  { id: "apiSecret", label: "API secret" },
  { id: "seedPhrase", label: "Seed phrase" },
  { id: "date", label: "Date" },
  { id: "monthYear", label: "Month / year" },
  { id: "cvv", label: "CVV" },
  { id: "pin", label: "PIN" },
  { id: "creditCardNumber", label: "Card number" },
  { id: "sshPrivateKey", label: "SSH private key" },
  { id: "sshPublicKey", label: "SSH public key" },
];

/** Whether the kind itself is secret, independent of the field's flag. */
export function isSecretKind(kind: string): boolean {
  return SECRET_KINDS[kind] === true;
}

export function isSecretField(field: Field): boolean {
  return field.sensitive || SECRET_KINDS[field.kind] === true;
}

export function isMultilineField(field: Field): boolean {
  return MULTILINE_KINDS[field.kind] === true;
}

/** The field the list pane shows as secondary text, if any. */
export function secondaryText(item: ItemSummary): string {
  if (item.username) return item.username;
  if (item.url) return hostOf(item.url);
  return metaFor(item.category).label;
}

export function hostOf(url: string): string {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).host;
  } catch {
    return url;
  }
}

export function fieldByKind(item: Item, kinds: string[]): Field | undefined {
  return item.fields.find((f) => kinds.includes(f.kind));
}

export function initialsOf(title: string): string {
  const cleaned = title.trim();
  if (!cleaned) return "—";
  const words = cleaned.split(/\s+/).slice(0, 2);
  return words.map((w) => w[0]?.toUpperCase() ?? "").join("");
}
