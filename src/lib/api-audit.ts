import { invoke } from "@tauri-apps/api/core";

/**
 * Audit payloads. The core sends ids, labels and prose only — no field
 * value ever appears in these objects.
 */
export type PasswordFindingKind = "breached" | "reused" | "weak";
export type ExpiryFindingKind = "expired" | "expiring";
export type AuditKind = PasswordFindingKind | ExpiryFindingKind;

export interface AuditFinding {
  itemId: string;
  title: string;
  fieldId: string;
  fieldLabel: string;
  kind: AuditKind;
  detail: string;
  /** Expiry findings only: the stored date as `YYYY-MM-DD`. */
  date?: string;
  /** Expiry findings only: whole days from today; negative once passed. */
  daysUntil?: number;
}

export interface AuditReport {
  weak: number;
  reused: number;
  breached: number;
  expiring: number;
  expired: number;
  findings: AuditFinding[];
  breachChecked: boolean;
  breachNote: string | null;
}

export const auditApi = {
  /** Offline pass: weak and reused passwords plus expiring credentials. */
  report: () => invoke<AuditReport>("audit_report"),
  /** Offline pass plus the k-anonymised HIBP range check from the core. */
  checkBreaches: () => invoke<AuditReport>("audit_check_breaches"),
};

/** Section order for password findings; expiry findings have their own list. */
export const KIND_ORDER: PasswordFindingKind[] = ["breached", "reused", "weak"];
