/**
 * Sync account bridge — mirrors `src-tauri/src/commands_account.rs`.
 *
 * Nothing here ever carries the account key back out. The Secret Key crosses
 * this bridge exactly once, in the return of `create`; the enrolment envelope
 * carries the account key but only in sealed form, and the card is the v1
 * transport for it. `revokeDevice` is the one network call on this bridge: the
 * core makes it with this device's signing key, and no key material crosses.
 * Device private halves never cross at all: `deviceIdentity` returns public
 * keys, and the private halves are opened only inside the core for the net
 * crate.
 */
import { invoke } from "@tauri-apps/api/core";

export interface AccountStatus {
  /** Whether this vault file has an account yet. */
  exists: boolean;
  /** 32 lower-case hex characters, chosen on this device. */
  accountId: string | null;
  /** Unix milliseconds of the account row. */
  createdAt: number | null;
  /** Devices the local mirror knows; zero until the sync service registers one. */
  deviceCount: number;
  /** Whether the sealed Secret Key row exists. It is never re-displayed. */
  secretKeySet: boolean;
}

export interface AccountCreated {
  accountId: string;
  /**
   * 13 groups of four base32 characters plus the checksum character. Shown
   * once and never stored by the renderer: the paper copy is the real one.
   */
  secretKey: string;
  createdAt: number;
}

export interface AccountSecretKey {
  present: boolean;
  /** The sealed Secret Key opens and derives the stored account key. */
  verified: boolean;
  createdAt: number | null;
}

export interface EnrolCode {
  /** A fresh code for one handover; it is not stored anywhere. */
  code: string;
}

export interface SealedEnrolment {
  /** The sender's X25519 agreement public key, 64 hex characters. */
  senderAgreementPub: string;
  /** `sender_pub || nonce || ciphertext || tag`, hex. */
  sealed: string;
}

/** This device's public keys. The private halves never cross this bridge. */
export interface DeviceIdentity {
  /** 32 lower-case hex characters, chosen on this device. */
  deviceId: string;
  /** Label other devices and the sync service display. */
  deviceName: string;
  /** Ed25519 public key, 64 hex characters. */
  signingPub: string;
  /** X25519 agreement public key, 64 hex characters. */
  agreementPub: string;
  /** Unix milliseconds of the keypair's creation. */
  createdAt: number;
}

/** The account a claim joined; the account key itself stays in the core. */
export interface AccountClaimed {
  /** 32 lower-case hex characters, recovered from the sealed blob. */
  accountId: string;
}

export interface AccountDevice {
  deviceId: string;
  signingPub: string;
  agreementPub: string;
  name: string;
  createdAt: number;
  lastSeen: number;
  /** Unix milliseconds of the local revocation, or null while the device is live. */
  revokedAt: number | null;
}

/**
 * What `revokeDevice` actually did. The card reads these facts instead of
 * assuming a server was told.
 */
export interface AccountRevocation {
  deviceId: string;
  /** Unix milliseconds when the local row was marked revoked; null when it was removed. */
  revokedAt: number | null;
  /** The sync service recorded the revocation and will refuse the device. */
  serverRevoked: boolean;
  /** The local mirror row was deleted because there was no service to tell. */
  localRemoved: boolean;
}

export const account = {
  /** Presence, id, device count and Secret Key presence; works while locked. */
  status: () => invoke<AccountStatus>("account_status"),
  /** Create the account; the Secret Key is returned by this call only. */
  create: () => invoke<AccountCreated>("account_create"),
  /** Integrity check of the sealed Secret Key; returns no key material. */
  secretKey: () => invoke<AccountSecretKey>("account_secret_key"),
  /** Mint an enrolment code for one handover. */
  enrolCode: () => invoke<EnrolCode>("account_enrol_code"),
  /** Seal this account's key to another device's agreement public key (hex). */
  sealForDevice: (code: string, deviceAgreementPub: string) =>
    invoke<SealedEnrolment>("account_seal_for_device", { code, deviceAgreementPub }),
  /** This device's public keys; generates the keypair on first call. */
  deviceIdentity: () => invoke<DeviceIdentity>("account_device_identity"),
  /** Redeem a code, sealed blob and sender agreement key on this device. */
  enrollClaim: (code: string, sealed: string, senderAgreementPub: string) =>
    invoke<AccountClaimed>("account_enroll_claim", {
      code,
      sealed,
      senderAgreementPub,
    }),
  /** Devices the local mirror knows. */
  devices: () => invoke<AccountDevice[]>("account_devices"),
  /**
   * Revoke another device. With a sync server configured this withdraws the
   * device's access there and keeps the local row as revoked; without one it
   * removes the mirror row and reports that nothing was sent.
   */
  revokeDevice: (deviceId: string) =>
    invoke<AccountRevocation>("account_revoke_device", { deviceId }),
};
