//! Sync account identity, the Secret Key and enrolment envelopes.
//!
//! This is the client half of the phase-4 account contract, with no network in
//! it: an account id, an account key, the printed Secret Key and the sealing
//! routine a second device is enrolled with.
//!
//! **Key hierarchy.** The master key stays exactly what the vault KDF already
//! produces; nothing here changes how an existing vault opens. The account key
//! is the contract's root for sync data and is derived from the Secret Key:
//!
//! ```text
//! account key = HKDF-SHA256(ikm = Secret Key, salt = account id,
//!                           info = "kestrel/v1/account")
//! ```
//!
//! The Secret Key is 32 random bytes, printed with the same codec as the
//! recovery kit and returned exactly once. It is then stored *sealed under the
//! master key*: the paper code is the authoritative copy, the row is the copy
//! the app can use, and neither is readable from a stolen database.
//!
//! The account key deliberately does not depend on the master key. It is the
//! root enrolled devices receive, so a master password change must re-seal its
//! row without changing the key itself; a derivation that included the master
//! key would strand every device that already holds the old value.
//!
//! **Enrolment.** The account key is sealed to a new device's X25519 agreement
//! public key:
//!
//! ```text
//! shared = X25519(sender_agreement_sk, receiver_agreement_pub)
//! key    = HKDF-SHA256(ikm = shared, salt = sha256(printed code),
//!                      info = "kestrel-sync/v1/enroll")
//! plain  = account_id(32 ASCII hex) || account_key(32)
//! sealed = sender_agreement_pub(32) || nonce(24) || ciphertext || tag
//! ```
//!
//! The sender public key is part of the envelope because the receiver cannot
//! derive the shared secret without it; it is public by construction. The
//! account id rides inside the same seal because the receiving device has to
//! learn which account it just joined, and the account key alone cannot tell it:
//! the key is derived *from* the id, not the other way round. Both are inside
//! the AEAD tag, so a blob rewritten with another account id no longer opens.
//!
//! The code is a credential: it is meant to be read aloud once, and it plus the
//! envelope is enough to receive the account key, so the card says so.
//!
//! Nothing here logs, serializes or stores the account key, the Secret Key or an
//! envelope except through the returns named below, and the types that carry
//! them have no `Debug` and wipe themselves on drop.

use super::devices::{
    agreement_public, agreement_secret, hex, shared_secret, unhex, unhex32, AGREEMENT_PUB_LEN,
};
use super::recovery::{format_code, parse_code};
use super::{Store, StoreError, VaultMeta};
use crate::crypto::{self, object_aad, SymKey, KEY_LEN};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF purpose of the account key. Distinct from the vault and item purposes,
/// so an account key can never stand in for either.
const ACCOUNT_PURPOSE: &[u8] = b"kestrel/v1/account";
/// HKDF purpose of an enrolment envelope (the contract's info string).
const ENROL_PURPOSE: &[u8] = b"kestrel-sync/v1/enroll";
/// `object_aad` kinds for the two sealed account rows.
const ACCOUNT_KEY_KIND: &str = "account-key";
const SECRET_KEY_KIND: &str = "account-secret";
/// 16 random bytes rendered as 32 lower-case hex characters.
const ACCOUNT_ID_BYTES: usize = 16;
/// The account id as it travels inside the envelope: 32 ASCII hex characters.
const ACCOUNT_ID_TEXT: usize = ACCOUNT_ID_BYTES * 2;
/// The sealed plaintext: the account id followed by the account key.
const ENVELOPE_PLAIN_LEN: usize = ACCOUNT_ID_TEXT + KEY_LEN;
/// `pub || nonce || ciphertext || tag`, fixed because the plaintext is always
/// one account id and one 32-byte account key.
const ENVELOPE_LEN: usize = AGREEMENT_PUB_LEN + crypto::NONCE_LEN + ENVELOPE_PLAIN_LEN + 16;
/// The one refusal every bad claim input produces. A wrong code, a tampered
/// blob, a blob for another device and a sender key that does not match the
/// envelope are indistinguishable to the caller: the form is not an oracle.
const CLAIM_REFUSED: &str = "that code, sealed blob or sender key does not open an account";


/// What Settings → Account shows. Safe to read while locked: ids, counts and a
/// creation timestamp, never key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountStatus {
    pub exists: bool,
    pub account_id: Option<String>,
    pub created_at: Option<u64>,
    /// Devices the local mirror knows: this device's own row plus every device
    /// the sync service reports. Zero before this device generates a keypair.
    pub device_count: i64,
    /// Whether the sealed Secret Key row exists. It is never re-displayed, and
    /// a device that joined an account has no Secret Key at all.
    pub secret_key_set: bool,
}

/// The one and only handing-over of a new Secret Key. The type has no `Debug`
/// and wipes the printed form on drop; `account_create` is the only producer.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct AccountCreated {
    pub account_id: String,
    /// 13 groups of four base32 characters plus the checksum character.
    pub secret_key: String,
    pub created_at: u64,
}

/// Proof that the stored Secret Key is intact, without returning it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountSecretKey {
    pub present: bool,
    /// The sealed Secret Key was opened and it derives the stored account key.
    /// A tampered row reports `false` rather than pretending, and the command
    /// errors if the row cannot be opened at all.
    pub verified: bool,
    pub created_at: Option<u64>,
}

/// A freshly minted enrolment code. It is a credential for exactly the duration
/// of one enrolment: the card holds it in component state, never in storage.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct EnrolCode {
    pub code: String,
}

/// The account key sealed to a new device. `sealed` is hex on the wire because
/// the renderer is the v1 transport: the user reads the code aloud and carries
/// the blob across by hand.
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct SealedEnrolment {
    pub sender_agreement_pub: String,
    pub sealed: String,
}

/// What a redeemed enrolment produced: the account this device joined. The
/// account key itself is sealed into the database by the same call and never
/// appears in a return value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountClaimed {
    pub account_id: String,
}

/// The contents of an opened envelope: the account it belongs to and the
/// account key. No `Debug`, no `Serialize`; the only consumer is the claim,
/// which seals the key into the account row and drops this value.
pub struct OpenedEnrolment {
    account_id: String,
    account_key: SymKey,
}

impl OpenedEnrolment {
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn account_key(&self) -> &SymKey {
        &self.account_key
    }
}

/// One device as the settings card lists it. Public keys only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountDevice {
    pub device_id: String,
    pub signing_pub: String,
    pub agreement_pub: String,
    pub name: String,
    pub created_at: u64,
    pub last_seen: u64,
    /// Unix milliseconds of the local revocation, if this device was revoked.
    /// A revoked row is kept so Settings can still name the device; it is never
    /// deleted by the revoke path when a sync server was told about it.
    pub revoked_at: Option<u64>,
}

struct AccountRow {
    account_id: String,
    account_key_wrapped: Vec<u8>,
    /// `None` on a device that *joined* the account: the Secret Key exists only
    /// on the device that minted the account, and enrolment transfers the
    /// account key, never the paper secret.
    secret_key: Option<Vec<u8>>,
    created_at: i64,
}

fn now_millis() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

/// Parse the account id that travelled inside an envelope. Hex in, canonical
/// lower-case hex out; anything else is a malformed envelope, never a hint
/// about which input was wrong.
fn account_id_text(bytes: &[u8]) -> Result<String, StoreError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| StoreError::Invalid("the sealed account key is malformed".into()))?;
    if text.len() != ACCOUNT_ID_TEXT || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StoreError::Invalid(
            "the sealed account key is malformed".into(),
        ));
    }
    Ok(text.to_ascii_lowercase())
}

/// The HKDF salt of an enrolment: SHA-256 of the canonical printed code.
///
/// The code is parsed first, so a typo is refused before any curve operation,
/// and then re-printed, so case, separators and the checksum character can never
/// change the key: two devices that read the same code reproduce the same salt.
fn code_salt(code: &str) -> Result<[u8; 32], StoreError> {
    let bytes = parse_code(code)?;
    let canonical = format_code(&bytes);
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

/// The account key: `HKDF(ikm = Secret Key, salt = account id)`.
///
/// Bindings: the Secret Key supplies the entropy, the account id separates one
/// account from another, and the purpose keeps the subkey out of every other
/// use. The master key is not an input, so rotating the password re-seals the
/// rows and leaves the key every enrolled device holds untouched.
fn derive_account_key(secret: &[u8], account_id: &str) -> Result<SymKey, StoreError> {
    let material = SymKey::from_slice(secret)?;
    Ok(material.derive(account_id.as_bytes(), ACCOUNT_PURPOSE)?)
}

/// AAD of the sealed account-key row: kind, account, vault, account id.
fn account_aad(meta: &VaultMeta, account_id: &str, kind: &str) -> Vec<u8> {
    object_aad(kind, &meta.account_uuid, &meta.vault_uuid, account_id, 1)
}

/// Seal `account_key` to a device's agreement public key under a printed code.
///
/// Returns `sender_agreement_pub || nonce || ciphertext || tag`, where the
/// plaintext is the account id followed by the account key. The sender
/// agreement keypair is fresh per envelope: the sender's own device keypair is
/// reserved for request signing and for receiving, and an ephemeral sender key
/// is the same construction with its private half discarded the moment the
/// envelope exists.
pub fn seal_account_key(
    sender_agreement_secret: &[u8; 32],
    receiver_agreement_public: &[u8; 32],
    code: &str,
    account_id: &str,
    account_key: &SymKey,
) -> Result<Vec<u8>, StoreError> {
    if account_id.len() != ACCOUNT_ID_TEXT || !account_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(StoreError::Invalid(
            "an account id is 32 hex characters".into(),
        ));
    }
    let salt = code_salt(code)?;
    let shared = shared_secret(sender_agreement_secret, receiver_agreement_public)?;
    let key = SymKey::from_slice(&shared)?.derive(&salt, ENROL_PURPOSE)?;
    let mut plain = zeroize::Zeroizing::new(Vec::with_capacity(ENVELOPE_PLAIN_LEN));
    plain.extend_from_slice(account_id.to_ascii_lowercase().as_bytes());
    plain.extend_from_slice(&account_key.to_bytes()[..]);
    let body = crypto::encrypt(&key, b"", &plain[..])?;
    let mut envelope = Vec::with_capacity(AGREEMENT_PUB_LEN + body.len());
    envelope.extend_from_slice(&agreement_public(sender_agreement_secret));
    envelope.extend_from_slice(&body);
    Ok(envelope)
}

/// Open an envelope addressed to `receiver_agreement_secret`.
///
/// A wrong code, a tampered envelope and an envelope meant for another device
/// all fail on the AEAD tag; the error deliberately does not say which, so the
/// caller cannot use this as an oracle.
pub fn open_sealed_account(
    receiver_agreement_secret: &[u8; 32],
    code: &str,
    envelope: &[u8],
) -> Result<OpenedEnrolment, StoreError> {
    if envelope.len() != ENVELOPE_LEN {
        return Err(StoreError::Invalid(
            "the sealed account key is malformed".into(),
        ));
    }
    let mut sender_public = [0u8; AGREEMENT_PUB_LEN];
    sender_public.copy_from_slice(&envelope[..AGREEMENT_PUB_LEN]);
    let salt = code_salt(code)?;
    let shared = shared_secret(receiver_agreement_secret, &sender_public)?;
    let key = SymKey::from_slice(&shared)?.derive(&salt, ENROL_PURPOSE)?;
    let plain = zeroize::Zeroizing::new(
        crypto::decrypt(&key, b"", &envelope[AGREEMENT_PUB_LEN..]).map_err(|_| {
            StoreError::Invalid("that code does not open the sealed account key".into())
        })?,
    );
    if plain.len() != ENVELOPE_PLAIN_LEN {
        return Err(StoreError::Invalid(
            "the sealed account key is malformed".into(),
        ));
    }
    let (account_id, account_key) = plain.split_at(ACCOUNT_ID_TEXT);
    Ok(OpenedEnrolment {
        account_id: account_id_text(account_id)?,
        account_key: SymKey::from_slice(account_key)?,
    })
}

impl Store {
    fn account_row(&self) -> Result<Option<AccountRow>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT account_id, account_key_wrapped, secret_key, created_at
                 FROM account LIMIT 1",
                [],
                |row| {
                    Ok(AccountRow {
                        account_id: row.get(0)?,
                        account_key_wrapped: row.get(1)?,
                        secret_key: row.get(2)?,
                        created_at: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// The account key, unwrapped with the master key.
    ///
    /// Sync needs it to seal and open item bodies: every device of the account
    /// holds the same account key, while the master key is this device's alone.
    /// The value has no `Debug`, never serializes and wipes itself on drop, so
    /// the only way it leaves this call is into a caller that keeps it in memory.
    pub fn account_key(&self, master: &SymKey) -> Result<SymKey, StoreError> {
        let anchor = self.meta_identity()?;
        let Some(row) = self.account_row()? else {
            return Err(StoreError::Invalid("this vault has no account".into()));
        };
        let plain = crypto::decrypt(
            master,
            &account_aad(&anchor, &row.account_id, ACCOUNT_KEY_KIND),
            &row.account_key_wrapped,
        )
        .map_err(|_| StoreError::Invalid("the stored account key does not open".into()))?;
        Ok(SymKey::from_slice(&plain)?)
    }

    /// Account presence, id, device count and whether the Secret Key row exists.
    /// Reads public shape only, so it answers while locked.
    pub fn account_status(&self) -> Result<AccountStatus, StoreError> {
        let row = self.account_row()?;
        let device_count: i64 =
            self.conn()
                .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))?;
        Ok(AccountStatus {
            exists: row.is_some(),
            account_id: row.as_ref().map(|row| row.account_id.clone()),
            created_at: row.as_ref().map(|row| row.created_at.max(0) as u64),
            device_count,
            secret_key_set: row
                .as_ref()
                .is_some_and(|row| row.secret_key.is_some()),
        })
    }

    /// Create the account for this vault file, once.
    ///
    /// The account key is derived from a fresh Secret Key and the new account
    /// id, then both values are sealed under the master key. The printed Secret
    /// Key is returned here and nowhere else. The creating device also gets its
    /// keypair here: it is device 1 of the account, and the sync service will
    /// be shown its public halves.
    pub fn account_create(&self, master: &SymKey) -> Result<AccountCreated, StoreError> {
        // Account rows are anchored to the vault file's default identity, not to
        // whichever vault the session happens to be scoped to: the AAD must not
        // change when the user switches vaults.
        let anchor = self.meta_identity()?;
        if self.account_row()?.is_some() {
            return Err(StoreError::Invalid(
                "this vault file already has an account".into(),
            ));
        }
        // Before the account row exists, so a failure here leaves no account
        // that no device can ever sign for.
        self.device_identity(master)?;
        let account_id = hex(&crypto::random_bytes::<ACCOUNT_ID_BYTES>());
        let secret = zeroize::Zeroizing::new(crypto::random_bytes::<KEY_LEN>());
        let account_key = derive_account_key(&secret[..], &account_id)?;
        let key_aad = account_aad(&anchor, &account_id, ACCOUNT_KEY_KIND);
        let wrapped = crypto::encrypt(master, &key_aad, &account_key.to_bytes()[..])?;
        let secret_aad = account_aad(&anchor, &account_id, SECRET_KEY_KIND);
        let sealed_secret = crypto::encrypt(master, &secret_aad, &secret[..])?;
        let created_at = now_millis();
        self.conn().execute(
            "INSERT INTO account(account_id, account_key_wrapped, secret_key, created_at)
             VALUES(?1, ?2, ?3, ?4)",
            params![account_id, wrapped, sealed_secret, created_at as i64],
        )?;
        Ok(AccountCreated {
            account_id,
            secret_key: format_code(&secret),
            created_at,
        })
    }

    /// Verify that the stored Secret Key still opens and still derives the
    /// stored account key. Never returns either value.
    ///
    /// A device that joined an account holds the account key but not the Secret
    /// Key, so it reports `present: false` rather than pretending.
    pub fn account_secret_key(&self, master: &SymKey) -> Result<AccountSecretKey, StoreError> {
        let anchor = self.meta_identity()?;
        let Some(row) = self.account_row()? else {
            return Ok(AccountSecretKey {
                present: false,
                verified: false,
                created_at: None,
            });
        };
        let Some(sealed_secret) = row.secret_key.as_ref() else {
            return Ok(AccountSecretKey {
                present: false,
                verified: false,
                created_at: Some(row.created_at.max(0) as u64),
            });
        };
        let secret = zeroize::Zeroizing::new(
            crypto::decrypt(
                master,
                &account_aad(&anchor, &row.account_id, SECRET_KEY_KIND),
                sealed_secret,
            )
            .map_err(|_| {
                StoreError::Invalid("the stored Secret Key does not open with this vault".into())
            })?,
        );
        let derived = derive_account_key(&secret[..], &row.account_id)?;
        let stored = crypto::decrypt(
            master,
            &account_aad(&anchor, &row.account_id, ACCOUNT_KEY_KIND),
            &row.account_key_wrapped,
        )
        .map_err(|_| StoreError::Invalid("the stored account key does not open".into()))?;
        let verified = stored.as_slice() == &derived.to_bytes()[..];
        Ok(AccountSecretKey {
            present: true,
            verified,
            created_at: Some(row.created_at.max(0) as u64),
        })
    }

    /// A fresh enrolment code. It is not stored anywhere: it exists for the one
    /// handover the caller performs.
    pub fn account_enrol_code(&self) -> EnrolCode {
        let secret = zeroize::Zeroizing::new(crypto::random_bytes::<KEY_LEN>());
        EnrolCode {
            code: format_code(&secret),
        }
    }

    /// Seal this account's key to `device_agreement_pub` under `code`.
    ///
    /// The account id rides inside the envelope: it is what the receiving
    /// device stores as the account it joined, and it cannot be recovered from
    /// the account key.
    pub fn account_seal_for_device(
        &self,
        master: &SymKey,
        code: &str,
        device_agreement_pub: &str,
    ) -> Result<SealedEnrolment, StoreError> {
        let anchor = self.meta_identity()?;
        let row = self
            .account_row()?
            .ok_or_else(|| StoreError::Invalid("this vault has no account yet".into()))?;
        let receiver = unhex32(device_agreement_pub)?;
        let account_key = SymKey::from_slice(&crypto::decrypt(
            master,
            &account_aad(&anchor, &row.account_id, ACCOUNT_KEY_KIND),
            &row.account_key_wrapped,
        )?)?;
        let sender = agreement_secret();
        let envelope = seal_account_key(&sender, &receiver, code, &row.account_id, &account_key)?;
        let mut sender_public = [0u8; AGREEMENT_PUB_LEN];
        sender_public.copy_from_slice(&envelope[..AGREEMENT_PUB_LEN]);
        Ok(SealedEnrolment {
            sender_agreement_pub: hex(&sender_public),
            sealed: hex(&envelope),
        })
    }

    /// Receive an account on this device: open the envelope with the local
    /// agreement key, store the recovered account key and this device's row.
    ///
    /// The local keypair must already exist, because the sending device can
    /// only have sealed to a public key this device showed it; the identity is
    /// created on first ask ([`Store::device_identity`]). Every failure that
    /// depends on the three user-supplied values — a code typo, a tampered or
    /// foreign blob, a sender key that is not the one inside the blob — returns
    /// the same `CLAIM_REFUSED` message, so the form cannot be probed.
    pub fn account_enroll_claim(
        &self,
        master: &SymKey,
        code: &str,
        sealed: &str,
        sender_agreement_pub: &str,
    ) -> Result<AccountClaimed, StoreError> {
        let anchor = self.meta_identity()?;
        if self.account_row()?.is_some() {
            return Err(StoreError::Invalid(
                "this vault file already has an account".into(),
            ));
        }
        let refused = || StoreError::Invalid(CLAIM_REFUSED.to_string());
        // The local keypair first: it is not one of the untrusted inputs, so a
        // failure here keeps its own message.
        self.device_identity(master)?;
        let keys = self.device_secret_keys(master)?;
        let sender = unhex32(sender_agreement_pub).map_err(|_| refused())?;
        let envelope = unhex(sealed).map_err(|_| refused())?;
        if envelope.len() < AGREEMENT_PUB_LEN || envelope[..AGREEMENT_PUB_LEN] != sender[..] {
            return Err(refused());
        }
        let opened = open_sealed_account(keys.agreement_secret(), code, &envelope)
            .map_err(|_| refused())?;
        let account_id = opened.account_id().to_string();
        let key_aad = account_aad(&anchor, &account_id, ACCOUNT_KEY_KIND);
        let wrapped = crypto::encrypt(master, &key_aad, &opened.account_key().to_bytes()[..])?;
        let created_at = now_millis();
        let tx = self.conn().unchecked_transaction()?;
        // A joined device has the account key but not the Secret Key, so that
        // column is NULL here; `account_secret_key` reports it as absent.
        self.conn().execute(
            "INSERT INTO account(account_id, account_key_wrapped, secret_key, created_at)
             VALUES(?1, ?2, NULL, ?3)",
            params![account_id, wrapped, created_at as i64],
        )?;
        self.conn().execute(
            "UPDATE devices SET last_seen = ?2 WHERE device_id = ?1",
            params![keys.device_id(), created_at as i64],
        )?;
        tx.commit()?;
        Ok(AccountClaimed { account_id })
    }

    /// Every device the local mirror knows, oldest first.
    pub fn account_devices(&self) -> Result<Vec<AccountDevice>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT device_id, signing_pub, agreement_pub, name, created_at, last_seen, revoked_at
             FROM devices ORDER BY created_at, device_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(AccountDevice {
                device_id: row.get(0)?,
                signing_pub: hex(&row.get::<_, Vec<u8>>(1)?),
                agreement_pub: hex(&row.get::<_, Vec<u8>>(2)?),
                name: row.get(3)?,
                created_at: row.get::<_, i64>(4)?.max(0) as u64,
                last_seen: row.get::<_, i64>(5)?.max(0) as u64,
                revoked_at: row.get::<_, Option<i64>>(6)?.map(|at| at.max(0) as u64),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Mark a mirrored device revoked locally, keeping its row.
    ///
    /// This is the client-side record of a revocation the sync service has
    /// already accepted, or — when no service is configured — the card's own
    /// statement that the device must not be used. The local device refuses:
    /// revoking yourself would strand this vault with no device that can sign,
    /// which the sync service also refuses. Idempotent: revoking twice returns
    /// the original timestamp instead of moving it.
    pub fn mark_device_revoked(&self, device_id: &str) -> Result<u64, StoreError> {
        if self.local_device_id()?.as_deref() == Some(device_id) {
            return Err(StoreError::Invalid(
                "this device cannot revoke itself".into(),
            ));
        }
        let existing: Option<Option<i64>> = self
            .conn()
            .query_row(
                "SELECT revoked_at FROM devices WHERE device_id = ?1",
                [device_id],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            None => Err(StoreError::Invalid(
                "that device is not in this vault's mirror".into(),
            )),
            Some(Some(at)) => Ok(at.max(0) as u64),
            Some(None) => {
                let now = now_millis();
                self.conn().execute(
                    "UPDATE devices SET revoked_at = ?2 WHERE device_id = ?1",
                    params![device_id, now as i64],
                )?;
                Ok(now)
            }
        }
    }

    /// Remove a mirrored device row. This is the no-sync-server path: there is
    /// no service to tell, so the honest local operation is to forget the row.
    /// The local device refuses for the same reason it cannot revoke itself.
    pub fn forget_device(&self, device_id: &str) -> Result<(), StoreError> {
        if self.local_device_id()?.as_deref() == Some(device_id) {
            return Err(StoreError::Invalid(
                "this device cannot forget itself".into(),
            ));
        }
        let deleted = self
            .conn()
            .execute("DELETE FROM devices WHERE device_id = ?1", [device_id])?;
        if deleted == 0 {
            return Err(StoreError::Invalid(
                "that device is not in this vault's mirror".into(),
            ));
        }
        Ok(())
    }

    /// Re-seal the account rows and this device's keypair under a new master
    /// key. Called by [`Store::change_password`] inside the rotation
    /// transaction: the account id and every stored blob must survive a
    /// password change, and the account key itself must not change, or every
    /// enrolled device would be cut off.
    ///
    /// The device keys are re-sealed even when there is no account row: a
    /// device that generated a keypair but has not joined yet must still be
    /// able to claim after a password change.
    pub(crate) fn rotate_account(
        &self,
        old_master: &SymKey,
        new_master: &SymKey,
    ) -> Result<(), StoreError> {
        self.rotate_device_keys(old_master, new_master)?;
        let anchor = self.meta_identity()?;
        let Some(row) = self.account_row()? else {
            return Ok(());
        };
        let account_key = crypto::decrypt(
            old_master,
            &account_aad(&anchor, &row.account_id, ACCOUNT_KEY_KIND),
            &row.account_key_wrapped,
        )?;
        let wrapped = crypto::encrypt(
            new_master,
            &account_aad(&anchor, &row.account_id, ACCOUNT_KEY_KIND),
            &account_key,
        )?;
        let sealed_secret = match row.secret_key.as_ref() {
            Some(blob) => {
                let secret = zeroize::Zeroizing::new(crypto::decrypt(
                    old_master,
                    &account_aad(&anchor, &row.account_id, SECRET_KEY_KIND),
                    blob,
                )?);
                Some(crypto::encrypt(
                    new_master,
                    &account_aad(&anchor, &row.account_id, SECRET_KEY_KIND),
                    &secret[..],
                )?)
            }
            None => None,
        };
        self.conn().execute(
            "UPDATE account SET account_key_wrapped = ?2, secret_key = ?3
             WHERE account_id = ?1",
            params![row.account_id, wrapped, sealed_secret],
        )?;
        Ok(())
    }
}
