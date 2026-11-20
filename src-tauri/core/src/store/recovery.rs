//! Printable recovery kit: a one-shot code that wraps the master key.
//!
//! The user prints 32 random bytes as 52 base32 characters plus a checksum.
//! Those bytes never reach the disk: they are HKDF-expanded into a subkey that
//! seals the master key, and only that ciphertext is stored in
//! `recovery(vault_uuid, wrapped, created_at)`. A database thief gets a blob
//! that is useless without the paper code, and the code cannot be recovered
//! from the database at any point.
//!
//! The sealed secret is the *master* key, not the per-vault key. A vault key is
//! HKDF-derived from the master and the derivation cannot be inverted, so a row
//! that held it could not perform the forced password change that a recovery
//! unlock exists to perform: re-keying every vault, item, archived version,
//! attachment and passkey needs the account-wide key. The row is bound to the
//! default vault (the vault the unlock gate opens) by its uuid, which is both
//! the HKDF salt and part of the AAD.
//!
//! One shot is structural: the row is replaced by `recovery_create`, so the
//! code that opened the vault is gone from the disk the moment the new kit is
//! minted ([`super::Store::recovery_create`]). Nothing here logs, serializes or
//! returns a code except [`RecoveryKit`], which is handed to the caller once.

use super::{Store, StoreError, VaultMeta, VERIFIER_PLAINTEXT};
use crate::crypto::{self, SymKey};
use base32::{encode as b32_encode, Alphabet};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// HKDF info string. Distinct from every other purpose in this crate, so a
/// recovery subkey can never stand in for a vault, item or history key.
const RECOVERY_PURPOSE: &[u8] = b"kestrel/v1/recovery";
/// Exactly the size of the master key it wraps and of the AEAD key derived from
/// it: no stretching step, every bit is entropy carried on paper.
const SECRET_LEN: usize = 32;
const BASE32: Alphabet = Alphabet::Rfc4648 { padding: false };
/// 32 bytes is 52 base32 characters: 13 display groups of four, the final
/// character padded with zero bits (checked on parse, never guessed at).
const BODY_LEN: usize = 52;
const GROUP_LEN: usize = 4;
/// Body plus the trailing checksum character.
const CODE_LEN: usize = BODY_LEN + 1;

/// Whether this vault has a kit, as the settings card shows it. Safe to read
/// while locked: it is one row of public shape, never key material.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStatus {
    pub enrolled: bool,
    /// Unix milliseconds of the current row, `None` while there is none.
    pub created_at: Option<u64>,
}

/// A freshly minted kit. This is the only shape in which a code leaves the
/// core, and it is handed over exactly once: no getter returns it later. The
/// code field is wiped when the value drops, and the type deliberately has no
/// `Debug`, so a stray `{:?}` cannot put it in a log.
#[derive(Clone, Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKit {
    /// Printed on the sheet so a stack of paper says which vault it opens.
    pub vault_name: String,
    /// The display form: 13 groups of four, then the checksum character.
    pub code: String,
    /// Unix milliseconds of the row this kit replaced.
    pub created_at: u64,
}

struct Row {
    wrapped: Vec<u8>,
    created_at: i64,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

/// One checksum character over the canonical body. Five bits of SHA-256 is
/// enough for its job: it exists to refuse a typo before a 64 MiB Argon2 or any
/// database read happens, not to resist an attacker who already holds the code.
fn checksum_char(body: &str) -> char {
    let digest = Sha256::digest(body.as_bytes());
    b32_encode(BASE32, &digest[..1])
        .chars()
        .next()
        .unwrap_or('A')
}

/// Render 32 secret bytes as `XXXX-XXXX-…-XXXX-C`.
///
/// Shared with the sync account: the Secret Key and an enrolment code are the
/// same printed shape, so they use this one implementation rather than a second
/// codec that could drift from the kit the user already knows.
pub(crate) fn format_code(secret: &[u8; SECRET_LEN]) -> String {
    let body = b32_encode(BASE32, secret);
    let mut out = String::with_capacity(CODE_LEN + BODY_LEN / GROUP_LEN);
    for (index, chunk) in body.as_bytes().chunks(GROUP_LEN).enumerate() {
        if index > 0 {
            out.push('-');
        }
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    out.push('-');
    out.push(checksum_char(&body));
    out
}

fn code_error(message: &str) -> StoreError {
    StoreError::Invalid(format!("recovery code: {message}"))
}

/// Parse the printed form back into the secret, rejecting a typo first.
///
/// Pure by construction: separators, case and the checksum are settled before
/// the caller touches the database or derives a key, so a mistyped code costs
/// nothing and leaves no trace. Only the canonical body is accepted — the last
/// character's padding bits are checked by re-encoding — which makes the
/// checksum cover the whole printed string rather than just its characters.
pub(crate) fn parse_code(input: &str) -> Result<Zeroizing<[u8; SECRET_LEN]>, StoreError> {
    const ALPHABET_ERROR: &str = "only letters A-Z and digits 2-7 are used";
    let mut normal = String::with_capacity(CODE_LEN);
    for ch in input.chars() {
        if ch.is_whitespace() || ch == '-' || ch == '_' {
            continue;
        }
        if !ch.is_ascii() {
            return Err(code_error(ALPHABET_ERROR));
        }
        normal.push(ch.to_ascii_uppercase());
    }
    if normal.len() != CODE_LEN {
        return Err(code_error(&format!(
            "expected {CODE_LEN} characters ({BODY_LEN} plus a checksum), found {}",
            normal.len()
        )));
    }
    let (body, check) = normal.split_at(BODY_LEN);
    if check.as_bytes().first() != Some(&(checksum_char(body) as u8)) {
        return Err(code_error("the checksum does not match, check for a typo"));
    }
    let bytes = base32::decode(BASE32, body).ok_or_else(|| code_error(ALPHABET_ERROR))?;
    if bytes.len() != SECRET_LEN || b32_encode(BASE32, &bytes) != body {
        return Err(code_error("the code is not in canonical base32 form"));
    }
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

/// The subkey the master key is sealed under. Salted with the vault uuid and
/// separated by [`RECOVERY_PURPOSE`], the same construction the vault and item
/// keys use (`SymKey::derive`).
fn recovery_key(secret: &[u8], vault_uuid: &str) -> Result<SymKey, StoreError> {
    let material = SymKey::from_slice(secret)?;
    Ok(material.derive(vault_uuid.as_bytes(), RECOVERY_PURPOSE)?)
}

/// AAD for the wrapped row: kind, account, vault. The code is not part of it
/// (the key already is), so the row cannot be replayed onto another vault.
fn recovery_aad(meta: &VaultMeta) -> Vec<u8> {
    crypto::object_aad(
        "recovery",
        &meta.account_uuid,
        &meta.vault_uuid,
        &meta.vault_uuid,
        1,
    )
}

impl Store {
    /// Whether a kit exists, without a key. The settings card calls this on
    /// mount; the answer is the row's presence, never a guess.
    pub fn recovery_status(&self) -> Result<RecoveryStatus, StoreError> {
        let meta = self.meta_identity()?;
        let row = self.read_recovery_row(&meta.vault_uuid)?;
        Ok(RecoveryStatus {
            enrolled: row.is_some(),
            created_at: row.map(|row| row.created_at.max(0) as u64),
        })
    }

    /// Mint a new code for `master` and replace any previous row.
    ///
    /// Replacing is the whole point: the previous code was printed once and
    /// cannot be re-derived, so leaving its row behind would mean two working
    /// codes and a kit the user cannot revoke. One row per vault, always the
    /// newest code.
    pub fn recovery_create(&self, master: &SymKey) -> Result<RecoveryKit, StoreError> {
        let meta = self.meta_identity()?;
        // Everything that can fail runs before the row is replaced: a code that
        // was generated and then lost to an error would leave the user with a
        // kit they never saw.
        let vault_name = self
            .list_vaults(master, &meta)?
            .into_iter()
            .find(|vault| vault.uuid == meta.vault_uuid)
            .map(|vault| vault.name)
            .unwrap_or_default();
        let secret = Zeroizing::new(crypto::random_bytes::<SECRET_LEN>());
        let code = format_code(&secret);
        let key = recovery_key(&secret[..], &meta.vault_uuid)?;
        let wrapped = crypto::encrypt(&key, &recovery_aad(&meta), &master.to_bytes()[..])?;
        let created_at = now_millis();
        self.conn().execute(
            "INSERT INTO recovery(vault_uuid, wrapped, created_at) VALUES(?1, ?2, ?3)
             ON CONFLICT(vault_uuid) DO UPDATE SET
                 wrapped    = excluded.wrapped,
                 created_at = excluded.created_at",
            params![meta.vault_uuid, wrapped, created_at as i64],
        )?;
        Ok(RecoveryKit {
            vault_name,
            code,
            created_at,
        })
    }

    /// Unwrap the master key from the printed code and prove it opens this
    /// vault. The checksum is checked before the first SQL statement; a wrong
    /// code fails on the AEAD tag and is reported without saying which part of
    /// the code was wrong.
    pub fn recovery_unwrap(&self, code: &str) -> Result<(SymKey, VaultMeta), StoreError> {
        let secret = parse_code(code)?;
        let meta = self.meta_identity()?;
        let row = self.read_recovery_row(&meta.vault_uuid)?.ok_or_else(|| {
            StoreError::Invalid("no recovery code is set for this vault".to_string())
        })?;
        let key = recovery_key(&secret[..], &meta.vault_uuid)?;
        // The unwrapped bytes are the master key: the heap copy is wiped on drop
        // and only the `SymKey` (which wipes itself) survives.
        let plain = Zeroizing::new(
            crypto::decrypt(&key, &recovery_aad(&meta), &row.wrapped).map_err(|_| {
                StoreError::Invalid("that recovery code does not open this vault".into())
            })?,
        );
        let master = SymKey::from_slice(&plain)?;
        self.verify_master(&master, &meta)?;
        Ok((master, meta))
    }

    /// Drop the row. Called when the wrapped key is known to be stale: a
    /// password rotation replaces the master key, and the code that sealed the
    /// old one is not stored anywhere, so the row cannot be re-sealed and would
    /// otherwise offer an unlock that can only fail.
    pub fn recovery_wipe(&self) -> Result<(), StoreError> {
        let meta = self.meta_identity()?;
        self.conn().execute(
            "DELETE FROM recovery WHERE vault_uuid = ?1",
            params![meta.vault_uuid],
        )?;
        Ok(())
    }

    fn read_recovery_row(&self, vault_uuid: &str) -> Result<Option<Row>, StoreError> {
        Ok(self
            .conn()
            .query_row(
                "SELECT wrapped, created_at FROM recovery WHERE vault_uuid = ?1",
                params![vault_uuid],
                |row| {
                    Ok(Row {
                        wrapped: row.get(0)?,
                        created_at: row.get(1)?,
                    })
                },
            )
            .optional()?)
    }

    /// The same authenticated proof [`Store::unlock`] gets from the password:
    /// decrypting the verifier under the vault key can only succeed with the
    /// key that wrote it.
    fn verify_master(&self, master: &SymKey, meta: &VaultMeta) -> Result<(), StoreError> {
        let vault_key = Self::vault_key(master, &meta.vault_uuid)?;
        let plain =
            crypto::decrypt(&vault_key, b"kestrel/verifier", &meta.verifier).map_err(|_| {
                StoreError::Invalid("that recovery code does not open this vault".into())
            })?;
        if plain != VERIFIER_PLAINTEXT {
            return Err(StoreError::Invalid(
                "that recovery code does not open this vault".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod format {
    use super::*;

    fn secret(fill: u8) -> [u8; SECRET_LEN] {
        [fill; SECRET_LEN]
    }

    #[test]
    fn printed_code_round_trips() {
        let secret = secret(0x5a);
        let code = format_code(&secret);
        let groups: Vec<&str> = code.split('-').collect();
        assert_eq!(groups.len(), 14, "13 groups of four and the checksum");
        assert!(groups[..13].iter().all(|group| group.len() == GROUP_LEN));
        assert_eq!(groups[13].len(), 1);
        assert_eq!(&parse_code(&code).unwrap()[..], &secret[..]);
    }

    #[test]
    fn separators_and_case_are_ignored() {
        let secret = secret(0x11);
        let code = format_code(&secret);
        let relaxed = format!(" {} \n", code.to_lowercase().replace('-', " "));
        assert_eq!(&parse_code(&relaxed).unwrap()[..], &secret[..]);
    }

    #[test]
    fn a_typo_is_refused_by_the_checksum() {
        let code = format_code(&secret(0x00));
        // The trailing character is the checksum; a different one is refused
        // before the body is ever decoded or a key derived.
        let mut chars: Vec<char> = code.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == b'A' as char {
            'B'
        } else {
            'A'
        };
        let broken: String = chars.into_iter().collect();
        let error = parse_code(&broken).expect_err("a changed checksum must fail");
        assert!(
            error.to_string().contains("checksum"),
            "the checksum, not the cipher, must reject it: {error}"
        );
    }

    #[test]
    fn short_codes_are_refused_without_deriving_anything() {
        let error = parse_code("ABCD-EFGH").expect_err("too short");
        assert!(error.to_string().contains("expected 53 characters"));
    }
}
