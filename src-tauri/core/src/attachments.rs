//! Attachments: arbitrary files sealed under the owning item's key.
//!
//! Every blob is encrypted with the vault's item key and bound to
//! `(account, vault, item, attachment)` through the AAD, so a row copied onto
//! another item can never be decrypted there. The non-secret columns
//! (`name`, `mime`, `size`, `digest`, `created_at`) exist only for listing;
//! the bytes themselves stay opaque on disk.

use crate::crypto;
use crate::session::{VaultError, VaultState};
use crate::store::{Store, StoreError};
use rusqlite::OptionalExtension;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Hard cap for one attachment. The renderer refuses earlier so the user is
/// not asked to push 25 MiB through the IPC bridge for nothing.
pub const MAX_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;

/// Metadata the UI may see. Never carries the blob.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentDto {
    pub id: String,
    pub name: String,
    pub mime: String,
    pub size: i64,
    pub digest: String,
    pub created_at: i64,
}

struct AttachmentRow {
    attachment_uuid: String,
    name: String,
    mime: String,
    size: i64,
    digest: String,
    created_at: i64,
}

impl VaultState {
    pub fn attachment_list(&self, item_id: &str) -> Result<Vec<AttachmentDto>, VaultError> {
        self.touch();
        self.with_session(|store, _, meta| {
            let mut stmt = store
                .conn()
                .prepare(
                    "SELECT attachment_uuid, name, mime, size, digest, created_at
                 FROM attachments WHERE vault_uuid = ?1 AND item_uuid = ?2
                 ORDER BY created_at ASC, attachment_uuid ASC",
                )
                .map_err(StoreError::Db)?;
            let rows = stmt
                .query_map(rusqlite::params![meta.vault_uuid, item_id], |row| {
                    Ok(AttachmentRow {
                        attachment_uuid: row.get(0)?,
                        name: row.get(1)?,
                        mime: row.get(2)?,
                        size: row.get(3)?,
                        digest: row.get(4)?,
                        created_at: row.get(5)?,
                    })
                })
                .map_err(StoreError::Db)?;
            let mut out = Vec::new();
            for row in rows {
                let row = row.map_err(StoreError::Db)?;
                out.push(AttachmentDto {
                    id: row.attachment_uuid,
                    name: row.name,
                    mime: row.mime,
                    size: row.size,
                    digest: row.digest,
                    created_at: row.created_at,
                });
            }
            Ok(out)
        })
    }

    pub fn attachment_add(
        &self,
        item_id: &str,
        name: &str,
        mime: &str,
        bytes: Vec<u8>,
    ) -> Result<AttachmentDto, VaultError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(VaultError::Invalid("attachment name is required".into()));
        }
        if bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err(VaultError::Invalid(
                "attachment exceeds the 25 MiB limit".into(),
            ));
        }
        if bytes.is_empty() {
            return Err(VaultError::Invalid("attachment is empty".into()));
        }
        self.touch();
        self.with_session(|store, master, meta| {
            // Refuse to attach to something that is not in this vault: the row
            // would be an orphan the moment it was written.
            let exists: bool = store
                .conn()
                .query_row(
                    "SELECT 1 FROM items WHERE vault_uuid = ?1 AND item_uuid = ?2",
                    rusqlite::params![meta.vault_uuid, item_id],
                    |_| Ok(true),
                )
                .optional()
                .map_err(StoreError::Db)?
                .unwrap_or(false);
            if !exists {
                return Err(VaultError::NotFound);
            }
            let attachment_id = uuid::Uuid::new_v4().to_string();
            let key = store.sealing_key(master, meta, item_id)?;
            let aad = Store::attachment_aad(meta, item_id, &attachment_id);
            let blob = crypto::encrypt(&key, &aad, &bytes).map_err(StoreError::Crypto)?;
            let size = bytes.len() as i64;
            let digest = digest_of(&bytes);
            let created_at = chrono::Utc::now().timestamp();
            let mime = if mime.trim().is_empty() {
                "application/octet-stream"
            } else {
                mime
            };
            store.conn().execute(
                "INSERT INTO attachments(
                     vault_uuid, item_uuid, attachment_uuid, name, mime, size, digest, created_at, data)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    meta.vault_uuid,
                    item_id,
                    attachment_id,
                    name,
                    mime,
                    size,
                    digest,
                    created_at,
                    blob
                ],
            )
            .map_err(StoreError::Db)?;
            Ok(AttachmentDto {
                id: attachment_id,
                name: name.to_string(),
                mime: mime.to_string(),
                size,
                digest,
                created_at,
            })
        })
    }

    pub fn attachment_read(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<Vec<u8>, VaultError> {
        self.touch();
        self.with_session(|store, master, meta| {
            let blob: Vec<u8> = store
                .conn()
                .query_row(
                    "SELECT data FROM attachments
                     WHERE vault_uuid = ?1 AND item_uuid = ?2 AND attachment_uuid = ?3",
                    rusqlite::params![meta.vault_uuid, item_id, attachment_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(StoreError::Db)?
                .ok_or(VaultError::NotFound)?;
            let key = store.sealing_key(master, meta, item_id)?;
            let aad = Store::attachment_aad(meta, item_id, attachment_id);
            Ok(crypto::decrypt(&key, &aad, &blob).map_err(StoreError::Crypto)?)
        })
    }

    /// Decrypt an attachment and write it to the OS downloads folder under a
    /// filesystem-safe name. Returns the absolute path for the UI to show;
    /// the bytes themselves never reach the renderer.
    pub fn attachment_save_as(
        &self,
        item_id: &str,
        attachment_id: &str,
    ) -> Result<String, VaultError> {
        self.touch();
        let (name, bytes) = self.with_session(|store, master, meta| {
            let row: (String, Vec<u8>) = store
                .conn()
                .query_row(
                    "SELECT name, data FROM attachments
                     WHERE vault_uuid = ?1 AND item_uuid = ?2 AND attachment_uuid = ?3",
                    rusqlite::params![meta.vault_uuid, item_id, attachment_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(StoreError::Db)?
                .ok_or(VaultError::NotFound)?;
            let key = store.sealing_key(master, meta, item_id)?;
            let aad = Store::attachment_aad(meta, item_id, attachment_id);
            let plain = crypto::decrypt(&key, &aad, &row.1).map_err(StoreError::Crypto)?;
            Ok((row.0, plain))
        })?;

        let dir = download_dir();
        std::fs::create_dir_all(&dir).map_err(StoreError::Io)?;
        let path = unique_path(&dir, &sanitise_file_name(&name));
        std::fs::write(&path, &bytes).map_err(StoreError::Io)?;
        let absolute = std::path::absolute(&path).map_err(StoreError::Io)?;
        Ok(absolute.to_string_lossy().into_owned())
    }

    pub fn attachment_remove(&self, item_id: &str, attachment_id: &str) -> Result<(), VaultError> {
        self.touch();
        self.with_session(|store, _, meta| {
            let removed = store
                .conn()
                .execute(
                    "DELETE FROM attachments
                 WHERE vault_uuid = ?1 AND item_uuid = ?2 AND attachment_uuid = ?3",
                    rusqlite::params![meta.vault_uuid, item_id, attachment_id],
                )
                .map_err(StoreError::Db)?;
            if removed == 0 {
                return Err(VaultError::NotFound);
            }
            Ok(())
        })
    }
}

/// Delete every attachment row belonging to an item. Item deletion is owned by
/// the store/session layer, so that path must call this before dropping the
/// item row; otherwise sealed blobs would linger with no readable owner.
pub fn purge_item_attachments(store: &Store, item_uuid: &str) -> Result<(), StoreError> {
    store
        .conn()
        .execute(
            "DELETE FROM attachments WHERE item_uuid = ?1",
            rusqlite::params![item_uuid],
        )
        .map_err(StoreError::Db)?;
    Ok(())
}

/// First 16 hex characters of SHA-256. Enough to compare copies by eye, far
/// too little to say anything about the bytes.
fn digest_of(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    let mut out = String::with_capacity(16);
    for byte in hash.iter().take(8) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Strip everything a filesystem (or a user double-clicking the result) could
/// misinterpret: path separators, control characters, Windows-reserved marks.
fn sanitise_file_name(name: &str) -> String {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .trim()
        .trim_matches('.');
    let cleaned: String = base
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' | '/' | '\\' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim().trim_matches('.').trim();
    if trimmed.is_empty() {
        "attachment".to_string()
    } else if is_reserved_windows_name(trimmed) {
        format!("_{trimmed}")
    } else {
        trimmed.to_string()
    }
}

fn is_reserved_windows_name(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim()
        .to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// `%USERPROFILE%\Downloads`, then the app data folder, then the temp folder.
/// The directory is created on demand so the first save always succeeds.
fn download_dir() -> PathBuf {
    if let Ok(home) = std::env::var("USERPROFILE") {
        if !home.trim().is_empty() {
            return Path::new(&home).join("Downloads");
        }
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        if !appdata.trim().is_empty() {
            return Path::new(&appdata).join("Kestrel").join("Downloads");
        }
    }
    std::env::temp_dir().join("Kestrel").join("Downloads")
}

/// Never overwrite a file the user already has: `report.pdf`, `report (2).pdf`.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("attachment");
    let extension = path.extension().and_then(|s| s.to_str());
    for n in 2..=9999 {
        let file = match extension {
            Some(ext) => format!("{stem} ({n}).{ext}"),
            None => format!("{stem} ({n})"),
        };
        let next = dir.join(file);
        if !next.exists() {
            return next;
        }
    }
    let file = match extension {
        Some(ext) => format!("{stem}-{}.{ext}", uuid::Uuid::new_v4()),
        None => format!("{stem}-{}", uuid::Uuid::new_v4()),
    };
    dir.join(file)
}
