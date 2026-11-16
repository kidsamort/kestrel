//! Attachment row helpers shared with account re-keying.

use super::{Store, StoreError, VaultMeta};
use crate::crypto::{self, object_aad};
use rusqlite::params;

/// An attachment row with its metadata and decrypted payload. Re-keying
/// decrypts each row and writes it back sealed with the new key, so metadata
/// and payload travel together.
pub(crate) struct StoredAttachment {
    pub(crate) item_uuid: String,
    pub(crate) attachment_uuid: String,
    pub(crate) name: String,
    pub(crate) mime: String,
    pub(crate) size: i64,
    pub(crate) digest: String,
    pub(crate) created_at: i64,
    pub(crate) plain: Vec<u8>,
}

impl Store {
    /// AAD binding for an attachment blob.
    pub(crate) fn attachment_aad(meta: &VaultMeta, item_id: &str, attachment_id: &str) -> Vec<u8> {
        object_aad(
            "attachment",
            &meta.account_uuid,
            &meta.vault_uuid,
            &format!("{item_id}:{attachment_id}"),
            1,
        )
    }

    /// Every attachment in one vault, decrypted; used by re-keying.
    pub(crate) fn load_attachments(
        &self,
        keys: &super::item_keys::ItemKeys,
        meta: &VaultMeta,
    ) -> Result<Vec<StoredAttachment>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT item_uuid, attachment_uuid, name, mime, size, digest, created_at, data
             FROM attachments WHERE vault_uuid = ?1",
        )?;
        let rows = stmt.query_map(params![meta.vault_uuid], |r| {
            Ok((
                StoredAttachment {
                    item_uuid: r.get(0)?,
                    attachment_uuid: r.get(1)?,
                    name: r.get(2)?,
                    mime: r.get(3)?,
                    size: r.get(4)?,
                    digest: r.get(5)?,
                    created_at: r.get(6)?,
                    plain: Vec::new(),
                },
                r.get::<_, Vec<u8>>(7)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (mut row, blob) = row?;
            let aad = Self::attachment_aad(meta, &row.item_uuid, &row.attachment_uuid);
            row.plain = crypto::decrypt(keys.for_item(&row.item_uuid), &aad, &blob)?;
            out.push(row);
        }
        Ok(out)
    }
}
