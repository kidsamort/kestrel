//! Import and export of vault contents.
//!
//! Three exchange formats are supported, all of them handled entirely inside
//! the core:
//!
//! * `json` — an array of full [`Item`]s (or `{ "items": [...] }`). Unknown
//!   keys are ignored, a missing title becomes `Untitled`, and an unknown
//!   category falls back to `login`.
//! * `csv` — a header row with the columns `title, category, username,
//!   password, url, notes, tags`. Quoted fields, embedded commas, embedded
//!   newlines and doubled quotes follow RFC 4180. Unknown columns are ignored.
//! * `1pux` — a 1Password zip archive; only `export.data` is read, and the
//!   1Password category codes are mapped onto Kestrel's categories.
//!
//! Imports always create new items with fresh ids: duplicates are imported
//! beside existing entries, never merged. A malformed row is reported in the
//! import report and never aborts the rest of the file.
//!
//! Exports are plaintext by nature. They require the current master password as
//! proof of presence, are returned to the caller, and are never written to disk
//! by the core. The 1PUX writer emits `export.data` only: attachment payloads
//! are **not** included (Kestrel's attachment store is separate), so an archive
//! produced here is portable for item data but loses files.
//!
//! The format parsers live in [`json`], [`csv`] and [`pux`]; [`common`] holds
//! the item construction they share. This file owns the session-facing API,
//! the report types and the format dispatch.

mod common;
mod csv;
mod json;
mod pux;

use crate::crypto::SymKey;
use crate::model::Item;
use crate::session::{VaultError, VaultState};
use crate::store::{Store, VaultMeta};
use serde::Serialize;
use serde_json::json;
use std::io::{Cursor, Write};

use csv::export_csv;
use pux::one_password_item;

/// How many rows a preview carries; the UI never needs more to prove a mapping.
const PREVIEW_ROWS: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportFailure {
    /// 1-based record number inside the source file (the header is row 1 for CSV).
    pub row: usize,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub imported: usize,
    pub skipped: usize,
    pub failed: Vec<ImportFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportSample {
    pub title: String,
    pub category: String,
    pub field_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreview {
    pub total: usize,
    pub sample: Vec<ImportSample>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Csv,
    Pux,
}

impl Format {
    fn parse(value: &str) -> Result<Format, VaultError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Format::Json),
            "csv" => Ok(Format::Csv),
            "1pux" | "pux" | "1password" => Ok(Format::Pux),
            other => Err(VaultError::Invalid(format!(
                "unsupported format `{other}`: use json, csv or 1pux"
            ))),
        }
    }
}

/// One item read from a file, with the record number that produced it.
pub(super) struct ParsedItem {
    pub(super) row: usize,
    pub(super) item: Item,
}

/// Everything one parse produced: importable items plus per-row accounting.
#[derive(Default)]
pub(super) struct Parsed {
    pub(super) items: Vec<ParsedItem>,
    pub(super) skipped: usize,
    pub(super) failed: Vec<ImportFailure>,
}

impl VaultState {
    /// Read a file and describe the first rows without storing anything.
    pub fn import_preview(
        &self,
        format: &str,
        bytes: Vec<u8>,
    ) -> Result<ImportPreview, VaultError> {
        self.touch();
        let format = Format::parse(format)?;
        self.with_session(|_, _, _| {
            let parsed = parse_import(format, &bytes)?;
            let sample = parsed
                .items
                .iter()
                .take(PREVIEW_ROWS)
                .map(|parsed| ImportSample {
                    title: parsed.item.title.clone(),
                    category: parsed.item.category.as_str().to_string(),
                    field_count: parsed.item.fields.len(),
                })
                .collect();
            Ok(ImportPreview {
                total: parsed.items.len(),
                sample,
            })
        })
    }

    /// Import every readable row, reporting per-row failures instead of
    /// aborting the file.
    pub fn import_items(&self, format: &str, bytes: Vec<u8>) -> Result<ImportReport, VaultError> {
        self.touch();
        let format = Format::parse(format)?;
        self.with_session(|store, master, meta| {
            let parsed = parse_import(format, &bytes)?;
            let mut report = ImportReport {
                imported: 0,
                skipped: parsed.skipped,
                failed: parsed.failed,
            };
            for parsed in parsed.items {
                match store.save_item(master, meta, parsed.item) {
                    Ok(_) => report.imported += 1,
                    Err(error) => report.failed.push(ImportFailure {
                        row: parsed.row,
                        reason: error.to_string(),
                    }),
                }
            }
            report.failed.sort_by_key(|failure| failure.row);
            Ok(report)
        })
    }

    /// Export the live items as text (JSON or CSV) after verifying `password`.
    pub fn export_items(&self, format: &str, password: &str) -> Result<String, VaultError> {
        self.touch();
        let format = Format::parse(format)?;
        if format == Format::Pux {
            return Err(VaultError::Invalid(
                "1PUX is a binary archive; use the 1PUX export instead".into(),
            ));
        }
        self.with_session(|store, master, meta| {
            store.unlock(password)?;
            let items = live_items(store, master, meta)?;
            match format {
                Format::Json => serde_json::to_string_pretty(&items)
                    .map_err(|error| VaultError::Invalid(format!("JSON export failed: {error}"))),
                Format::Csv => Ok(export_csv(&items)),
                Format::Pux => unreachable!("handled above"),
            }
        })
    }

    /// Export the live items as a 1PUX zip. Attachment payloads are omitted.
    pub fn export_1pux(&self, password: &str) -> Result<Vec<u8>, VaultError> {
        self.touch();
        self.with_session(|store, master, meta| {
            store.unlock(password)?;
            let items = live_items(store, master, meta)?;
            let payload = json!({
                "accounts": [{
                    "attrs": { "accountName": "Kestrel", "name": "Kestrel" },
                    "vaults": [{
                        "attrs": { "name": "Personal", "desc": "" },
                        "items": items.iter().map(one_password_item).collect::<Vec<_>>(),
                    }],
                }],
            });
            let text = serde_json::to_vec_pretty(&payload)
                .map_err(|error| VaultError::Invalid(format!("1PUX export failed: {error}")))?;
            let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            archive
                .start_file("export.data", options)
                .map_err(|error| VaultError::Invalid(format!("1PUX export failed: {error}")))?;
            archive
                .write_all(&text)
                .map_err(|error| VaultError::Invalid(format!("1PUX export failed: {error}")))?;
            let cursor = archive
                .finish()
                .map_err(|error| VaultError::Invalid(format!("1PUX export failed: {error}")))?;
            Ok(cursor.into_inner())
        })
    }
}

fn live_items(store: &Store, master: &SymKey, meta: &VaultMeta) -> Result<Vec<Item>, VaultError> {
    let mut items: Vec<Item> = store
        .load_rows(master, meta)?
        .into_iter()
        .filter(|(_, deleted_at)| deleted_at.is_none())
        .map(|(item, _)| item)
        .collect();
    items.sort_by(|left, right| {
        left.title
            .to_lowercase()
            .cmp(&right.title.to_lowercase())
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(items)
}

fn parse_import(format: Format, bytes: &[u8]) -> Result<Parsed, VaultError> {
    match format {
        Format::Json => json::parse_json(bytes),
        Format::Csv => csv::parse_csv(bytes),
        Format::Pux => pux::parse_1pux(bytes),
    }
}
