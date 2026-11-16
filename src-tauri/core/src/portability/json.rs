//! JSON import: a forgiving view of an item array.

use super::common::{build_item, category_from, new_id, non_empty, utf8};
use super::{ImportFailure, Parsed, ParsedItem};
use crate::model::{Category, Field, Item};
use crate::session::VaultError;
use serde::Deserialize;
use serde_json::Value;

/// A forgiving view of an item: every key is optional so a partial export from
/// another tool still imports, and unknown keys are ignored by serde.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LenientItem {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    fields: Vec<LenientField>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    totp_secret: Option<String>,
    #[serde(default)]
    created_at: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LenientField {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    sensitive: bool,
}

pub(super) fn parse_json(bytes: &[u8]) -> Result<Parsed, VaultError> {
    let value: Value = serde_json::from_str(utf8(bytes, "JSON")?).map_err(|error| {
        VaultError::Invalid(format!("the JSON file could not be parsed: {error}"))
    })?;
    let rows = match value {
        Value::Array(rows) => rows,
        Value::Object(mut object) => {
            match object.remove("items") {
                Some(Value::Array(rows)) => rows,
                Some(_) => {
                    return Err(VaultError::Invalid(
                        "`items` in the JSON file must be an array".into(),
                    ))
                }
                None => return Err(VaultError::Invalid(
                    "the JSON file must be an array of items or an object with an `items` array"
                        .into(),
                )),
            }
        }
        _ => {
            return Err(VaultError::Invalid(
                "the JSON file must be an array of items or an object with an `items` array".into(),
            ))
        }
    };

    let mut parsed = Parsed::default();
    for (index, row) in rows.into_iter().enumerate() {
        let row_number = index + 1;
        match json_to_item(row) {
            Ok(Some(item)) => parsed.items.push(ParsedItem {
                row: row_number,
                item,
            }),
            Ok(None) => parsed.skipped += 1,
            Err(reason) => parsed.failed.push(ImportFailure {
                row: row_number,
                reason,
            }),
        }
    }
    Ok(parsed)
}

fn json_to_item(value: Value) -> Result<Option<Item>, String> {
    if value.is_null() {
        return Ok(None);
    }
    if !value.is_object() {
        return Err("entry is not a JSON object".into());
    }
    let row: LenientItem = serde_json::from_value(value)
        .map_err(|error| format!("does not match the item shape: {error}"))?;
    let category = row
        .category
        .as_deref()
        .map(category_from)
        .unwrap_or(Category::Login);
    let mut fields = Vec::with_capacity(row.fields.len());
    for (index, field) in row.fields.into_iter().enumerate() {
        fields.push(Field {
            id: non_empty(field.id).unwrap_or_else(new_id),
            label: non_empty(field.label).unwrap_or_else(|| format!("field {}", index + 1)),
            kind: non_empty(field.kind).unwrap_or_else(|| "text".to_string()),
            value: field.value.unwrap_or_default(),
            sensitive: field.sensitive,
        });
    }
    Ok(Some(build_item(
        row.title.unwrap_or_default(),
        category,
        fields,
        row.notes.unwrap_or_default(),
        row.urls,
        row.tags,
        row.favorite,
        non_empty(row.totp_secret),
        row.created_at,
    )))
}
