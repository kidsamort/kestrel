//! 1PUX import and export.
//!
//! The archive is a zip whose `export.data` member is JSON. Only item data is
//! read on import; the writer emits `export.data` only, so attachment payloads
//! are not part of the exchange.

use super::common::{build_item, category_from, field};
use super::{ImportFailure, Parsed, ParsedItem};
use crate::model::{Category, Field, Item};
use crate::session::VaultError;
use serde_json::{json, Map, Value};
use std::io::{Cursor, Read};

pub(super) fn parse_1pux(bytes: &[u8]) -> Result<Parsed, VaultError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|error| {
        VaultError::Invalid(format!("the file is not a readable 1PUX archive: {error}"))
    })?;
    let mut entry_name = None;
    for index in 0..archive.len() {
        let file = archive.by_index(index).map_err(|error| {
            VaultError::Invalid(format!("1PUX entry {index} could not be read: {error}"))
        })?;
        let name = file.name().to_string();
        if name == "export.data" || name.ends_with("/export.data") {
            entry_name = Some(name);
            break;
        }
    }
    let entry_name = entry_name
        .ok_or_else(|| VaultError::Invalid("the 1PUX archive has no `export.data`".into()))?;
    let mut entry = archive.by_name(&entry_name).map_err(|error| {
        VaultError::Invalid(format!("`{entry_name}` could not be opened: {error}"))
    })?;
    let mut data = Vec::new();
    entry.read_to_end(&mut data).map_err(|error| {
        VaultError::Invalid(format!("`{entry_name}` could not be read: {error}"))
    })?;
    let value: Value = serde_json::from_slice(&data).map_err(|error| {
        VaultError::Invalid(format!("`export.data` is not valid JSON: {error}"))
    })?;
    let accounts = value
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(|| VaultError::Invalid("`export.data` has no `accounts` array".into()))?;

    let mut parsed = Parsed::default();
    let mut row = 0;
    for account in accounts {
        let Some(vaults) = account.get("vaults").and_then(Value::as_array) else {
            continue;
        };
        for vault in vaults {
            let Some(items) = vault.get("items").and_then(Value::as_array) else {
                continue;
            };
            for item in items {
                row += 1;
                match one_password_to_item(item) {
                    Ok(Some(item)) => parsed.items.push(ParsedItem { row, item }),
                    Ok(None) => parsed.skipped += 1,
                    Err(reason) => parsed.failed.push(ImportFailure { row, reason }),
                }
            }
        }
    }
    Ok(parsed)
}

/// Map one 1Password item. `Ok(None)` means the entry is `null` and carries
/// nothing; a shape error is reported for that row only.
fn one_password_to_item(value: &Value) -> Result<Option<Item>, String> {
    if value.is_null() {
        return Ok(None);
    }
    let object = value
        .as_object()
        .ok_or_else(|| "entry is not a 1Password item object".to_string())?;

    let (title, notes) = pux_title_notes(value);
    let category = string_at(value, &["categoryUuid"])
        .or_else(|| string_at(value, &["category"]))
        .or_else(|| string_at(value, &["typeName"]))
        .map(|raw| one_password_category(&raw))
        .unwrap_or(Category::Login);

    // Login fields always precede section fields: that is the order the 1PUX
    // writer emits them in, so an exported item re-imports byte-for-byte.
    let mut fields = pux_login_fields(object);
    pux_section_fields(object, &mut fields);

    let favorite = object
        .get("favIndex")
        .and_then(Value::as_i64)
        .is_some_and(|index| index > 0);
    let created_at = object.get("createdAt").and_then(Value::as_i64);

    Ok(Some(build_item(
        title,
        category,
        fields,
        notes,
        pux_urls(object),
        pux_tags(object),
        favorite,
        None,
        created_at,
    )))
}

fn pux_title_notes(value: &Value) -> (String, String) {
    let title = string_at(value, &["overview", "title"])
        .or_else(|| string_at(value, &["title"]))
        .unwrap_or_default();
    let notes = string_at(value, &["details", "notesPlain"])
        .or_else(|| string_at(value, &["notesPlain"]))
        .unwrap_or_default();
    (title, notes)
}

/// The primary url first, then the extra urls, without duplicates. Empty urls
/// are dropped so the item never carries a blank entry.
fn pux_urls(object: &Map<String, Value>) -> Vec<String> {
    let mut urls: Vec<String> = Vec::new();
    if let Some(overview) = object.get("overview") {
        if let Some(primary) = overview.get("url").and_then(Value::as_str) {
            push_unique(&mut urls, primary);
        }
        if let Some(list) = overview.get("urls").and_then(Value::as_array) {
            for entry in list {
                if let Some(url) = entry.get("url").and_then(Value::as_str) {
                    push_unique(&mut urls, url);
                }
            }
        }
    }
    urls
}

/// Tags are either plain strings or `{ "tag": ... }` objects, depending on the
/// 1Password version that wrote the archive.
fn pux_tags(object: &Map<String, Value>) -> Vec<String> {
    object
        .get("overview")
        .and_then(|overview| overview.get("tags"))
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|tag| match tag {
                    Value::String(text) => Some(text.clone()),
                    Value::Object(_) => tag
                        .get("tag")
                        .or_else(|| tag.get("name"))
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    _ => None,
                })
                .filter(|tag| !tag.trim().is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn pux_login_fields(object: &Map<String, Value>) -> Vec<Field> {
    let Some(login_fields) = object
        .get("details")
        .and_then(|details| details.get("loginFields"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    login_fields
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            let value = entry.get("value").and_then(value_as_string)?;
            if value.is_empty() {
                return None;
            }
            let designation = entry
                .get("designation")
                .and_then(Value::as_str)
                .unwrap_or("");
            let kind = match designation {
                "username" => "username",
                "password" => "password",
                _ => "text",
            };
            let label = match designation {
                "username" => "username".to_string(),
                "password" => "password".to_string(),
                _ => entry
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("field {}", index + 1)),
            };
            Some(field(
                &label,
                kind,
                &value,
                kind == "password" || entry.get("fieldType").and_then(Value::as_str) == Some("P"),
            ))
        })
        .collect()
}

fn pux_section_fields(object: &Map<String, Value>, fields: &mut Vec<Field>) {
    let Some(sections) = object
        .get("details")
        .and_then(|details| details.get("sections"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for section in sections {
        let Some(entries) = section.get("fields").and_then(Value::as_array) else {
            continue;
        };
        for (index, entry) in entries.iter().enumerate() {
            let Some(value) = entry.get("value").and_then(value_as_string) else {
                continue;
            };
            if value.is_empty() {
                continue;
            }
            let label = entry
                .get("title")
                .and_then(Value::as_str)
                .filter(|title| !title.trim().is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("field {}", index + 1));
            let concealed = entry
                .get("value")
                .and_then(|value| value.get("concealed"))
                .is_some();
            let sensitive = entry
                .get("guarded")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || concealed;
            fields.push(field(
                &label,
                if sensitive { "password" } else { "text" },
                &value,
                sensitive,
            ));
        }
    }
}

pub(super) fn one_password_item(item: &Item) -> Value {
    let login_fields: Vec<Value> = item
        .fields
        .iter()
        .filter(|field| field.kind == "username" || field.kind == "password")
        .map(|field| {
            json!({
                "id": field.id,
                "name": field.label,
                "designation": field.kind,
                "fieldType": if field.kind == "password" { "P" } else { "T" },
                "value": field.value,
            })
        })
        .collect();
    let section_fields: Vec<Value> = item
        .fields
        .iter()
        .filter(|field| field.kind != "username" && field.kind != "password")
        .map(|field| {
            json!({
                "id": field.id,
                "title": field.label,
                "value": { "string": field.value },
                "guarded": field.sensitive,
                "inputTraits": { "keyboard": "default" },
            })
        })
        .collect();
    let urls: Vec<Value> = item
        .urls
        .iter()
        .map(|url| json!({ "label": "website", "url": url }))
        .collect();

    json!({
        "uuid": item.id,
        "favIndex": if item.favorite { 1 } else { 0 },
        "createdAt": item.created_at,
        "updatedAt": item.updated_at,
        "state": "active",
        "categoryUuid": category_uuid(item.category),
        "overview": {
            "title": item.title,
            "url": item.urls.first().cloned().unwrap_or_default(),
            "urls": urls,
            "tags": item.tags,
        },
        "details": {
            "loginFields": login_fields,
            "notesPlain": item.notes,
            "sections": [{ "title": "", "name": "section", "fields": section_fields }],
        },
    })
}

/// 1Password's published category codes, plus the codes Kestrel writes for
/// categories 1Password has no public code for.
fn category_uuid(category: Category) -> &'static str {
    match category {
        Category::Login => "001",
        Category::CreditCard => "002",
        Category::SecureNote => "003",
        Category::Identity => "004",
        Category::Password => "005",
        Category::Document => "006",
        Category::SoftwareLicense => "100",
        Category::BankAccount => "101",
        Category::Database => "102",
        Category::DriverLicense => "103",
        Category::Membership => "105",
        Category::Passport => "106",
        Category::WirelessRouter => "109",
        Category::Server => "110",
        Category::CryptoWallet => "111",
        Category::ApiCredential => "112",
        Category::MedicalRecord => "113",
        Category::SshKey => "114",
    }
}

fn one_password_category(raw: &str) -> Category {
    match raw.trim() {
        "001" => Category::Login,
        "002" => Category::CreditCard,
        "003" => Category::SecureNote,
        "004" => Category::Identity,
        "005" => Category::Password,
        "006" => Category::Document,
        "100" => Category::SoftwareLicense,
        "101" => Category::BankAccount,
        "102" => Category::Database,
        "103" => Category::DriverLicense,
        "105" | "107" => Category::Membership,
        "106" => Category::Passport,
        "108" => Category::Identity,
        "109" => Category::WirelessRouter,
        "110" => Category::Server,
        "111" => Category::CryptoWallet,
        "112" => Category::ApiCredential,
        "113" => Category::MedicalRecord,
        "114" => Category::SshKey,
        other => category_from(other),
    }
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(key)?;
    }
    current.as_str().map(str::to_string)
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        Value::Object(map) => [
            "string",
            "concealed",
            "totp",
            "email",
            "url",
            "phone",
            "date",
            "monthYear",
            "creditCardNumber",
            "menu",
        ]
        .iter()
        .find_map(|key| map.get(*key).and_then(Value::as_str).map(str::to_string)),
        _ => None,
    }
}

fn push_unique(urls: &mut Vec<String>, url: &str) {
    let url = url.trim();
    if !url.is_empty() && !urls.iter().any(|existing| existing == url) {
        urls.push(url.to_string());
    }
}
