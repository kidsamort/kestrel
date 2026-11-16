//! Item construction and small parsing helpers shared by every format.

use crate::model::{Category, Field, Item};
use crate::session::VaultError;

/// Build the stored [`Item`] from a parsed row, normalising the parts every
/// format has to agree on: a blank title becomes `Untitled`, blank urls and
/// tags are dropped, and timestamps default to now.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_item(
    title: String,
    category: Category,
    fields: Vec<Field>,
    notes: String,
    urls: Vec<String>,
    tags: Vec<String>,
    favorite: bool,
    totp_secret: Option<String>,
    created_at: Option<i64>,
) -> Item {
    let now = chrono::Utc::now().timestamp();
    let title = title.trim();
    Item {
        id: new_id(),
        title: if title.is_empty() {
            "Untitled".to_string()
        } else {
            title.to_string()
        },
        category,
        fields,
        notes,
        urls: urls
            .into_iter()
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty())
            .collect(),
        tags: tags
            .into_iter()
            .map(|tag| tag.trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect(),
        favorite,
        totp_secret,
        created_at: created_at.unwrap_or(now),
        updated_at: now,
    }
}

pub(super) fn field(label: &str, kind: &str, value: &str, sensitive: bool) -> Field {
    Field {
        id: new_id(),
        label: label.to_string(),
        kind: kind.to_string(),
        value: value.to_string(),
        sensitive,
    }
}

pub(super) fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub(super) fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}

/// Decode a text export, tolerating the UTF-8 BOM that spreadsheet tools add.
pub(super) fn utf8<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str, VaultError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| VaultError::Invalid(format!("the {label} file is not valid UTF-8")))?;
    Ok(text.strip_prefix('\u{feff}').unwrap_or(text))
}

pub(super) fn category_from(raw: &str) -> Category {
    let compact: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect();
    match compact.as_str() {
        "login" | "logins" => Category::Login,
        "password" | "passwords" => Category::Password,
        "creditcard" | "creditcards" | "card" => Category::CreditCard,
        "identity" | "identities" => Category::Identity,
        "securenote" | "securenotes" | "note" | "notes" => Category::SecureNote,
        "document" | "documents" => Category::Document,
        "sshkey" | "sshkeys" => Category::SshKey,
        "server" | "servers" => Category::Server,
        "database" | "databases" => Category::Database,
        "bankaccount" | "bankaccounts" => Category::BankAccount,
        "cryptowallet" | "cryptowallets" | "wallet" => Category::CryptoWallet,
        "driverlicense" | "driverslicense" | "driverlicence" => Category::DriverLicense,
        "passport" | "passports" => Category::Passport,
        "membership" | "memberships" => Category::Membership,
        "medicalrecord" | "medicalrecords" | "medical" => Category::MedicalRecord,
        "softwarelicense" | "softwarelicenses" | "license" | "licenses" => {
            Category::SoftwareLicense
        }
        "apicredential" | "apicredentials" | "api" => Category::ApiCredential,
        "wirelessrouter" | "wirelessrouters" | "router" => Category::WirelessRouter,
        _ => Category::from_str(raw),
    }
}
