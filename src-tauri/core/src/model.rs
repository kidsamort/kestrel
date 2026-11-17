//! Vault data model.
//!
//! Item shape is a small typed header plus an ordered list of fields: enough to
//! describe every category, small enough that a new category needs no table. Keeping fields generic
//! is what lets one editor serve every category without per-category code.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Category {
    Login,
    Password,
    CreditCard,
    Identity,
    SecureNote,
    Document,
    SshKey,
    Server,
    Database,
    BankAccount,
    CryptoWallet,
    DriverLicense,
    Passport,
    Membership,
    MedicalRecord,
    SoftwareLicense,
    ApiCredential,
    WirelessRouter,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Login => "login",
            Category::Password => "password",
            Category::CreditCard => "creditCard",
            Category::Identity => "identity",
            Category::SecureNote => "secureNote",
            Category::Document => "document",
            Category::SshKey => "sshKey",
            Category::Server => "server",
            Category::Database => "database",
            Category::BankAccount => "bankAccount",
            Category::CryptoWallet => "cryptoWallet",
            Category::DriverLicense => "driverLicense",
            Category::Passport => "passport",
            Category::Membership => "membership",
            Category::MedicalRecord => "medicalRecord",
            Category::SoftwareLicense => "softwareLicense",
            Category::ApiCredential => "apiCredential",
            Category::WirelessRouter => "wirelessRouter",
        }
    }

    /// Lenient, infallible parse used when reading foreign exports: an unknown
    /// name falls back to `Login` instead of failing, so this is deliberately
    /// not `FromStr` (which must be able to reject input).
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(value: &str) -> Category {
        match value {
            "password" => Category::Password,
            "creditCard" => Category::CreditCard,
            "identity" => Category::Identity,
            "secureNote" => Category::SecureNote,
            "document" => Category::Document,
            "sshKey" => Category::SshKey,
            "server" => Category::Server,
            "database" => Category::Database,
            "bankAccount" => Category::BankAccount,
            "cryptoWallet" => Category::CryptoWallet,
            "driverLicense" => Category::DriverLicense,
            "passport" => Category::Passport,
            "membership" => Category::Membership,
            "medicalRecord" => Category::MedicalRecord,
            "softwareLicense" => Category::SoftwareLicense,
            "apiCredential" => Category::ApiCredential,
            "wirelessRouter" => Category::WirelessRouter,
            _ => Category::Login,
        }
    }

    pub fn default_fields(self) -> Vec<Field> {
        let f = |label: &str, kind: &str, sensitive: bool| Field {
            id: uuid::Uuid::new_v4().to_string(),
            label: label.to_string(),
            kind: kind.to_string(),
            value: String::new(),
            sensitive,
        };
        match self {
            Category::Login => vec![
                f("username", "username", false),
                f("password", "password", true),
                f("website", "url", false),
            ],
            Category::Password => vec![f("password", "password", true)],
            Category::CreditCard => vec![
                f("cardholder", "text", false),
                f("number", "creditCardNumber", true),
                f("expiry", "monthYear", false),
                f("verification number", "cvv", true),
                f("PIN", "pin", true),
            ],
            Category::Identity => vec![
                f("first name", "text", false),
                f("last name", "text", false),
                f("date of birth", "date", false),
                f("national ID number", "text", true),
            ],
            Category::SecureNote => Vec::new(),
            Category::Document => Vec::new(),
            Category::SshKey => vec![
                f("private key", "sshPrivateKey", true),
                f("public key", "sshPublicKey", false),
                f("fingerprint", "text", false),
            ],
            Category::Server => vec![
                f("hostname", "host", false),
                f("port", "port", false),
                f("username", "username", false),
                f("password", "password", true),
            ],
            Category::Database => vec![
                f("hostname", "host", false),
                f("port", "port", false),
                f("database", "text", false),
                f("username", "username", false),
                f("password", "password", true),
            ],
            Category::BankAccount => vec![
                f("account holder", "text", false),
                f("account number", "text", true),
                f("routing number", "text", true),
                f("bank name", "text", false),
            ],
            Category::CryptoWallet => vec![
                f("wallet address", "text", false),
                f("network", "text", false),
                f("derivation path", "text", false),
                f("recovery phrase", SEED_PHRASE_KIND, true),
                f("spending password", "password", true),
            ],
            Category::DriverLicense => vec![
                f("number", "text", true),
                f("license class", "text", false),
                f("expiry", "date", false),
            ],
            Category::Passport => vec![
                f("number", "text", true),
                f("issuing country", "text", false),
                f("expiry", "date", false),
            ],
            Category::Membership => vec![
                f("member number", "text", false),
                f("member name", "text", false),
            ],
            Category::MedicalRecord => vec![
                f("patient", "text", false),
                f("condition", "text", false),
                f("medication", "text", false),
            ],
            Category::SoftwareLicense => vec![
                f("license key", "text", true),
                f("registered to", "text", false),
                f("version", "text", false),
            ],
            Category::ApiCredential => vec![
                f("provider", "text", false),
                f("base url", "url", false),
                f("client id", "text", false),
                f("client secret", "apiSecret", true),
                f("token", "apiSecret", true),
                f("expires at", DATE_KIND, false),
            ],
            Category::WirelessRouter => vec![
                f("router name", "text", false),
                f("admin password", "password", true),
                f("network name", "text", false),
                f("wireless security", "text", false),
                f("wireless password", "password", true),
            ],
        }
    }
}

/// Field kind for a wallet recovery phrase / mnemonic.
///
/// Multi-line and masked in the detail pane, and **always** marked
/// `sensitive`: the search projection drops sensitive fields before reading
/// their value, so a phrase never becomes plaintext indexable text.
pub const SEED_PHRASE_KIND: &str = "seedPhrase";

/// Field kind for a single calendar date (`YYYY-MM-DD`). The renderer keeps the
/// stored string verbatim and derives an expiry hint from it; the audit rules
/// parse the same value.
pub const DATE_KIND: &str = "date";

/// Word counts a BIP-39 mnemonic can have. A phrase outside this set is still
/// stored and still copyable — the editor shows a warning, never a block.
pub const SEED_WORD_COUNTS: [usize; 5] = [12, 15, 18, 21, 24];

/// Collapse every whitespace run to one space and trim the ends, so a phrase
/// pasted with line breaks compares equal to the same phrase typed by hand.
pub fn normalize_seed_phrase(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Words in a seed phrase after [`normalize_seed_phrase`]; `0` for an empty
/// phrase rather than the one empty split the raw string would produce.
pub fn seed_word_count(value: &str) -> usize {
    normalize_seed_phrase(value)
        .split(' ')
        .filter(|word| !word.is_empty())
        .count()
}

/// Whether the phrase has a BIP-39 length. An empty phrase is fine (a field
/// that has not been filled yet must not warn); anything else that is not
/// 12/15/18/21/24 words warrants the editor's warning.
pub fn seed_word_count_ok(value: &str) -> bool {
    let count = seed_word_count(value);
    count == 0 || SEED_WORD_COUNTS.contains(&count)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub id: String,
    pub label: String,
    /// Renderer hint: `password`, `username`, `url`, `cvv`, `date`, `text`, …
    /// The two kinds with behaviour beyond display are [`SEED_PHRASE_KIND`]
    /// (masked, word-counted, never searchable) and [`DATE_KIND`] (expiry
    /// hint, audit rule).
    pub kind: String,
    pub value: String,
    pub sensitive: bool,
}

/// Item as stored inside the encrypted blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Item {
    pub id: String,
    pub title: String,
    pub category: Category,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    /// Base32 TOTP secret, stored encrypted with the item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// What the UI gets when listing: never includes secret field values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    pub id: String,
    pub title: String,
    pub category: String,
    pub username: String,
    pub url: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub has_totp: bool,
    pub updated_at: i64,
    /// Set only for trashed items, so the Trash view can show when they went.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<i64>,
}

impl Item {
    pub fn new(category: Category, title: String) -> Item {
        let now = chrono::Utc::now().timestamp();
        Item {
            id: uuid::Uuid::new_v4().to_string(),
            title,
            category,
            fields: category.default_fields(),
            notes: String::new(),
            urls: Vec::new(),
            tags: Vec::new(),
            favorite: false,
            totp_secret: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn summary(&self) -> ItemSummary {
        let field = |kind: &str| {
            self.fields
                .iter()
                .find(|f| f.kind == kind)
                .map(|f| f.value.clone())
                .unwrap_or_default()
        };
        let url = self.urls.first().cloned().unwrap_or_else(|| field("url"));
        ItemSummary {
            id: self.id.clone(),
            title: self.title.clone(),
            category: self.category.as_str().to_string(),
            username: field("username"),
            url,
            tags: self.tags.clone(),
            favorite: self.favorite,
            has_totp: self.totp_secret.as_deref().is_some_and(|s| !s.is_empty()),
            updated_at: self.updated_at,
            deleted_at: None,
        }
    }
}

/// Public metadata for one WebAuthn credential.
///
/// The private key is deliberately absent: this shape is what the detail pane
/// may see. `credential_id` is a public identifier (RFC 6749 §7.1), not a
/// secret, but it still never leaves the Rust side except as this structured
/// value for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRow {
    pub credential_id: Vec<u8>,
    pub item_uuid: String,
    pub rp_id: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// A credential row plus its opened private scalar and signature counter.
///
/// `private_key` wipes itself when dropped, so an assertion path that returns
/// early still leaves no scalar in freed memory. The `Debug` impl redacts the
/// scalar: a stray `{:?}` must never put a key in a log.
pub struct PasskeySecret {
    pub row: PasskeyRow,
    pub private_key: Vec<u8>,
    pub sign_count: u32,
}

impl std::fmt::Debug for PasskeySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeySecret")
            .field("row", &self.row)
            .field("private_key", &"<redacted>")
            .field("sign_count", &self.sign_count)
            .finish()
    }
}

impl Drop for PasskeySecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key.zeroize();
    }
}
