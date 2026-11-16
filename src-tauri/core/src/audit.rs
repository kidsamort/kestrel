//! Security audit: weak, reused, and breached passwords, plus credentials whose
//! expiry date is near or past.
//!
//! Everything happens inside the core. The renderer receives item ids, field
//! ids, labels and prose details — never a password value. Breach checks are
//! the only network call in the vault, and they are k-anonymous: only the
//! first five characters of a SHA-1 hash leave this process.

use crate::model::{Category, Field, Item};
use crate::session::{VaultError, VaultState};
use chrono::{Local, NaiveDate};
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::time::Duration;

const HIBP_RANGE_URL: &str = "https://api.pwnedpasswords.com/range";
const MIN_LENGTH: usize = 12;
const MIN_CLASSES: usize = 3;
/// A `date` field this close to its expiry is reported as `expiring`.
const EXPIRING_WINDOW_DAYS: i64 = 30;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuditFinding {
    pub item_id: String,
    pub title: String,
    pub field_id: String,
    pub field_label: String,
    pub kind: String,
    pub detail: String,
    /// Expiry findings only: the stored date normalised to `YYYY-MM-DD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// Expiry findings only: whole days from today to that date, negative
    /// once it has passed. Computed here so the renderer needs no clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_until: Option<i64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuditReport {
    pub weak: usize,
    pub reused: usize,
    pub breached: usize,
    pub expiring: usize,
    pub expired: usize,
    pub findings: Vec<AuditFinding>,
    pub breach_checked: bool,
    pub breach_note: Option<String>,
}

/// One password-shaped field, detached from the decrypted item so the session
/// lock can be released before any network work starts.
struct PasswordEntry {
    item_id: String,
    title: String,
    field_id: String,
    field_label: String,
    value: String,
}

impl VaultState {
    /// Offline audit: weak and reused passwords, plus expiring credentials.
    /// Breaches are recorded as unchecked so the UI can offer the explicit
    /// network action.
    pub fn audit_report(&self) -> Result<AuditReport, VaultError> {
        self.touch();
        let (entries, mut findings) = self.audit_entries(Local::now().date_naive())?;
        let (offline, _) = offline_findings(&entries);
        findings.extend(offline);
        sort_findings(&mut findings);
        Ok(report_from(findings, false, None))
    }

    /// Offline audit plus a k-anonymised Have I Been Pwned range check.
    ///
    /// A network or TLS failure never fails the command: the offline findings
    /// stand and `breach_checked` stays false with a short note.
    pub fn audit_check_breaches(&self) -> Result<AuditReport, VaultError> {
        self.touch();
        let (entries, mut findings) = self.audit_entries(Local::now().date_naive())?;
        let (offline, usage) = offline_findings(&entries);
        findings.extend(offline);

        let unique: Vec<&str> = usage.keys().map(String::as_str).collect();
        let (hits, checked) = if unique.is_empty() {
            (HashMap::new(), true)
        } else {
            check_breaches(&unique)
        };

        for entry in &entries {
            if let Some(times) = hits.get(entry.value.as_str()) {
                findings.push(AuditFinding {
                    item_id: entry.item_id.clone(),
                    title: entry.title.clone(),
                    field_id: entry.field_id.clone(),
                    field_label: entry.field_label.clone(),
                    kind: "breached".into(),
                    detail: format!("seen {times} times in breach data"),
                    date: None,
                    days_until: None,
                });
            }
        }

        sort_findings(&mut findings);
        let note = if checked {
            None
        } else {
            Some("Offline — reuse and strength are still checked.".to_string())
        };
        Ok(report_from(findings, checked, note))
    }

    /// Decrypt live items once and collect both password entries and expiry
    /// findings, so one audit pass never reads the vault twice.
    fn audit_entries(
        &self,
        today: NaiveDate,
    ) -> Result<(Vec<PasswordEntry>, Vec<AuditFinding>), VaultError> {
        self.with_session(|store, master, meta| {
            let mut passwords = Vec::new();
            let mut expiry = Vec::new();
            for (item, deleted_at) in store.load_rows(master, meta)? {
                if deleted_at.is_some() {
                    continue;
                }
                for field in &item.fields {
                    if is_password_field(&item, field) && !field.value.is_empty() {
                        passwords.push(PasswordEntry {
                            item_id: item.id.clone(),
                            title: item.title.clone(),
                            field_id: field.id.clone(),
                            field_label: field.label.clone(),
                            value: field.value.clone(),
                        });
                    }
                    if let Some(finding) = expiry_finding(&item, field, today) {
                        expiry.push(finding);
                    }
                }
            }
            Ok((passwords, expiry))
        })
    }
}

/// `password` fields everywhere, plus credential secrets (`apiSecret`, and
/// `token` on API credential items). Other sensitive fields — card numbers,
/// private keys — are not passwords and are deliberately out of scope.
fn is_password_field(item: &Item, field: &Field) -> bool {
    match field.kind.as_str() {
        "password" | "apiSecret" => true,
        "token" => item.category == Category::ApiCredential,
        _ => false,
    }
}

/// A credential date: a `date` field whose label talks about expiry. Parsing is
/// strict enough that an empty or free-form value yields no finding at all — a
/// false "expired" on a field that never held a date would train people to
/// ignore the report.
fn expiry_finding(item: &Item, field: &Field, today: NaiveDate) -> Option<AuditFinding> {
    if field.kind != "date" || !label_mentions_expiry(&field.label) {
        return None;
    }
    let date = parse_date(&field.value)?;
    let days_until = date.signed_duration_since(today).num_days();
    let (kind, detail) = if days_until < 0 {
        ("expired", format!("expired on {date}"))
    } else if days_until <= EXPIRING_WINDOW_DAYS {
        ("expiring", format!("expires on {date}"))
    } else {
        return None;
    };
    Some(AuditFinding {
        item_id: item.id.clone(),
        title: item.title.clone(),
        field_id: field.id.clone(),
        field_label: field.label.clone(),
        kind: kind.into(),
        detail,
        date: Some(date.to_string()),
        days_until: Some(days_until),
    })
}

/// Label matching is intentionally broad (`expiry`, `expires at`,
/// `expiration date` all match) and case-insensitive.
fn label_mentions_expiry(label: &str) -> bool {
    label.to_lowercase().contains("expir")
}

/// `YYYY-MM-DD`, plus the date half of an ISO timestamp
/// (`2026-11-25T09:00:00Z`) that some imports carry. Anything else is
/// unparseable and skipped.
fn parse_date(value: &str) -> Option<NaiveDate> {
    let date_part = value.trim().split(['T', ' ']).next()?;
    NaiveDate::parse_from_str(date_part, "%Y-%m-%d").ok()
}

fn char_classes(value: &str) -> usize {
    let mut lower = false;
    let mut upper = false;
    let mut digit = false;
    let mut symbol = false;
    for ch in value.chars() {
        if ch.is_lowercase() {
            lower = true;
        } else if ch.is_uppercase() {
            upper = true;
        } else if ch.is_ascii_digit() {
            digit = true;
        } else {
            symbol = true;
        }
    }
    [lower, upper, digit, symbol]
        .into_iter()
        .filter(|present| *present)
        .count()
}

fn class_word(count: usize) -> &'static str {
    match count {
        0 => "no",
        1 => "one",
        2 => "two",
        3 => "three",
        _ => "four",
    }
}

/// `Some(detail)` when the value is weak, with a prose explanation.
fn weakness(value: &str) -> Option<String> {
    let length = value.chars().count();
    let classes = char_classes(value);
    if length >= MIN_LENGTH && classes >= MIN_CLASSES {
        return None;
    }
    let length_word = if length == 1 {
        "character"
    } else {
        "characters"
    };
    let class_word_text = if classes == 1 { "class" } else { "classes" };
    Some(format!(
        "{length} {length_word}, {} character {class_word_text}",
        class_word(classes)
    ))
}

/// Offline findings, plus how many distinct items each value appears in.
fn offline_findings(entries: &[PasswordEntry]) -> (Vec<AuditFinding>, HashMap<String, usize>) {
    let mut items_by_value: HashMap<&str, HashSet<&str>> = HashMap::new();
    for entry in entries {
        items_by_value
            .entry(entry.value.as_str())
            .or_default()
            .insert(entry.item_id.as_str());
    }
    let usage: HashMap<String, usize> = items_by_value
        .iter()
        .map(|(value, items)| ((*value).to_string(), items.len()))
        .collect();

    let mut findings = Vec::new();
    for entry in entries {
        if let Some(detail) = weakness(&entry.value) {
            findings.push(finding(entry, "weak", detail));
        }
        if let Some(count) = usage.get(entry.value.as_str()).filter(|n| **n >= 2) {
            findings.push(finding(entry, "reused", format!("used in {count} items")));
        }
    }
    (findings, usage)
}

fn finding(entry: &PasswordEntry, kind: &str, detail: String) -> AuditFinding {
    AuditFinding {
        item_id: entry.item_id.clone(),
        title: entry.title.clone(),
        field_id: entry.field_id.clone(),
        field_label: entry.field_label.clone(),
        kind: kind.into(),
        detail,
        date: None,
        days_until: None,
    }
}

fn report_from(
    findings: Vec<AuditFinding>,
    breach_checked: bool,
    breach_note: Option<String>,
) -> AuditReport {
    let count = |kind: &str| findings.iter().filter(|f| f.kind == kind).count();
    AuditReport {
        weak: count("weak"),
        reused: count("reused"),
        breached: count("breached"),
        expiring: count("expiring"),
        expired: count("expired"),
        findings,
        breach_checked,
        breach_note,
    }
}

fn kind_rank(kind: &str) -> u8 {
    match kind {
        "breached" => 0,
        "reused" => 1,
        "expired" => 3,
        "expiring" => 4,
        _ => 2,
    }
}

fn sort_findings(findings: &mut [AuditFinding]) {
    findings.sort_by(|a, b| {
        kind_rank(&a.kind)
            .cmp(&kind_rank(&b.kind))
            .then_with(|| match a.kind.as_str() {
                "expired" | "expiring" => a
                    .days_until
                    .unwrap_or(i64::MAX)
                    .cmp(&b.days_until.unwrap_or(i64::MAX)),
                _ => Ordering::Equal,
            })
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
            .then_with(|| a.field_label.cmp(&b.field_label))
            .then_with(|| a.item_id.cmp(&b.item_id))
    });
}

/// SHA-1 is required by the range API; it is a lookup index here, never a
/// security primitive. The digest never leaves this function whole.
fn sha1_upper(value: &str) -> String {
    let digest = Sha1::digest(value.as_bytes());
    let mut out = String::with_capacity(40);
    for byte in digest {
        let _ = write!(out, "{byte:02X}");
    }
    out
}

/// Distinct password values → times seen in breach data. `false` means at
/// least one range could not be fetched, so the check is incomplete.
fn check_breaches(values: &[&str]) -> (HashMap<String, u64>, bool) {
    let agent = ureq::AgentBuilder::new()
        .user_agent(concat!("Kestrel/", env!("CARGO_PKG_VERSION")))
        .timeout_connect(Duration::from_secs(4))
        .timeout(Duration::from_secs(8))
        .build();

    let mut by_prefix: HashMap<String, Vec<(&str, String)>> = HashMap::new();
    for value in values {
        let hash = sha1_upper(value);
        let (prefix, suffix) = hash.split_at(5);
        by_prefix
            .entry(prefix.to_string())
            .or_default()
            .push((value, suffix.to_string()));
    }

    let mut hits = HashMap::new();
    for (prefix, group) in by_prefix {
        let range = match fetch_range(&agent, &prefix) {
            Ok(range) => range,
            Err(_) => return (hits, false),
        };
        for (value, suffix) in group {
            if let Some(times) = range.get(&suffix) {
                hits.insert(value.to_string(), *times);
            }
        }
    }
    (hits, true)
}

fn fetch_range(agent: &ureq::Agent, prefix: &str) -> Result<HashMap<String, u64>, String> {
    let url = format!("{HIBP_RANGE_URL}/{prefix}");
    let response = match agent.get(&url).set("Add-Padding", "true").call() {
        Ok(response) => response,
        Err(ureq::Error::Status(code, _)) => return Err(format!("status {code}")),
        Err(ureq::Error::Transport(err)) => return Err(err.to_string()),
    };
    if response.status() != 200 {
        return Err(format!("status {}", response.status()));
    }
    let body = response.into_string().map_err(|err| err.to_string())?;
    Ok(parse_range(&body))
}

/// Parse `SUFFIX:COUNT` lines. Padding rows have a zero count and are dropped,
/// so a padded range cannot produce a false positive.
fn parse_range(body: &str) -> HashMap<String, u64> {
    let mut map = HashMap::new();
    for line in body.lines() {
        let Some((suffix, count)) = line.trim().split_once(':') else {
            continue;
        };
        let suffix = suffix.trim().to_ascii_uppercase();
        if suffix.len() != 35 || !suffix.chars().all(|ch| ch.is_ascii_hexdigit()) {
            continue;
        }
        let Ok(count) = count.trim().parse::<u64>() else {
            continue;
        };
        if count == 0 {
            continue;
        }
        map.insert(suffix, count);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const MATCH: &str = "00D4F6E8FA6EECAD2A3AA415EEC418D38EC";
    const PADDING: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn synthetic_body() -> String {
        format!(
            "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
             {MATCH}:42\r\n\
             {PADDING}:0\r\n\
             not-a-line\r\n\
             1234:9\r\n\
             FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3\r\n"
        )
    }

    #[test]
    fn range_parser_matches_case_insensitively() {
        let upper = parse_range(&synthetic_body());
        assert_eq!(
            upper.get(MATCH).copied(),
            Some(42),
            "the suffix in the body must be found"
        );

        let lower_body = format!("{}:42\r\n", MATCH.to_ascii_lowercase());
        let lower = parse_range(&lower_body);
        assert_eq!(
            lower.get(MATCH).copied(),
            Some(42),
            "a lower-case response suffix normalises to upper case"
        );
    }

    #[test]
    fn range_parser_skips_padding_and_malformed_rows() {
        let range = parse_range(&synthetic_body());
        assert!(
            !range.contains_key(PADDING),
            "zero-count padding is ignored"
        );
        assert_eq!(range.len(), 3, "malformed rows are not stored: {range:?}");
    }

    #[test]
    fn range_parser_returns_none_for_unknown_suffix() {
        let suffix = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        assert!(!parse_range(&synthetic_body()).contains_key(suffix));
    }

    #[test]
    fn character_classes_counts_lower_upper_digit_symbol() {
        assert_eq!(char_classes("abc"), 1);
        assert_eq!(char_classes("aB3!"), 4);
        assert_eq!(char_classes(""), 0);
        assert_eq!(char_classes("123"), 1);
    }

    #[test]
    fn weakness_flags_short_or_simple_values() {
        assert!(weakness("Ab3$xy").is_some(), "six characters is short");
        assert!(
            weakness("alllowercaseletters").is_some(),
            "one class is weak even at length"
        );
        assert!(
            weakness("Abcdefghijkl1").is_none(),
            "three classes, 13 chars"
        );
        assert!(weakness("correct-horse-battery-9").is_none());
    }

    #[test]
    fn expiry_dates_parse_date_only_and_iso_timestamp() {
        let expected = NaiveDate::from_ymd_opt(2026, 11, 25);
        assert_eq!(parse_date("2026-11-25"), expected);
        assert_eq!(parse_date(" 2026-11-25T09:30:00Z "), expected);
        assert_eq!(parse_date("2026-11-25 09:30"), expected);
        assert_eq!(parse_date(""), None);
        assert_eq!(parse_date("   "), None);
        assert_eq!(parse_date("not-a-date"), None);
    }

    #[test]
    fn sha1_prefix_is_forty_uppercase_hex_chars() {
        let hash = sha1_upper("password");
        assert_eq!(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(hash.split_at(5).0, "5BAA6");
    }
}
