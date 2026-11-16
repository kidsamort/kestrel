//! Audit behaviour: what the core counts, what it refuses to serialize,
//! and how findings are described.

use chrono::{Duration, Local};
use kestrel_core::model::{Category, Field, Item};
use kestrel_core::session::VaultState;

const PW: &str = "correct horse battery staple";

/// A calendar date `offset` days from today, formatted as the editor stores it.
fn day(offset: i64) -> String {
    (Local::now().date_naive() + Duration::days(offset)).to_string()
}

fn date_field(id: &str, label: &str, value: &str) -> Field {
    Field {
        id: id.into(),
        label: label.into(),
        kind: "date".into(),
        value: value.into(),
        sensitive: false,
    }
}

fn passport_with_expiry(label: &str, value: &str) -> Item {
    let mut item = Item::new(Category::Passport, "Passport".into());
    item.fields.push(date_field("expiry-field", label, value));
    item
}

fn scratch() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

fn unlocked() -> (tempfile::TempDir, VaultState) {
    let (dir, path) = scratch();
    let state = VaultState::open(path).unwrap();
    state.create(PW).unwrap();
    (dir, state)
}

fn with_password(category: Category, title: &str, password: &str) -> Item {
    let mut item = Item::new(category, title.into());
    let field = item
        .fields
        .iter_mut()
        .find(|field| field.kind == "password")
        .expect("category has a password field");
    field.value = password.into();
    item
}

#[test]
fn short_password_is_reported_weak() {
    let (_dir, state) = unlocked();
    state
        .save(with_password(Category::Password, "Router", "Ab3$xy"))
        .unwrap();

    let report = state.audit_report().unwrap();
    assert_eq!(report.weak, 1);
    assert_eq!(report.reused, 0);
    assert_eq!(report.breached, 0);
    assert!(!report.breach_checked, "audit_report is offline only");
    assert!(report.breach_note.is_none());

    let finding = &report.findings[0];
    assert_eq!(finding.kind, "weak");
    assert_eq!(finding.title, "Router");
    assert_eq!(finding.field_label, "password");
    assert!(!finding.field_id.is_empty());
    assert!(
        finding.detail.contains("6 characters"),
        "detail describes the length: {}",
        finding.detail
    );
    assert!(
        finding.detail.contains("four character classes"),
        "six-character value uses four classes: {}",
        finding.detail
    );
    assert!(
        !finding.detail.contains("Ab3$xy"),
        "no secret in the detail"
    );
}

#[test]
fn reuse_across_two_items_yields_two_findings_with_one_count() {
    let (_dir, state) = unlocked();
    let shared = "Run-away-pony-55!";
    let first = state
        .save(with_password(Category::Login, "Mail", shared))
        .unwrap();
    let second = state
        .save(with_password(Category::Login, "Bank", shared))
        .unwrap();

    let report = state.audit_report().unwrap();
    assert_eq!(report.reused, 2);
    assert_eq!(report.weak, 0, "the shared value is strong");
    assert_eq!(report.findings.len(), 2);
    assert!(report.findings.iter().all(|f| f.kind == "reused"));
    assert!(report
        .findings
        .iter()
        .all(|f| f.detail == "used in 2 items"));

    let ids: Vec<&str> = report.findings.iter().map(|f| f.item_id.as_str()).collect();
    assert!(ids.contains(&first.id.as_str()));
    assert!(ids.contains(&second.id.as_str()));
}

#[test]
fn strong_unique_password_produces_no_findings() {
    let (_dir, state) = unlocked();
    state
        .save(with_password(
            Category::Password,
            "Unique",
            "Zx9!long-unique-secret",
        ))
        .unwrap();

    let report = state.audit_report().unwrap();
    assert_eq!(report.weak, 0);
    assert_eq!(report.reused, 0);
    assert_eq!(report.breached, 0);
    assert!(report.findings.is_empty());
}

#[test]
fn serialized_report_never_contains_the_password_text() {
    let (_dir, state) = unlocked();
    let secret = "Very-Secret-Value-9876";
    state
        .save(with_password(Category::Login, "Portal", secret))
        .unwrap();
    state
        .save(with_password(Category::Login, "Portal copy", secret))
        .unwrap();

    let report = state.audit_report().unwrap();
    assert_eq!(report.reused, 2);
    let json = serde_json::to_string(&report).unwrap();
    assert!(
        !json.contains(secret),
        "serialized audit report leaked the password: {json}"
    );
    assert!(json.contains("\"breachChecked\":false"), "{json}");
    assert!(json.contains("\"detail\":\"used in 2 items\""), "{json}");
}

#[test]
fn findings_sort_reused_before_weak_then_by_title() {
    let (_dir, state) = unlocked();
    let shared = "short";
    state
        .save(with_password(Category::Password, "Zeta", shared))
        .unwrap();
    state
        .save(with_password(Category::Password, "Alpha", shared))
        .unwrap();

    let report = state.audit_report().unwrap();
    let kinds: Vec<&str> = report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert_eq!(kinds, vec!["reused", "reused", "weak", "weak"]);
    let reused_titles: Vec<&str> = report.findings[..2]
        .iter()
        .map(|f| f.title.as_str())
        .collect();
    assert_eq!(reused_titles, vec!["Alpha", "Zeta"]);
}

#[test]
fn api_credential_secrets_are_audited() {
    let (_dir, state) = unlocked();
    let mut item = Item::new(Category::ApiCredential, "Billing API".into());
    item.fields
        .iter_mut()
        .find(|field| field.kind == "apiSecret")
        .expect("api credential has a secret field")
        .value = "abc".into();
    state.save(item).unwrap();

    let report = state.audit_report().unwrap();
    assert_eq!(report.weak, 1);
    assert_eq!(report.findings[0].field_label, "client secret");
    assert_eq!(report.findings[0].kind, "weak");
}

#[test]
fn locked_vault_refuses_to_audit() {
    let (_dir, state) = unlocked();
    state
        .save(with_password(Category::Password, "Router", "Ab3$xy"))
        .unwrap();
    state.lock().unwrap();

    let error = state.audit_report().unwrap_err();
    assert!(error.to_string().contains("locked"), "{error}");
}

#[test]
fn date_in_ten_days_is_expiring() {
    let (_dir, state) = unlocked();
    let expires = day(10);
    let item = state
        .save(passport_with_expiry("expires at", &expires))
        .unwrap();

    let report = state.audit_report().unwrap();
    assert_eq!(report.expiring, 1);
    assert_eq!(report.expired, 0);
    assert_eq!(report.weak, 0, "the passport holds no password field");

    let finding = report
        .findings
        .iter()
        .find(|f| f.kind == "expiring")
        .expect("the near-date field is reported");
    assert_eq!(finding.item_id, item.id);
    assert_eq!(finding.title, "Passport");
    assert_eq!(finding.field_id, "expiry-field");
    assert_eq!(finding.field_label, "expires at");
    assert_eq!(finding.date.as_deref(), Some(expires.as_str()));
    assert_eq!(finding.days_until, Some(10));
    assert_eq!(finding.detail, format!("expires on {expires}"));
}

#[test]
fn yesterday_is_expired() {
    let (_dir, state) = unlocked();
    let expires = day(-1);
    let item = state
        .save(passport_with_expiry("expiry", &expires))
        .unwrap();

    let report = state.audit_report().unwrap();
    assert_eq!(report.expired, 1);
    assert_eq!(report.expiring, 0);
    assert_eq!(report.findings[0].kind, "expired");
    assert_eq!(report.findings[0].item_id, item.id);
    assert_eq!(report.findings[0].field_label, "expiry");
    assert_eq!(report.findings[0].date.as_deref(), Some(expires.as_str()));
    assert_eq!(report.findings[0].days_until, Some(-1));
    assert_eq!(report.findings[0].detail, format!("expired on {expires}"));
}

#[test]
fn date_beyond_the_window_is_not_reported() {
    let (_dir, state) = unlocked();
    state
        .save(passport_with_expiry("expires at", &day(60)))
        .unwrap();

    let report = state.audit_report().unwrap();
    assert_eq!(report.expiring, 0);
    assert_eq!(report.expired, 0);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn the_thirtieth_day_is_inside_the_window_but_the_thirty_first_is_not() {
    let (_dir, state) = unlocked();
    state
        .save(passport_with_expiry("expires at", &day(30)))
        .unwrap();
    assert_eq!(state.audit_report().unwrap().expiring, 1);

    let (_dir, state) = unlocked();
    state
        .save(passport_with_expiry("expires at", &day(31)))
        .unwrap();
    assert_eq!(state.audit_report().unwrap().expiring, 0);
}

#[test]
fn empty_and_malformed_dates_are_skipped() {
    let (_dir, state) = unlocked();
    let mut blank = passport_with_expiry("expires at", "");
    blank.title = "Blank date".into();
    state.save(blank).unwrap();
    let mut garbage = passport_with_expiry("expiry", "not-a-date");
    garbage.title = "Garbage date".into();
    state.save(garbage).unwrap();

    let report = state.audit_report().unwrap();
    assert_eq!(report.expired, 0, "an empty date is never expired");
    assert_eq!(report.expiring, 0);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn non_expiry_date_field_is_ignored() {
    let (_dir, state) = unlocked();
    let mut item = Item::new(Category::Identity, "Me".into());
    item.fields
        .push(date_field("dob", "date of birth", "1990-04-12"));
    state.save(item).unwrap();

    let report = state.audit_report().unwrap();
    assert_eq!(report.expiring, 0);
    assert_eq!(report.expired, 0);
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn expired_findings_sort_before_expiring_ones() {
    let (_dir, state) = unlocked();
    let mut old = passport_with_expiry("expires at", &day(-3));
    old.title = "Old passport".into();
    state.save(old).unwrap();
    let mut soon = passport_with_expiry("expires at", &day(2));
    soon.title = "New passport".into();
    state.save(soon).unwrap();

    let report = state.audit_report().unwrap();
    let kinds: Vec<&str> = report.findings.iter().map(|f| f.kind.as_str()).collect();
    assert_eq!(kinds, vec!["expired", "expiring"]);
    let days: Vec<i64> = report
        .findings
        .iter()
        .map(|f| f.days_until.expect("expiry findings carry daysUntil"))
        .collect();
    assert_eq!(days, vec![-3, 2]);
}

#[test]
fn serialized_expiry_finding_carries_the_date_but_password_findings_do_not() {
    let (_dir, state) = unlocked();
    let expires = day(10);
    state
        .save(passport_with_expiry("expires at", &expires))
        .unwrap();
    state
        .save(with_password(Category::Password, "Router", "Ab3$xy"))
        .unwrap();

    let report = state.audit_report().unwrap();
    let json = serde_json::to_string(&report).unwrap();
    assert!(
        json.contains(&format!("\"date\":\"{expires}\"")),
        "the parsed date is serialized: {json}"
    );
    assert!(json.contains("\"daysUntil\":10"), "{json}");
    assert!(json.contains("\"expiring\":1"), "{json}");
    assert!(json.contains("\"expired\":0"), "{json}");

    let password_json = serde_json::to_string(
        report
            .findings
            .iter()
            .find(|f| f.kind == "weak")
            .expect("the weak password is still reported"),
    )
    .unwrap();
    assert!(
        !password_json.contains("daysUntil"),
        "password findings stay free of expiry keys: {password_json}"
    );
}
