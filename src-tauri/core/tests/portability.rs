//! Import/export behaviour, exercised against the real core.

use kestrel_core::model::{Category, Field, Item};
use kestrel_core::session::VaultState;
use std::io::{Cursor, Read, Write};
use std::path::PathBuf;

const PW: &str = "correct horse battery staple";

fn scratch() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

fn unlocked() -> (tempfile::TempDir, VaultState) {
    let (dir, path) = scratch();
    let state = VaultState::open(path).expect("open vault");
    state.create(PW).expect("create vault");
    (dir, state)
}

fn set_field(item: &mut Item, kind: &str, value: &str) {
    let field = item
        .fields
        .iter_mut()
        .find(|field| field.kind == kind)
        .unwrap_or_else(|| panic!("no {kind} field on {}", item.title));
    field.value = value.to_string();
}

fn zip_export_data(payload: &str) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            "export.data",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .expect("start entry");
    writer.write_all(payload.as_bytes()).expect("write entry");
    writer.finish().expect("finish zip").into_inner()
}

fn read_export_data(bytes: &[u8]) -> String {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("archive opens");
    let mut entry = archive.by_name("export.data").expect("export.data entry");
    let mut text = String::new();
    entry.read_to_string(&mut text).expect("entry reads");
    text
}

#[test]
fn csv_handles_quoted_commas_and_embedded_newlines() {
    let (_dir, state) = unlocked();
    let csv = "title,category,username,password,url,notes,tags\n\
               \"Acme, Inc.\",login,alice,\"pa,ss\",\"https://acme.test\",\"line one\nline two\",work;vip\n\
               Beta,server,bob,secret,,,\n";
    let report = state.import_items("csv", csv.as_bytes().to_vec()).unwrap();
    assert_eq!(report.imported, 2, "{report:?}");
    assert_eq!(report.skipped, 0);
    assert!(report.failed.is_empty(), "{report:?}");

    let summaries = state.list("", None, false).unwrap();
    assert_eq!(summaries.len(), 2);
    let acme = summaries
        .iter()
        .find(|summary| summary.title == "Acme, Inc.")
        .expect("quoted title imported verbatim");
    let full = state.get(&acme.id).unwrap();
    assert_eq!(full.category, Category::Login);
    assert_eq!(
        full.fields
            .iter()
            .find(|field| field.kind == "password")
            .unwrap()
            .value,
        "pa,ss"
    );
    assert_eq!(full.notes, "line one\nline two");
    assert_eq!(full.urls, vec!["https://acme.test".to_string()]);
    assert_eq!(full.tags, vec!["work".to_string(), "vip".to_string()]);

    let beta = summaries
        .iter()
        .find(|summary| summary.title == "Beta")
        .expect("second row imported");
    assert_eq!(beta.category, "server");
    assert_eq!(beta.username, "bob");
}

#[test]
fn csv_export_uses_the_importer_header_and_round_trips() {
    let (_dir, state) = unlocked();
    let mut item = Item::new(Category::Login, "Round trip".to_string());
    set_field(&mut item, "username", "alice");
    set_field(&mut item, "password", "s3cret");
    item.urls = vec!["https://example.test".into()];
    item.notes = "note, with comma".into();
    item.tags = vec!["work".into(), "ops".into()];
    state.save(item).unwrap();

    let csv = state.export_items("csv", PW).unwrap();
    assert_eq!(
        csv.lines().next().unwrap(),
        "title,category,username,password,url,notes,tags"
    );
    assert!(csv.contains("\"note, with comma\""));

    let (_other_dir, target) = unlocked();
    let report = target
        .import_items("csv", csv.into_bytes())
        .expect("exported CSV imports");
    assert_eq!(report.imported, 1);
    let full = target
        .get(&target.list("", None, false).unwrap()[0].id)
        .unwrap();
    assert_eq!(full.title, "Round trip");
    assert_eq!(full.notes, "note, with comma");
    assert_eq!(full.tags, vec!["work".to_string(), "ops".to_string()]);
    assert_eq!(
        full.fields
            .iter()
            .find(|field| field.kind == "password")
            .unwrap()
            .value,
        "s3cret"
    );
}

#[test]
fn json_export_reimports_into_a_fresh_vault_with_identical_fields() {
    let (_source_dir, source) = unlocked();
    let mut login = Item::new(Category::Login, "GitHub".to_string());
    set_field(&mut login, "username", "alice");
    set_field(&mut login, "password", "s3cr3t-value");
    login.notes = "2FA enabled".into();
    login.tags = vec!["work".into()];
    login.favorite = true;

    let mut note = Item::new(Category::SecureNote, "Router".to_string());
    note.notes = "line one\nline two".into();
    note.urls = vec!["https://router.test".into()];
    note.fields.push(Field {
        id: "custom-field".into(),
        label: "PIN".into(),
        kind: "text".into(),
        value: "1234".into(),
        sensitive: true,
    });
    let original_login = source.save(login).unwrap();
    let original_note = source.save(note).unwrap();

    let json = source.export_items("json", PW).unwrap();
    let (_target_dir, target) = unlocked();
    let report = target
        .import_items("json", json.into_bytes())
        .expect("JSON exports import");
    assert_eq!(report.imported, 2, "{report:?}");
    assert_eq!(report.skipped, 0);
    assert!(report.failed.is_empty(), "{report:?}");

    let summaries = target.list("", None, false).unwrap();
    let by_title = |title: &str| {
        let summary = summaries
            .iter()
            .find(|summary| summary.title == title)
            .unwrap_or_else(|| panic!("{title} missing from {summaries:?}"));
        target.get(&summary.id).unwrap()
    };

    let imported_login = by_title("GitHub");
    assert_ne!(
        imported_login.id, original_login.id,
        "imports get fresh ids"
    );
    assert_eq!(imported_login.category, Category::Login);
    assert_eq!(imported_login.notes, "2FA enabled");
    assert_eq!(imported_login.tags, vec!["work".to_string()]);
    assert!(imported_login.favorite);
    let shape = |item: &Item| {
        let mut fields: Vec<(String, String, String, bool)> = item
            .fields
            .iter()
            .map(|field| {
                (
                    field.label.clone(),
                    field.kind.clone(),
                    field.value.clone(),
                    field.sensitive,
                )
            })
            .collect();
        fields.sort();
        fields
    };
    assert_eq!(shape(&imported_login), shape(&original_login));
    assert_eq!(shape(&by_title("Router")), shape(&original_note));
    assert_eq!(
        by_title("Router").urls,
        vec!["https://router.test".to_string()]
    );
}

#[test]
fn a_missing_title_becomes_untitled() {
    let (_dir, state) = unlocked();
    let csv = "title,category,username\n,login,alice\n";
    let report = state.import_items("csv", csv.as_bytes().to_vec()).unwrap();
    assert_eq!(report.imported, 1);
    let summaries = state.list("", None, false).unwrap();
    assert_eq!(summaries[0].title, "Untitled");
    assert_eq!(summaries[0].username, "alice");
}

#[test]
fn a_malformed_csv_row_is_reported_without_aborting_the_file() {
    let (_dir, state) = unlocked();
    let csv = "title,category\nGood,login\n\"Broken\"junk,login\nAfter,login\n";
    let report = state.import_items("csv", csv.as_bytes().to_vec()).unwrap();
    assert_eq!(report.imported, 2, "{report:?}");
    assert_eq!(report.failed.len(), 1, "{report:?}");
    assert_eq!(report.failed[0].row, 3);
    assert!(
        report.failed[0].reason.contains("closing quote"),
        "{}",
        report.failed[0].reason
    );
    let titles: Vec<String> = state
        .list("", None, false)
        .unwrap()
        .into_iter()
        .map(|summary| summary.title)
        .collect();
    assert_eq!(titles, vec!["After".to_string(), "Good".to_string()]);
}

#[test]
fn preview_reports_the_total_and_caps_the_sample() {
    let (_dir, state) = unlocked();
    let mut csv = String::from("title,category\n");
    for index in 0..8 {
        csv.push_str(&format!("Item {index},login\n"));
    }
    let preview = state.import_preview("csv", csv.into_bytes()).unwrap();
    assert_eq!(preview.total, 8);
    assert_eq!(preview.sample.len(), 5);
    assert_eq!(preview.sample[0].title, "Item 0");
    assert_eq!(preview.sample[0].category, "login");
    assert_eq!(preview.sample[0].field_count, 0);
}

#[test]
fn export_with_the_wrong_password_fails() {
    let (_dir, state) = unlocked();
    state
        .save(Item::new(Category::Login, "Locked".to_string()))
        .unwrap();
    let error = state
        .export_items("json", "not the master password")
        .unwrap_err();
    assert!(
        error.to_string().contains("authentication failed"),
        "{error}"
    );
    let error = state.export_1pux("not the master password").unwrap_err();
    assert!(
        error.to_string().contains("authentication failed"),
        "{error}"
    );
}

#[test]
fn export_1pux_is_a_readable_zip_with_the_item_titles() {
    let (_dir, state) = unlocked();
    state
        .save(Item::new(Category::Login, "Alpha".to_string()))
        .unwrap();
    state
        .save(Item::new(Category::SecureNote, "Beta Notes".to_string()))
        .unwrap();
    let bytes = state.export_1pux(PW).unwrap();
    let text = read_export_data(&bytes);
    assert!(text.contains("Alpha"), "{text}");
    assert!(text.contains("Beta Notes"), "{text}");
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        value["accounts"][0]["vaults"][0]["items"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn one_pux_import_maps_categories_and_fields() {
    let (_dir, state) = unlocked();
    let payload = serde_json::json!({
        "accounts": [{
            "attrs": { "accountName": "Test" },
            "vaults": [{
                "attrs": { "name": "Private" },
                "items": [
                    {
                        "uuid": "wifi-item",
                        "categoryUuid": "109",
                        "overview": { "title": "Home Wi-Fi", "tags": ["home"] },
                        "details": {
                            "loginFields": [
                                { "designation": "username", "value": "admin", "fieldType": "T" },
                                { "designation": "password", "value": "hunter2", "fieldType": "P" }
                            ],
                            "notesPlain": "see the label",
                            "sections": [{
                                "title": "",
                                "fields": [{
                                    "title": "PIN",
                                    "value": { "concealed": "1234" },
                                    "guarded": true
                                }]
                            }]
                        }
                    },
                    {
                        "uuid": "license-item",
                        "categoryUuid": "100",
                        "overview": { "title": "Editor License" },
                        "details": { "notesPlain": "serial in the email" }
                    }
                ]
            }]
        }]
    });
    let bytes = zip_export_data(&payload.to_string());
    let report = state.import_items("1pux", bytes).unwrap();
    assert_eq!(report.imported, 2, "{report:?}");
    assert!(report.failed.is_empty(), "{report:?}");

    let summaries = state.list("", None, false).unwrap();
    let wifi = summaries
        .iter()
        .find(|summary| summary.title == "Home Wi-Fi")
        .expect("wifi item imported");
    assert_eq!(wifi.category, "wirelessRouter");
    let wifi = state.get(&wifi.id).unwrap();
    assert_eq!(wifi.notes, "see the label");
    assert_eq!(wifi.tags, vec!["home".to_string()]);
    assert_eq!(
        wifi.fields
            .iter()
            .find(|field| field.kind == "username")
            .unwrap()
            .value,
        "admin"
    );
    assert_eq!(
        wifi.fields
            .iter()
            .find(|field| field.kind == "password" && field.label == "password")
            .unwrap()
            .value,
        "hunter2"
    );
    let pin = wifi
        .fields
        .iter()
        .find(|field| field.label == "PIN")
        .expect("concealed section field imported");
    assert_eq!(pin.value, "1234");
    assert!(pin.sensitive);

    let license = summaries
        .iter()
        .find(|summary| summary.title == "Editor License")
        .expect("license item imported");
    assert_eq!(license.category, "softwareLicense");
}
