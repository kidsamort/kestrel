//! First-class field kinds: wallet seed phrases and dates.
//!
//! The seed-phrase tests are adversarial in one direction: a phrase is the most
//! valuable text a vault can hold, so it must be masked, word-counted and —
//! because the field is `sensitive` — absent from the plaintext search
//! projection. The projection test saves a real item and searches the SQLite
//! column, not just the in-memory helper, so a regression in `search_text`
//! fails here.

use kestrel_core::model::{
    normalize_seed_phrase, seed_word_count, seed_word_count_ok, Category, Field, Item,
    DATE_KIND, SEED_PHRASE_KIND, SEED_WORD_COUNTS,
};
use kestrel_core::store::{search_text, Store};
use std::path::PathBuf;

const PW: &str = "correct horse battery staple";

/// Twelve BIP-39-shaped words; `zebra` is the distinctive needle.
const PHRASE: &str = "zebra orbit lantern canyon velvet meadow copper falcon garden whisper marble tide";

fn scratch() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("kestrel.db");
    (dir, path)
}

fn shape(fields: &[Field]) -> Vec<(String, String, bool)> {
    fields
        .iter()
        .map(|f| (f.label.clone(), f.kind.clone(), f.sensitive))
        .collect()
}

fn assert_unique_ids(fields: &[Field]) {
    let mut ids: Vec<&str> = fields.iter().map(|f| f.id.as_str()).collect();
    ids.sort_unstable();
    let before = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), before, "every default field gets its own id");
}

/// Join `count` words so the whitespace-normalising helpers see a real phrase.
fn phrase_of(count: usize) -> String {
    (1..=count).map(|n| format!("word{n}")).collect::<Vec<_>>().join(" ")
}

#[test]
fn wallet_template_is_address_network_path_phrase_and_password() {
    let item = Item::new(Category::CryptoWallet, "My wallet".into());
    assert_eq!(
        shape(&item.fields),
        vec![
            ("wallet address".to_string(), "text".to_string(), false),
            ("network".to_string(), "text".to_string(), false),
            ("derivation path".to_string(), "text".to_string(), false),
            ("recovery phrase".to_string(), SEED_PHRASE_KIND.to_string(), true),
            ("spending password".to_string(), "password".to_string(), true),
        ]
    );
    assert_unique_ids(&item.fields);

    let phrase = item
        .fields
        .iter()
        .find(|f| f.kind == SEED_PHRASE_KIND)
        .expect("a wallet has a seed phrase field");
    assert!(phrase.sensitive, "the phrase is sensitive from birth");
    assert_eq!(phrase.value, "", "templates are empty, not placeholders");
}

#[test]
fn api_credential_template_ends_in_a_date() {
    let item = Item::new(Category::ApiCredential, "Stripe".into());
    assert_eq!(
        shape(&item.fields),
        vec![
            ("provider".to_string(), "text".to_string(), false),
            ("base url".to_string(), "url".to_string(), false),
            ("client id".to_string(), "text".to_string(), false),
            ("client secret".to_string(), "apiSecret".to_string(), true),
            ("token".to_string(), "apiSecret".to_string(), true),
            ("expires at".to_string(), DATE_KIND.to_string(), false),
        ]
    );
    assert_unique_ids(&item.fields);
}

#[test]
fn seed_phrase_whitespace_is_normalised_to_single_spaces() {
    let messy = "  zebra\n\norbit\tlantern   canyon \r\n velvet ";
    assert_eq!(
        normalize_seed_phrase(messy),
        "zebra orbit lantern canyon velvet"
    );

    // A phrase pasted with newlines compares equal to the same phrase typed.
    let typed = normalize_seed_phrase(PHRASE);
    let pasted = normalize_seed_phrase(&PHRASE.replace(' ', "\n"));
    assert_eq!(typed, pasted);
    assert_eq!(typed, PHRASE);

    // Counts are taken after normalisation, so line breaks never inflate them.
    assert_eq!(seed_word_count(messy), 5);
    assert_eq!(seed_word_count(&PHRASE.replace(' ', "\n\t ")), 12);
    assert_eq!(seed_word_count(""), 0);
    assert_eq!(seed_word_count("   \n\t "), 0);
    assert_eq!(normalize_seed_phrase("   \n\t "), "");
}

#[test]
fn word_count_warning_accepts_only_bip39_lengths() {
    for count in 0..=30 {
        let phrase = phrase_of(count);
        let expected = count == 0 || SEED_WORD_COUNTS.contains(&count);
        assert_eq!(
            seed_word_count_ok(&phrase),
            expected,
            "{count} words should {} warn",
            if expected { "not" } else { "" }
        );
        assert_eq!(seed_word_count(&phrase), count);
    }

    // Empty and whitespace-only fields have not been filled yet: no warning.
    assert!(seed_word_count_ok(""));
    assert!(seed_word_count_ok("  \n "));

    // The warning is not a gate: a 13-word phrase is still a phrase.
    let thirteen = phrase_of(13);
    assert!(!seed_word_count_ok(&thirteen));
    assert_eq!(seed_word_count(&thirteen), 13);

    // Messy spacing does not turn a valid 24-word phrase into a warning.
    let spaced = phrase_of(24).replace(' ', "\n  ");
    assert_eq!(seed_word_count(&spaced), 24);
    assert!(seed_word_count_ok(&spaced));

    for &count in &SEED_WORD_COUNTS {
        assert!(seed_word_count_ok(&phrase_of(count)), "{count} is BIP-39");
    }
}

#[test]
fn a_saved_seed_phrase_never_reaches_the_search_projection() {
    let (_dir, path) = scratch();
    let store = Store::open(&path).unwrap();
    let (master, meta) = store.initialise(PW).unwrap();

    let mut item = Item::new(Category::CryptoWallet, "Cold storage".into());
    let phrase = item
        .fields
        .iter_mut()
        .find(|f| f.kind == SEED_PHRASE_KIND)
        .expect("wallet template has a phrase");
    phrase.value = PHRASE.to_string();
    let saved = store.save_item(&master, &meta, item).unwrap();

    // The projection is built by the same gate the column is written from.
    let projection = search_text(&saved);
    assert!(
        !projection.contains("zebra"),
        "the phrase must not be searchable: {projection:?}"
    );
    assert!(!projection.contains(PHRASE));
    assert!(
        !projection.contains("recovery phrase"),
        "a sensitive field contributes neither value nor label"
    );

    // Prove it against the stored column, not just the helper: the needle is a
    // word that exists only inside the phrase.
    for needle in ["zebra", "lantern", "tide"] {
        let page = store
            .list_page(&master, &meta, needle, None, false, 10, 0)
            .unwrap();
        assert_eq!(page.total, 0, "searching {needle:?} must not match");
        assert!(
            store.list(&master, &meta, needle).unwrap().is_empty(),
            "the unpaged search must not match {needle:?} either"
        );
    }

    // The item is still found by its title, and the phrase itself round-trips
    // through the encrypted blob unchanged.
    let by_title = store
        .list_page(&master, &meta, "cold storage", None, false, 10, 0)
        .unwrap();
    assert_eq!(by_title.total, 1);
    let reopened = store.get(&master, &meta, &saved.id).unwrap();
    let reopened_phrase = reopened
        .fields
        .iter()
        .find(|f| f.kind == SEED_PHRASE_KIND)
        .expect("phrase survives the round trip");
    assert_eq!(reopened_phrase.value, PHRASE);
}
