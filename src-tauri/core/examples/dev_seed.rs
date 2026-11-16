//! Development helper: seeds a vault so the UI can be inspected with realistic
//! content. Uses the public core API only — the same calls the app makes.
//!
//! Usage: cargo run -p kestrel-core --example dev_seed -- <db path> <password>

use kestrel_core::model::{Category, Item};
use kestrel_core::session::VaultState;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("db path");
    let password = args.next().expect("master password");

    let state = VaultState::open(path.into()).expect("open vault");
    if !state.state().unwrap().initialized {
        state.create(&password).expect("create vault");
    } else {
        state.unlock(&password).expect("unlock vault");
    }

    let seed: Vec<(Category, &str, &[(&str, &str)], &[&str])> = vec![
        (
            Category::Login,
            "GitHub",
            &[
                ("username", "alice@kestrel.dev"),
                ("password", "Vh8#q!7kLm2@Rx4t"),
            ],
            &["work", "code"],
        ),
        (
            Category::Login,
            "Figma",
            &[
                ("username", "alice@kestrel.dev"),
                ("password", "d3sign!Studio#42"),
            ],
            &["work", "design"],
        ),
        (
            Category::Login,
            "Mailbox",
            &[
                ("username", "alice@kestrel.dev"),
                ("password", "p0stal-Corner-9"),
            ],
            &["personal"],
        ),
        (
            Category::ApiCredential,
            "Stripe (test)",
            &[
                ("client id", "pk_test_51Kestrel"),
                ("client secret", "sk_test_51KestrelSecret"),
            ],
            &["work", "payments"],
        ),
        (
            Category::SshKey,
            "work laptop",
            &[(
                "public key",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey kestrel",
            )],
            &["work", "infra"],
        ),
        (
            Category::SecureNote,
            "Recovery kit checklist",
            &[],
            &["personal"],
        ),
    ];

    let existing = state.list("", None, false).unwrap();
    for (category, title, fields, tags) in seed {
        if existing.iter().any(|item| item.title == title) {
            continue;
        }
        let mut item = Item::new(category, title.to_string());
        for field in item.fields.iter_mut() {
            if let Some((_, value)) = fields.iter().find(|(kind, _)| *kind == field.kind) {
                field.value = value.to_string();
            }
        }
        item.tags = tags.iter().map(|t| t.to_string()).collect();
        if title == "GitHub" {
            item.totp_secret = Some("JBSWY3DPEHPK3PXP".into());
            item.favorite = true;
            item.urls = vec!["https://github.com".into()];
            item.notes = "SSO enforced; recovery codes in the safe.".into();
        }
        if title == "Recovery kit checklist" {
            item.notes =
                "1. Print the recovery kit\n2. Store the second half offline\n3. Verify quarterly"
                    .into();
        }
        state.save(item).expect("save item");
    }

    println!(
        "seeded vault at {} with {} items",
        state.state().unwrap().item_count,
        state.list("", None, false).unwrap().len()
    );
}
