//! Browser-bridge ops behind `browser.*`.
//!
//! The protocol layer decides *whether* a Browser token may ask; this module
//! turns the request into a session read and maps the core's types onto the
//! wire. The policy that matters — origin normalisation, `fill` only, the
//! item/origin match, the audit row — lives in the core's
//! [`VaultState::browser_reveal`], so it runs under the same lock as the
//! decryption and cannot be bypassed by a different caller of this trait.
//!
//! `browser.status` also reports host installation and the token file, which
//! are shell concerns, not vault concerns. It reads those through
//! [`crate::browser::snapshot`]; the rule count still comes from the vault.

use super::protocol::{BrowserField, BrowserItem, BrowserStatus};
use kestrel_core::session::{VaultError, VaultState};

/// `browser.status`. Requires an open session (the protocol already answered
/// `locked` otherwise); rule counting is the only vault read.
pub(super) fn status(state: &VaultState) -> Result<BrowserStatus, VaultError> {
    let rules = state.browser_rules()?.len();
    let host = crate::browser::snapshot(rules);
    Ok(BrowserStatus {
        installed: host.installed,
        host: host.host_name,
        rules,
        extension_id: host.extension_id,
        token_present: host.token_present,
    })
}

/// `browser.items`: metadata only, mapped to the wire names.
pub(super) fn items(state: &VaultState, origin: &str) -> Result<Vec<BrowserItem>, VaultError> {
    Ok(state
        .browser_items(origin)?
        .into_iter()
        .map(|item| BrowserItem {
            id: item.id,
            title: item.title,
            category: item.category,
            fields: item
                .fields
                .into_iter()
                .map(|field| BrowserField {
                    id: field.id,
                    label: field.label,
                    kind: field.kind,
                })
                .collect(),
        })
        .collect())
}

/// `browser.reveal`: the core owns every check and the audit.
pub(super) fn reveal(
    state: &VaultState,
    origin: &str,
    item_id: &str,
    field: &str,
) -> Result<String, VaultError> {
    state.browser_reveal(origin, item_id, field)
}

