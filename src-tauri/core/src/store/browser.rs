//! Per-origin rules for the browser bridge, and the origin grammar the bridge
//! and the chip share.
//!
//! One row per canonical origin (`scheme://host[:port]`): `fill`, `ask` or
//! `off`. A missing row is `ask` — the chip may appear, but `browser.reveal`
//! is refused until the person changes the rule to `fill` in Settings. `off`
//! hides the chip and refuses reveal.
//!
//! # Canonical origin
//!
//! A rule key has exactly one spelling. [`canonical_origin`] lower-cases the
//! scheme and host, drops a default port (`:80` for `http`, `:443` for
//! `https`), strips any path/query/fragment, and rejects everything that is
//! not `http` or `https`. So `https://Example.COM:443/path` and
//! `https://example.com` are one key, and a pasted `example.com` is read as
//! `https://example.com`. An origin that cannot be parsed is an error, not a
//! default: a typo must never become a rule that matches something else.
//!
//! The keys are policy, not content: nothing here is encrypted, so the table
//! can be read while the vault is locked. The rows name a site, never an item
//! or a value.
//!
//! Table shape is in [`super::migrate`] (schema v7).

use super::{Store, StoreError};
use rusqlite::{params, OptionalExtension};
use serde::Serialize;

/// What the bridge may do on one origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BrowserMode {
    /// The chip may fill after the person clicks Fill in the page.
    Fill,
    /// The chip may appear, but no value is released. This is the default.
    Ask,
    /// No chip and no reveal.
    Off,
}

impl BrowserMode {
    fn as_str(self) -> &'static str {
        match self {
            BrowserMode::Fill => "fill",
            BrowserMode::Ask => "ask",
            BrowserMode::Off => "off",
        }
    }

    /// Strict parse for a command argument. A typo is an error rather than a
    /// silent downgrade to the default.
    fn parse(raw: &str) -> Option<BrowserMode> {
        match raw {
            "fill" => Some(BrowserMode::Fill),
            "ask" => Some(BrowserMode::Ask),
            "off" => Some(BrowserMode::Off),
            _ => None,
        }
    }

    /// Tolerant parse for a stored value. An unknown mode is never permission
    /// to fill, so it degrades to [`BrowserMode::Ask`].
    fn from_row(raw: &str) -> BrowserMode {
        BrowserMode::parse(raw).unwrap_or(BrowserMode::Ask)
    }
}

/// One explicit `browser_sites` row. A missing row is not listed: the settings
/// table shows decisions the user made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserRuleRow {
    pub origin: String,
    pub mode: String,
    pub updated_at: i64,
}

/// Parse `raw` into one canonical `scheme://host[:port]`, or `None`.
///
/// Accepts an origin, a full URL, or a bare host (read as `https`). Rejects
/// userinfo, non-http(s) schemes, whitespace inside the authority, port 0 and
/// malformed IPv6 brackets.
pub fn canonical_origin(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => ("https".to_string(), trimmed),
    };
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') || authority.chars().any(char::is_whitespace)
    {
        return None;
    }
    let (host, port) = split_host_port(authority)?;
    let host = host.to_ascii_lowercase();
    if host.is_empty() || host.starts_with('.') {
        return None;
    }
    let host = host.trim_end_matches('.').to_string();
    if host.is_empty() {
        return None;
    }
    let default_port = if scheme == "https" { 443 } else { 80 };
    match port {
        None => Some(format!("{scheme}://{host}")),
        Some(443) if default_port == 443 => Some(format!("{scheme}://{host}")),
        Some(80) if default_port == 80 => Some(format!("{scheme}://{host}")),
        Some(port) => Some(format!("{scheme}://{host}:{port}")),
    }
}

/// Split an authority into host and optional port. IPv6 literals must be
/// bracketed, as in a URL.
fn split_host_port(authority: &str) -> Option<(String, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return None;
        }
        let after = &rest[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(text) => Some(parse_port(text)?),
            None if after.is_empty() => None,
            None => return None,
        };
        return Some((format!("[{host}]"), port));
    }
    // A host without brackets may contain at most one colon: the port.
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(parse_port(port)?)),
        Some(_) => return None,
        None => (authority, None),
    };
    if host.is_empty() || host.chars().any(|c| c.is_control()) {
        return None;
    }
    Some((host.to_string(), port))
}

fn parse_port(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port: u16 = text.parse().ok()?;
    (port != 0).then_some(port)
}

/// Whether a URL saved on an item points at `origin`. Both sides are
/// canonicalised, so a stored `https://Example.com/login` matches the rule
/// `https://example.com`.
pub fn origin_matches_url(origin: &str, url: &str) -> bool {
    let Some(rule) = canonical_origin(origin) else {
        return false;
    };
    canonical_origin(url).is_some_and(|candidate| candidate == rule)
}

impl Store {
    /// Canonical spelling of an origin. Exposed as an inherent method so the
    /// session layer can use the grammar without naming this private module.
    pub fn canonical_browser_origin(raw: &str) -> Option<String> {
        canonical_origin(raw)
    }

    /// Whether a saved URL belongs to `origin`, using the same grammar.
    pub fn browser_url_matches(origin: &str, url: &str) -> bool {
        origin_matches_url(origin, url)
    }

    /// The rule for `origin`, with the documented default when no row exists.
    /// This is the only read path used by the bridge, so "no row" and "ask"
    /// cannot diverge.
    pub fn browser_rule(&self, origin: &str) -> Result<String, StoreError> {
        let origin = canonical_origin(origin).ok_or_else(|| {
            StoreError::Invalid(format!("{origin} is not an http or https origin"))
        })?;
        let stored: Option<String> = self
            .conn()
            .query_row(
                "SELECT mode FROM browser_sites WHERE origin = ?1",
                params![origin],
                |row| row.get(0),
            )
            .optional()?;
        Ok(stored
            .as_deref()
            .map(BrowserMode::from_row)
            .unwrap_or(BrowserMode::Ask)
            .as_str()
            .to_string())
    }

    /// Every explicit rule, alphabetically by origin.
    pub fn browser_rules(&self) -> Result<Vec<BrowserRuleRow>, StoreError> {
        let mut stmt = self
            .conn()
            .prepare("SELECT origin, mode, updated_at FROM browser_sites ORDER BY origin")?;
        let rows = stmt.query_map([], |row| {
            Ok(BrowserRuleRow {
                origin: row.get(0)?,
                mode: BrowserMode::from_row(&row.get::<_, String>(1)?)
                    .as_str()
                    .to_string(),
                updated_at: row.get(2)?,
            })
        })?;
        let mut rules = Vec::new();
        for rule in rows {
            rules.push(rule?);
        }
        Ok(rules)
    }

    /// Upsert a rule. `origin` is canonicalised; `mode` must be one of the
    /// three literals. An invalid origin is an error, never a wildcard.
    pub fn set_browser_rule(&self, origin: &str, mode: &str) -> Result<(), StoreError> {
        let origin = canonical_origin(origin).ok_or_else(|| {
            StoreError::Invalid(format!("{origin} is not an http or https origin"))
        })?;
        let mode = BrowserMode::parse(mode).ok_or_else(|| {
            StoreError::Invalid(format!(
                "{mode} is not a browser rule; expected fill, ask or off"
            ))
        })?;
        self.conn().execute(
            "INSERT INTO browser_sites(origin, mode, updated_at) VALUES(?1, ?2, ?3)
             ON CONFLICT(origin) DO UPDATE SET
                mode = excluded.mode,
                updated_at = excluded.updated_at",
            params![origin, mode.as_str(), now_secs()],
        )?;
        Ok(())
    }

    /// Drop a rule so the origin falls back to the default (`ask`).
    pub fn clear_browser_rule(&self, origin: &str) -> Result<bool, StoreError> {
        let origin = canonical_origin(origin).ok_or_else(|| {
            StoreError::Invalid(format!("{origin} is not an http or https origin"))
        })?;
        let changed = self.conn().execute(
            "DELETE FROM browser_sites WHERE origin = ?1",
            params![origin],
        )?;
        Ok(changed > 0)
    }
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempStore {
        path: PathBuf,
        store: Store,
    }

    impl TempStore {
        fn new() -> TempStore {
            let path =
                std::env::temp_dir().join(format!("kestrel-browser-{}.db", uuid::Uuid::new_v4()));
            let store = Store::open(&path).expect("store opens");
            TempStore { path, store }
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(self.path.with_extension("db-wal"));
            let _ = std::fs::remove_file(self.path.with_extension("db-shm"));
        }
    }

    #[test]
    fn scheme_and_host_are_lower_case_and_default_ports_disappear() {
        assert_eq!(
            canonical_origin("https://Example.COM:443").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            canonical_origin("https://Example.COM:443/login?next=1").as_deref(),
            Some("https://example.com")
        );
        assert_eq!(
            canonical_origin("http://Example.com:80/").as_deref(),
            Some("http://example.com")
        );
        assert_eq!(
            canonical_origin("https://example.com:8443/x").as_deref(),
            Some("https://example.com:8443")
        );
        // A bare host is an https origin, which is the only safe guess.
        assert_eq!(
            canonical_origin(" example.com/path ").as_deref(),
            Some("https://example.com")
        );
        // A trailing root label is not a different site.
        assert_eq!(
            canonical_origin("https://example.com.").as_deref(),
            Some("https://example.com")
        );
    }

    #[test]
    fn ipv6_literals_keep_their_brackets() {
        assert_eq!(
            canonical_origin("http://[::1]:8080/login").as_deref(),
            Some("http://[::1]:8080")
        );
        assert_eq!(
            canonical_origin("http://[::1]:80").as_deref(),
            Some("http://[::1]")
        );
        assert_eq!(canonical_origin("http://::1/"), None);
    }

    #[test]
    fn non_http_input_is_rejected_not_guessed() {
        for raw in [
            "",
            "   ",
            "ftp://example.com",
            "file:///c:/secret",
            "javascript:alert(1)",
            "https://user:pass@example.com",
            "https://example.com:0",
            "https://example.com:notaport",
            "https://",
            "https://exa mple.com",
        ] {
            assert_eq!(canonical_origin(raw), None, "{raw} must not parse");
        }
    }

    #[test]
    fn missing_rule_is_ask_and_unknown_modes_degrade_to_ask() {
        let temp = TempStore::new();
        assert_eq!(
            temp.store.browser_rule("https://example.com").unwrap(),
            "ask"
        );
        temp.store
            .conn()
            .execute(
                "INSERT INTO browser_sites(origin, mode, updated_at)
                 VALUES('https://odd.example', 'fill-everything', 0)",
                [],
            )
            .unwrap();
        assert_eq!(
            temp.store.browser_rule("https://odd.example").unwrap(),
            "ask"
        );
    }

    #[test]
    fn rules_round_trip_under_one_key_and_clear_back_to_ask() {
        let temp = TempStore::new();
        temp.store
            .set_browser_rule("https://Example.COM:443/bank", "fill")
            .unwrap();
        assert_eq!(
            temp.store.browser_rule("https://example.com").unwrap(),
            "fill"
        );
        assert_eq!(temp.store.browser_rules().unwrap().len(), 1);

        let other_spelling = TempStore::new();
        other_spelling
            .store
            .set_browser_rule("https://example.com/other", "off")
            .unwrap();
        assert_eq!(
            other_spelling.store.browser_rules().unwrap().len(),
            1,
            "a path never creates a second key"
        );

        assert!(temp
            .store
            .clear_browser_rule("https://example.com")
            .unwrap());
        assert_eq!(
            temp.store.browser_rule("https://example.com").unwrap(),
            "ask"
        );
        assert!(temp.store.browser_rules().unwrap().is_empty());
    }

    #[test]
    fn invalid_rules_are_errors() {
        let temp = TempStore::new();
        assert!(temp.store.set_browser_rule("ftp://x", "fill").is_err());
        assert!(temp
            .store
            .set_browser_rule("https://example.com", "sometimes")
            .is_err());
        assert!(temp.store.set_browser_rule("", "fill").is_err());
    }

    #[test]
    fn an_item_url_matches_its_origin_but_not_a_sibling() {
        assert!(origin_matches_url(
            "https://example.com",
            "https://EXAMPLE.com/login?x=1"
        ));
        assert!(origin_matches_url(
            "https://example.com:443",
            "https://example.com"
        ));
        assert!(!origin_matches_url(
            "https://example.com",
            "https://example.com.evil.test/login"
        ));
        assert!(!origin_matches_url(
            "https://example.com",
            "http://example.com"
        ));
        assert!(!origin_matches_url(
            "https://example.com",
            "https://sub.example.com"
        ));
    }
}
