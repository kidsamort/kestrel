//! Client configuration and the transport policy it enforces.
//!
//! The config is deliberately plain data: a base URL, the device's identity,
//! its signing key, and one escape hatch for a lab deployment that really does
//! speak plain HTTP. Refusing an insecure remote happens at construction, so a
//! caller cannot accidentally start syncing passwords through a clear channel
//! after a `new` that succeeded.

use std::fmt;
use std::net::IpAddr;

/// Everything [`crate::SyncClient`] needs to authenticate itself.
#[derive(Clone)]
pub struct ClientConfig {
    /// Origin of the sync service, for example `https://sync.example.com` or
    /// `http://127.0.0.1:8787`. A trailing slash is allowed; a path prefix,
    /// query, fragment or credentials are not.
    pub base_url: String,
    /// 32 hex characters. Normalised to lowercase at construction.
    pub account_id: String,
    /// 32 hex characters. This is the id sent in every `Authorization` header.
    pub device_id: String,
    /// The Ed25519 seed. The public key is derived; the caller never passes a
    /// separate public key that could disagree with the private one.
    pub signing_key: [u8; 32],
    /// Permit `http://` to a host that is not loopback. Off by default: a
    /// remote plain-http endpoint is a vault in the clear.
    pub allow_insecure: bool,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A signing key in a log line is a stolen device.
        f.debug_struct("ClientConfig")
            .field("base_url", &self.base_url)
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("signing_key", &"[redacted]")
            .field("allow_insecure", &self.allow_insecure)
            .finish()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("base_url must be an absolute http:// or https:// URL, got {url:?}")]
    InvalidUrl { url: String },
    #[error(
        "base_url must not carry credentials, a query, a fragment or a path prefix, got {url:?}"
    )]
    InvalidUrlShape { url: String },
    #[error(
        "refusing plain http to {host}: plain http is only allowed to a loopback host; \
         set allow_insecure to override"
    )]
    InsecureTransport { host: String },
    #[error("{field} must be 32 hex characters, got {value:?}")]
    InvalidId { field: &'static str, value: String },
    #[error("the signing key is a weak Ed25519 key and could never authenticate")]
    WeakSigningKey,
}

/// A parsed, normalised origin. The client appends request targets to
/// [`BaseUrl::as_str`], so the string that is signed is the string that is
/// sent.
#[derive(Debug, Clone)]
pub(crate) struct BaseUrl {
    text: String,
}

/// Validate a service origin the way [`crate::SyncClient`] will, without
/// building a client: the same scheme, shape and transport policy checks.
///
/// Settings saves a URL before any device key exists, so the check has to be
/// available without an identity. The returned string is the normalised origin
/// (no trailing slash) that the client will sign against.
pub fn check_base_url(raw: &str, allow_insecure: bool) -> Result<String, ConfigError> {
    Ok(BaseUrl::parse(raw, allow_insecure)?.as_str().to_string())
}

impl BaseUrl {
    pub(crate) fn parse(raw: &str, allow_insecure: bool) -> Result<BaseUrl, ConfigError> {
        let raw = raw.trim();
        let invalid = || ConfigError::InvalidUrl {
            url: raw.to_string(),
        };
        let shape = || ConfigError::InvalidUrlShape {
            url: raw.to_string(),
        };

        let (scheme, rest) = raw.split_once("://").ok_or_else(invalid)?;
        if rest.is_empty() || rest.chars().any(char::is_whitespace) {
            return Err(invalid());
        }
        let secure = match scheme.to_ascii_lowercase().as_str() {
            "https" => true,
            "http" => false,
            _ => return Err(invalid()),
        };
        if rest.contains('?') || rest.contains('#') || rest.contains('@') {
            return Err(shape());
        }

        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, ""),
        };
        if path != "" && path != "/" {
            return Err(shape());
        }
        if authority.is_empty() {
            return Err(invalid());
        }

        let (host, port, bracketed) = split_authority(authority).ok_or_else(invalid)?;
        let host = host.to_ascii_lowercase();
        let port = match port {
            Some(text) => Some(text.parse::<u16>().map_err(|_| invalid())?),
            None => None,
        };
        let host_text = if bracketed {
            format!("[{host}]")
        } else {
            host.clone()
        };
        if !secure && !is_loopback(&host) && !allow_insecure {
            return Err(ConfigError::InsecureTransport { host: host_text });
        }

        let mut text = format!("{}://{host_text}", scheme.to_ascii_lowercase());
        if let Some(port) = port {
            text.push(':');
            text.push_str(&port.to_string());
        }

        Ok(BaseUrl { text })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.text
    }
}

/// Splits `host`, `host:port` or `[ipv6]:port`. A bare IPv6 literal without
/// brackets is rejected, because the resulting URL would be ambiguous.
fn split_authority(authority: &str) -> Option<(&str, Option<&str>, bool)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        if host.is_empty() {
            return None;
        }
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        Some((host, port, true))
    } else {
        if authority.contains('[') || authority.contains(']') {
            return None;
        }
        match authority.rsplit_once(':') {
            Some((host, port)) => {
                // A second colon means this was an unbracketed IPv6 literal,
                // not a port separator.
                if host.contains(':') || host.is_empty() {
                    return None;
                }
                Some((host, Some(port), false))
            }
            None => Some((authority, None, false)),
        }
    }
}

fn is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => address.is_loopback(),
        Ok(IpAddr::V6(address)) => address.is_loopback(),
        Err(_) => false,
    }
}

/// Ids are identifiers, not secrets: uppercase is valid input and is
/// normalised, exactly as the service normalises it.
pub(crate) fn normalise_id(field: &'static str, value: &str) -> Result<String, ConfigError> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::InvalidId {
            field,
            value: value.to_string(),
        });
    }
    Ok(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(raw: &str, allow_insecure: bool) -> Result<String, ConfigError> {
        BaseUrl::parse(raw, allow_insecure).map(|url| url.as_str().to_string())
    }

    #[test]
    fn https_is_always_allowed_and_lowercased() {
        assert_eq!(
            origin("HTTPS://Sync.Example.COM", false).expect("https origin"),
            "https://sync.example.com"
        );
        assert_eq!(
            origin("https://sync.example.com/", false).expect("trailing slash"),
            "https://sync.example.com"
        );
        assert_eq!(
            origin("https://sync.example.com:8443", false).expect("explicit port"),
            "https://sync.example.com:8443"
        );
    }

    #[test]
    fn plain_http_is_loopback_only_unless_allowed() {
        for loopback in [
            "http://127.0.0.1:8787",
            "http://127.1.2.3:8787",
            "http://localhost:8787",
            "http://LocalHost:8787",
            "http://[::1]:8787",
        ] {
            assert!(
                origin(loopback, false).is_ok(),
                "{loopback} should be allowed"
            );
        }

        let error = origin("http://192.168.1.10:8787", false).expect_err("remote plain http");
        assert!(matches!(error, ConfigError::InsecureTransport { .. }));
        assert!(origin("http://sync.example.com", false).is_err());
        assert_eq!(
            origin("http://sync.example.com", true).expect("allow_insecure"),
            "http://sync.example.com"
        );
    }

    #[test]
    fn nonsense_origins_are_rejected() {
        for url in [
            "",
            "sync.example.com",
            "ftp://sync.example.com",
            "http://",
            "http://:8787",
            "http://sync.example.com:notaport",
            "http://sync.example.com:70000",
            "http://user:pass@sync.example.com",
            "https://sync.example.com?x=1",
            "https://sync.example.com#frag",
            "https://sync.example.com/api",
            "https://sync.example.com//",
            "http://::1:8787",
            "http://sync example.com",
        ] {
            assert!(origin(url, true).is_err(), "{url:?} should be rejected");
        }
    }

    #[test]
    fn ids_are_length_checked_and_normalised() {
        assert_eq!(
            normalise_id("device_id", "0A1B2C3D4E5F60718293A4B5C6D7E8F9").expect("valid id"),
            "0a1b2c3d4e5f60718293a4b5c6d7e8f9"
        );
        assert!(normalise_id("device_id", "0a1b2c3d").is_err());
        assert!(normalise_id("device_id", "zz1b2c3d4e5f60718293a4b5c6d7e8f9").is_err());
    }
}
