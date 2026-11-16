//! Time-based one-time passwords (RFC 6238), compatible with the `otpauth://`
//! secrets people already paste into password managers.

use base32::Alphabet;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroize;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    #[error("invalid base32 secret")]
    Secret,
    #[error("unsupported algorithm")]
    Algorithm,
}

/// Parse `otpauth://totp/...?secret=...&digits=6&period=30` or a bare secret.
pub fn parse_secret(raw: &str) -> Result<(Vec<u8>, u32, u32), TotpError> {
    let trimmed = raw.trim();
    if trimmed.to_lowercase().starts_with("otpauth://") {
        let query = trimmed.split('?').nth(1).unwrap_or("");
        let mut secret = String::new();
        let mut digits = 6u32;
        let mut period = 30u32;
        for pair in query.split('&') {
            let mut it = pair.splitn(2, '=');
            let key = it.next().unwrap_or("");
            let value = it.next().unwrap_or("");
            match key.to_lowercase().as_str() {
                "secret" => secret = value.to_string(),
                // A hostile or careless secret must not reach the cycle
                // arithmetic: `period = 0` would divide by zero.
                "digits" => digits = value.parse().unwrap_or(6).clamp(1, 10),
                "period" => period = value.parse().unwrap_or(30).max(1),
                "algorithm" if !value.eq_ignore_ascii_case("SHA1") => {
                    return Err(TotpError::Algorithm)
                }
                _ => {}
            }
        }
        let bytes = base32::decode(Alphabet::Rfc4648 { padding: false }, &secret.to_uppercase())
            .ok_or(TotpError::Secret)?;
        Ok((bytes, digits, period))
    } else {
        let cleaned: String = trimmed
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect();
        let bytes = base32::decode(
            Alphabet::Rfc4648 { padding: false },
            &cleaned.to_uppercase(),
        )
        .ok_or(TotpError::Secret)?;
        Ok((bytes, 6, 30))
    }
}

pub fn code_at(secret: &[u8], digits: u32, period: u32, unix_time: u64) -> String {
    let counter = unix_time / period.max(1) as u64;
    let mut msg = counter.to_be_bytes();
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&msg);
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    msg.zeroize();
    let modulo = 10u32.pow(digits.min(9));
    format!("{:0width$}", binary % modulo, width = digits as usize)
}

/// The code for the current step together with the step geometry the UI needs
/// to draw a truthful cycle ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentCode {
    pub code: String,
    pub seconds_remaining: u64,
    /// Seconds per cycle, as declared by the `otpauth://` secret (default 30).
    pub period: u64,
}

pub fn code_now(secret: &str) -> Result<CurrentCode, TotpError> {
    let (bytes, digits, period) = parse_secret(secret)?;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let code = code_at(&bytes, digits, period, now);
    let remaining = period as u64 - (now % period as u64);
    Ok(CurrentCode {
        code,
        seconds_remaining: remaining,
        period: period as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vectors() {
        // RFC 6238 appendix B, SHA-1, 8 digits.
        let secret = b"12345678901234567890";
        assert_eq!(code_at(secret, 8, 30, 59), "94287082");
        assert_eq!(code_at(secret, 8, 30, 1111111109), "07081804");
        assert_eq!(code_at(secret, 8, 30, 1234567890), "89005924");
    }

    #[test]
    fn parses_otpauth_uri() {
        let (bytes, digits, period) =
            parse_secret("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&digits=6&period=30")
                .unwrap();
        assert_eq!(digits, 6);
        assert_eq!(period, 30);
        assert_eq!(bytes, b"Hello!\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn rejects_bad_secret() {
        assert!(parse_secret("not-base32-@@@").is_err());
    }
}
