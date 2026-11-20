//! Native messaging host for the Kestrel browser extension.
//!
//! Chrome and Edge start this binary and speak length-prefixed JSON on
//! stdin/stdout; it forwards each request to the running app over
//! `\\.\pipe\kestrel-sdk`. No vault code lives here.
//!
//! # What this process can do
//!
//! It has no key, no database and no copy of the vault. It reads one token from
//! the user-only `bridge.token` file and puts it on the request — any token the
//! extension sent is overwritten, so the extension can never choose its own
//! scope. The app's pipe then applies the Browser scope and the per-origin
//! rule; this binary only moves bytes.
//!
//! A missing token is reported as `unauthorized` with an install hint. The
//! extension shows that message; it is the normal state before Settings →
//! Browser has been used.
//!
//! # Failure shape
//!
//! Every failure is one JSON object `{"ok":false,"error":...,"message":...}`.
//! A framing failure ends the process after one such frame: once the length
//! prefix is wrong, there is no way to find the next message boundary, so
//! guessing would be worse than stopping.

mod frame;
mod pipe;
mod token;

use serde_json::{json, Value};
use std::io::{stdin, stdout};

fn main() {
    let mut input = stdin().lock();
    let mut output = stdout().lock();
    loop {
        let body = match frame::read(&mut input) {
            Ok(Some(body)) => body,
            Ok(None) => return,
            Err(error) => {
                let _ = frame::write(&mut output, &error_frame("bad_request", &error.to_string()));
                std::process::exit(1);
            }
        };
        let response = handle(&body);
        if let Err(error) = frame::write(&mut output, &response) {
            eprintln!("kestrel-nmhost: cannot answer: {error}");
            std::process::exit(1);
        }
    }
}

/// One message in, one message out. Split out from the loop so the scope and
/// token rules are testable without stdin.
fn handle(body: &[u8]) -> Value {
    let mut request: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) => return error_frame("bad_request", &format!("invalid JSON: {error}")),
    };
    let Some(object) = request.as_object_mut() else {
        return error_frame("bad_request", "the request must be a JSON object");
    };
    let Some(op) = object.get("op").and_then(Value::as_str) else {
        return error_frame("bad_request", "the request has no op");
    };
    if op.is_empty() {
        return error_frame("bad_request", "the request has an empty op");
    }

    let token = match token::read() {
        Ok(Some(token)) => token,
        Ok(None) => {
            return error_frame(
                "unauthorized",
                "Kestrel is not paired for the browser. Install the bridge in Kestrel → Settings → Browser.",
            )
        }
        Err(error) => return error_frame("unauthorized", &error),
    };
    // The file is the only authority on which token this process may present.
    inject_token(&mut request, &token);

    match pipe::round_trip(&request) {
        Ok(response) => response,
        Err(error) => error_frame("internal", &error),
    }
}

fn error_frame(code: &str, message: &str) -> Value {
    json!({ "ok": false, "error": code, "message": message })
}

/// Overwrite any `token` the extension sent. A request that names its own
/// token is not trusted to choose a scope; the file is.
fn inject_token(request: &mut Value, token: &str) {
    if let Some(object) = request.as_object_mut() {
        object.insert("token".into(), Value::String(token.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_object_request_is_refused_before_the_pipe() {
        let response = handle(b"[1,2,3]");
        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["error"], json!("bad_request"));
    }

    #[test]
    fn a_request_without_an_op_is_refused() {
        let response = handle(br#"{"origin":"https://example.com"}"#);
        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["error"], json!("bad_request"));
    }

    #[test]
    fn invalid_json_is_a_coded_error() {
        let response = handle(b"{");
        assert_eq!(response["ok"], json!(false));
        assert_eq!(response["error"], json!("bad_request"));
        assert!(response["message"]
            .as_str()
            .unwrap()
            .contains("invalid JSON"));
    }

    #[test]
    fn the_bridge_file_overrides_a_supplied_token() {
        // The host never lets the extension choose a scope, even if the page
        // or an older client sends a token of its own.
        let mut request = json!({
            "op": "browser.items",
            "origin": "https://example.com",
            "token": "attacker-chosen",
        });
        inject_token(&mut request, "from-file");
        assert_eq!(request["token"], json!("from-file"));
    }
}
