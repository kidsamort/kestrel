//! MCP server: JSON-RPC 2.0 handlers, one message per line on stdio.
//!
//! # Spec revision and framing
//!
//! This implements **MCP 2025-06-18** (the revision whose transport section
//! defines stdio as newline-delimited JSON-RPC: "messages are delimited by
//! newlines and MUST NOT contain embedded newlines"). `Content-Length` framing
//! belongs to the Language Server Protocol, not to MCP, so it is not used here.
//! JSON-RPC batching was removed from MCP in 2025-06-18; a batch array is
//! therefore answered with one `-32600` error.
//!
//! # What this server is allowed to do
//!
//! Two tools only:
//!
//! * `list_secrets` asks the app for `secrets.list` — item ids, titles and field
//!   ids/labels, never a value;
//! * `get_secret` asks for `items.reveal`, which the app answers only for the
//!   fields this client was granted in Settings. The value is written to this
//!   process's stdout and nowhere else: no log line, no error message, no copy.
//!
//! A refusal from the app is a *tool* error (`isError: true`), because the tool
//! ran and the answer is "no"; a malformed call or an unknown tool is a
//! JSON-RPC error, because the request never reached a tool at all.

use crate::pipe::Backend;
use serde_json::{json, Map, Value};
use std::io::BufRead;

/// Same cap the app applies to one request line. A message that exceeds it is
/// refused instead of buffered: this process must not grow with a client's bug.
pub const MAX_LINE: usize = 64 * 1024;

/// The revision this server implements, and the two older revisions it can
/// negotiate down to when a client asks for them.
pub const LATEST_PROTOCOL: &str = "2025-06-18";
const SUPPORTED_PROTOCOLS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

const INSTRUCTIONS: &str = "\
Kestrel exposes only the fields granted to this client in Settings → Developer. \
Call list_secrets for item and field ids, then get_secret for one field value. \
Every granted read is recorded in Kestrel's audit list; the vault must be \
unlocked in the app.";

/// One JSON-RPC connection state: the token, and the app to ask.
pub struct Server<'a> {
    token: String,
    backend: &'a dyn Backend,
}

impl<'a> Server<'a> {
    pub fn new(token: String, backend: &'a dyn Backend) -> Server<'a> {
        Server { token, backend }
    }

    /// Answer one message. `None` means "send nothing": notifications have no
    /// response, by JSON-RPC rule, and an empty line is not a message.
    pub fn handle_line(&mut self, line: &[u8]) -> Option<Value> {
        if line.iter().all(u8::is_ascii_whitespace) {
            return None;
        }
        let message: Value = match serde_json::from_slice(line) {
            Ok(value) => value,
            Err(error) => {
                return Some(error_response(
                    Value::Null,
                    PARSE_ERROR,
                    &format!("parse error: {error}"),
                ))
            }
        };
        let Some(object) = message.as_object() else {
            // 2025-06-18 removed batching, so an array is not a request either.
            return Some(error_response(
                Value::Null,
                INVALID_REQUEST,
                "a message must be a JSON object; batching is not supported",
            ));
        };
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
            return Some(error_response(
                id_of(object),
                INVALID_REQUEST,
                "jsonrpc must be \"2.0\"",
            ));
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return Some(error_response(
                id_of(object),
                INVALID_REQUEST,
                "method must be a string",
            ));
        };
        // A notification has no id. MCP's own hello (`notifications/initialized`)
        // is one, and the spec is explicit that it gets no reply.
        let Some(id) = object.get("id").cloned() else {
            return None;
        };
        let params = object.get("params").cloned().unwrap_or(Value::Null);

        match self.dispatch(method, &params) {
            Ok(result) => Some(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
            Err((code, message)) => Some(error_response(id, code, &message)),
        }
    }

    fn dispatch(&mut self, method: &str, params: &Value) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => Ok(self.initialize(params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(tools()),
            "tools/call" => self.call_tool(params),
            "notifications/initialized" => Ok(json!({})),
            other => Err((METHOD_NOT_FOUND, format!("unknown method: {other}"))),
        }
    }

    /// Echo the client's identity and the protocol version it asked for.
    ///
    /// The `clientInfo` member is not required by the spec; it is echoed so the
    /// transcript (and this server's own tests) show which client handshook.
    /// Clients ignore unknown result members.
    fn initialize(&mut self, params: &Value) -> Value {
        let requested = params.get("protocolVersion").and_then(Value::as_str);
        let protocol = requested
            .filter(|version| SUPPORTED_PROTOCOLS.contains(version))
            .unwrap_or(LATEST_PROTOCOL);
        let mut result = json!({
            "protocolVersion": protocol,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": {
                "name": "kestrel-mcp",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": INSTRUCTIONS,
        });
        if let Some(client) = params.get("clientInfo").filter(|value| value.is_object()) {
            result["clientInfo"] = client.clone();
        }
        result
    }

    fn call_tool(&mut self, params: &Value) -> Result<Value, (i64, String)> {
        let Some(object) = params.as_object() else {
            return Err((INVALID_PARAMS, "params must be an object".into()));
        };
        let Some(name) = object.get("name").and_then(Value::as_str) else {
            return Err((INVALID_PARAMS, "tools/call needs a tool name".into()));
        };
        let arguments = match object.get("arguments") {
            None | Some(Value::Null) => Map::new(),
            Some(Value::Object(map)) => map.clone(),
            Some(_) => {
                return Err((INVALID_PARAMS, "arguments must be an object".into()));
            }
        };
        match name {
            "list_secrets" => Ok(self.list_secrets()),
            "get_secret" => self.get_secret(&arguments),
            other => Err((INVALID_PARAMS, format!("unknown tool: {other}"))),
        }
    }

    fn list_secrets(&mut self) -> Value {
        let request = json!({ "op": "secrets.list", "token": self.token });
        match self.ask(&request, "items") {
            Ok(items) => text_result(json!({ "items": items }).to_string()),
            Err(message) => tool_error(message),
        }
    }

    fn get_secret(&mut self, arguments: &Map<String, Value>) -> Result<Value, (i64, String)> {
        let id = required_argument(arguments, "id")?;
        let field = required_argument(arguments, "field")?;
        let request = json!({
            "op": "items.reveal",
            "token": self.token,
            "id": id,
            "field": field,
        });
        Ok(match self.ask(&request, "value") {
            Ok(Value::String(value)) => text_result(value),
            Ok(_) => tool_error("Kestrel answered without a value".into()),
            Err(message) => tool_error(message),
        })
    }

    /// Round-trip through the app and unwrap its `{"ok":true, <key>:...}` shape.
    /// Both failure modes — pipe down, request refused — become tool errors.
    fn ask(&self, request: &Value, key: &str) -> Result<Value, String> {
        let response = self.backend.call(request).map_err(|error| error.0)?;
        answer(response, key)
    }
}

fn required_argument<'a>(
    arguments: &'a Map<String, Value>,
    name: &str,
) -> Result<&'a str, (i64, String)> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| (INVALID_PARAMS, format!("get_secret needs a non-empty {name:?}")))
}

/// The app's shape is always `{"ok":bool, ...}`. A refused read becomes the
/// message of a tool error, with the app's own code so the reader can look it
/// up; a transport failure becomes one too, because the tool did not run.
fn answer(response: Value, key: &str) -> Result<Value, String> {
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        return response
            .get(key)
            .cloned()
            .ok_or_else(|| "Kestrel answered without the expected field".to_string());
    }
    let code = response
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("internal");
    let message = response
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("the request was refused");
    Err(format!("Kestrel refused the read: {code} — {message}"))
}

fn text_result(text: String) -> Value {
    json!({ "content": [ { "type": "text", "text": text } ] })
}

fn tool_error(message: String) -> Value {
    json!({
        "content": [ { "type": "text", "text": message } ],
        "isError": true,
    })
}

fn tools() -> Value {
    json!({
        "tools": [
            {
                "name": "list_secrets",
                "description": "List vault items and their field ids and names. \
                                Returns no values; every item is listed, reads are gated.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                }
            },
            {
                "name": "get_secret",
                "description": "Read one field value. Only fields granted to this \
                                client in Kestrel are readable, and every granted read \
                                is recorded in Kestrel's audit list.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Item id returned by list_secrets."
                        },
                        "field": {
                            "type": "string",
                            "description": "Field id returned by list_secrets."
                        }
                    },
                    "required": ["id", "field"],
                    "additionalProperties": false
                }
            }
        ]
    })
}

fn id_of(object: &Map<String, Value>) -> Value {
    object.get("id").cloned().unwrap_or(Value::Null)
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

/* ------------------------------------------------------------------- stdio */

/// One message read from stdin.
pub enum Message {
    Line(Vec<u8>),
    /// The line hit [`MAX_LINE`] before a newline; the rest was discarded.
    TooLarge,
}

/// Run the loop until stdin closes. Each response is one line, flushed before
/// the next read so a client waiting on the answer is never blocked by us.
pub fn serve<R: std::io::BufRead, W: std::io::Write>(
    reader: &mut R,
    writer: &mut W,
    token: String,
    backend: &dyn Backend,
) -> std::io::Result<()> {
    let mut server = Server::new(token, backend);
    let mut line = Vec::new();
    while let Some(message) = read_message(reader, &mut line)? {
        let response = match message {
            Message::Line(bytes) => server.handle_line(&bytes),
            Message::TooLarge => Some(error_response(
                Value::Null,
                INVALID_REQUEST,
                &format!("message exceeds {MAX_LINE} bytes"),
            )),
        };
        if let Some(response) = response {
            let mut bytes = serde_json::to_vec(&response)
                .unwrap_or_else(|_| br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"response could not be serialised"}}"#.to_vec());
            bytes.push(b'\n');
            writer.write_all(&bytes)?;
            writer.flush()?;
        }
    }
    Ok(())
}

/// Read one newline-terminated message, capped at [`MAX_LINE`].
fn read_message<R: std::io::BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> std::io::Result<Option<Message>> {
    line.clear();
    let mut limited: std::io::Take<&mut R> =
        std::io::Read::take(&mut *reader, MAX_LINE as u64);
    let read = limited.read_until(b'\n', line)?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        return Ok(Some(Message::Line(std::mem::take(line))));
    }
    if read >= MAX_LINE {
        // The cap landed before the newline. Drop the remainder so the next
        // read starts at a message boundary instead of mid-line.
        discard_to_newline(reader)?;
        line.clear();
        return Ok(Some(Message::TooLarge));
    }
    // EOF with a partial last message: still a message, just unterminated.
    Ok(Some(Message::Line(std::mem::take(line))))
}

fn discard_to_newline<R: std::io::BufRead>(reader: &mut R) -> std::io::Result<()> {
    loop {
        let (length, newline) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                return Ok(());
            }
            (
                available.len(),
                available.iter().position(|byte| *byte == b'\n'),
            )
        };
        match newline {
            Some(position) => {
                reader.consume(position + 1);
                return Ok(());
            }
            None => reader.consume(length),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipe::PipeError;
    use std::sync::Mutex;

    const TOKEN: &str = "token-abc";

    /// How the fake app answers `items.reveal`.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Reveal {
        Granted,
        NotGranted,
        CliToken,
    }

    /// The app's side of the pipe, with its rules restated: a grant is what
    /// makes a read succeed, and one reveal request is what the app audits.
    struct FakePipe {
        reveal: Reveal,
        requests: Mutex<Vec<Value>>,
    }

    impl FakePipe {
        fn new(reveal: Reveal) -> FakePipe {
            FakePipe {
                reveal,
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<Value> {
            self.requests.lock().expect("requests").clone()
        }
    }

    const SECRET: &str = "correct-horse-battery-staple";

    impl Backend for FakePipe {
        fn call(&self, request: &Value) -> Result<Value, PipeError> {
            self.requests.lock().expect("requests").push(request.clone());
            match request["op"].as_str() {
                Some("secrets.list") => Ok(json!({
                    "ok": true,
                    "items": [{
                        "id": "item-1",
                        "title": "Deploy target",
                        "fields": [
                            { "id": "field-1", "label": "username", "kind": "username" },
                            { "id": "field-2", "label": "password", "kind": "password" }
                        ]
                    }]
                })),
                Some("items.reveal") => match self.reveal {
                    Reveal::Granted => Ok(json!({ "ok": true, "value": SECRET })),
                    Reveal::NotGranted => Ok(json!({
                        "ok": false,
                        "error": "not_granted",
                        "message": "this client has no grant for that field",
                    })),
                    Reveal::CliToken => Ok(json!({
                        "ok": false,
                        "error": "unauthorized",
                        "message": "token is not paired",
                    })),
                },
                other => Ok(json!({
                    "ok": false,
                    "error": "unknown_op",
                    "message": format!("unknown operation: {other:?}"),
                })),
            }
        }
    }

    fn server<'a>(pipe: &'a FakePipe) -> Server<'a> {
        Server::new(TOKEN.to_string(), pipe)
    }

    fn ask(server: &mut Server<'_>, message: Value) -> Value {
        let line = serde_json::to_vec(&message).expect("message json");
        server
            .handle_line(&line)
            .unwrap_or_else(|| panic!("expected a response to {message}"))
    }

    fn call(server: &mut Server<'_>, id: i64, name: &str, arguments: Value) -> Value {
        ask(
            server,
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": { "name": name, "arguments": arguments },
            }),
        )
    }

    #[test]
    fn initialize_echoes_the_client_identity_and_advertises_tools() {
        let pipe = FakePipe::new(Reveal::Granted);
        let mut server = server(&pipe);
        let response = ask(
            &mut server,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "test-client", "version": "1.2.3" }
                }
            }),
        );
        let result = &response["result"];
        assert_eq!(response["jsonrpc"], json!("2.0"));
        assert_eq!(response["id"], json!(1));
        assert_eq!(result["protocolVersion"], json!(LATEST_PROTOCOL));
        assert_eq!(result["capabilities"]["tools"]["listChanged"], json!(false));
        assert_eq!(result["serverInfo"]["name"], json!("kestrel-mcp"));
        assert_eq!(result["clientInfo"]["name"], json!("test-client"));
        assert_eq!(result["clientInfo"]["version"], json!("1.2.3"));
        assert!(result["instructions"].as_str().is_some());
        // No tools are called during a handshake, so the app saw nothing.
        assert!(pipe.requests().is_empty());
    }

    #[test]
    fn initialize_honours_a_supported_older_revision_and_falls_back_otherwise() {
        let pipe = FakePipe::new(Reveal::Granted);
        let mut server = server(&pipe);
        for (offered, expected) in [
            ("2024-11-05", "2024-11-05"),
            ("2025-06-18", "2025-06-18"),
            ("1999-01-01", LATEST_PROTOCOL),
        ] {
            let response = ask(
                &mut server,
                json!({
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "initialize",
                    "params": { "protocolVersion": offered }
                }),
            );
            assert_eq!(response["result"]["protocolVersion"], json!(expected), "{offered}");
        }
    }

    #[test]
    fn the_initialized_notification_gets_no_response() {
        let pipe = FakePipe::new(Reveal::Granted);
        let mut server = server(&pipe);
        let line = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        assert!(server.handle_line(line).is_none());
        // ...and the next request is still answered normally.
        let response = ask(
            &mut server,
            json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        );
        assert!(response.get("result").is_some());
    }

    #[test]
    fn tools_list_is_exactly_the_two_tools() {
        let pipe = FakePipe::new(Reveal::Granted);
        let mut server = server(&pipe);
        let response = ask(
            &mut server,
            json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" }),
        );
        let tools = response["result"]["tools"]
            .as_array()
            .expect("tools array");
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().expect("tool name"))
            .collect();
        assert_eq!(names, vec!["list_secrets", "get_secret"]);
        let schema = &tools[1]["inputSchema"];
        assert_eq!(schema["type"], json!("object"));
        assert_eq!(schema["required"], json!(["id", "field"]));
        assert_eq!(schema["properties"]["id"]["type"], json!("string"));
        assert_eq!(schema["properties"]["field"]["type"], json!("string"));
        // No tool advertises a value-shaped output property.
        for tool in tools {
            let serialised = tool.to_string();
            assert!(!serialised.contains("\"value\""), "{serialised}");
        }
    }

    #[test]
    fn list_secrets_returns_names_and_no_value() {
        let pipe = FakePipe::new(Reveal::Granted);
        let mut server = server(&pipe);
        let response = call(&mut server, 4, "list_secrets", json!({}));
        assert!(response.get("error").is_none(), "{response}");
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("item-1"));
        assert!(text.contains("Deploy target"));
        assert!(text.contains("field-2"));
        assert!(text.contains("password"));
        assert!(!text.contains(SECRET), "list leaked a value: {text}");

        let requests = pipe.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["op"], json!("secrets.list"));
        assert_eq!(requests[0]["token"], json!(TOKEN));
        assert!(
            !requests.iter().any(|request| request["op"] == json!("items.reveal")),
            "listing must never reveal: {requests:?}"
        );
    }

    #[test]
    fn get_secret_with_a_grant_returns_the_value_and_one_reveal_request() {
        let pipe = FakePipe::new(Reveal::Granted);
        let mut server = server(&pipe);
        let response = call(
            &mut server,
            5,
            "get_secret",
            json!({ "id": "item-1", "field": "field-2" }),
        );
        assert_eq!(
            response["result"]["content"][0]["text"],
            json!(SECRET),
            "the value is the tool's answer, once"
        );
        assert!(response["result"].get("isError").is_none());

        // Exactly one reveal went to the app — and that call is what the app
        // audits before it answers — carrying the token, item and field.
        let requests = pipe.requests();
        assert_eq!(requests.len(), 1, "{requests:?}");
        assert_eq!(
            requests[0],
            json!({
                "op": "items.reveal",
                "token": TOKEN,
                "id": "item-1",
                "field": "field-2",
            })
        );
    }

    #[test]
    fn get_secret_without_a_grant_is_a_tool_error_with_no_value() {
        let pipe = FakePipe::new(Reveal::NotGranted);
        let mut server = server(&pipe);
        let response = call(
            &mut server,
            6,
            "get_secret",
            json!({ "id": "item-1", "field": "field-1" }),
        );
        assert_eq!(response["result"]["isError"], json!(true));
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("not_granted"), "{text}");
        assert!(!text.contains(SECRET));
        assert_eq!(pipe.requests().len(), 1, "one attempt, nothing more");
    }

    #[test]
    fn a_cli_token_is_refused_and_never_yields_a_value() {
        let pipe = FakePipe::new(Reveal::CliToken);
        let mut server = server(&pipe);
        let response = call(
            &mut server,
            7,
            "get_secret",
            json!({ "id": "item-1", "field": "field-2" }),
        );
        assert_eq!(response["result"]["isError"], json!(true));
        let text = response["result"]["content"][0]["text"]
            .as_str()
            .expect("text content");
        assert!(text.contains("unauthorized"), "{text}");
        assert!(!text.contains(SECRET));
    }

    #[test]
    fn an_unknown_tool_is_a_jsonrpc_error_and_the_server_keeps_going() {
        let pipe = FakePipe::new(Reveal::Granted);
        let mut server = server(&pipe);
        let response = call(&mut server, 8, "delete_everything", json!({}));
        assert_eq!(response["error"]["code"], json!(INVALID_PARAMS));
        assert!(response["error"]["message"]
            .as_str()
            .expect("message")
            .contains("delete_everything"));
        assert!(response.get("result").is_none());

        // The same server instance answers the next message.
        let next = ask(
            &mut server,
            json!({ "jsonrpc": "2.0", "id": 9, "method": "ping" }),
        );
        assert_eq!(next["result"], json!({}));
    }

    #[test]
    fn missing_arguments_are_invalid_params_not_a_crash() {
        let pipe = FakePipe::new(Reveal::Granted);
        let mut server = server(&pipe);
        for arguments in [
            json!({}),
            json!({ "id": "item-1" }),
            json!({ "id": "", "field": "field-2" }),
            json!({ "id": 7, "field": "field-2" }),
        ] {
            let response = call(&mut server, 10, "get_secret", arguments.clone());
            assert_eq!(
                response["error"]["code"],
                json!(INVALID_PARAMS),
                "{arguments}"
            );
        }
        assert!(pipe.requests().is_empty(), "nothing reached the app");
    }

    #[test]
    fn malformed_messages_are_coded_errors() {
        let pipe = FakePipe::new(Reveal::Granted);
        let mut server = server(&pipe);
        for (line, code) in [
            (b"{".as_slice(), PARSE_ERROR),
            (b"[]".as_slice(), INVALID_REQUEST),
            (b"42".as_slice(), INVALID_REQUEST),
            (br#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#.as_slice(), INVALID_REQUEST),
            (br#"{"jsonrpc":"2.0","id":1}"#.as_slice(), INVALID_REQUEST),
        ] {
            let response = server.handle_line(line).expect("an error response");
            assert_eq!(response["error"]["code"], json!(code), "{line:?}");
            assert_eq!(response["jsonrpc"], json!("2.0"));
        }
        // An unknown method is a JSON-RPC method-not-found, not a crash.
        let response = ask(
            &mut server,
            json!({ "jsonrpc": "2.0", "id": 11, "method": "resources/list" }),
        );
        assert_eq!(response["error"]["code"], json!(METHOD_NOT_FOUND));
    }

    #[test]
    fn the_stdio_loop_writes_one_line_per_request() {
        let pipe = FakePipe::new(Reveal::Granted);
        let input = [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_secret","arguments":{"id":"item-1","field":"field-2"}}}"#,
        ]
        .join("\r\n");
        let mut reader = std::io::Cursor::new(format!("{input}\r\n").into_bytes());
        let mut output = Vec::new();
        serve(&mut reader, &mut output, TOKEN.to_string(), &pipe).expect("serve");

        let text = String::from_utf8(output).expect("utf-8");
        let lines: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).expect("each line is one message"))
            .collect();
        assert_eq!(lines.len(), 3, "the notification produced no line: {text}");
        assert_eq!(lines[0]["id"], json!(1));
        assert_eq!(lines[1]["id"], json!(2));
        assert_eq!(lines[2]["result"]["content"][0]["text"], json!(SECRET));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn an_overlong_line_is_refused_and_the_loop_recovers() {
        let pipe = FakePipe::new(Reveal::Granted);
        let mut input = vec![b' '; MAX_LINE + 10];
        input.push(b'\n');
        input.extend_from_slice(br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#);
        input.push(b'\n');
        let mut reader = std::io::Cursor::new(input);
        let mut output = Vec::new();
        serve(&mut reader, &mut output, TOKEN.to_string(), &pipe).expect("serve");

        let lines: Vec<Value> = String::from_utf8(output)
            .expect("utf-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("json"))
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["error"]["code"], json!(INVALID_REQUEST));
        assert_eq!(lines[1]["result"], json!({}));
    }
}
