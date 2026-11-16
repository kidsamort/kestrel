//! `kestrel-mcp` — MCP (Model Context Protocol) server for Kestrel secrets.
//!
//! It is a pipe client and nothing else: no vault code is linked in, and the
//! only way to reach a value is `items.reveal`, which the app answers only when
//! the token's scope is `Mcp` *and* the field was granted when this client was
//! paired in Settings → Developer. The value is written to this process's
//! stdout (the MCP transport) and nowhere else.
//!
//! Transport: MCP 2025-06-18 over stdio, one JSON-RPC message per line.
//! Configuration: `KESTREL_TOKEN` from the pairing card, e.g.
//!
//! ```json
//! {
//!   "mcpServers": {
//!     "kestrel": {
//!       "command": "C:\\path\\to\\kestrel-mcp.exe",
//!       "env": { "KESTREL_TOKEN": "<token>" }
//!     }
//!   }
//! }
//! ```
//!
//! Exit codes: 0 stdin closed, 4 no token, 5 the stdio loop failed.

mod pipe;
mod rpc;

use std::process::ExitCode;

const EXIT_OK: u8 = 0;
const EXIT_NOT_PAIRED: u8 = 4;
const EXIT_TRANSPORT: u8 = 5;

const TOKEN_ENV: &str = "KESTREL_TOKEN";

fn main() -> ExitCode {
    let token = match std::env::var(TOKEN_ENV) {
        Ok(token) if !token.trim().is_empty() => token.trim().to_string(),
        _ => {
            // stderr is not the MCP channel, so this can never be mistaken for
            // a protocol message by the client.
            eprintln!(
                "kestrel-mcp: {TOKEN_ENV} is empty or unset. Pair an MCP client in \
                 Kestrel → Settings → Developer and paste the token into this \
                 server's environment."
            );
            return ExitCode::from(EXIT_NOT_PAIRED);
        }
    };

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    match rpc::serve(&mut input, &mut output, token, &pipe::KestrelPipe) {
        Ok(()) => ExitCode::from(EXIT_OK),
        Err(error) => {
            eprintln!("kestrel-mcp: stdio failed: {error}");
            ExitCode::from(EXIT_TRANSPORT)
        }
    }
}
