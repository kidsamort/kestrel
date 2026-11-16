//! `kestrel-sync` — the self-hostable sync service.
//!
//! Configuration comes from the environment; see `PROTOCOL.md` and
//! `deploy/README.md`. Exit codes: 0 clean shutdown, 2 bad configuration,
//! 3 the database or the listener could not be opened. A runtime failure after
//! a successful start is also 3, because the process is no longer serving.

use std::process::ExitCode;

use kestrel_sync::{Config, Server};

const EXIT_CONFIG: u8 = 2;
const EXIT_RUNTIME: u8 = 3;

#[tokio::main]
async fn main() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("kestrel-sync: {error}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };

    let server = match Server::bind(config.clone()).await {
        Ok(server) => server,
        Err(error) => {
            eprintln!("kestrel-sync: {error}");
            return ExitCode::from(EXIT_RUNTIME);
        }
    };

    eprintln!(
        "kestrel-sync: listening on http://{} (database {}, blobs {}, max body {} bytes, max accounts {})",
        server.local_addr(),
        config.db_path.display(),
        config.blob_dir.display(),
        config.max_body,
        if config.max_accounts == 0 {
            "unlimited".to_string()
        } else {
            config.max_accounts.to_string()
        }
    );

    let shutdown = async {
        #[cfg(unix)]
        {
            // `docker stop` sends SIGTERM; `ctrl_c` alone would let the process
            // die mid-request. SQLite would survive it, but a clean exit is
            // cheaper to reason about.
            let mut terminate = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ) {
                Ok(signal) => signal,
                Err(error) => {
                    eprintln!("kestrel-sync: could not listen for SIGTERM: {error}");
                    let _ = tokio::signal::ctrl_c().await;
                    return;
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            if let Err(error) = tokio::signal::ctrl_c().await {
                eprintln!("kestrel-sync: could not listen for ctrl-c: {error}");
            }
        }
        eprintln!("kestrel-sync: shutting down");
    };

    match server.run(shutdown).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kestrel-sync: {error}");
            ExitCode::from(EXIT_RUNTIME)
        }
    }
}
