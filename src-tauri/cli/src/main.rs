//! `kestrel-cli` — a terminal client for the Kestrel automation pipe.
//!
//! It is a pipe client and nothing else: no vault code is linked into this
//! binary, so the only way to reach a secret is through the server's own
//! `items.copy` and `run` ops, which never return a value.
//!
//! Exit codes are stable so scripts can branch on them: 0 ok, 2 usage,
//! 3 vault locked, 4 not paired, 5 server error. A successful `run` exits with
//! the child's code.

use serde::Serialize;
use serde_json::{json, Map, Value};
use std::io::{BufRead, BufReader, Write};

const PIPE_PATH: &str = r"\\.\pipe\kestrel-sdk";
const TOKEN_ENV: &str = "KESTREL_TOKEN";

const EXIT_OK: i32 = 0;
const EXIT_USAGE: i32 = 2;
const EXIT_LOCKED: i32 = 3;
const EXIT_NOT_PAIRED: i32 = 4;
const EXIT_SERVER: i32 = 5;

const USAGE: &str = "\
usage: kestrel-cli [--token <token>] <command>

commands:
  status                                  pipe, pairing and vault state
  list                                    item metadata (id, category, title)
  copy --id <item> --field <field>        copy a field with the core's timed wipe
  run [--env <item>:<field>=<VAR>]... -- <command> [args...]
                                          run a command with vault values in its
                                          environment

The token comes from --token or KESTREL_TOKEN; pair a CLI in Settings →
Developer. Exit codes: 0 ok, 2 usage, 3 vault locked, 4 not paired, 5 server
error. `run` exits with the child's code when the request itself succeeded.";

/// One `--env` binding, parsed from `<item>:<field>=<VAR>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct EnvSpec {
    id: String,
    field: String,
    #[serde(rename = "as")]
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Help,
    Status,
    List,
    Copy {
        id: String,
        field: String,
    },
    Run {
        env: Vec<EnvSpec>,
        argv: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    token: Option<String>,
    command: Command,
}

fn main() {
    std::process::exit(execute(std::env::args().skip(1).collect()));
}

fn execute(args: Vec<String>) -> i32 {
    let cli = match parse(&args) {
        Ok(cli) => cli,
        Err(message) => {
            eprintln!("kestrel-cli: {message}\n\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    if cli.command == Command::Help {
        println!("{USAGE}");
        return EXIT_OK;
    }
    let token = cli
        .token
        .or_else(|| std::env::var(TOKEN_ENV).ok())
        .filter(|token| !token.is_empty());
    let request = request_for(&cli.command, token.as_deref());
    match round_trip(&request) {
        Ok(response) => print_response(&cli.command, &response),
        Err(message) => {
            eprintln!("kestrel-cli: {message}");
            EXIT_SERVER
        }
    }
}

/* -------------------------------------------------------------------- parse */

fn parse(args: &[String]) -> Result<Cli, String> {
    let mut index = 0;
    let mut token = None;
    // Only `--token` and `--help` may precede the command; everything after it
    // belongs to the command (and, for `run`, to the child after `--`).
    while index < args.len() {
        match args[index].as_str() {
            "--token" => {
                let value = value_at(args, index, "--token")?;
                if value.is_empty() {
                    return Err("--token must not be empty".into());
                }
                token = Some(value.to_string());
                index += 2;
            }
            "--help" | "-h" => {
                return Ok(Cli {
                    token,
                    command: Command::Help,
                })
            }
            arg if arg.starts_with('-') => {
                return Err(format!("unknown option {arg} (try --help)"));
            }
            _ => break,
        }
    }

    let name = args
        .get(index)
        .ok_or_else(|| "missing command (try --help)".to_string())?;
    let rest = &args[index + 1..];
    let command = match name.as_str() {
        "status" => {
            no_arguments(rest, "status")?;
            Command::Status
        }
        "list" => {
            no_arguments(rest, "list")?;
            Command::List
        }
        "copy" => parse_copy(rest)?,
        "run" => parse_run(rest)?,
        other => return Err(format!("unknown command {other}")),
    };
    Ok(Cli { token, command })
}

fn no_arguments(args: &[String], command: &str) -> Result<(), String> {
    match args.first() {
        Some(extra) => Err(format!("{command} takes no arguments, got {extra}")),
        None => Ok(()),
    }
}

fn value_at<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index + 1)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} needs a value"))
}

fn parse_copy(args: &[String]) -> Result<Command, String> {
    let mut id = None;
    let mut field = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--id" => {
                id = Some(value_at(args, index, "--id")?.to_string());
                index += 2;
            }
            "--field" => {
                field = Some(value_at(args, index, "--field")?.to_string());
                index += 2;
            }
            other => return Err(format!("copy: unexpected argument {other}")),
        }
    }
    Ok(Command::Copy {
        id: id
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "copy needs --id <item>".to_string())?,
        field: field
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "copy needs --field <field>".to_string())?,
    })
}

fn parse_run(args: &[String]) -> Result<Command, String> {
    let mut env = Vec::new();
    let mut argv = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--env" => {
                env.push(parse_env_spec(value_at(args, index, "--env")?)?);
                index += 2;
            }
            "--" => {
                argv = Some(args[index + 1..].to_vec());
                break;
            }
            other => return Err(format!("run: expected --env or -- before {other}")),
        }
    }
    let argv = argv.ok_or_else(|| "run needs `-- <command> [args...]`".to_string())?;
    if argv.is_empty() {
        return Err("run needs a command after --".into());
    }
    Ok(Command::Run { env, argv })
}

/// `<item>:<field>=<VAR>`. The variable name is validated by the server; the
/// CLI only checks the shape it cannot send otherwise.
fn parse_env_spec(raw: &str) -> Result<EnvSpec, String> {
    let (target, name) = raw
        .rsplit_once('=')
        .ok_or_else(|| format!("--env {raw:?} needs the form <item>:<field>=<VAR>"))?;
    let (id, field) = target
        .split_once(':')
        .ok_or_else(|| format!("--env {raw:?} needs the form <item>:<field>=<VAR>"))?;
    if id.is_empty() || field.is_empty() || name.is_empty() {
        return Err(format!("--env {raw:?} has an empty part"));
    }
    // The server validates this too; failing here keeps a typo a usage error
    // (exit 2) instead of a round trip that ends as a server error.
    let mut chars = name.chars();
    let valid_start = chars
        .next()
        .is_some_and(|c| c.is_ascii_uppercase() || c == '_');
    let valid_rest = chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if !valid_start || !valid_rest {
        return Err(format!(
            "--env {raw:?}: {name:?} is not a valid environment name"
        ));
    }
    Ok(EnvSpec {
        id: id.to_string(),
        field: field.to_string(),
        name: name.to_string(),
    })
}

/* ------------------------------------------------------------------- wire */

fn request_for(command: &Command, token: Option<&str>) -> Value {
    let op = match command {
        Command::Status => "status",
        Command::List => "items.list",
        Command::Copy { .. } => "items.copy",
        Command::Run { .. } => "run",
        // Help never reaches the pipe.
        Command::Help => return Value::Null,
    };
    let mut object = Map::new();
    object.insert("op".into(), Value::String(op.into()));
    if let Some(token) = token {
        object.insert("token".into(), Value::String(token.into()));
    }
    match command {
        Command::Copy { id, field } => {
            object.insert("id".into(), Value::String(id.clone()));
            object.insert("field".into(), Value::String(field.clone()));
        }
        Command::Run { env, argv } => {
            object.insert("argv".into(), json!(argv));
            if !env.is_empty() {
                object.insert(
                    "env".into(),
                    serde_json::to_value(env).expect("env bindings serialise"),
                );
            }
        }
        _ => {}
    }
    Value::Object(object)
}

/// Open the pipe, waiting out `ERROR_PIPE_BUSY`.
///
/// The server creates the next instance only after a client has connected, so
/// two CLI processes started together can find no free instance for a moment.
/// A busy pipe is not an error; it is a millisecond of scheduling.
fn open_pipe() -> Result<std::fs::File, String> {
    const ERROR_PIPE_BUSY: i32 = 231;
    for attempt in 0..20 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(PIPE_PATH)
        {
            Ok(stream) => return Ok(stream),
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                std::thread::sleep(std::time::Duration::from_millis(50 * (attempt + 1)));
            }
            Err(error) => {
                return Err(format!(
                    "cannot open {PIPE_PATH}: {error} — is Kestrel running?"
                ))
            }
        }
    }
    Err(format!(
        "cannot open {PIPE_PATH}: every instance stayed busy — is another client running?"
    ))
}

fn round_trip(request: &Value) -> Result<Value, String> {
    let stream = open_pipe()?;
    let mut writer = &stream;
    let mut line = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    line.push(b'\n');
    writer
        .write_all(&line)
        .map_err(|error| format!("cannot send the request: {error}"))?;
    writer.flush().ok();

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|error| format!("cannot read the response: {error}"))?;
    if response.trim().is_empty() {
        return Err("the server closed the pipe without a response".into());
    }
    serde_json::from_str(&response).map_err(|error| format!("malformed response: {error}"))
}

/* ----------------------------------------------------------------- output */

fn print_response(command: &Command, response: &Value) -> i32 {
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        let code = response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("internal");
        let message = response
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or(code);
        eprintln!("kestrel-cli: {message} ({code})");
        return match code {
            "locked" => EXIT_LOCKED,
            "unauthorized" => EXIT_NOT_PAIRED,
            _ => EXIT_SERVER,
        };
    }

    match command {
        Command::Status => {
            println!("pipe:     {}", text(response, "pipe"));
            println!("running:  {}", yes_no(response, "running"));
            println!("paired:   {}", yes_no(response, "paired"));
            println!("unlocked: {}", yes_no(response, "unlocked"));
            EXIT_OK
        }
        Command::List => {
            let items = response
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if items.is_empty() {
                println!("No items.");
            }
            for item in &items {
                println!(
                    "{}  {:<16}  {}",
                    text(item, "id"),
                    text(item, "category"),
                    text(item, "title")
                );
            }
            EXIT_OK
        }
        Command::Copy { id, field } => {
            println!("Copied {field} from {id} to the clipboard; the vault's timer clears it.");
            EXIT_OK
        }
        Command::Run { .. } => {
            if let Some(stdout) = response.get("stdout").and_then(Value::as_str) {
                print!("{stdout}");
            }
            if let Some(stderr) = response.get("stderr").and_then(Value::as_str) {
                eprint!("{stderr}");
            }
            if response.get("truncated").and_then(Value::as_bool) == Some(true) {
                eprintln!("kestrel-cli: output was truncated by the server");
            }
            match response.get("exitCode").and_then(Value::as_i64) {
                Some(code) => code as i32,
                None => EXIT_SERVER,
            }
        }
        Command::Help => EXIT_OK,
    }
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn yes_no(value: &Value, key: &str) -> &'static str {
    match value.get(key).and_then(Value::as_bool) {
        Some(true) => "yes",
        _ => "no",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn parses_status_and_list() {
        assert_eq!(
            parse(&args("status")).expect("status"),
            Cli {
                token: None,
                command: Command::Status
            }
        );
        assert_eq!(parse(&args("list")).expect("list").command, Command::List);
        assert!(parse(&args("status extra")).is_err());
    }

    #[test]
    fn parses_copy_in_either_flag_order() {
        let expected = Command::Copy {
            id: "item-1".into(),
            field: "field-2".into(),
        };
        assert_eq!(
            parse(&args("copy --id item-1 --field field-2"))
                .expect("copy")
                .command,
            expected
        );
        assert_eq!(
            parse(&args("copy --field field-2 --id item-1"))
                .expect("copy")
                .command,
            expected
        );
        assert!(
            parse(&args("copy --id item-1")).is_err(),
            "field is required"
        );
        assert!(parse(&args("copy --id item-1 --bogus x")).is_err());
    }

    #[test]
    fn parses_run_with_bindings_and_the_command_boundary() {
        let cli = parse(&args(
            "run --env item-1:field-2=DB_PASSWORD --env item-1:field-3=DB_USER -- psql --db dev",
        ))
        .expect("run");
        let Command::Run { env, argv } = cli.command else {
            panic!("expected a run command");
        };
        assert_eq!(
            env,
            vec![
                EnvSpec {
                    id: "item-1".into(),
                    field: "field-2".into(),
                    name: "DB_PASSWORD".into()
                },
                EnvSpec {
                    id: "item-1".into(),
                    field: "field-3".into(),
                    name: "DB_USER".into()
                },
            ]
        );
        assert_eq!(argv, vec!["psql", "--db", "dev"]);
    }

    #[test]
    fn run_requires_the_boundary_and_a_command() {
        assert!(parse(&args("run echo hi")).is_err());
        assert!(parse(&args("run --")).is_err());
        assert!(parse(&args("run --env item-1:field-2=VAR")).is_err());
        assert!(parse(&args("run --env bad=VAR -- cmd")).is_err());
        assert!(parse(&args("run --env item-1:field-2= -- cmd")).is_err());
    }

    #[test]
    fn token_precedes_the_command_only() {
        let cli = parse(&args("--token abc123 list")).expect("token + list");
        assert_eq!(cli.token.as_deref(), Some("abc123"));
        assert_eq!(cli.command, Command::List);

        // A token-shaped argument after `run --` belongs to the child.
        let cli = parse(&args("run -- cmd --token nope")).expect("child args");
        let Command::Run { argv, .. } = cli.command else {
            panic!("expected a run command");
        };
        assert_eq!(argv, vec!["cmd", "--token", "nope"]);
    }

    #[test]
    fn help_and_unknown_commands() {
        assert_eq!(parse(&args("--help")).expect("help").command, Command::Help);
        assert_eq!(parse(&args("-h")).expect("help").command, Command::Help);
        assert!(parse(&args("delete")).is_err());
        assert!(parse(&args("--bogus list")).is_err());
        assert!(parse(&args("")).is_err());
    }

    #[test]
    fn request_bodies_match_the_protocol() {
        let run = request_for(
            &Command::Run {
                env: vec![EnvSpec {
                    id: "i".into(),
                    field: "f".into(),
                    name: "VAR".into(),
                }],
                argv: vec!["cmd".into(), "/c".into()],
            },
            Some("tok"),
        );
        assert_eq!(run["op"], json!("run"));
        assert_eq!(run["token"], json!("tok"));
        assert_eq!(run["argv"], json!(["cmd", "/c"]));
        assert_eq!(run["env"], json!([{"id":"i","field":"f","as":"VAR"}]));

        let status = request_for(&Command::Status, None);
        assert_eq!(status, json!({"op": "status"}));

        let copy = request_for(
            &Command::Copy {
                id: "i".into(),
                field: "f".into(),
            },
            Some("tok"),
        );
        assert_eq!(
            copy,
            json!({"op":"items.copy","token":"tok","id":"i","field":"f"})
        );
    }

    #[test]
    fn error_codes_map_to_exit_codes() {
        assert_eq!(
            print_response(
                &Command::List,
                &json!({"ok":false,"error":"locked","message":"vault is locked"})
            ),
            EXIT_LOCKED
        );
        assert_eq!(
            print_response(
                &Command::List,
                &json!({"ok":false,"error":"unauthorized","message":"no token"})
            ),
            EXIT_NOT_PAIRED
        );
        assert_eq!(
            print_response(
                &Command::List,
                &json!({"ok":false,"error":"unknown_op","message":"no"})
            ),
            EXIT_SERVER
        );
    }

    #[test]
    fn run_output_propagates_the_child_exit_code() {
        assert_eq!(
            print_response(
                &Command::Run {
                    env: Vec::new(),
                    argv: vec!["cmd".into()]
                },
                &json!({"ok":true,"exitCode":7,"stdout":"","stderr":""})
            ),
            7
        );
    }
}
