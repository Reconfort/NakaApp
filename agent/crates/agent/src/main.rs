//! `serveros-agent` — command line entry point.
//!
//! Subcommands:
//!
//! ```text
//!   serve      run the agent (what systemd starts)
//!   enroll     mint this server's identity and print the enrollment bundle
//!   status     ask a running agent how it is, over the local Unix socket
//!   config     print the effective configuration
//!   version    print version information
//! ```

use serveros_agent::{VERSION, activity, api, auth, config, enroll, logging, state};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("serve");

    let config_path = flag_value(&args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(config::DEFAULT_CONFIG_PATH));

    match command {
        "serve" => cmd_serve(&config_path),
        "enroll" => cmd_enroll(&config_path, args.iter().any(|a| a == "--force")),
        "status" => cmd_status(&config_path),
        "config" => cmd_config(&config_path),
        "version" | "--version" | "-V" => {
            println!("serveros-agent {VERSION} (api v{})", serveros_agent::API_VERSION);
            ExitCode::SUCCESS
        }
        "help" | "--help" | "-h" => {
            print_usage();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("serveros-agent: unknown command '{other}'\n");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!(
        "ServerOS agent {VERSION}

USAGE:
    serveros-agent <COMMAND> [--config <PATH>]

COMMANDS:
    serve       Run the agent. This is what the systemd unit starts.
    enroll      Generate this server's identity and print its enrollment bundle.
                Add --force to replace an existing key (disconnects any Mac
                currently paired with this server).
    status      Query a running agent over its local Unix socket.
    config      Print the effective configuration as JSON.
    version     Print version information.

The agent listens on loopback and a Unix socket only. It is reached from the
ServerOS desktop app through an SSH-forwarded port; see docs/SECURITY.md."
    );
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    let idx = args.iter().position(|a| a == name)?;
    args.get(idx + 1).cloned()
}

fn cmd_serve(config_path: &std::path::Path) -> ExitCode {
    let config = match config::Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("serveros-agent: {e}");
            return ExitCode::from(78); // EX_CONFIG
        }
    };
    logging::set_level(config.log_level);

    let secret = match auth::load_secret(&config.key_path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "serveros-agent: this server is not enrolled yet ({} does not exist).\n\
                 Run `serveros-agent enroll` first, or re-run the ServerOS installer.",
                config.key_path.display()
            );
            return ExitCode::from(78);
        }
        Err(e) => {
            eprintln!("serveros-agent: cannot read the agent key: {e}");
            return ExitCode::from(77); // EX_NOPERM
        }
    };

    if config.binds_publicly() {
        // Loud, every start, forever. An operator who chose this should keep
        // being reminded that they did.
        logging::warn_with(
            "agent is bound to a routable address; it is reachable from the network",
            serveros_json::Object::new().set("bind", config.bind.to_string()),
        );
    }

    let server_config = serveros_http::ServerConfig {
        port: config.port,
        bind: config.bind,
        unix_socket: config.unix_socket.clone(),
        idle_timeout: std::time::Duration::from_secs(120),
        read_timeout: std::time::Duration::from_secs(30),
        max_connections: config.max_connections,
        spool_dir: config.spool_dir(),
    };

    let state = Arc::new(state::AgentState::new(config, secret));
    state.activity.record(
        activity::Event::new("agent.start", "agent", &state.config.server_id)
            .actor("system")
            .summary(format!("ServerOS agent {VERSION} started")),
    );

    let router = api::build_router();
    logging::info_with(
        "agent listening",
        serveros_json::Object::new()
            .set("version", VERSION)
            .set("routes", router.len())
            .set_opt("port", state.config.port)
            .set_opt(
                "unix_socket",
                state.config.unix_socket.as_ref().map(|p| p.display().to_string()),
            )
            .set("capabilities", state.capabilities()),
    );

    let server = serveros_http::Server::new(server_config, router, state);
    match server.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            logging::error(&format!("agent stopped: {e}"));
            ExitCode::FAILURE
        }
    }
}

fn cmd_enroll(config_path: &std::path::Path, force: bool) -> ExitCode {
    match enroll::enroll(config_path, force) {
        Ok(e) => {
            // This single line is what the installer captures over SSH. Nothing
            // else may be written to stdout by this command.
            println!("{}", e.bundle_line());
            eprintln!(
                "Enrolled as {}. The key is at {} and is readable only by root.",
                e.server_id,
                config::Config::load(config_path)
                    .map(|c| c.key_path.display().to_string())
                    .unwrap_or_else(|_| config::DEFAULT_KEY_PATH.into())
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("serveros-agent: enrollment failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_status(config_path: &std::path::Path) -> ExitCode {
    let config = match config::Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("serveros-agent: {e}");
            return ExitCode::from(78);
        }
    };

    let Some(socket) = config.unix_socket.clone() else {
        eprintln!("serveros-agent: no Unix socket is configured, so status cannot be queried locally");
        return ExitCode::FAILURE;
    };

    let client = serveros_http::client::HttpClient::unix(&socket);
    match client.get("/v1/health") {
        Ok(resp) if resp.is_success() => {
            println!("{}", resp.json().map(|v| v.to_string_pretty()).unwrap_or_else(|e| e));
            ExitCode::SUCCESS
        }
        Ok(resp) => {
            eprintln!("serveros-agent: agent replied {} — {}", resp.status, resp.text());
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!(
                "serveros-agent: cannot reach the agent on {}: {e}\n\
                 Is it running?  systemctl status serveros-agent",
                socket.display()
            );
            ExitCode::FAILURE
        }
    }
}

fn cmd_config(config_path: &std::path::Path) -> ExitCode {
    match config::Config::load(config_path) {
        Ok(c) => {
            println!("{}", c.to_json().to_string_pretty());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("serveros-agent: {e}");
            ExitCode::from(78)
        }
    }
}
