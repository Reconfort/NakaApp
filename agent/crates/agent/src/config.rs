//! Agent configuration.
//!
//! Config lives at `/etc/serveros/agent.json` and is deliberately small — an
//! agent with many knobs is an agent that is misconfigured in production.
//!
//! The shared secret is **not** in this file. It lives in a separate
//! `agent.key` with mode 0600 so the config can be read, diffed, backed up and
//! pasted into a support ticket without leaking anything.

use serveros_json::{Object, Value};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/serveros/agent.json";
pub const DEFAULT_KEY_PATH: &str = "/etc/serveros/agent.key";
pub const DEFAULT_PORT: u16 = 8723;

#[derive(Debug, Clone)]
pub struct Config {
    /// Stable identifier for this server, minted at enrollment.
    pub server_id: String,
    pub bind: IpAddr,
    pub port: Option<u16>,
    pub unix_socket: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub key_path: PathBuf,
    pub docker_socket: PathBuf,
    pub log_level: LogLevel,
    pub max_connections: usize,
    /// Must be explicitly true before the agent will bind a routable address.
    pub allow_public_bind: bool,
    /// Directories the file browser may touch. Empty means the whole
    /// filesystem, minus the always-denied set enforced by `serveros-fsops`.
    pub file_roots: Vec<PathBuf>,
    /// Move deletions to a trash directory instead of unlinking.
    pub trash_deletes: bool,
    pub postgres: PostgresConfig,
    /// Seconds between metric samples pushed on the live channel.
    pub metrics_interval_secs: u64,
}

#[derive(Debug, Clone)]
pub struct PostgresConfig {
    pub enabled: bool,
    pub user: String,
    pub database: String,
    pub socket_dir: PathBuf,
    /// A loopback TCP address to use *instead of* the socket.
    ///
    /// The socket is the better default — no TCP stack, no listener to
    /// expose — but it is subject to `peer` authentication, which matches the
    /// connecting process's OS user against the role name. The agent runs as
    /// root, and its role is deliberately not root, so on a stock Ubuntu
    /// `pg_hba.conf` (`local all all peer`) the socket can never work no matter
    /// what password is set. TCP to 127.0.0.1 uses the `host` rules instead,
    /// which are password-based and independent of which user the agent runs
    /// as. `PgHost::Tcp` refuses any address that is not loopback.
    pub host: Option<String>,
    pub port: u16,
    /// Password for the monitoring role, if the role needs one. Read from a
    /// separate file so it never appears in the config or in process listings.
    pub password_file: Option<PathBuf>,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        PostgresConfig {
            enabled: true,
            user: "serveros".into(),
            database: "postgres".into(),
            socket_dir: PathBuf::from("/var/run/postgresql"),
            host: None,
            port: 5432,
            password_file: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
}

impl LogLevel {
    pub fn parse(s: &str) -> Option<LogLevel> {
        Some(match s.to_ascii_lowercase().as_str() {
            "error" => LogLevel::Error,
            "warn" | "warning" => LogLevel::Warn,
            "info" => LogLevel::Info,
            "debug" | "trace" => LogLevel::Debug,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server_id: String::new(),
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: Some(DEFAULT_PORT),
            unix_socket: Some(PathBuf::from("/run/serveros/agent.sock")),
            data_dir: PathBuf::from("/var/lib/serveros"),
            key_path: PathBuf::from(DEFAULT_KEY_PATH),
            docker_socket: PathBuf::from("/var/run/docker.sock"),
            log_level: LogLevel::Info,
            max_connections: 64,
            allow_public_bind: false,
            file_roots: Vec::new(),
            trash_deletes: true,
            postgres: PostgresConfig::default(),
            metrics_interval_secs: 2,
        }
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(String),
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "cannot read configuration: {e}"),
            ConfigError::Parse(m) => write!(f, "configuration is not valid JSON: {m}"),
            ConfigError::Invalid(m) => write!(f, "configuration is invalid: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl Config {
    /// Load from disk, falling back to defaults when the file does not exist.
    ///
    /// A missing config is normal on a fresh install — the agent is usable with
    /// defaults the moment it is enrolled. A *malformed* config is fatal,
    /// because silently ignoring it could mean binding an address or exposing a
    /// path the operator believed they had restricted.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(text) => Config::parse(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(ConfigError::Io(e)),
        }
    }

    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let value = serveros_json::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let obj = value
            .as_object()
            .ok_or_else(|| ConfigError::Invalid("top level must be an object".into()))?;

        let mut cfg = Config::default();

        if let Some(v) = obj.get("server_id").and_then(|v| v.as_str()) {
            cfg.server_id = v.to_string();
        }
        if let Some(v) = obj.get("bind").and_then(|v| v.as_str()) {
            cfg.bind = v
                .parse()
                .map_err(|_| ConfigError::Invalid(format!("bind is not an IP address: {v}")))?;
        }
        match obj.get("port") {
            Some(Value::Null) => cfg.port = None,
            Some(v) => {
                let n = v
                    .as_u64()
                    .ok_or_else(|| ConfigError::Invalid("port must be a number or null".into()))?;
                if n == 0 || n > 65535 {
                    return Err(ConfigError::Invalid(format!("port out of range: {n}")));
                }
                cfg.port = Some(n as u16);
            }
            None => {}
        }
        match obj.get("unix_socket") {
            Some(Value::Null) => cfg.unix_socket = None,
            Some(v) => {
                let s = v
                    .as_str()
                    .ok_or_else(|| ConfigError::Invalid("unix_socket must be a string".into()))?;
                cfg.unix_socket = Some(PathBuf::from(s));
            }
            None => {}
        }
        if let Some(v) = obj.get("data_dir").and_then(|v| v.as_str()) {
            cfg.data_dir = PathBuf::from(v);
        }
        if let Some(v) = obj.get("key_path").and_then(|v| v.as_str()) {
            cfg.key_path = PathBuf::from(v);
        }
        if let Some(v) = obj.get("docker_socket").and_then(|v| v.as_str()) {
            cfg.docker_socket = PathBuf::from(v);
        }
        if let Some(v) = obj.get("log_level").and_then(|v| v.as_str()) {
            cfg.log_level = LogLevel::parse(v)
                .ok_or_else(|| ConfigError::Invalid(format!("unknown log level: {v}")))?;
        }
        if let Some(v) = obj.get("max_connections").and_then(|v| v.as_u64()) {
            // A ceiling of 4 is nonsense and a ceiling of 100 000 is a memory
            // bomb; clamp rather than trusting the file.
            cfg.max_connections = (v as usize).clamp(8, 1024);
        }
        if let Some(v) = obj.get("allow_public_bind").and_then(|v| v.as_bool()) {
            cfg.allow_public_bind = v;
        }
        if let Some(v) = obj.get("trash_deletes").and_then(|v| v.as_bool()) {
            cfg.trash_deletes = v;
        }
        if let Some(arr) = obj.get("file_roots").and_then(|v| v.as_array()) {
            let mut roots = Vec::new();
            for item in arr {
                let s = item.as_str().ok_or_else(|| {
                    ConfigError::Invalid("file_roots entries must be strings".into())
                })?;
                let p = PathBuf::from(s);
                if !p.is_absolute() {
                    return Err(ConfigError::Invalid(format!(
                        "file_roots entries must be absolute paths: {s}"
                    )));
                }
                roots.push(p);
            }
            cfg.file_roots = roots;
        }
        if let Some(v) = obj.get("metrics_interval_secs").and_then(|v| v.as_u64()) {
            cfg.metrics_interval_secs = v.clamp(1, 60);
        }
        if let Some(pg) = obj.get("postgres").and_then(|v| v.as_object()) {
            if let Some(v) = pg.get("enabled").and_then(|v| v.as_bool()) {
                cfg.postgres.enabled = v;
            }
            if let Some(v) = pg.get("user").and_then(|v| v.as_str()) {
                cfg.postgres.user = v.to_string();
            }
            if let Some(v) = pg.get("database").and_then(|v| v.as_str()) {
                cfg.postgres.database = v.to_string();
            }
            if let Some(v) = pg.get("socket_dir").and_then(|v| v.as_str()) {
                cfg.postgres.socket_dir = PathBuf::from(v);
            }
            if let Some(v) = pg.get("host").and_then(|v| v.as_str()) {
                cfg.postgres.host = Some(v.to_string());
            }
            if let Some(v) = pg.get("port").and_then(|v| v.as_u64()) {
                cfg.postgres.port = v.clamp(1, 65535) as u16;
            }
            if let Some(v) = pg.get("password_file").and_then(|v| v.as_str()) {
                cfg.postgres.password_file = Some(PathBuf::from(v));
            }
            // A literal password in the config would end up in backups and
            // support tickets. Refuse it loudly rather than accepting it.
            if pg.contains_key("password") {
                return Err(ConfigError::Invalid(
                    "postgres.password is not supported; use postgres.password_file so the \
                     credential is not stored in a world-readable config"
                        .into(),
                ));
            }
        }

        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.port.is_none() && self.unix_socket.is_none() {
            return Err(ConfigError::Invalid(
                "at least one of port or unix_socket must be configured".into(),
            ));
        }
        if !self.bind.is_loopback() && !self.allow_public_bind {
            return Err(ConfigError::Invalid(format!(
                "refusing to bind {} because allow_public_bind is not set. The agent is designed \
                 to be reached through an SSH-forwarded port; binding a routable address exposes \
                 it to the network",
                self.bind
            )));
        }
        Ok(())
    }

    /// Round-trip the config back to JSON, for `serveros-agent config show`.
    pub fn to_json(&self) -> Value {
        let pg = Object::new()
            .set("enabled", self.postgres.enabled)
            .set("user", self.postgres.user.as_str())
            .set("database", self.postgres.database.as_str())
            .set("socket_dir", self.postgres.socket_dir.display().to_string())
            .set("port", self.postgres.port)
            .set_opt(
                "password_file",
                self.postgres.password_file.as_ref().map(|p| p.display().to_string()),
            );

        Object::new()
            .set("server_id", self.server_id.as_str())
            .set("bind", self.bind.to_string())
            .set_opt("port", self.port)
            .set_opt("unix_socket", self.unix_socket.as_ref().map(|p| p.display().to_string()))
            .set("data_dir", self.data_dir.display().to_string())
            .set("key_path", self.key_path.display().to_string())
            .set("docker_socket", self.docker_socket.display().to_string())
            .set("log_level", self.log_level.as_str())
            .set("max_connections", self.max_connections)
            .set("allow_public_bind", self.allow_public_bind)
            .set("trash_deletes", self.trash_deletes)
            .set(
                "file_roots",
                Value::Array(
                    self.file_roots.iter().map(|p| Value::from(p.display().to_string())).collect(),
                ),
            )
            .set("metrics_interval_secs", self.metrics_interval_secs)
            .set("postgres", pg)
            .into()
    }

    /// Whether this configuration puts the agent on a routable address.
    ///
    /// `validate` already refuses that unless `allow_public_bind` is set, so
    /// reaching here means an operator asked for it deliberately — and the
    /// agent warns about it on every start rather than only once.
    pub fn binds_publicly(&self) -> bool {
        !self.bind.is_loopback()
    }

    pub fn activity_log_path(&self) -> PathBuf {
        self.data_dir.join("activity.jsonl")
    }

    pub fn spool_dir(&self) -> PathBuf {
        self.data_dir.join("spool")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_loopback_only() {
        let c = Config::default();
        assert!(c.bind.is_loopback());
        assert!(!c.allow_public_bind);
        assert_eq!(c.port, Some(DEFAULT_PORT));
    }

    #[test]
    fn missing_file_yields_defaults() {
        let c = Config::load(Path::new("/nonexistent/serveros/agent.json")).unwrap();
        assert_eq!(c.port, Some(DEFAULT_PORT));
    }

    #[test]
    fn parses_a_full_config() {
        let c = Config::parse(
            r#"{"server_id":"srv_1","bind":"127.0.0.1","port":9000,
                "unix_socket":"/tmp/a.sock","data_dir":"/var/lib/x","log_level":"debug",
                "max_connections":32,"file_roots":["/srv","/var/www"],
                "metrics_interval_secs":5,
                "postgres":{"enabled":false,"user":"pgmon","port":5433}}"#,
        )
        .unwrap();
        assert_eq!(c.server_id, "srv_1");
        assert_eq!(c.port, Some(9000));
        assert_eq!(c.log_level, LogLevel::Debug);
        assert_eq!(c.file_roots.len(), 2);
        assert_eq!(c.metrics_interval_secs, 5);
        assert!(!c.postgres.enabled);
        assert_eq!(c.postgres.port, 5433);
    }

    #[test]
    fn postgres_host_is_read_and_defaults_to_the_socket() {
        // The exact block ServerOS writes when it provisions database access.
        // If this key is ever dropped, the agent silently falls back to the
        // Unix socket, peer authentication rejects it, and the app reports
        // "PostgreSQL rejected these credentials" with no way to tell why.
        let c = Config::parse(
            r#"{"postgres":{"enabled":true,"user":"serveros","host":"127.0.0.1",
                "port":5432,"password_file":"/etc/serveros/postgres.pw"}}"#,
        )
        .unwrap();
        assert_eq!(c.postgres.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(c.postgres.user, "serveros");
        assert_eq!(
            c.postgres.password_file.as_deref(),
            Some(std::path::Path::new("/etc/serveros/postgres.pw"))
        );

        assert_eq!(
            Config::parse("{}").unwrap().postgres.host,
            None,
            "a config without the key keeps the socket behaviour it always had"
        );
    }

    #[test]
    fn null_disables_a_listener() {
        let c = Config::parse(r#"{"port":null,"unix_socket":"/tmp/a.sock"}"#).unwrap();
        assert_eq!(c.port, None);
        assert!(c.unix_socket.is_some());
    }

    #[test]
    fn rejects_a_config_with_no_listener() {
        let err = Config::parse(r#"{"port":null,"unix_socket":null}"#).unwrap_err();
        assert!(err.to_string().contains("at least one"), "{err}");
    }

    #[test]
    fn refuses_a_public_bind_without_explicit_opt_in() {
        // This is the single most important line in the file: a config that
        // quietly exposes the agent to the internet must not load.
        let err = Config::parse(r#"{"bind":"0.0.0.0"}"#).unwrap_err();
        assert!(err.to_string().contains("allow_public_bind"), "{err}");

        let ok = Config::parse(r#"{"bind":"0.0.0.0","allow_public_bind":true}"#).unwrap();
        assert!(!ok.bind.is_loopback());
    }

    #[test]
    fn refuses_an_inline_postgres_password() {
        let err = Config::parse(r#"{"postgres":{"password":"hunter2"}}"#).unwrap_err();
        assert!(err.to_string().contains("password_file"), "{err}");
    }

    #[test]
    fn rejects_malformed_and_hostile_values() {
        assert!(Config::parse("not json").is_err());
        assert!(Config::parse("[]").is_err(), "top level must be an object");
        assert!(Config::parse(r#"{"port":0}"#).is_err());
        assert!(Config::parse(r#"{"port":70000}"#).is_err());
        assert!(Config::parse(r#"{"bind":"not-an-ip"}"#).is_err());
        assert!(Config::parse(r#"{"log_level":"chatty"}"#).is_err());
        assert!(Config::parse(r#"{"file_roots":["relative/path"]}"#).is_err());
        assert!(Config::parse(r#"{"file_roots":[7]}"#).is_err());
    }

    #[test]
    fn clamps_absurd_numbers_instead_of_trusting_them() {
        let c = Config::parse(r#"{"max_connections":1000000,"metrics_interval_secs":9999}"#).unwrap();
        assert_eq!(c.max_connections, 1024);
        assert_eq!(c.metrics_interval_secs, 60);

        let c = Config::parse(r#"{"max_connections":1}"#).unwrap();
        assert_eq!(c.max_connections, 8);
    }

    #[test]
    fn json_round_trips() {
        let original = Config::parse(
            r#"{"server_id":"srv_1","port":9000,"file_roots":["/srv"],"log_level":"warn"}"#,
        )
        .unwrap();
        let reparsed = Config::parse(&original.to_json().to_string()).unwrap();
        assert_eq!(reparsed.server_id, original.server_id);
        assert_eq!(reparsed.port, original.port);
        assert_eq!(reparsed.file_roots, original.file_roots);
        assert_eq!(reparsed.log_level, original.log_level);
    }

    #[test]
    fn serialised_config_never_contains_a_secret() {
        let c = Config::parse(r#"{"server_id":"srv_1"}"#).unwrap();
        let text = c.to_json().to_string();
        assert!(!text.contains("secret"));
        assert!(!text.contains("password\""));
        // The key PATH is fine to show; the key itself lives elsewhere.
        assert!(text.contains("key_path"));
    }
}
