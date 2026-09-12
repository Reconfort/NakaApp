//! Containers: listing, inspection, lifecycle, stats and logs.
//!
//! This is the module the app spends its time in, so three things get more care
//! here than elsewhere:
//!
//! * **Environment variables are masked by default** ([`mask_env`]). This is a
//!   security control, not a nicety — see the function's own docs.
//! * **Log streams are demultiplexed properly** ([`DemuxReader`]). Docker frames
//!   non-TTY output with an 8-byte header; naively printing the stream puts
//!   binary garbage in front of every line and loses the stdout/stderr split.
//! * **CPU percentage is computed from two samples**, the way Docker documents
//!   it. A single sample cannot produce a meaningful number, and a wrong "100%"
//!   on a dashboard sends people hunting a problem that does not exist.

use crate::{
    DEFAULT_STOP_TIMEOUT, DockerClient, DockerError, bool_field, i64_field, map_to_json,
    parse_rfc3339, short_id, str_field, str_path, string_list, string_map, transport, u64_field,
};
use serveros_http::Method;
use serveros_http::uri::{build_query, percent_encode};
use serveros_json::{Object, Value, round};
use std::io::{self, Read};
use std::time::Duration;

/// Largest single log frame we will allocate for.
///
/// Docker's log driver never emits anything near this; a larger size field means
/// a corrupt or hostile stream, and we would rather fail than allocate 4 GiB.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Environment variable name fragments that force masking.
///
/// Substring match, case-insensitive, on the **key**. The list is deliberately
/// broad — see [`mask_env`] for why over-masking is the correct failure mode.
pub const SECRET_KEY_FRAGMENTS: &[&str] = &[
    "PASS",
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "KEY",
    "CREDENTIAL",
    "AUTH",
    "PRIVATE",
    "DSN",
    "CONNECTION_STRING",
];

// ---- types ---------------------------------------------------------------

/// A published or exposed port.
#[derive(Debug, Clone, PartialEq)]
pub struct Port {
    /// Port inside the container.
    pub private: u16,
    /// Port on the host, when published.
    pub public: Option<u16>,
    /// `tcp`, `udp` or `sctp`.
    pub protocol: String,
    /// Host interface the port is bound to, when published.
    pub ip: Option<String>,
}

impl Port {
    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(4)
                .set("private", self.private)
                .set_opt("public", self.public)
                .set("type", self.protocol.clone())
                .set_opt("ip", self.ip.clone()),
        )
    }
}

/// A container as the list and detail views need it.
///
/// `cpu_percent` and the memory fields are `None` unless [`Container::apply_stats`]
/// has been called: stats are a separate, much more expensive request, and a
/// list of thirty containers must not trigger thirty of them.
#[derive(Debug, Clone, PartialEq)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub image_id: String,
    /// `running`, `exited`, `paused`, `created`, `restarting`, `dead`.
    pub state: String,
    /// Human string from Docker (`Up 2 hours`), or one we synthesise from
    /// inspect, which has no such field.
    pub status: String,
    /// `healthy` / `unhealthy` / `starting`, or `None` with no healthcheck.
    pub health: Option<String>,
    pub created_at: Option<i64>,
    /// Only available from inspect.
    pub started_at: Option<i64>,
    /// Only available from inspect.
    pub restart_count: Option<i64>,
    pub ports: Vec<Port>,
    pub labels: Vec<(String, String)>,
    pub compose_project: Option<String>,
    pub compose_service: Option<String>,
    pub networks: Vec<String>,
    pub cpu_percent: Option<f64>,
    pub memory_bytes: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
    pub memory_percent: Option<f64>,
}

/// Compose label carrying the project name.
pub const LABEL_PROJECT: &str = "com.docker.compose.project";
/// Compose label carrying the service name within a project.
pub const LABEL_SERVICE: &str = "com.docker.compose.service";
/// Compose label carrying the directory the project was brought up from.
pub const LABEL_WORKING_DIR: &str = "com.docker.compose.project.working_dir";

impl Container {
    /// Parse one entry of `GET /containers/json`.
    ///
    /// Every field is treated as optional. A container that is mid-removal, or
    /// created by a tool that does not populate `NetworkSettings`, still has to
    /// render rather than take the whole list down.
    pub fn from_list_entry(v: &Value) -> Container {
        let id = str_field(v, "Id").unwrap_or_default();
        let labels = string_map(v.get("Labels"));
        let status = str_field(v, "Status").unwrap_or_default();

        Container {
            name: list_name(v),
            image: str_field(v, "Image").unwrap_or_default(),
            image_id: str_field(v, "ImageID").unwrap_or_default(),
            state: str_field(v, "State").unwrap_or_else(|| "unknown".into()),
            // The list endpoint has no Health field; Docker folds health into
            // the status string ("Up 6 seconds (healthy)") and its own CLI
            // reads it back out the same way.
            health: health_from_status(&status),
            status,
            created_at: i64_field(v, "Created"),
            started_at: None,
            restart_count: None,
            ports: parse_list_ports(v.get("Ports")),
            compose_project: label(&labels, LABEL_PROJECT),
            compose_service: label(&labels, LABEL_SERVICE),
            labels,
            networks: network_names(v.path("NetworkSettings/Networks")),
            id,
            cpu_percent: None,
            memory_bytes: None,
            memory_limit_bytes: None,
            memory_percent: None,
        }
    }

    /// Attach a stats sample, filling in the live metrics.
    pub fn apply_stats(&mut self, stats: &ContainerStats) {
        self.cpu_percent = Some(stats.cpu_percent);
        self.memory_bytes = Some(stats.memory_bytes);
        self.memory_limit_bytes = Some(stats.memory_limit_bytes);
        self.memory_percent = Some(stats.memory_percent);
    }

    pub fn short_id(&self) -> String {
        short_id(&self.id)
    }

    /// Look up one label.
    pub fn label(&self, key: &str) -> Option<&str> {
        self.labels.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    /// The API shape the Mac app decodes.
    ///
    /// Optional fields are *omitted* rather than emitted as `null` (Swift
    /// decodes both to `nil`, and omission keeps payloads small on a list of
    /// hundreds). The one exception is `env` inside [`ContainerDetail`], where
    /// an explicit `null` is what makes `masked` unambiguous.
    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(20)
                .set("id", self.id.clone())
                .set("short_id", self.short_id())
                .set("name", self.name.clone())
                .set("image", self.image.clone())
                .set("image_id", self.image_id.clone())
                .set("state", self.state.clone())
                .set("status", self.status.clone())
                .set_opt("health", self.health.clone())
                .set_opt("created_at", self.created_at)
                .set_opt("started_at", self.started_at)
                .set_opt("restart_count", self.restart_count)
                .set("ports", Value::Array(self.ports.iter().map(Port::to_json).collect()))
                .set("labels", map_to_json(&self.labels))
                .set_opt("compose_project", self.compose_project.clone())
                .set_opt("compose_service", self.compose_service.clone())
                .set("networks", Value::from(self.networks.clone()))
                .set_opt("cpu_percent", self.cpu_percent.map(|v| round(v, 1)))
                .set_opt("memory_bytes", self.memory_bytes)
                .set_opt("memory_limit_bytes", self.memory_limit_bytes)
                .set_opt("memory_percent", self.memory_percent.map(|v| round(v, 1))),
        )
    }
}

/// A mount as reported by inspect.
#[derive(Debug, Clone, PartialEq)]
pub struct MountInfo {
    /// `volume`, `bind`, `tmpfs` or `npipe`.
    pub kind: String,
    /// Host path, or the volume's data directory.
    pub source: Option<String>,
    pub destination: String,
    pub mode: Option<String>,
    pub rw: bool,
}

impl MountInfo {
    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(5)
                .set("type", self.kind.clone())
                .set_opt("source", self.source.clone())
                .set("destination", self.destination.clone())
                .set_opt("mode", self.mode.clone())
                .set("rw", self.rw),
        )
    }
}

/// One network a container is attached to, with its addressing.
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkAttachment {
    pub name: String,
    pub ip_address: Option<String>,
    pub gateway: Option<String>,
    pub mac_address: Option<String>,
}

impl NetworkAttachment {
    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(4)
                .set("name", self.name.clone())
                .set_opt("ip_address", self.ip_address.clone())
                .set_opt("gateway", self.gateway.clone())
                .set_opt("mac_address", self.mac_address.clone()),
        )
    }
}

/// A container's restart policy.
#[derive(Debug, Clone, PartialEq)]
pub struct RestartPolicy {
    /// `no`, `always`, `unless-stopped` or `on-failure`.
    pub name: String,
    pub max_retry_count: i64,
}

impl RestartPolicy {
    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(2)
                .set("name", self.name.clone())
                .set("max_retry_count", self.max_retry_count),
        )
    }
}

/// A container's configured healthcheck, plus how it is currently doing.
#[derive(Debug, Clone, PartialEq)]
pub struct HealthCheck {
    pub test: Vec<String>,
    pub interval_seconds: Option<i64>,
    pub timeout_seconds: Option<i64>,
    pub retries: Option<i64>,
    pub start_period_seconds: Option<i64>,
    /// Consecutive failures so far. From `State.Health`, not from the config.
    pub failing_streak: Option<i64>,
}

impl HealthCheck {
    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(6)
                .set("test", Value::from(self.test.clone()))
                .set_opt("interval_seconds", self.interval_seconds)
                .set_opt("timeout_seconds", self.timeout_seconds)
                .set_opt("retries", self.retries)
                .set_opt("start_period_seconds", self.start_period_seconds)
                .set_opt("failing_streak", self.failing_streak),
        )
    }
}

/// One environment variable, possibly with its value withheld.
///
/// `value` is `None` exactly when `masked` is true, and serialises as an
/// explicit `null` so a client can tell "withheld" from "empty string".
#[derive(Debug, Clone, PartialEq)]
pub struct EnvVar {
    pub key: String,
    pub value: Option<String>,
    pub masked: bool,
}

impl EnvVar {
    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(3)
                .set("key", self.key.clone())
                // Explicit null, not an omitted key: `{"key":"X","masked":true}`
                // would be ambiguous with a variable we simply failed to read.
                .set("value", Value::from(self.value.clone()))
                .set("masked", self.masked),
        )
    }
}

/// Everything `GET /containers/{id}/json` adds on top of a list entry.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerDetail {
    pub container: Container,
    pub command: Vec<String>,
    pub entrypoint: Vec<String>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
    /// Whether a pseudo-TTY was allocated. Decides how logs are framed.
    pub tty: bool,
    pub platform: Option<String>,
    pub restart_policy: Option<RestartPolicy>,
    pub mounts: Vec<MountInfo>,
    pub network_attachments: Vec<NetworkAttachment>,
    /// Raw `KEY=VALUE` strings, exactly as Docker returned them.
    ///
    /// Kept raw and *private to the process*: masking happens on the way out in
    /// [`ContainerDetail::to_json`], so no caller can accidentally serialise the
    /// unmasked form by reaching for a field.
    env: Vec<String>,
    pub health_check: Option<HealthCheck>,
    pub exit_code: Option<i64>,
    pub finished_at: Option<i64>,
}

impl ContainerDetail {
    /// Parse `GET /containers/{id}/json`.
    pub fn from_inspect(v: &Value) -> ContainerDetail {
        let state = v.get("State");
        let config = v.get("Config");
        let labels = string_map(config.and_then(|c| c.get("Labels")));

        let status = str_path(v, "State/Status").unwrap_or_else(|| "unknown".into());
        let exit_code = state.and_then(|s| i64_field(s, "ExitCode"));

        let container = Container {
            id: str_field(v, "Id").unwrap_or_default(),
            name: str_field(v, "Name")
                .map(|n| n.trim_start_matches('/').to_string())
                .unwrap_or_default(),
            // Top-level `Image` is the resolved digest; `Config.Image` is the
            // reference the user actually asked for, which is what to show.
            image: config
                .and_then(|c| str_field(c, "Image"))
                .or_else(|| str_field(v, "Image"))
                .unwrap_or_default(),
            image_id: str_field(v, "Image").unwrap_or_default(),
            // Inspect has no human-readable status line, so synthesise one
            // rather than leaving a hole the UI has to special-case.
            status: synth_status(&status, exit_code),
            health: str_path(v, "State/Health/Status"),
            created_at: str_field(v, "Created").as_deref().and_then(parse_rfc3339),
            started_at: str_path(v, "State/StartedAt").as_deref().and_then(parse_rfc3339),
            restart_count: i64_field(v, "RestartCount"),
            ports: parse_inspect_ports(v.path("NetworkSettings/Ports")),
            compose_project: label(&labels, LABEL_PROJECT),
            compose_service: label(&labels, LABEL_SERVICE),
            labels,
            networks: network_names(v.path("NetworkSettings/Networks")),
            state: status,
            cpu_percent: None,
            memory_bytes: None,
            memory_limit_bytes: None,
            memory_percent: None,
        };

        ContainerDetail {
            container,
            command: string_list(config.and_then(|c| c.get("Cmd"))),
            entrypoint: string_list(config.and_then(|c| c.get("Entrypoint"))),
            working_dir: config.and_then(|c| str_field(c, "WorkingDir")),
            user: config.and_then(|c| str_field(c, "User")),
            tty: config.and_then(|c| bool_field(c, "Tty")).unwrap_or(false),
            platform: str_field(v, "Platform"),
            restart_policy: v.path("HostConfig/RestartPolicy").map(|p| RestartPolicy {
                name: str_field(p, "Name").unwrap_or_else(|| "no".into()),
                max_retry_count: i64_field(p, "MaximumRetryCount").unwrap_or(0),
            }),
            mounts: parse_mounts(v.get("Mounts")),
            network_attachments: parse_attachments(v.path("NetworkSettings/Networks")),
            env: string_list(config.and_then(|c| c.get("Env"))),
            health_check: parse_health_check(config.and_then(|c| c.get("Healthcheck")), state),
            exit_code,
            finished_at: str_path(v, "State/FinishedAt").as_deref().and_then(parse_rfc3339),
        }
    }

    /// Environment variables with secret-looking values withheld.
    pub fn env(&self) -> Vec<EnvVar> {
        mask_env(&self.env)
    }

    /// Environment variables, optionally unmasked.
    ///
    /// `reveal` must only ever be `true` for a request the HTTP layer has
    /// explicitly authorised — it is the difference between an audit log that
    /// records "read env" and one that contains the password.
    pub fn env_with(&self, reveal: bool) -> Vec<EnvVar> {
        read_env(&self.env, reveal)
    }

    /// Serialise with environment masked. This is the default for a reason.
    pub fn to_json(&self) -> Value {
        self.to_json_with(false)
    }

    /// Serialise, optionally revealing environment values.
    ///
    /// See [`ContainerDetail::env_with`] for when `reveal` may be true.
    ///
    /// Note that `networks` is *replaced* here: a list entry carries bare
    /// network names, while a detail carries `{name, ip_address, gateway,
    /// mac_address}` objects. The two endpoints decode into different models,
    /// and the detail view is the only place the addressing is available.
    pub fn to_json_with(&self, reveal: bool) -> Value {
        let mut obj = match self.container.to_json() {
            Value::Object(o) => o,
            other => return other,
        };
        obj.insert("command", Value::from(self.command.clone()));
        obj.insert("entrypoint", Value::from(self.entrypoint.clone()));
        obj = obj
            .set_opt("working_dir", self.working_dir.clone())
            .set_opt("user", self.user.clone())
            .set("tty", self.tty)
            .set_opt("platform", self.platform.clone())
            .set_opt("restart_policy", self.restart_policy.as_ref().map(RestartPolicy::to_json))
            .set(
                "mounts",
                Value::Array(self.mounts.iter().map(MountInfo::to_json).collect()),
            )
            .set(
                "networks",
                Value::Array(
                    self.network_attachments.iter().map(NetworkAttachment::to_json).collect(),
                ),
            )
            .set(
                "env",
                Value::Array(self.env_with(reveal).iter().map(EnvVar::to_json).collect()),
            )
            .set_opt("health_check", self.health_check.as_ref().map(HealthCheck::to_json))
            .set_opt("exit_code", self.exit_code)
            .set_opt("finished_at", self.finished_at);
        Value::Object(obj)
    }
}

// ---- environment masking -------------------------------------------------

/// Split `KEY=VALUE` pairs into [`EnvVar`]s, withholding anything secret-looking.
///
/// **This is a security control.** `Config.Env` is where a deployed service
/// keeps `POSTGRES_PASSWORD`, `AWS_SECRET_ACCESS_KEY`, `STRIPE_API_KEY` and the
/// database URL with the password inline. Whatever this function returns ends
/// up on a user's screen, in the control plane's audit log, and in any support
/// bundle taken from it. A miss here is a credential leak with a long tail.
///
/// The rule is therefore deliberately blunt and deliberately over-inclusive:
///
/// * mask when the **key** contains any of [`SECRET_KEY_FRAGMENTS`]
///   (case-insensitive substring, so `pg_password`, `API_KEY` and
///   `SecretKeyBase` all match), or
/// * mask when the **value** looks like a URL with inline credentials
///   (`scheme://user:pass@host`), which catches `DATABASE_URL`,
///   `REDIS_URL`, `AMQP_URL` and friends whose keys say nothing suspicious.
///
/// Over-masking is the safe direction. `KEYBOARD_LAYOUT` contains `KEY` and so
/// is masked; hiding a keyboard layout costs a user one click through the
/// "reveal" path, while showing one password costs a great deal more. If a
/// specific benign key becomes annoying in practice, add an explicit allow-list
/// entry — do not loosen the fragments.
pub fn mask_env(pairs: &[String]) -> Vec<EnvVar> {
    read_env(pairs, false)
}

/// [`mask_env`], with an escape hatch.
///
/// `reveal: true` returns values verbatim and must only be reached from a
/// request the HTTP layer has explicitly authorised for secret disclosure.
pub fn read_env(pairs: &[String], reveal: bool) -> Vec<EnvVar> {
    pairs
        .iter()
        .map(|raw| {
            // Docker always emits `KEY=VALUE`, but a container can be created
            // through the API with a bare `KEY`; treat that as an empty value
            // rather than dropping the variable.
            let (key, value) = match raw.split_once('=') {
                Some((k, v)) => (k, v),
                None => (raw.as_str(), ""),
            };
            let secret = is_secret_key(key) || value_has_embedded_credentials(value);
            EnvVar {
                key: key.to_string(),
                value: if secret && !reveal { None } else { Some(value.to_string()) },
                masked: secret && !reveal,
            }
        })
        .collect()
}

/// Whether a variable name looks like it names a secret.
pub fn is_secret_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    SECRET_KEY_FRAGMENTS.iter().any(|f| upper.contains(f))
}

/// Whether a value looks like `scheme://user:pass@host`.
///
/// Only the authority component is examined, so a password-free URL with an
/// `@` later in the path or query is not mistaken for a credential.
pub fn value_has_embedded_credentials(value: &str) -> bool {
    let Some(rest) = value.split_once("://").map(|(_, r)| r) else {
        return false;
    };
    // Authority ends at the first `/`, `?` or `#`.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    let Some((userinfo, _host)) = authority.rsplit_once('@') else {
        return false;
    };
    // `user:pass@host` is a credential; bare `user@host` is only an identity,
    // and Docker images legitimately use it for things like git remotes.
    userinfo.contains(':')
}

// ---- stats ---------------------------------------------------------------

/// One stats sample, reduced to the numbers a dashboard shows.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerStats {
    pub id: String,
    pub read_at: Option<i64>,
    pub cpu_percent: f64,
    pub online_cpus: u64,
    pub memory_bytes: u64,
    pub memory_limit_bytes: u64,
    pub memory_percent: f64,
    pub pids: Option<u64>,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

impl ContainerStats {
    /// Parse one sample of `GET /containers/{id}/stats?stream=false`.
    pub fn from_json(v: &Value) -> ContainerStats {
        let (memory_bytes, memory_limit_bytes) = compute_memory(v);
        let memory_percent = if memory_limit_bytes > 0 {
            (memory_bytes as f64 / memory_limit_bytes as f64) * 100.0
        } else {
            0.0
        };
        let (net_rx_bytes, net_tx_bytes) = compute_network(v);

        ContainerStats {
            id: str_field(v, "id").unwrap_or_default(),
            read_at: str_field(v, "read").as_deref().and_then(parse_rfc3339),
            cpu_percent: compute_cpu_percent(v),
            online_cpus: online_cpus(v.get("cpu_stats")),
            memory_bytes,
            memory_limit_bytes,
            memory_percent,
            pids: v.path("pids_stats/current").and_then(Value::as_u64),
            net_rx_bytes,
            net_tx_bytes,
        }
    }

    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(10)
                .set("id", self.id.clone())
                .set_opt("read_at", self.read_at)
                .set("cpu_percent", round(self.cpu_percent, 1))
                .set("online_cpus", self.online_cpus)
                .set("memory_bytes", self.memory_bytes)
                .set("memory_limit_bytes", self.memory_limit_bytes)
                .set("memory_percent", round(self.memory_percent, 1))
                .set_opt("pids", self.pids)
                .set("net_rx_bytes", self.net_rx_bytes)
                .set("net_tx_bytes", self.net_tx_bytes),
        )
    }
}

/// CPU percentage, per Docker's documented formula.
///
/// ```text
/// cpu_delta    = cpu_usage.total_usage      - precpu.cpu_usage.total_usage
/// system_delta = cpu_stats.system_cpu_usage - precpu.system_cpu_usage
/// percent      = cpu_delta / system_delta * online_cpus * 100
/// ```
///
/// Both deltas must be positive. The interesting case is the *first* sample:
/// with `one-shot=true`, or on a container that has just started, `precpu` is
/// zero — and `total / system * cpus * 100` against a zero baseline yields a
/// number that looks plausible and is meaningless. We return 0.0 there instead,
/// which reads as "no sample yet" rather than as a lie.
pub fn compute_cpu_percent(stats: &Value) -> f64 {
    let cpu = stats.get("cpu_stats");
    let pre = stats.get("precpu_stats");

    let total = cpu.and_then(|c| c.path("cpu_usage/total_usage")).and_then(Value::as_f64);
    let pre_total = pre.and_then(|c| c.path("cpu_usage/total_usage")).and_then(Value::as_f64);
    let system = cpu.and_then(|c| c.get("system_cpu_usage")).and_then(Value::as_f64);
    let pre_system = pre.and_then(|c| c.get("system_cpu_usage")).and_then(Value::as_f64);

    let (Some(total), Some(pre_total), Some(system), Some(pre_system)) =
        (total, pre_total, system, pre_system)
    else {
        return 0.0; // missing fields, or a stopped container's empty stats
    };

    // A zero previous system time means there is no previous sample at all.
    if pre_system <= 0.0 {
        return 0.0;
    }

    let cpu_delta = total - pre_total;
    let system_delta = system - pre_system;
    if system_delta <= 0.0 || cpu_delta <= 0.0 {
        return 0.0;
    }

    let cpus = online_cpus(cpu) as f64;
    let percent = (cpu_delta / system_delta) * cpus * 100.0;
    if percent.is_finite() { percent } else { 0.0 }
}

/// How many CPUs the sample covers.
///
/// `online_cpus` was added in API 1.27; older daemons only report `percpu_usage`,
/// and a container pinned to a cpuset has fewer than the host. Falling back to 1
/// under-reports rather than inventing parallelism that is not there.
pub fn online_cpus(cpu_stats: Option<&Value>) -> u64 {
    let Some(cpu) = cpu_stats else { return 1 };
    if let Some(n) = cpu.get("online_cpus").and_then(Value::as_u64) {
        if n > 0 {
            return n;
        }
    }
    if let Some(list) = cpu.path("cpu_usage/percpu_usage").and_then(Value::as_array) {
        if !list.is_empty() {
            return list.len() as u64;
        }
    }
    1
}

/// Working-set memory and its limit.
///
/// Raw `memory_stats.usage` includes the page cache, which makes an idle
/// container that once read a large file look like it is using gigabytes. What
/// people expect to see — and what `docker stats` shows — is usage minus the
/// reclaimable file cache:
///
/// * **cgroup v1** reports `stats.cache`.
/// * **cgroup v2** reports `stats.inactive_file` and has no `cache`.
///
/// Both are handled, the subtraction is skipped if it would underflow, and a
/// sample with neither field falls back to raw `usage`.
pub fn compute_memory(stats: &Value) -> (u64, u64) {
    let mem = stats.get("memory_stats");
    let usage = mem.and_then(|m| m.get("usage")).and_then(Value::as_u64).unwrap_or(0);
    let limit = mem.and_then(|m| m.get("limit")).and_then(Value::as_u64).unwrap_or(0);

    let inner = mem.and_then(|m| m.get("stats"));
    let reclaimable = inner
        .and_then(|s| s.get("cache"))
        .and_then(Value::as_u64)
        .or_else(|| inner.and_then(|s| s.get("inactive_file")).and_then(Value::as_u64));

    let working_set = match reclaimable {
        Some(c) if c <= usage => usage - c,
        // A cache larger than usage means the two were sampled at different
        // moments; trust `usage` rather than emitting a wrapped number.
        _ => usage,
    };
    (working_set, limit)
}

/// Total received and transmitted bytes across every interface in the sample.
fn compute_network(stats: &Value) -> (u64, u64) {
    let Some(nets) = stats.get("networks").and_then(Value::as_object) else {
        return (0, 0);
    };
    let mut rx = 0u64;
    let mut tx = 0u64;
    for (_iface, v) in nets.iter() {
        rx = rx.saturating_add(u64_field(v, "rx_bytes").unwrap_or(0));
        tx = tx.saturating_add(u64_field(v, "tx_bytes").unwrap_or(0));
    }
    (rx, tx)
}

// ---- log demultiplexing --------------------------------------------------

/// Which of a container's streams a chunk of output came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Stdin,
    Stdout,
    Stderr,
    /// A frame type Docker has not documented. Kept rather than dropped so a
    /// future stream type still shows up in the UI.
    Unknown(u8),
}

impl StreamKind {
    pub fn from_byte(b: u8) -> StreamKind {
        match b {
            0 => StreamKind::Stdin,
            1 => StreamKind::Stdout,
            2 => StreamKind::Stderr,
            other => StreamKind::Unknown(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            StreamKind::Stdin => "stdin",
            StreamKind::Stdout => "stdout",
            StreamKind::Stderr => "stderr",
            StreamKind::Unknown(_) => "unknown",
        }
    }
}

/// One demultiplexed chunk of container output.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    pub stream: StreamKind,
    pub data: Vec<u8>,
}

/// Decodes Docker's multiplexed stream format.
///
/// A container created **without** a TTY has separate stdout and stderr, so the
/// daemon cannot just concatenate them — it prefixes each chunk with an 8-byte
/// header:
///
/// ```text
/// [0]     stream type: 0 stdin, 1 stdout, 2 stderr
/// [1..4]  zero padding
/// [4..8]  payload length, big-endian u32
/// [8..]   payload
/// ```
///
/// A container created **with** a TTY has one merged stream and no headers at
/// all — see [`LogStream`], which picks the right mode from `Config.Tty`.
///
/// Reads are looped until a frame is complete, so a header or payload split
/// across two `read()` calls (routine on a socket) is handled correctly.
pub struct DemuxReader<R: Read> {
    inner: R,
    eof: bool,
}

impl<R: Read> DemuxReader<R> {
    pub fn new(inner: R) -> DemuxReader<R> {
        DemuxReader { inner, eof: false }
    }

    /// Read the next frame, or `None` at a clean end of stream.
    pub fn next_frame(&mut self) -> io::Result<Option<Frame>> {
        if self.eof {
            return Ok(None);
        }

        let mut header = [0u8; 8];
        let got = read_full(&mut self.inner, &mut header)?;
        if got == 0 {
            self.eof = true;
            return Ok(None);
        }
        if got < header.len() {
            self.eof = true;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated docker stream header",
            ));
        }

        let stream = StreamKind::from_byte(header[0]);
        let size = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if size > MAX_FRAME {
            self.eof = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "docker stream frame exceeds maximum size",
            ));
        }
        if size == 0 {
            // Legal and observed: an empty write still produces a header.
            return Ok(Some(Frame { stream, data: Vec::new() }));
        }

        let mut data = vec![0u8; size];
        let got = read_full(&mut self.inner, &mut data)?;
        if got < size {
            self.eof = true;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated docker stream payload",
            ));
        }
        Ok(Some(Frame { stream, data }))
    }
}

/// Fill `buf`, looping over short reads. Returns how many bytes were read;
/// fewer than `buf.len()` means the stream ended.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// A container log stream in either framing mode.
///
/// Implements [`Read`], yielding the *payload* bytes with headers stripped, so
/// it can be piped straight into a WebSocket relay. Use
/// [`LogStream::next_frame`] instead when the stdout/stderr split matters.
pub struct LogStream {
    source: Source,
    pending: Vec<u8>,
    offset: usize,
}

enum Source {
    /// Non-TTY: multiplexed, needs framing removed.
    Demux(DemuxReader<Box<dyn Read + Send>>),
    /// TTY: raw bytes, stdout and stderr already merged by the pty.
    Raw(Box<dyn Read + Send>),
}

impl LogStream {
    /// Wrap a reader, choosing the framing from the container's `Config.Tty`.
    pub fn new(inner: Box<dyn Read + Send>, tty: bool) -> LogStream {
        let source = if tty { Source::Raw(inner) } else { Source::Demux(DemuxReader::new(inner)) };
        LogStream { source, pending: Vec::new(), offset: 0 }
    }

    /// Next chunk of output, tagged with its stream.
    ///
    /// In TTY mode everything is reported as stdout, because the pty genuinely
    /// merged the two and no information survives to separate them.
    pub fn next_frame(&mut self) -> io::Result<Option<Frame>> {
        match &mut self.source {
            Source::Demux(d) => d.next_frame(),
            Source::Raw(r) => {
                let mut buf = vec![0u8; 32 * 1024];
                let n = r.read(&mut buf)?;
                if n == 0 {
                    return Ok(None);
                }
                buf.truncate(n);
                Ok(Some(Frame { stream: StreamKind::Stdout, data: buf }))
            }
        }
    }
}

impl Read for LogStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.offset < self.pending.len() {
                let n = (self.pending.len() - self.offset).min(buf.len());
                buf[..n].copy_from_slice(&self.pending[self.offset..self.offset + n]);
                self.offset += n;
                return Ok(n);
            }
            match self.next_frame()? {
                Some(frame) => {
                    self.pending = frame.data;
                    self.offset = 0;
                    // A zero-length frame is not end-of-stream; go round again.
                    if self.pending.is_empty() {
                        continue;
                    }
                }
                None => return Ok(0),
            }
        }
    }
}

/// One line of container output.
#[derive(Debug, Clone, PartialEq)]
pub struct LogLine {
    pub stream: StreamKind,
    /// Unix seconds, when the request asked for timestamps.
    pub timestamp: Option<i64>,
    pub message: String,
}

impl LogLine {
    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(3)
                .set("stream", self.stream.as_str())
                .set_opt("timestamp", self.timestamp)
                .set("message", self.message.clone()),
        )
    }
}

/// Split demultiplexed frames into lines.
///
/// Frames do not necessarily end on a line boundary — a long line is split
/// across frames — so partial lines are carried per stream and only emitted
/// when their newline arrives, or at end of stream.
pub fn frames_to_lines(frames: &[Frame], timestamps: bool) -> Vec<LogLine> {
    let mut out = Vec::new();
    // Small vec keyed by stream: there are at most three.
    let mut partial: Vec<(StreamKind, Vec<u8>)> = Vec::new();

    for frame in frames {
        let slot = match partial.iter().position(|(k, _)| *k == frame.stream) {
            Some(i) => i,
            None => {
                partial.push((frame.stream, Vec::new()));
                partial.len() - 1
            }
        };
        partial[slot].1.extend_from_slice(&frame.data);

        while let Some(nl) = partial[slot].1.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = partial[slot].1.drain(..=nl).collect();
            out.push(make_line(frame.stream, &line[..line.len() - 1], timestamps));
        }
    }

    // Whatever is left has no trailing newline but is still output.
    for (stream, rest) in partial {
        if !rest.is_empty() {
            out.push(make_line(stream, &rest, timestamps));
        }
    }
    out
}

fn make_line(stream: StreamKind, raw: &[u8], timestamps: bool) -> LogLine {
    // Container output is not guaranteed to be UTF-8; lossy conversion keeps
    // the line readable instead of dropping it.
    let mut text = String::from_utf8_lossy(raw).into_owned();
    // A TTY writes CRLF; leaving the CR in produces stray blank lines in the UI.
    if text.ends_with('\r') {
        text.pop();
    }

    let mut timestamp = None;
    if timestamps {
        if let Some((head, rest)) = text.split_once(' ') {
            if let Some(ts) = parse_rfc3339(head) {
                timestamp = Some(ts);
                text = rest.to_string();
            }
        }
    }
    LogLine { stream, timestamp, message: text }
}

// ---- parsing helpers -----------------------------------------------------

/// `Names` is an array because of the legacy container-links feature; the first
/// entry is the container's own name and carries a leading slash.
fn list_name(v: &Value) -> String {
    v.get("Names")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .map(|n| n.trim_start_matches('/').to_string())
        .unwrap_or_default()
}

/// Pull health out of a status string such as `Up 6 seconds (healthy)`.
fn health_from_status(status: &str) -> Option<String> {
    let start = status.rfind('(')?;
    let end = status.rfind(')')?;
    if end <= start + 1 {
        return None;
    }
    let inner = &status[start + 1..end];
    match inner {
        "healthy" | "unhealthy" => Some(inner.to_string()),
        // Docker writes "health: starting" during the start period.
        _ if inner.starts_with("health: ") => Some(inner["health: ".len()..].to_string()),
        _ => None, // e.g. "(Paused)", "Exited (137)"
    }
}

/// Build the human status line inspect does not provide.
fn synth_status(state: &str, exit_code: Option<i64>) -> String {
    match state {
        "running" => "Up".to_string(),
        "exited" => match exit_code {
            Some(c) => format!("Exited ({c})"),
            None => "Exited".to_string(),
        },
        "paused" => "Paused".to_string(),
        "created" => "Created".to_string(),
        "restarting" => "Restarting".to_string(),
        "removing" => "Removing".to_string(),
        "dead" => "Dead".to_string(),
        other => other.to_string(),
    }
}

fn label(labels: &[(String, String)], key: &str) -> Option<String> {
    labels.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
}

/// `NetworkSettings.Networks` is a map keyed by network name.
fn network_names(v: Option<&Value>) -> Vec<String> {
    let Some(obj) = v.and_then(Value::as_object) else {
        return Vec::new();
    };
    obj.iter().map(|(k, _)| k.to_string()).collect()
}

fn parse_attachments(v: Option<&Value>) -> Vec<NetworkAttachment> {
    let Some(obj) = v.and_then(Value::as_object) else {
        return Vec::new();
    };
    obj.iter()
        .map(|(name, net)| NetworkAttachment {
            name: name.to_string(),
            ip_address: str_field(net, "IPAddress"),
            gateway: str_field(net, "Gateway"),
            mac_address: str_field(net, "MacAddress"),
        })
        .collect()
}

/// `Ports` from the list endpoint: an array of flat objects.
fn parse_list_ports(v: Option<&Value>) -> Vec<Port> {
    let Some(arr) = v.and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|p| {
            Some(Port {
                private: u64_field(p, "PrivatePort")? as u16,
                // Absent on a merely *exposed* port that was never published.
                public: u64_field(p, "PublicPort").map(|n| n as u16),
                protocol: str_field(p, "Type").unwrap_or_else(|| "tcp".into()),
                ip: str_field(p, "IP"),
            })
        })
        .collect()
}

/// `NetworkSettings.Ports` from inspect: a map of `"80/tcp"` to host bindings
/// (or to `null` when the port is exposed but not published).
fn parse_inspect_ports(v: Option<&Value>) -> Vec<Port> {
    let Some(obj) = v.and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (spec, bindings) in obj.iter() {
        let (port, proto) = match spec.split_once('/') {
            Some((p, t)) => (p, t),
            None => (spec, "tcp"),
        };
        let Ok(private) = port.parse::<u16>() else { continue };

        match bindings.as_array() {
            Some(list) if !list.is_empty() => {
                for b in list {
                    out.push(Port {
                        private,
                        public: str_field(b, "HostPort").and_then(|p| p.parse().ok()),
                        protocol: proto.to_string(),
                        ip: str_field(b, "HostIp"),
                    });
                }
            }
            _ => out.push(Port {
                private,
                public: None,
                protocol: proto.to_string(),
                ip: None,
            }),
        }
    }
    // Map iteration order follows the daemon's JSON; sort so the UI is stable.
    out.sort_by_key(|p| (p.private, p.public));
    out
}

fn parse_mounts(v: Option<&Value>) -> Vec<MountInfo> {
    let Some(arr) = v.and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .map(|m| MountInfo {
            kind: str_field(m, "Type").unwrap_or_else(|| "bind".into()),
            // A named volume reports both `Name` and the host `Source`; the
            // name is what the user recognises, so prefer it.
            source: str_field(m, "Name").or_else(|| str_field(m, "Source")),
            destination: str_field(m, "Destination").unwrap_or_default(),
            mode: str_field(m, "Mode"),
            rw: bool_field(m, "RW").unwrap_or(true),
        })
        .collect()
}

/// Merge `Config.Healthcheck` (the definition) with `State.Health` (how it is
/// going). Durations come back in nanoseconds; seconds are what people read.
fn parse_health_check(config: Option<&Value>, state: Option<&Value>) -> Option<HealthCheck> {
    let config = config?;
    let test = string_list(config.get("Test"));
    // `Test: ["NONE"]` is how an image explicitly disables an inherited check.
    if test.is_empty() || test == ["NONE"] {
        return None;
    }
    let ns = |key: &str| i64_field(config, key).filter(|n| *n > 0).map(|n| n / 1_000_000_000);
    Some(HealthCheck {
        test,
        interval_seconds: ns("Interval"),
        timeout_seconds: ns("Timeout"),
        retries: i64_field(config, "Retries"),
        start_period_seconds: ns("StartPeriod"),
        failing_streak: state.and_then(|s| s.path("Health/FailingStreak")).and_then(Value::as_i64),
    })
}

/// Parse a whole `GET /containers/json` response.
pub fn parse_list(v: &Value) -> Result<Vec<Container>, DockerError> {
    let arr = v
        .as_array()
        .ok_or_else(|| DockerError::Decode("expected an array of containers".into()))?;
    Ok(arr.iter().map(Container::from_list_entry).collect())
}

// ---- client methods ------------------------------------------------------

impl DockerClient {
    /// List containers. `all` includes stopped ones.
    pub fn list(&self, all: bool) -> Result<Vec<Container>, DockerError> {
        let path = if all { "/containers/json?all=1" } else { "/containers/json" };
        parse_list(&self.get_json(path)?)
    }

    /// Inspect one container by id or name.
    pub fn inspect(&self, id: &str) -> Result<ContainerDetail, DockerError> {
        let v = self.get_json(&format!("/containers/{}/json", percent_encode(id)))?;
        Ok(ContainerDetail::from_inspect(&v))
    }

    /// Take a single stats sample.
    ///
    /// `one-shot=false` is not a typo: with `one-shot=true` the daemon skips the
    /// pre-read, `precpu_stats` comes back zeroed, and no CPU percentage can be
    /// derived. Paying for the extra ~1s pre-read is the price of a real number.
    pub fn stats_once(&self, id: &str) -> Result<ContainerStats, DockerError> {
        let v = self.get_json(&format!(
            "/containers/{}/stats?stream=false&one-shot=false",
            percent_encode(id)
        ))?;
        Ok(ContainerStats::from_json(&v))
    }

    pub fn start(&self, id: &str) -> Result<(), DockerError> {
        self.post_action(&format!("/containers/{}/start", percent_encode(id)))
    }

    /// Stop, waiting `timeout` seconds for a graceful exit before SIGKILL.
    pub fn stop(&self, id: &str, timeout: Option<i64>) -> Result<(), DockerError> {
        let t = timeout.unwrap_or(DEFAULT_STOP_TIMEOUT).max(0);
        self.post_action(&format!("/containers/{}/stop?t={}", percent_encode(id), t))
    }

    pub fn restart(&self, id: &str, timeout: Option<i64>) -> Result<(), DockerError> {
        let t = timeout.unwrap_or(DEFAULT_STOP_TIMEOUT).max(0);
        self.post_action(&format!("/containers/{}/restart?t={}", percent_encode(id), t))
    }

    pub fn pause(&self, id: &str) -> Result<(), DockerError> {
        self.post_action(&format!("/containers/{}/pause", percent_encode(id)))
    }

    pub fn unpause(&self, id: &str) -> Result<(), DockerError> {
        self.post_action(&format!("/containers/{}/unpause", percent_encode(id)))
    }

    /// Remove a container. `volumes` also removes its anonymous volumes.
    pub fn remove(&self, id: &str, force: bool, volumes: bool) -> Result<(), DockerError> {
        let query = build_query([
            ("force", if force { "1" } else { "0" }),
            ("v", if volumes { "1" } else { "0" }),
        ]);
        self.delete_action(&format!("/containers/{}?{}", percent_encode(id), query))
    }

    /// Read the last `tail` lines of a container's logs.
    ///
    /// `tail == 0` means "everything", matching `docker logs` with no `--tail`.
    /// `since` is a Unix timestamp.
    ///
    /// An `inspect` call happens first: whether the stream is framed depends on
    /// `Config.Tty`, and guessing from the bytes would misread any log line that
    /// happens to start with byte 0x01.
    pub fn logs(
        &self,
        id: &str,
        tail: usize,
        since: Option<i64>,
        timestamps: bool,
    ) -> Result<Vec<LogLine>, DockerError> {
        let tty = self.inspect(id)?.tty;
        let path = self.logs_path(id, tail, since, timestamps, false);
        let resp = self.http().get(&path).map_err(transport)?;
        let resp = crate::check(resp)?;

        let mut stream = LogStream::new(Box::new(io::Cursor::new(resp.body)), tty);
        let mut frames = Vec::new();
        loop {
            match stream.next_frame() {
                Ok(Some(f)) => frames.push(f),
                Ok(None) => break,
                // A truncated trailing frame is worth surfacing, but not at the
                // cost of the lines we did read.
                Err(_) => break,
            }
        }
        Ok(frames_to_lines(&frames, timestamps))
    }

    /// Open a following log stream, demultiplexed.
    ///
    /// The returned reader yields payload bytes only. Use [`DockerClient::logs_frames`]
    /// when stdout and stderr must stay apart.
    pub fn logs_stream(
        &self,
        id: &str,
        tail: usize,
        since: Option<i64>,
        timestamps: bool,
    ) -> Result<impl Read, DockerError> {
        self.logs_frames(id, tail, since, timestamps)
    }

    /// Open a following log stream with frame-level access.
    ///
    /// The read timeout is deliberately long: a follow on a quiet container is
    /// *supposed* to block, and a 30-second default would tear the stream down
    /// every half minute.
    pub fn logs_frames(
        &self,
        id: &str,
        tail: usize,
        since: Option<i64>,
        timestamps: bool,
    ) -> Result<LogStream, DockerError> {
        let tty = self.inspect(id)?.tty;
        let path = self.logs_path(id, tail, since, timestamps, true);
        let resp = self
            .http()
            .request_streaming(
                Method::Get,
                &path,
                &serveros_http::Headers::new(),
                None,
                Some(Duration::from_secs(3600)),
            )
            .map_err(transport)?;

        if !resp.is_success() {
            return Err(DockerError::Api {
                status: resp.status,
                message: format!("could not follow logs for {id}"),
            });
        }
        Ok(LogStream::new(Box::new(resp.reader()), tty))
    }

    fn logs_path(
        &self,
        id: &str,
        tail: usize,
        since: Option<i64>,
        timestamps: bool,
        follow: bool,
    ) -> String {
        let tail_s = if tail == 0 { "all".to_string() } else { tail.to_string() };
        let since_s = since.map(|s| s.to_string());
        let mut pairs: Vec<(&str, &str)> = vec![
            ("stdout", "1"),
            ("stderr", "1"),
            ("tail", tail_s.as_str()),
            ("timestamps", if timestamps { "1" } else { "0" }),
            ("follow", if follow { "1" } else { "0" }),
        ];
        if let Some(s) = since_s.as_deref() {
            pairs.push(("since", s));
        }
        self.url(&format!("/containers/{}/logs?{}", percent_encode(id), build_query(pairs)))
    }
}
