//! Daemon-level facts: version, storage, capacity and warnings.
//!
//! This is what fills the "Docker" card on a server's overview — one request
//! that answers "is Docker healthy, how much is running, and is anything
//! misconfigured", rather than a wall of the ~70 fields `/info` actually
//! returns.

use crate::{DockerClient, DockerError, i64_field, str_field, string_list, u64_field};
use serveros_json::{Object, Value};

/// A summary of the daemon.
#[derive(Debug, Clone, PartialEq)]
pub struct DaemonInfo {
    /// Engine version, e.g. `29.4.3`.
    pub version: String,
    /// The API version *we negotiated*, not the daemon's maximum — this is the
    /// one that explains our behaviour if a field is missing.
    pub api_version: String,
    pub root_dir: String,
    pub storage_driver: String,
    pub containers_total: i64,
    pub containers_running: i64,
    pub containers_stopped: i64,
    pub containers_paused: i64,
    pub images: i64,
    pub cpus: i64,
    pub memory_bytes: u64,
    /// `1` or `2`. Decides how memory stats are interpreted.
    pub cgroup_version: Option<String>,
    /// Whether containers keep running across a daemon restart.
    pub live_restore: bool,
    /// The daemon's own warnings — deprecated cgroup v1, disabled IP
    /// forwarding, missing swap limit. Worth showing verbatim: they explain
    /// most "why is Docker behaving oddly" tickets.
    pub warnings: Vec<String>,
}

impl DaemonInfo {
    /// Combine `GET /info` and `GET /version`.
    ///
    /// Pure so it can be tested against captured payloads; the client method
    /// below does the two requests.
    pub fn from_json(info: &Value, version: &Value, negotiated_api: &str) -> DaemonInfo {
        DaemonInfo {
            version: str_field(version, "Version")
                .or_else(|| str_field(info, "ServerVersion"))
                .unwrap_or_default(),
            api_version: negotiated_api.to_string(),
            root_dir: str_field(info, "DockerRootDir").unwrap_or_default(),
            storage_driver: str_field(info, "Driver").unwrap_or_default(),
            containers_total: i64_field(info, "Containers").unwrap_or(0),
            containers_running: i64_field(info, "ContainersRunning").unwrap_or(0),
            containers_stopped: i64_field(info, "ContainersStopped").unwrap_or(0),
            containers_paused: i64_field(info, "ContainersPaused").unwrap_or(0),
            images: i64_field(info, "Images").unwrap_or(0),
            cpus: i64_field(info, "NCPU").unwrap_or(0),
            memory_bytes: u64_field(info, "MemTotal").unwrap_or(0),
            cgroup_version: str_field(info, "CgroupVersion"),
            live_restore: info
                .get("LiveRestoreEnabled")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            warnings: string_list(info.get("Warnings")),
        }
    }

    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(14)
                .set("version", self.version.clone())
                .set("api_version", self.api_version.clone())
                .set("root_dir", self.root_dir.clone())
                .set("storage_driver", self.storage_driver.clone())
                .set("containers_total", self.containers_total)
                .set("containers_running", self.containers_running)
                .set("containers_stopped", self.containers_stopped)
                .set("containers_paused", self.containers_paused)
                .set("images", self.images)
                .set("cpus", self.cpus)
                .set("memory_bytes", self.memory_bytes)
                .set_opt("cgroup_version", self.cgroup_version.clone())
                .set("live_restore", self.live_restore)
                .set("warnings", Value::from(self.warnings.clone())),
        )
    }
}

impl DockerClient {
    /// Summarise the daemon.
    pub fn info(&self) -> Result<DaemonInfo, DockerError> {
        let info = self.get_json("/info")?;
        // A daemon that answered /info will answer /version; if it somehow does
        // not, ServerVersion from /info still fills the gap.
        let version = self.get_json("/version").unwrap_or(Value::Null);
        Ok(DaemonInfo::from_json(&info, &version, self.api_version()))
    }
}
