//! Shared agent state.
//!
//! One `AgentState` is built at startup and shared by every request thread.
//! Two rules shape it:
//!
//!   * **Subsystems are discovered lazily and may be absent.** Docker may not be
//!     installed; systemd may not be the init system; PostgreSQL may not exist.
//!     None of those is an error — each is a capability the desktop app should
//!     simply not offer. `capabilities()` is what the app reads to decide which
//!     sidebar sections to show.
//!   * **A subsystem that goes away at runtime must not take the agent with
//!     it.** Docker being restarted underneath us produces a failed request,
//!     not a dead agent, and the next request re-probes.

use crate::activity::ActivityLog;
use crate::auth::Authenticator;
use crate::config::Config;
use crate::logging;
use serveros_docker::DockerClient;
use serveros_fsops::PathPolicy;
use serveros_json::{Object, Value};
use serveros_linux::MetricsSampler;
use serveros_systemd::ServiceManager;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

pub struct AgentState {
    pub config: Config,
    pub auth: Authenticator,
    pub activity: ActivityLog,
    pub path_policy: PathPolicy,
    /// Metric sampling is stateful — CPU and network rates are deltas between
    /// consecutive samples — so one sampler is shared and serialised.
    pub sampler: Mutex<MetricsSampler>,
    docker: RwLock<Option<Arc<DockerClient>>>,
    services: RwLock<Option<Arc<dyn ServiceManager>>>,
    started_at: Instant,
    started_at_unix: i64,
}

impl AgentState {
    pub fn new(config: Config, secret: Vec<u8>) -> AgentState {
        let activity = ActivityLog::open(config.activity_log_path());

        let path_policy = if config.file_roots.is_empty() {
            PathPolicy::whole_filesystem()
        } else {
            PathPolicy::rooted_at(config.file_roots.clone())
        };

        let state = AgentState {
            auth: Authenticator::new(secret),
            activity,
            path_policy,
            sampler: Mutex::new(MetricsSampler::new()),
            docker: RwLock::new(None),
            services: RwLock::new(None),
            started_at: Instant::now(),
            started_at_unix: crate::auth::now_unix(),
            config,
        };
        state.probe_subsystems();
        state
    }

    /// Probe optional subsystems once at startup so the first request is fast
    /// and so the startup log states plainly what this agent can do.
    fn probe_subsystems(&self) {
        match DockerClient::connect(self.config.docker_socket.clone()) {
            Ok(client) => {
                logging::info_with(
                    "docker detected",
                    Object::new().set("api_version", client.api_version()),
                );
                *self.docker.write().unwrap() = Some(Arc::new(client));
            }
            Err(e) => logging::info_with(
                "docker not available; container features disabled",
                Object::new().set("reason", e.to_string()),
            ),
        }

        match serveros_systemd::detect() {
            Ok(manager) => {
                logging::info_with(
                    "service manager detected",
                    Object::new().set("backend", manager.backend_name()),
                );
                *self.services.write().unwrap() = Some(Arc::from(manager));
            }
            Err(e) => logging::info_with(
                "no service manager; service features disabled",
                Object::new().set("reason", e.to_string()),
            ),
        }
    }

    /// The Docker client, re-probing if the daemon was absent at startup.
    ///
    /// Re-probing matters: installing Docker after the agent is running is a
    /// normal thing to do, and it should not require restarting the agent.
    pub fn docker(&self) -> Option<Arc<DockerClient>> {
        if let Some(existing) = self.docker.read().ok()?.clone() {
            return Some(existing);
        }
        let client = DockerClient::connect(self.config.docker_socket.clone()).ok()?;
        let client = Arc::new(client);
        if let Ok(mut slot) = self.docker.write() {
            *slot = Some(client.clone());
        }
        Some(client)
    }

    pub fn services(&self) -> Option<Arc<dyn ServiceManager>> {
        self.services.read().ok()?.clone()
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub fn started_at_unix(&self) -> i64 {
        self.started_at_unix
    }

    /// What this agent can actually do on this host.
    ///
    /// The desktop app uses this to hide sections rather than showing a section
    /// that errors when opened. An empty state saying "Docker isn't installed
    /// on this server" is a better answer than a spinner followed by a 503.
    pub fn capabilities(&self) -> Value {
        let docker = self.docker.read().ok().and_then(|d| d.clone());
        let services = self.services.read().ok().and_then(|s| s.clone());

        Object::new()
            .set("metrics", true)
            .set("processes", true)
            .set("users", true)
            .set("files", true)
            .set("logs", true)
            .set("docker", docker.is_some())
            .set_opt("docker_api_version", docker.as_ref().map(|d| d.api_version().to_string()))
            .set("services", services.is_some())
            .set_opt("service_backend", services.as_ref().map(|s| s.backend_name().to_string()))
            .set("journal", serveros_fsops::journal_available())
            .set("postgres", self.config.postgres.enabled)
            .into()
    }
}
