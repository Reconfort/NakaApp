//! Compose projects, reconstructed from container labels.
//!
//! Docker has no concept of a "project" — Compose invents one and records it on
//! every container it creates, as `com.docker.compose.project` and friends. That
//! label is the only link between the three containers of an application, so
//! grouping by it is how the agent turns a flat container list back into the
//! thing the user actually deployed.
//!
//! This is why the app can show "Estatify · 3 services · running" instead of
//! three unrelated rows, and it costs no extra API call: the labels are already
//! in the container list.

use crate::containers::{Container, LABEL_WORKING_DIR};
use crate::{DockerClient, DockerError};
use serveros_json::{Object, Value};

/// A group of containers brought up together by Compose.
#[derive(Debug, Clone, PartialEq)]
pub struct Project {
    pub name: String,
    /// Directory the project was brought up from, when Compose recorded it.
    /// Older Compose versions do not set the label.
    pub working_dir: Option<String>,
    /// Distinct service names, sorted.
    pub services: Vec<String>,
    pub containers: Vec<Container>,
}

impl Project {
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    pub fn container_count(&self) -> usize {
        self.containers.len()
    }

    pub fn running(&self) -> usize {
        self.containers.iter().filter(|c| c.state == "running").count()
    }

    /// `running` when every container is up, `stopped` when none is, and
    /// `partial` in between.
    ///
    /// `partial` is the state worth designing for: it is what a half-failed
    /// deployment looks like, and collapsing it into "stopped" would hide the
    /// most important case on the screen.
    pub fn state(&self) -> &'static str {
        let running = self.running();
        if running == 0 {
            "stopped"
        } else if running == self.containers.len() {
            "running"
        } else {
            "partial"
        }
    }

    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(8)
                .set("name", self.name.clone())
                .set("service_count", self.service_count())
                .set("container_count", self.container_count())
                .set("running", self.running())
                .set("state", self.state())
                .set_opt("working_dir", self.working_dir.clone())
                .set("services", Value::from(self.services.clone()))
                .set(
                    "containers",
                    Value::Array(self.containers.iter().map(Container::to_json).collect()),
                ),
        )
    }
}

/// Group containers into projects by their Compose labels.
///
/// Containers without a project label are skipped: they are standalone, and
/// inventing a synthetic "(none)" project for them would put a fake application
/// on the user's screen. The Docker view already lists every container.
///
/// Output is sorted by project name, and each project's containers by name, so
/// a refresh does not reshuffle the UI.
pub fn group_projects(containers: &[Container]) -> Vec<Project> {
    let mut projects: Vec<Project> = Vec::new();

    for c in containers {
        let Some(name) = c.compose_project.clone() else { continue };
        let idx = match projects.iter().position(|p| p.name == name) {
            Some(i) => i,
            None => {
                projects.push(Project {
                    name,
                    working_dir: None,
                    services: Vec::new(),
                    containers: Vec::new(),
                });
                projects.len() - 1
            }
        };

        // Any container in the project can carry the working-dir label; they
        // should agree, and the first non-empty one wins if they do not.
        if projects[idx].working_dir.is_none() {
            projects[idx].working_dir = c.label(LABEL_WORKING_DIR).map(str::to_owned);
        }
        if let Some(service) = &c.compose_service {
            if !projects[idx].services.contains(service) {
                projects[idx].services.push(service.clone());
            }
        }
        projects[idx].containers.push(c.clone());
    }

    for p in projects.iter_mut() {
        p.services.sort();
        p.containers.sort_by(|a, b| a.name.cmp(&b.name));
    }
    projects.sort_by(|a, b| a.name.cmp(&b.name));
    projects
}

impl DockerClient {
    /// Compose projects on this server, including stopped containers.
    ///
    /// Stopped containers are included on purpose: a project whose containers
    /// have all exited must still appear, or "my app vanished from the app"
    /// becomes the bug report.
    pub fn projects(&self) -> Result<Vec<Project>, DockerError> {
        Ok(group_projects(&self.list(true)?))
    }
}
