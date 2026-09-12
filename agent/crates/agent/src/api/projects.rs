//! Compose projects — the application layer above containers.
//!
//! # Why this is its own resource
//!
//! The product's mental model is `Server → Project → Container`, not a flat
//! list of containers. A user thinks "is Estatify up?", and the honest answer
//! is not "eleven of twelve containers are running" but "Estatify is *partly*
//! up, and it is the API that is down". Grouping by Compose label is what turns
//! the Docker view into an applications view, and `partial` — a project with
//! some containers up and some down — is the state this screen exists to make
//! visible, because it is what a half-failed deployment looks like.
//!
//! Containers without a Compose project are deliberately absent here rather
//! than collected into a synthetic "(none)" project: inventing an application
//! that does not exist would be worse than the Docker view already listing
//! every container.

use crate::api::{collection_with, not_found};
use crate::auth::Principal;
use crate::state::AgentState;
use serveros_http::{Request, Response};
use serveros_json::{Object, Value};

/// `GET /v1/projects` — every Compose project on this server.
///
/// Stopped containers are included, so a project whose containers have all
/// exited still appears. The alternative is an application that vanishes from
/// the app at exactly the moment the user needs to find it.
pub fn list(state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    let docker = match super::docker::client(state) {
        Ok(docker) => docker,
        Err(response) => return response,
    };

    match docker.projects() {
        Ok(projects) => {
            let running = projects.iter().filter(|p| p.state() == "running").count();
            let degraded = projects.iter().filter(|p| p.state() == "partial").count();
            let items: Vec<Value> = projects.iter().map(|p| p.to_json()).collect();
            collection_with(
                items,
                Object::new().set("running", running).set("degraded", degraded),
            )
        }
        Err(e) => super::docker::docker_response(e),
    }
}

/// `GET /v1/projects/{name}` — one project and its containers.
pub fn get(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let docker = match super::docker::client(state) {
        Ok(docker) => docker,
        Err(response) => return response,
    };
    let name = req.param("name").unwrap_or_default().to_string();

    match docker.projects() {
        Ok(projects) => match projects.iter().find(|p| p.name == name) {
            Some(project) => Response::json(project.to_json()),
            None => not_found("project", &name),
        },
        Err(e) => super::docker::docker_response(e),
    }
}
