//! Images, volumes and networks — read-only.
//!
//! Creation and deletion of these live elsewhere (or nowhere yet): the MVP
//! needs to *show* what a server holds, and destructive operations on images
//! and volumes deserve their own design pass on confirmation and blast radius.
//!
//! One wrinkle worth knowing about: Docker removed per-resource usage detail
//! from the list endpoints for performance. `GET /volumes` no longer carries
//! `UsageData`, and `GET /networks` no longer carries the `Containers` map
//! (verified against Docker 29.4.3, API 1.54). Rather than show "0 containers"
//! on a network that plainly has some, this module can derive both from the
//! container list — see [`apply_volume_usage`] and [`apply_network_counts`].

use crate::{
    DockerClient, DockerError, bool_field, i64_field, map_to_json, parse_rfc3339, short_id,
    str_field, string_list, string_map, u64_field,
};
use serveros_json::{Object, Value};

/// The tag Docker gives an image with no repository or tag of its own.
pub const NONE_TAG: &str = "<none>:<none>";

/// A local image.
#[derive(Debug, Clone, PartialEq)]
pub struct Image {
    pub id: String,
    pub repo_tags: Vec<String>,
    pub repository: Option<String>,
    pub tag: Option<String>,
    pub size_bytes: u64,
    pub created_at: Option<i64>,
    /// Containers using this image, or `None` when the daemon did not count
    /// them (it only does with `?shared-size=1`, which is expensive).
    pub containers: Option<i64>,
    /// Untagged: reachable only by digest, and usually reclaimable space.
    pub dangling: bool,
}

impl Image {
    pub fn from_json(v: &Value) -> Image {
        let repo_tags: Vec<String> = string_list(v.get("RepoTags"))
            .into_iter()
            .filter(|t| t != NONE_TAG)
            .collect();
        let (repository, tag) = match repo_tags.first() {
            Some(first) => split_repo_tag(first),
            None => (None, None),
        };
        Image {
            id: str_field(v, "Id").unwrap_or_default(),
            // `Containers: -1` is Docker's "did not compute", not "none".
            containers: i64_field(v, "Containers").filter(|n| *n >= 0),
            dangling: repo_tags.is_empty(),
            repo_tags,
            repository,
            tag,
            size_bytes: u64_field(v, "Size").unwrap_or(0),
            created_at: i64_field(v, "Created"),
        }
    }

    pub fn short_id(&self) -> String {
        short_id(&self.id)
    }

    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(9)
                .set("id", self.id.clone())
                .set("short_id", self.short_id())
                .set("repo_tags", Value::from(self.repo_tags.clone()))
                .set_opt("repository", self.repository.clone())
                .set_opt("tag", self.tag.clone())
                .set("size_bytes", self.size_bytes)
                .set_opt("created_at", self.created_at)
                .set_opt("containers", self.containers)
                .set("dangling", self.dangling),
        )
    }
}

/// Split `registry:5000/team/app:1.4` into repository and tag.
///
/// The last colon is only a tag separator if no `/` follows it — otherwise it
/// is a registry port, and splitting there would produce `registry` / `5000/...`.
pub fn split_repo_tag(reference: &str) -> (Option<String>, Option<String>) {
    match reference.rfind(':') {
        Some(idx) if !reference[idx + 1..].contains('/') => {
            let repo = &reference[..idx];
            let tag = &reference[idx + 1..];
            (
                (!repo.is_empty()).then(|| repo.to_string()),
                (!tag.is_empty()).then(|| tag.to_string()),
            )
        }
        _ => ((!reference.is_empty()).then(|| reference.to_string()), None),
    }
}

/// A named volume.
#[derive(Debug, Clone, PartialEq)]
pub struct Volume {
    pub name: String,
    pub driver: String,
    pub mountpoint: String,
    pub created_at: Option<i64>,
    pub labels: Vec<(String, String)>,
    /// Only present when the daemon computed usage (`/system/df`).
    pub size_bytes: Option<i64>,
    /// Whether any container mounts it. `None` until determined.
    pub in_use: Option<bool>,
}

impl Volume {
    pub fn from_json(v: &Value) -> Volume {
        let usage = v.get("UsageData");
        Volume {
            name: str_field(v, "Name").unwrap_or_default(),
            driver: str_field(v, "Driver").unwrap_or_else(|| "local".into()),
            mountpoint: str_field(v, "Mountpoint").unwrap_or_default(),
            created_at: str_field(v, "CreatedAt").as_deref().and_then(parse_rfc3339),
            labels: string_map(v.get("Labels")),
            // Both are `-1` when Docker declined to compute them.
            size_bytes: usage.and_then(|u| i64_field(u, "Size")).filter(|n| *n >= 0),
            in_use: usage.and_then(|u| i64_field(u, "RefCount")).filter(|n| *n >= 0).map(|n| n > 0),
        }
    }

    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(7)
                .set("name", self.name.clone())
                .set("driver", self.driver.clone())
                .set("mountpoint", self.mountpoint.clone())
                .set_opt("created_at", self.created_at)
                .set("labels", map_to_json(&self.labels))
                .set_opt("size_bytes", self.size_bytes)
                .set_opt("in_use", self.in_use),
        )
    }
}

/// A Docker network.
#[derive(Debug, Clone, PartialEq)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub scope: String,
    /// Internal networks have no outbound route.
    pub internal: bool,
    pub subnet: Option<String>,
    pub gateway: Option<String>,
    /// Attached containers, or `None` until determined.
    pub container_count: Option<usize>,
}

impl Network {
    pub fn from_json(v: &Value) -> Network {
        // IPAM.Config is an array because a network may have several pools
        // (v4 and v6, typically). The first is the one people mean.
        let ipam = v.path("IPAM/Config").and_then(Value::as_array).and_then(|a| a.first());
        Network {
            id: str_field(v, "Id").unwrap_or_default(),
            name: str_field(v, "Name").unwrap_or_default(),
            driver: str_field(v, "Driver").unwrap_or_default(),
            scope: str_field(v, "Scope").unwrap_or_else(|| "local".into()),
            internal: bool_field(v, "Internal").unwrap_or(false),
            subnet: ipam.and_then(|c| str_field(c, "Subnet")),
            gateway: ipam.and_then(|c| str_field(c, "Gateway")),
            container_count: v.get("Containers").and_then(Value::as_object).map(|o| o.len()),
        }
    }

    pub fn short_id(&self) -> String {
        short_id(&self.id)
    }

    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::with_capacity(8)
                .set("id", self.id.clone())
                .set("name", self.name.clone())
                .set("driver", self.driver.clone())
                .set("scope", self.scope.clone())
                .set("internal", self.internal)
                .set_opt("subnet", self.subnet.clone())
                .set_opt("gateway", self.gateway.clone())
                .set_opt("container_count", self.container_count),
        )
    }
}

/// Fill in `in_use` from a raw `GET /containers/json?all=1` response.
///
/// A stopped container still holds its volume, so the list must include stopped
/// containers or a volume will look reclaimable when it is not.
pub fn apply_volume_usage(volumes: &mut [Volume], container_list: &Value) {
    let Some(containers) = container_list.as_array() else { return };
    let mut used: Vec<&str> = Vec::new();
    for c in containers {
        let Some(mounts) = c.get("Mounts").and_then(Value::as_array) else { continue };
        for m in mounts {
            if let Some(name) = m.get("Name").and_then(Value::as_str) {
                used.push(name);
            }
        }
    }
    for v in volumes.iter_mut() {
        if v.in_use.is_none() {
            v.in_use = Some(used.contains(&v.name.as_str()));
        }
    }
}

/// Fill in `container_count` from a raw `GET /containers/json?all=1` response.
pub fn apply_network_counts(networks: &mut [Network], container_list: &Value) {
    let Some(containers) = container_list.as_array() else { return };
    for n in networks.iter_mut() {
        if n.container_count.is_some() {
            continue;
        }
        let count = containers
            .iter()
            .filter(|c| {
                c.path("NetworkSettings/Networks")
                    .and_then(Value::as_object)
                    .is_some_and(|o| o.contains_key(&n.name))
            })
            .count();
        n.container_count = Some(count);
    }
}

/// Parse `GET /images/json`.
pub fn parse_images(v: &Value) -> Result<Vec<Image>, DockerError> {
    let arr =
        v.as_array().ok_or_else(|| DockerError::Decode("expected an array of images".into()))?;
    Ok(arr.iter().map(Image::from_json).collect())
}

/// Parse `GET /volumes`, whose payload is `{"Volumes":[...],"Warnings":null}`.
pub fn parse_volumes(v: &Value) -> Result<Vec<Volume>, DockerError> {
    // `Volumes` is null, not `[]`, when there are none.
    let Some(arr) = v.get("Volumes").and_then(Value::as_array) else {
        if v.get("Volumes").is_some() || v.as_object().is_some() {
            return Ok(Vec::new());
        }
        return Err(DockerError::Decode("expected a volume list object".into()));
    };
    Ok(arr.iter().map(Volume::from_json).collect())
}

/// Parse `GET /networks`.
pub fn parse_networks(v: &Value) -> Result<Vec<Network>, DockerError> {
    let arr =
        v.as_array().ok_or_else(|| DockerError::Decode("expected an array of networks".into()))?;
    Ok(arr.iter().map(Network::from_json).collect())
}

impl DockerClient {
    /// All local images.
    pub fn images(&self) -> Result<Vec<Image>, DockerError> {
        parse_images(&self.get_json("/images/json")?)
    }

    /// All volumes, with `in_use` resolved against the container list.
    pub fn volumes(&self) -> Result<Vec<Volume>, DockerError> {
        let mut volumes = parse_volumes(&self.get_json("/volumes")?)?;
        if volumes.iter().any(|v| v.in_use.is_none()) {
            // Best effort: a volume list without usage is still worth showing.
            if let Ok(list) = self.get_json("/containers/json?all=1") {
                apply_volume_usage(&mut volumes, &list);
            }
        }
        Ok(volumes)
    }

    /// All networks, with `container_count` resolved against the container list.
    pub fn networks(&self) -> Result<Vec<Network>, DockerError> {
        let mut networks = parse_networks(&self.get_json("/networks")?)?;
        if networks.iter().any(|n| n.container_count.is_none()) {
            if let Ok(list) = self.get_json("/containers/json?all=1") {
                apply_network_counts(&mut networks, &list);
            }
        }
        Ok(networks)
    }
}
