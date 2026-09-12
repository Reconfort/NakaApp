//! Tests for the Docker client.
//!
//! Two kinds, and the split is deliberate:
//!
//! * **Fixture tests** always run. Every JSON blob below was captured with
//!   `curl --unix-socket /var/run/docker.sock` against a real daemon
//!   (Docker 29.4.3, API 1.54, cgroup v1) and pasted in verbatim, trimmed only
//!   of fields this crate does not read. They pin the mapping against what
//!   Docker actually sends rather than against what we assumed it sends.
//!
//! * **Live tests** are guarded by [`daemon_available`] and skip with a message
//!   when there is no daemon, so the suite passes in CI and in a build sandbox.
//!   Each creates its own container, asserts on it, and removes it.

use super::*;
use crate::containers::{
    Container, ContainerDetail, ContainerStats, DemuxReader, LogStream, Port, StreamKind,
    compute_cpu_percent, compute_memory, frames_to_lines, is_secret_key, online_cpus, parse_list,
    read_env, value_has_embedded_credentials,
};
use crate::projects::group_projects;
use crate::resources::{
    Image, Network, Volume, apply_network_counts, apply_volume_usage, parse_images, parse_networks,
    parse_volumes, split_repo_tag,
};
use serveros_http::Headers;
use serveros_http::client::ClientResponse;
use serveros_json::{Object, from_str};
use std::io::Read;

fn json(s: &str) -> Value {
    from_str(s).expect("fixture must be valid JSON")
}

// ==========================================================================
// Fixtures captured from a live daemon
// ==========================================================================

/// `GET /v1.43/containers/json?all=1` — two real entries: one Compose-labelled
/// container with no ports, one with published, mapped and merely exposed ports
/// and no labels at all.
const FIXTURE_LIST: &str = r#"[
  {
    "Id": "9af8c3aa01c73e3ba7d45a0fe911083835eb2de1dcf47beb98b865ce481f4555",
    "Names": ["/serveros-probe"],
    "Image": "serveros-test:base",
    "ImageID": "sha256:9a0cea180511c1f7d51534d424819516cfa0a04f81499075c6bd38796357a950",
    "Command": "/bin/sh -c 'echo out; echo err >&2; sleep 3600'",
    "Created": 1789200759,
    "Ports": [],
    "Labels": {
      "com.docker.compose.project": "estatify",
      "com.docker.compose.project.working_dir": "/srv/estatify",
      "com.docker.compose.service": "api"
    },
    "State": "running",
    "Status": "Up 12 seconds",
    "HostConfig": { "NetworkMode": "bridge" },
    "NetworkSettings": { "Networks": { "bridge": { "IPAddress": "", "Gateway": "" } } },
    "Mounts": []
  },
  {
    "Id": "cb8d8a747c483a6c2bdd0e7e6fbc69106c862209f344739dfcac05bcf67960bc",
    "Names": ["/serveros-ports"],
    "Image": "serveros-test:base",
    "ImageID": "sha256:9a0cea180511c1f7d51534d424819516cfa0a04f81499075c6bd38796357a950",
    "Command": "/bin/sh -c 'sleep 120'",
    "Created": 1789201474,
    "Ports": [
      { "IP": "", "PrivatePort": 5432, "Type": "tcp" },
      { "IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 18080, "Type": "tcp" },
      { "IP": "0.0.0.0", "PrivatePort": 9000, "PublicPort": 9000, "Type": "udp" }
    ],
    "Labels": {},
    "State": "running",
    "Status": "Up 7 seconds",
    "HostConfig": { "NetworkMode": "serveros-testnet" },
    "NetworkSettings": {
      "Networks": {
        "serveros-testnet": {
          "NetworkID": "6feed715e796494062437db1c552bde313526605fe8857a6f30f75a10fbf4d1e",
          "EndpointID": "4f88668b84e7ac4662530eb3d69b06db4bd78f2b7338d8f238d98a55c0a51d3c",
          "Gateway": "172.17.0.1",
          "IPAddress": "172.17.0.2",
          "MacAddress": "1e:e3:f3:72:7a:b0",
          "IPPrefixLen": 16
        }
      }
    },
    "Mounts": []
  }
]"#;

/// `GET /v1.43/containers/{id}/json` — real inspect output with the fields this
/// crate reads. Env, entrypoint, working dir, user, restart policy, mounts and
/// network addressing are all as the daemon returned them.
const FIXTURE_INSPECT: &str = r#"{
  "Id": "a95021534025934d25af24153cd934f19398a56c443acccdd9d59eca58f469fc",
  "Created": "2026-09-12T08:16:11.482714299Z",
  "Path": "/bin/sh",
  "Args": ["-c", "sleep 300"],
  "Image": "sha256:9a0cea180511c1f7d51534d424819516cfa0a04f81499075c6bd38796357a950",
  "Name": "/serveros-env",
  "RestartCount": 0,
  "Platform": "linux",
  "Driver": "overlayfs",
  "State": {
    "Status": "running",
    "Running": true,
    "Paused": false,
    "Restarting": false,
    "OOMKilled": false,
    "Dead": false,
    "Pid": 4211,
    "ExitCode": 0,
    "Error": "",
    "StartedAt": "2026-09-12T08:16:11.533932885Z",
    "FinishedAt": "0001-01-01T00:00:00Z"
  },
  "Config": {
    "Hostname": "a95021534025",
    "User": "0:0",
    "Tty": false,
    "Env": [
      "DATABASE_URL=postgres://u:p@h/db",
      "NODE_ENV=production",
      "POSTGRES_PASSWORD=hunter2"
    ],
    "Cmd": ["-c", "sleep 300"],
    "Image": "serveros-test:base",
    "WorkingDir": "/srv/app",
    "Entrypoint": ["/bin/sh"],
    "Labels": {
      "com.docker.compose.project": "estatify",
      "com.docker.compose.service": "worker"
    }
  },
  "HostConfig": {
    "NetworkMode": "serveros-testnet",
    "RestartPolicy": { "Name": "on-failure", "MaximumRetryCount": 3 },
    "LogConfig": { "Type": "json-file", "Config": {} }
  },
  "Mounts": [
    {
      "Type": "volume",
      "Name": "serveros-testvol",
      "Source": "/var/lib/docker/volumes/serveros-testvol/_data",
      "Destination": "/data",
      "Driver": "local",
      "Mode": "z",
      "RW": true,
      "Propagation": ""
    },
    {
      "Type": "bind",
      "Source": "/etc/hostname",
      "Destination": "/hostname",
      "Mode": "ro",
      "RW": false,
      "Propagation": "rprivate"
    }
  ],
  "NetworkSettings": {
    "Ports": {
      "5432/tcp": null,
      "80/tcp": [{ "HostIp": "0.0.0.0", "HostPort": "18080" }],
      "9000/udp": [{ "HostIp": "0.0.0.0", "HostPort": "9000" }]
    },
    "Networks": {
      "serveros-testnet": {
        "NetworkID": "6feed715e796494062437db1c552bde313526605fe8857a6f30f75a10fbf4d1e",
        "EndpointID": "4f88668b84e7ac4662530eb3d69b06db4bd78f2b7338d8f238d98a55c0a51d3c",
        "Gateway": "172.17.0.1",
        "IPAddress": "172.17.0.2",
        "MacAddress": "1e:e3:f3:72:7a:b0",
        "IPPrefixLen": 16
      }
    }
  }
}"#;

/// Real `State` and `Config.Healthcheck` from a container started with
/// `--health-cmd`, plus a real stopped-container `State`.
const FIXTURE_HEALTH: &str = r#"{
  "Id": "3f0d",
  "Name": "/serveros-health",
  "Created": "2026-09-12T08:13:50.310000000Z",
  "State": {
    "Status": "running",
    "Running": true,
    "StartedAt": "2026-09-12T08:13:50.373657899Z",
    "FinishedAt": "0001-01-01T00:00:00Z",
    "ExitCode": 0,
    "Health": {
      "Status": "healthy",
      "FailingStreak": 0,
      "Log": [{ "Start": "2026-09-12T08:13:52.473127161Z", "ExitCode": 0, "Output": "ok\n" }]
    }
  },
  "Config": {
    "Tty": false,
    "Image": "serveros-test:base",
    "Healthcheck": { "Test": ["CMD-SHELL", "/bin/echo ok"], "Interval": 2000000000, "Retries": 2 }
  }
}"#;

const FIXTURE_EXITED: &str = r#"{
  "Id": "9af8",
  "Name": "/serveros-probe",
  "Created": "2026-09-12T08:12:39.198400815Z",
  "State": {
    "Status": "exited",
    "Running": false,
    "Paused": false,
    "ExitCode": 137,
    "StartedAt": "2026-09-12T08:12:39.251855266Z",
    "FinishedAt": "2026-09-12T08:14:19.148877932Z"
  },
  "Config": { "Tty": false, "Image": "serveros-test:base" }
}"#;

/// A real one-shot stats sample from a container spinning in a shell loop.
/// cpu_delta 1_001_592_880 / system_delta 2_000_000_000 * 2 CPUs * 100 = 100.159%.
const FIXTURE_STATS_BUSY: &str = r#"{
  "id": "d2cbd9822f62",
  "read": "2026-09-12T08:25:05.25185418Z",
  "cpu_stats": {
    "cpu_usage": {
      "total_usage": 3047449544,
      "percpu_usage": [26170264, 3021279280],
      "usage_in_kernelmode": 10000000,
      "usage_in_usermode": 3030000000
    },
    "system_cpu_usage": 5721330000000,
    "online_cpus": 2,
    "throttling_data": { "periods": 0, "throttled_periods": 0, "throttled_time": 0 }
  },
  "precpu_stats": {
    "cpu_usage": {
      "total_usage": 2045856664,
      "percpu_usage": [26170264, 2019686400],
      "usage_in_kernelmode": 10000000,
      "usage_in_usermode": 2030000000
    },
    "system_cpu_usage": 5719330000000,
    "online_cpus": 2,
    "throttling_data": { "periods": 0, "throttled_periods": 0, "throttled_time": 0 }
  },
  "memory_stats": {
    "usage": 536576,
    "limit": 67108864,
    "stats": { "cache": 0, "rss": 110592, "inactive_file": 0, "total_inactive_file": 0 }
  },
  "pids_stats": { "current": 1 },
  "networks": {
    "eth0": { "rx_bytes": 1024, "tx_bytes": 2048 },
    "eth1": { "rx_bytes": 1, "tx_bytes": 2 }
  }
}"#;

/// A real sample from a *stopped* container: the daemon answers 200 with
/// everything zeroed and `memory_stats` empty.
const FIXTURE_STATS_STOPPED: &str = r#"{
  "id": "9af8c3aa01c7",
  "read": "0001-01-01T00:00:00Z",
  "cpu_stats": {
    "cpu_usage": { "total_usage": 0, "usage_in_kernelmode": 0, "usage_in_usermode": 0 },
    "throttling_data": { "periods": 0, "throttled_periods": 0, "throttled_time": 0 }
  },
  "memory_stats": {},
  "pids_stats": {}
}"#;

const FIXTURE_IMAGES: &str = r#"[
  {
    "Containers": -1,
    "Created": 1789200756,
    "Id": "sha256:9a0cea180511c1f7d51534d424819516cfa0a04f81499075c6bd38796357a950",
    "Labels": {},
    "ParentId": "",
    "RepoDigests": ["serveros-test@sha256:9a0cea180511c1f7d51534d424819516cfa0a04f81499075c6bd38796357a950"],
    "RepoTags": ["serveros-test:base"],
    "SharedSize": -1,
    "Size": 3857897,
    "VirtualSize": 3857897
  }
]"#;

const FIXTURE_VOLUMES: &str = r#"{
  "Volumes": [
    {
      "CreatedAt": "2026-09-12T08:13:50Z",
      "Driver": "local",
      "Labels": null,
      "Mountpoint": "/var/lib/docker/volumes/serveros-testvol/_data",
      "Name": "serveros-testvol",
      "Options": null,
      "Scope": "local"
    }
  ],
  "Warnings": null
}"#;

const FIXTURE_NETWORKS: &str = r#"[
  {
    "Name": "none",
    "Id": "2f2838f97cc680a57a3a0acdc9d15c7d4dcbee8182d9a59fb114a9973055b696",
    "Created": "2026-09-12T07:38:51.258557703Z",
    "Scope": "local",
    "Driver": "null",
    "IPAM": { "Driver": "default", "Options": null, "Config": null },
    "Internal": false,
    "Attachable": false,
    "Options": {},
    "Labels": {}
  },
  {
    "Name": "serveros-testnet",
    "Id": "6feed715e796494062437db1c552bde313526605fe8857a6f30f75a10fbf4d1e",
    "Created": "2026-09-12T08:13:22.424418192Z",
    "Scope": "local",
    "Driver": "bridge",
    "IPAM": {
      "Driver": "default",
      "Options": {},
      "Config": [{ "Subnet": "172.17.0.0/16", "Gateway": "172.17.0.1" }]
    },
    "Internal": false,
    "Attachable": false,
    "Options": {},
    "Labels": {}
  }
]"#;

const FIXTURE_INFO: &str = r#"{
  "Containers": 4,
  "ContainersRunning": 3,
  "ContainersPaused": 0,
  "ContainersStopped": 1,
  "Images": 1,
  "Driver": "overlayfs",
  "CgroupDriver": "cgroupfs",
  "CgroupVersion": "1",
  "LoggingDriver": "json-file",
  "KernelVersion": "6.18.44-fc-v24",
  "OperatingSystem": "Ubuntu 24.04.4 LTS",
  "OSType": "linux",
  "Architecture": "x86_64",
  "NCPU": 2,
  "MemTotal": 8413380608,
  "DockerRootDir": "/var/lib/docker",
  "LiveRestoreEnabled": false,
  "ServerVersion": "29.4.3",
  "Warnings": [
    "WARNING: Support for cgroup v1 is deprecated and planned to be removed by no later than May 2029 (https://github.com/moby/moby/issues/51111)",
    "WARNING: IPv4 forwarding is disabled"
  ]
}"#;

const FIXTURE_VERSION: &str = r#"{
  "Platform": { "Name": "Docker Engine - Community" },
  "Version": "29.4.3",
  "ApiVersion": "1.54",
  "MinAPIVersion": "1.40",
  "GitCommit": "56be731",
  "GoVersion": "go1.26.2",
  "Os": "linux",
  "Arch": "amd64",
  "KernelVersion": "6.18.44-fc-v24"
}"#;

/// Real bytes from `GET /containers/{id}/logs` on a non-TTY container that ran
/// `echo out; echo err >&2`. Two frames: stdout then stderr.
const LOG_BYTES_MUX: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, b'o', b'u', b't', b'\n', 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, b'e', b'r', b'r', b'\n',
];

/// The same container's logs with `timestamps=1`.
const LOG_BYTES_TS: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23, b'2', b'0', b'2', b'6', b'-', b'0', b'9', b'-',
    b'1', b'2', b'T', b'0', b'8', b':', b'1', b'2', b':', b'3', b'9', b'.', b'7', b'0', b'4', b'2',
    b'9', b'2', b'0', b'0', b'5', b'Z', b' ', b'o', b'u', b't', b'\n',
];

// ==========================================================================
// Version negotiation
// ==========================================================================

#[test]
fn negotiate_pins_to_our_maximum_against_a_newer_daemon() {
    // The live daemon: API 1.54, min 1.40. We stay at our tested ceiling.
    assert_eq!(negotiate_version("1.54", "1.40"), "1.43");
}

#[test]
fn negotiate_drops_to_the_daemon_version_when_it_is_older() {
    // Docker 20.10 speaks 1.41; asking for 1.43 would be rejected outright.
    assert_eq!(negotiate_version("1.41", "1.12"), "1.41");
}

#[test]
fn negotiate_respects_a_minimum_above_our_ceiling() {
    // A future daemon that has dropped 1.43: its floor wins over our ceiling.
    assert_eq!(negotiate_version("1.70", "1.50"), "1.50");
}

#[test]
fn negotiate_falls_back_when_the_daemon_says_nothing_useful() {
    assert_eq!(negotiate_version("", ""), FALLBACK_API_VERSION);
    assert_eq!(negotiate_version("not-a-version", "1.40"), FALLBACK_API_VERSION);
}

#[test]
fn negotiate_ignores_an_unparseable_minimum() {
    assert_eq!(negotiate_version("1.54", "garbage"), "1.43");
}

#[test]
fn version_comparison_is_numeric_not_lexical() {
    // "1.9" > "1.43" as strings; as versions it is not. Getting this wrong
    // negotiates a version the daemon rejects.
    assert!(parse_version("1.9").unwrap() < parse_version("1.43").unwrap());
    assert_eq!(negotiate_version("1.9", "1.5"), "1.9");
    assert_eq!(parse_version("nope"), None);
    assert_eq!(parse_version("1"), None);
}

#[test]
fn client_prefixes_every_path_with_the_negotiated_version() {
    let c = DockerClient::with_http(
        serveros_http::client::HttpClient::unix("/nonexistent.sock"),
        "1.43",
    );
    assert_eq!(c.api_version(), "1.43");
    assert_eq!(c.url("/containers/json"), "/v1.43/containers/json");
}

// ==========================================================================
// Timestamps
// ==========================================================================

#[test]
fn rfc3339_parses_a_plain_utc_timestamp() {
    // 2026-09-12T08:12:39Z
    assert_eq!(parse_rfc3339("2026-09-12T08:12:39Z"), Some(1_789_200_759));
}

#[test]
fn rfc3339_ignores_fractional_seconds() {
    assert_eq!(parse_rfc3339("2026-09-12T08:12:39.198400815Z"), Some(1_789_200_759));
}

#[test]
fn rfc3339_treats_gos_zero_time_as_absent() {
    // Docker uses this for "never": FinishedAt on a running container.
    assert_eq!(parse_rfc3339("0001-01-01T00:00:00Z"), None);
}

#[test]
fn rfc3339_applies_a_numeric_offset() {
    let utc = parse_rfc3339("2026-09-12T08:12:39Z").unwrap();
    assert_eq!(parse_rfc3339("2026-09-12T10:12:39+02:00"), Some(utc));
    assert_eq!(parse_rfc3339("2026-09-12T06:12:39-02:00"), Some(utc));
}

#[test]
fn rfc3339_rejects_malformed_input() {
    assert_eq!(parse_rfc3339(""), None);
    assert_eq!(parse_rfc3339("yesterday"), None);
    assert_eq!(parse_rfc3339("2026-09-12"), None);
    assert_eq!(parse_rfc3339("2026-13-12T00:00:00Z"), None);
    assert_eq!(parse_rfc3339("2026-09-12T25:00:00Z"), None);
    assert_eq!(parse_rfc3339("20x6-09-12T08:12:39Z"), None);
}

#[test]
fn rfc3339_handles_the_epoch_itself() {
    assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(parse_rfc3339("1969-12-31T23:59:59Z"), Some(-1));
}

// ==========================================================================
// Errors
// ==========================================================================

fn response(status: u16, body: &str) -> ClientResponse {
    ClientResponse { status, headers: Headers::new(), body: body.as_bytes().to_vec() }
}

#[test]
fn a_404_becomes_not_found_carrying_dockers_own_wording() {
    // Real body from `GET /v1.43/containers/nope-xyz/json`.
    let err = check(response(404, r#"{"message":"No such container: nope-xyz"}"#)).err().unwrap();
    match err {
        DockerError::NotFound(m) => assert_eq!(m, "No such container: nope-xyz"),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn other_statuses_keep_the_code_and_the_message() {
    let err = check(response(409, r#"{"message":"container is not running"}"#)).err().unwrap();
    match err {
        DockerError::Api { status, message } => {
            assert_eq!(status, 409);
            assert_eq!(message, "container is not running");
        }
        other => panic!("expected Api, got {other:?}"),
    }
}

#[test]
fn a_non_json_error_body_is_surfaced_as_text() {
    assert_eq!(error_message(b"page not found", 404), "page not found");
    assert_eq!(error_message(b"", 500), "HTTP 500");
    assert_eq!(error_message(b"{}", 500), "HTTP 500");
    assert_eq!(error_message(br#"{"message":""}"#, 500), "HTTP 500");
}

#[test]
fn errors_expose_a_stable_code_and_a_readable_message() {
    assert!(DockerError::Unavailable.is_unavailable());
    assert!(!DockerError::NotFound("x".into()).is_unavailable());
    assert_eq!(DockerError::Unavailable.code(), "docker_unavailable");
    assert_eq!(DockerError::NotFound("x".into()).code(), "not_found");
    assert_eq!(
        DockerError::Api { status: 500, message: "boom".into() }.to_string(),
        "docker error 500: boom"
    );
}

#[test]
fn a_successful_response_passes_through_untouched() {
    let ok = check(response(204, "")).ok().unwrap();
    assert_eq!(ok.status, 204);
}

// ==========================================================================
// Container list
// ==========================================================================

#[test]
fn list_maps_every_field_of_a_real_entry() {
    let list = parse_list(&json(FIXTURE_LIST)).unwrap();
    assert_eq!(list.len(), 2);
    let c = &list[0];

    assert_eq!(c.id, "9af8c3aa01c73e3ba7d45a0fe911083835eb2de1dcf47beb98b865ce481f4555");
    assert_eq!(c.short_id(), "9af8c3aa01c7");
    assert_eq!(c.name, "serveros-probe", "the leading slash must be stripped");
    assert_eq!(c.image, "serveros-test:base");
    assert_eq!(
        c.image_id,
        "sha256:9a0cea180511c1f7d51534d424819516cfa0a04f81499075c6bd38796357a950"
    );
    assert_eq!(c.state, "running");
    assert_eq!(c.status, "Up 12 seconds");
    assert_eq!(c.created_at, Some(1_789_200_759));
    assert_eq!(c.networks, vec!["bridge"]);
    assert_eq!(c.compose_project.as_deref(), Some("estatify"));
    assert_eq!(c.compose_service.as_deref(), Some("api"));
    assert_eq!(c.labels.len(), 3);
    // Stats are a separate request; a list must not pretend to have them.
    assert_eq!(c.cpu_percent, None);
    assert_eq!(c.memory_bytes, None);
    assert_eq!(c.started_at, None);
    assert_eq!(c.restart_count, None);
}

#[test]
fn list_maps_published_mapped_and_exposed_ports() {
    let list = parse_list(&json(FIXTURE_LIST)).unwrap();
    let ports = &list[1].ports;
    assert_eq!(ports.len(), 3);

    // Exposed but never published: no PublicPort, and IP is "" not absent.
    assert_eq!(
        ports[0],
        Port { private: 5432, public: None, protocol: "tcp".into(), ip: None }
    );
    assert_eq!(
        ports[1],
        Port { private: 80, public: Some(18080), protocol: "tcp".into(), ip: Some("0.0.0.0".into()) }
    );
    assert_eq!(ports[2].protocol, "udp");
}

#[test]
fn list_reads_health_out_of_the_status_string() {
    // The list endpoint has no Health field; Docker folds it into Status.
    let healthy = json(r#"[{"Status":"Up 6 seconds (healthy)","State":"running"}]"#);
    assert_eq!(parse_list(&healthy).unwrap()[0].health.as_deref(), Some("healthy"));

    let unhealthy = json(r#"[{"Status":"Up 2 minutes (unhealthy)","State":"running"}]"#);
    assert_eq!(parse_list(&unhealthy).unwrap()[0].health.as_deref(), Some("unhealthy"));

    let starting = json(r#"[{"Status":"Up 1 second (health: starting)","State":"running"}]"#);
    assert_eq!(parse_list(&starting).unwrap()[0].health.as_deref(), Some("starting"));
}

#[test]
fn list_reports_no_health_for_containers_without_a_check() {
    let plain = parse_list(&json(FIXTURE_LIST)).unwrap();
    assert_eq!(plain[0].health, None);

    // "Exited (137) 1 second ago" has parentheses but is not a health state.
    let exited = json(r#"[{"Status":"Exited (137) 1 second ago","State":"exited"}]"#);
    assert_eq!(parse_list(&exited).unwrap()[0].health, None);

    let paused = json(r#"[{"Status":"Up 3 hours (Paused)","State":"paused"}]"#);
    assert_eq!(parse_list(&paused).unwrap()[0].health, None);
}

#[test]
fn list_survives_a_hostile_entry() {
    // Null NetworkSettings, no Names, no Labels, no Image — everything a
    // container mid-removal or created by a third-party tool might look like.
    let hostile = json(r#"[{ "Id": "abc", "NetworkSettings": null, "Names": [], "Ports": null }]"#);
    let c = &parse_list(&hostile).unwrap()[0];
    assert_eq!(c.id, "abc");
    assert_eq!(c.name, "");
    assert_eq!(c.state, "unknown");
    assert!(c.networks.is_empty());
    assert!(c.ports.is_empty());
    assert!(c.labels.is_empty());
    assert_eq!(c.compose_project, None);
}

#[test]
fn list_survives_a_completely_empty_object() {
    let c = &parse_list(&json("[{}]")).unwrap()[0];
    assert_eq!(c.id, "");
    assert_eq!(c.created_at, None);
    // to_json must still produce a decodable document.
    assert!(c.to_json().to_string().starts_with('{'));
}

#[test]
fn parse_list_rejects_a_non_array_payload() {
    let err = parse_list(&json(r#"{"message":"boom"}"#)).unwrap_err();
    assert!(matches!(err, DockerError::Decode(_)));
}

#[test]
fn container_json_has_the_shape_the_app_decodes() {
    let list = parse_list(&json(FIXTURE_LIST)).unwrap();
    let v = list[0].to_json();

    assert_eq!(v.get("short_id").unwrap().as_str(), Some("9af8c3aa01c7"));
    assert_eq!(v.get("name").unwrap().as_str(), Some("serveros-probe"));
    assert_eq!(v.get("compose_project").unwrap().as_str(), Some("estatify"));
    assert_eq!(
        v.path("labels/com.docker.compose.service").unwrap().as_str(),
        Some("api")
    );
    assert_eq!(v.get("networks").unwrap().as_array().unwrap().len(), 1);
    // Absent rather than null, so list payloads stay small.
    assert!(v.get("cpu_percent").is_none());
    assert!(v.get("health").is_none());
}

#[test]
fn applying_stats_fills_in_the_live_metrics() {
    let mut c = parse_list(&json(FIXTURE_LIST)).unwrap().remove(0);
    let stats = ContainerStats::from_json(&json(FIXTURE_STATS_BUSY));
    c.apply_stats(&stats);

    let v = c.to_json();
    assert_eq!(v.get("cpu_percent").unwrap().as_f64(), Some(100.2));
    assert_eq!(v.get("memory_bytes").unwrap().as_u64(), Some(536_576));
    assert_eq!(v.get("memory_limit_bytes").unwrap().as_u64(), Some(67_108_864));
    assert_eq!(v.get("memory_percent").unwrap().as_f64(), Some(0.8));
}

// ==========================================================================
// Container inspect
// ==========================================================================

#[test]
fn inspect_maps_the_core_container_fields() {
    let d = ContainerDetail::from_inspect(&json(FIXTURE_INSPECT));
    let c = &d.container;

    assert_eq!(c.name, "serveros-env");
    // Config.Image is the reference the user asked for; Image is the digest.
    assert_eq!(c.image, "serveros-test:base");
    assert!(c.image_id.starts_with("sha256:"));
    assert_eq!(c.state, "running");
    assert_eq!(c.status, "Up", "inspect has no human status line, so we synthesise one");
    assert_eq!(c.created_at, Some(1_789_200_971));
    assert_eq!(c.started_at, Some(1_789_200_971));
    assert_eq!(c.restart_count, Some(0));
    assert_eq!(c.compose_service.as_deref(), Some("worker"));
    assert_eq!(d.finished_at, None, "Go's zero FinishedAt must not become a real date");
}

#[test]
fn inspect_maps_command_entrypoint_workdir_user_and_platform() {
    let d = ContainerDetail::from_inspect(&json(FIXTURE_INSPECT));
    assert_eq!(d.command, vec!["-c", "sleep 300"]);
    assert_eq!(d.entrypoint, vec!["/bin/sh"]);
    assert_eq!(d.working_dir.as_deref(), Some("/srv/app"));
    assert_eq!(d.user.as_deref(), Some("0:0"));
    assert_eq!(d.platform.as_deref(), Some("linux"));
    assert!(!d.tty);
}

#[test]
fn inspect_maps_the_restart_policy() {
    let d = ContainerDetail::from_inspect(&json(FIXTURE_INSPECT));
    let p = d.restart_policy.as_ref().unwrap();
    assert_eq!(p.name, "on-failure");
    assert_eq!(p.max_retry_count, 3);
    assert_eq!(p.to_json().get("max_retry_count").unwrap().as_i64(), Some(3));
}

#[test]
fn inspect_maps_volume_and_bind_mounts() {
    let d = ContainerDetail::from_inspect(&json(FIXTURE_INSPECT));
    assert_eq!(d.mounts.len(), 2);

    let vol = &d.mounts[0];
    assert_eq!(vol.kind, "volume");
    // The volume's name, not its host path: that is what the user recognises.
    assert_eq!(vol.source.as_deref(), Some("serveros-testvol"));
    assert_eq!(vol.destination, "/data");
    assert!(vol.rw);

    let bind = &d.mounts[1];
    assert_eq!(bind.kind, "bind");
    assert_eq!(bind.source.as_deref(), Some("/etc/hostname"));
    assert_eq!(bind.mode.as_deref(), Some("ro"));
    assert!(!bind.rw);
}

#[test]
fn inspect_maps_network_addressing() {
    let d = ContainerDetail::from_inspect(&json(FIXTURE_INSPECT));
    assert_eq!(d.network_attachments.len(), 1);
    let n = &d.network_attachments[0];
    assert_eq!(n.name, "serveros-testnet");
    assert_eq!(n.ip_address.as_deref(), Some("172.17.0.2"));
    assert_eq!(n.gateway.as_deref(), Some("172.17.0.1"));
    assert_eq!(n.mac_address.as_deref(), Some("1e:e3:f3:72:7a:b0"));
}

#[test]
fn inspect_maps_the_port_map_including_unpublished_ports() {
    let d = ContainerDetail::from_inspect(&json(FIXTURE_INSPECT));
    let ports = &d.container.ports;
    assert_eq!(ports.len(), 3);
    // Sorted, so the UI does not reshuffle between refreshes.
    assert_eq!(ports[0].private, 80);
    assert_eq!(ports[0].public, Some(18080));
    assert_eq!(ports[1].private, 5432);
    assert_eq!(ports[1].public, None, "\"5432/tcp\": null means exposed, not published");
    assert_eq!(ports[2].private, 9000);
    assert_eq!(ports[2].protocol, "udp");
}

#[test]
fn inspect_reads_health_from_state_and_the_check_from_config() {
    let d = ContainerDetail::from_inspect(&json(FIXTURE_HEALTH));
    assert_eq!(d.container.health.as_deref(), Some("healthy"));

    let hc = d.health_check.as_ref().unwrap();
    assert_eq!(hc.test, vec!["CMD-SHELL", "/bin/echo ok"]);
    assert_eq!(hc.interval_seconds, Some(2), "nanoseconds must be converted");
    assert_eq!(hc.retries, Some(2));
    assert_eq!(hc.timeout_seconds, None);
    assert_eq!(hc.failing_streak, Some(0));
}

#[test]
fn inspect_reports_no_healthcheck_when_there_is_none() {
    let d = ContainerDetail::from_inspect(&json(FIXTURE_INSPECT));
    assert_eq!(d.health_check, None);
    assert_eq!(d.container.health, None);

    // ["NONE"] is how an image explicitly disables an inherited check.
    let disabled = json(r#"{"Config":{"Healthcheck":{"Test":["NONE"]}}}"#);
    assert_eq!(ContainerDetail::from_inspect(&disabled).health_check, None);
}

#[test]
fn inspect_synthesises_a_status_for_a_stopped_container() {
    let d = ContainerDetail::from_inspect(&json(FIXTURE_EXITED));
    assert_eq!(d.container.state, "exited");
    assert_eq!(d.container.status, "Exited (137)");
    assert_eq!(d.exit_code, Some(137));
    assert_eq!(d.finished_at, Some(1_789_200_859));
}

#[test]
fn inspect_survives_an_empty_document() {
    let d = ContainerDetail::from_inspect(&json("{}"));
    assert_eq!(d.container.state, "unknown");
    assert!(d.command.is_empty());
    assert!(d.mounts.is_empty());
    assert!(d.env().is_empty());
    assert!(d.to_json().to_string().starts_with('{'));
}

#[test]
fn inspect_json_carries_the_detail_fields() {
    let v = ContainerDetail::from_inspect(&json(FIXTURE_INSPECT)).to_json();
    assert_eq!(v.get("working_dir").unwrap().as_str(), Some("/srv/app"));
    assert_eq!(v.get("user").unwrap().as_str(), Some("0:0"));
    assert_eq!(v.get("tty").unwrap().as_bool(), Some(false));
    assert_eq!(v.path("restart_policy/name").unwrap().as_str(), Some("on-failure"));
    assert_eq!(v.get("mounts").unwrap().as_array().unwrap().len(), 2);
    // In detail form, `networks` is the addressing list, not bare names.
    let nets = v.get("networks").unwrap().as_array().unwrap();
    assert_eq!(nets[0].get("name").unwrap().as_str(), Some("serveros-testnet"));
    assert_eq!(nets[0].get("ip_address").unwrap().as_str(), Some("172.17.0.2"));
    assert_eq!(v.get("env").unwrap().as_array().unwrap().len(), 3);
}

// ==========================================================================
// Environment masking — this is a security control
// ==========================================================================

fn mask_one(pair: &str) -> EnvVar {
    mask_env(&[pair.to_string()]).remove(0)
}

#[test]
fn masks_an_obvious_password() {
    let v = mask_one("DB_PASSWORD=hunter2");
    assert_eq!(v.key, "DB_PASSWORD");
    assert!(v.masked);
    assert_eq!(v.value, None);
}

#[test]
fn masks_regardless_of_case() {
    for pair in ["mypassword=x", "MyPassWord=x", "pg_pass=x", "Secret=x"] {
        assert!(mask_one(pair).masked, "{pair} must be masked");
    }
}

#[test]
fn masks_api_keys_and_tokens() {
    for pair in [
        "api_key=abc123",
        "API_KEY=abc123",
        "SECRET_KEY_BASE=deadbeef",
        "GITHUB_TOKEN=ghp_xxx",
        "AWS_SECRET_ACCESS_KEY=wJalr",
        "JWT_PRIVATE_KEY=-----BEGIN",
        "STRIPE_CREDENTIALS=sk_live",
        "BASIC_AUTH=admin:admin",
        "SENTRY_DSN=https://k@o.ingest/1",
        "DB_CONNECTION_STRING=Server=x;Password=y",
    ] {
        assert!(mask_one(pair).masked, "{pair} must be masked");
    }
}

#[test]
fn masks_a_url_whose_key_looks_harmless() {
    // The key says nothing suspicious; the value carries the password.
    let v = mask_one("DATABASE_URL=postgres://u:p@h/db");
    assert!(v.masked);
    assert_eq!(v.value, None);

    assert!(mask_one("REDIS_URL=redis://:sekrit@cache:6379/0").masked);
    assert!(mask_one("AMQP=amqp://guest:guest@rabbit:5672").masked);
}

#[test]
fn over_masks_benign_keys_that_contain_a_fragment() {
    // KEYBOARD_LAYOUT contains "KEY". It is masked, and that is the intended
    // behaviour: hiding a keyboard layout costs one click through the reveal
    // path; showing one password costs far more. Over-masking is the safe
    // direction, and this test exists so the behaviour is a decision rather
    // than an accident.
    assert!(mask_one("KEYBOARD_LAYOUT=us").masked);
    assert!(mask_one("PASSENGER_ROOT=/opt").masked);
    assert!(mask_one("AUTHOR=alice").masked);
}

#[test]
fn leaves_ordinary_variables_alone() {
    for pair in [
        "NODE_ENV=production",
        "PATH=/usr/local/sbin:/usr/bin",
        "LANG=C.UTF-8",
        "PORT=8080",
        "HOME=/root",
        "TZ=Europe/London",
    ] {
        let v = mask_one(pair);
        assert!(!v.masked, "{pair} must not be masked");
        assert_eq!(v.value.as_deref(), Some(pair.split_once('=').unwrap().1));
    }
}

#[test]
fn a_url_without_credentials_is_not_masked() {
    assert!(!mask_one("API_BASE=https://api.example.com/v1").masked);
    assert!(!mask_one("HOMEPAGE=http://example.com").masked);
    // An `@` in the path or query is not an authority credential.
    assert!(!mask_one("CALLBACK=https://example.com/u/@alice?x=1").masked);
    // Bare userinfo with no password is an identity, not a secret.
    assert!(!mask_one("GIT_REMOTE=ssh://git@github.com/acme/app").masked);
}

#[test]
fn credential_url_detection_handles_edge_cases() {
    assert!(value_has_embedded_credentials("postgres://u:p@h/db"));
    assert!(value_has_embedded_credentials("mongodb://user:pass@host:27017/db?ssl=true"));
    assert!(!value_has_embedded_credentials("not a url"));
    assert!(!value_has_embedded_credentials(""));
    assert!(!value_has_embedded_credentials("user:pass@host"), "no scheme, no authority");
    assert!(!value_has_embedded_credentials("https://host/a:b@c"));
}

#[test]
fn key_fragment_matching_is_substring_and_case_insensitive() {
    assert!(is_secret_key("X_TOKEN_Y"));
    assert!(is_secret_key("token"));
    assert!(!is_secret_key("NODE_ENV"));
    assert!(!is_secret_key(""));
}

#[test]
fn reveal_returns_the_values_verbatim() {
    // Only ever reachable from an explicitly authorised request.
    let pairs = vec!["DB_PASSWORD=hunter2".to_string()];
    let revealed = read_env(&pairs, true).remove(0);
    assert!(!revealed.masked);
    assert_eq!(revealed.value.as_deref(), Some("hunter2"));
}

#[test]
fn detail_json_masks_by_default_and_reveals_only_when_asked() {
    let d = ContainerDetail::from_inspect(&json(FIXTURE_INSPECT));

    let masked = d.to_json();
    let env = masked.get("env").unwrap().as_array().unwrap();
    assert_eq!(env[0].get("key").unwrap().as_str(), Some("DATABASE_URL"));
    assert!(env[0].get("value").unwrap().is_null(), "value must be an explicit null");
    assert_eq!(env[0].get("masked").unwrap().as_bool(), Some(true));
    assert_eq!(env[1].get("key").unwrap().as_str(), Some("NODE_ENV"));
    assert_eq!(env[1].get("value").unwrap().as_str(), Some("production"));
    assert_eq!(env[1].get("masked").unwrap().as_bool(), Some(false));
    assert!(env[2].get("value").unwrap().is_null(), "POSTGRES_PASSWORD must be withheld");

    // The serialised document must not contain the secrets anywhere.
    let text = masked.to_string();
    assert!(!text.contains("hunter2"));
    assert!(!text.contains("postgres://u:p@h/db"));

    let revealed = d.to_json_with(true).to_string();
    assert!(revealed.contains("hunter2"));
}

#[test]
fn variables_without_an_equals_sign_are_kept() {
    // Legal through the API: `Env: ["FOO"]` inherits from the daemon.
    let v = mask_one("SOME_FLAG");
    assert_eq!(v.key, "SOME_FLAG");
    assert_eq!(v.value.as_deref(), Some(""));
    assert!(!v.masked);
}

#[test]
fn masking_preserves_order_and_never_drops_a_variable() {
    let pairs: Vec<String> = ["A=1", "PASSWORD=2", "B=3", "TOKEN=4", "C=5"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let out = mask_env(&pairs);
    assert_eq!(out.len(), 5);
    assert_eq!(
        out.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(),
        vec!["A", "PASSWORD", "B", "TOKEN", "C"]
    );
    assert_eq!(out.iter().filter(|e| e.masked).count(), 2);
}

#[test]
fn an_empty_value_is_distinguishable_from_a_withheld_one() {
    let empty = mask_one("NODE_ENV=");
    assert_eq!(empty.value.as_deref(), Some(""));
    assert!(!empty.masked);
    assert_eq!(empty.to_json().get("value").unwrap().as_str(), Some(""));

    let withheld = mask_one("SECRET=");
    assert_eq!(withheld.value, None);
    assert!(withheld.to_json().get("value").unwrap().is_null());
}

// ==========================================================================
// Stats
// ==========================================================================

#[test]
fn stats_map_a_real_busy_sample() {
    let s = ContainerStats::from_json(&json(FIXTURE_STATS_BUSY));
    assert_eq!(s.id, "d2cbd9822f62");
    assert_eq!(s.read_at, Some(1_789_201_505));
    assert_eq!(s.online_cpus, 2);
    assert_eq!(s.memory_bytes, 536_576);
    assert_eq!(s.memory_limit_bytes, 67_108_864);
    assert_eq!(s.pids, Some(1));
    assert_eq!(s.net_rx_bytes, 1025, "interfaces are summed");
    assert_eq!(s.net_tx_bytes, 2050);
}

#[test]
fn cpu_percent_follows_dockers_documented_formula() {
    // (3047449544 - 2045856664) / (5721330000000 - 5719330000000) * 2 * 100
    let pct = compute_cpu_percent(&json(FIXTURE_STATS_BUSY));
    assert!((pct - 100.159_288).abs() < 0.000_1, "got {pct}");
    assert_eq!(serveros_json::round(pct, 1), 100.2);
}

#[test]
fn cpu_percent_is_zero_when_the_system_delta_is_not_positive() {
    // Two samples taken within the same jiffy: dividing would be nonsense.
    let v = json(
        r#"{"cpu_stats":{"cpu_usage":{"total_usage":200},"system_cpu_usage":1000,"online_cpus":4},
            "precpu_stats":{"cpu_usage":{"total_usage":100},"system_cpu_usage":1000}}"#,
    );
    assert_eq!(compute_cpu_percent(&v), 0.0);
}

#[test]
fn cpu_percent_is_zero_when_there_is_no_previous_sample() {
    // What `one-shot=true` produces. A baseline of zero would yield a
    // plausible-looking number with no meaning behind it.
    let v = json(
        r#"{"cpu_stats":{"cpu_usage":{"total_usage":5000000},"system_cpu_usage":9000000000,"online_cpus":2},
            "precpu_stats":{"cpu_usage":{"total_usage":0},"system_cpu_usage":0}}"#,
    );
    assert_eq!(compute_cpu_percent(&v), 0.0);

    // And when precpu_stats is missing altogether.
    let v = json(r#"{"cpu_stats":{"cpu_usage":{"total_usage":5},"system_cpu_usage":9}}"#);
    assert_eq!(compute_cpu_percent(&v), 0.0);
}

#[test]
fn cpu_percent_is_zero_for_a_stopped_container() {
    let s = ContainerStats::from_json(&json(FIXTURE_STATS_STOPPED));
    assert_eq!(s.cpu_percent, 0.0);
    assert_eq!(s.memory_bytes, 0);
    assert_eq!(s.memory_limit_bytes, 0);
    assert_eq!(s.memory_percent, 0.0, "no limit must not divide by zero");
    assert_eq!(s.read_at, None);
}

#[test]
fn cpu_count_falls_back_to_percpu_then_to_one() {
    let with_online = json(r#"{"online_cpus":8,"cpu_usage":{"percpu_usage":[1,2]}}"#);
    assert_eq!(online_cpus(Some(&with_online)), 8);

    // Pre-1.27 daemons only report percpu_usage.
    let percpu = json(r#"{"cpu_usage":{"percpu_usage":[1,2,3,4]}}"#);
    assert_eq!(online_cpus(Some(&percpu)), 4);

    let neither = json(r#"{"cpu_usage":{}}"#);
    assert_eq!(online_cpus(Some(&neither)), 1);
    assert_eq!(online_cpus(None), 1);

    // online_cpus: 0 is nonsense; do not multiply a percentage by zero.
    let zero = json(r#"{"online_cpus":0,"cpu_usage":{"percpu_usage":[1,2,3]}}"#);
    assert_eq!(online_cpus(Some(&zero)), 3);
}

#[test]
fn cpu_percent_scales_with_the_cpu_count() {
    let one = json(
        r#"{"cpu_stats":{"cpu_usage":{"total_usage":1100},"system_cpu_usage":11000,"online_cpus":1},
            "precpu_stats":{"cpu_usage":{"total_usage":100},"system_cpu_usage":1000}}"#,
    );
    // 1000/10000 * 1 * 100 = 10%
    assert!((compute_cpu_percent(&one) - 10.0).abs() < 1e-9);

    let four = json(
        r#"{"cpu_stats":{"cpu_usage":{"total_usage":1100},"system_cpu_usage":11000,"online_cpus":4},
            "precpu_stats":{"cpu_usage":{"total_usage":100},"system_cpu_usage":1000}}"#,
    );
    assert!((compute_cpu_percent(&four) - 40.0).abs() < 1e-9);
}

#[test]
fn memory_subtracts_the_page_cache_on_cgroup_v1() {
    let v = json(
        r#"{"memory_stats":{"usage":1000,"limit":4000,"stats":{"cache":400,"rss":600}}}"#,
    );
    assert_eq!(compute_memory(&v), (600, 4000));
}

#[test]
fn memory_subtracts_inactive_file_on_cgroup_v2() {
    // cgroup v2 has no `cache` key at all.
    let v = json(
        r#"{"memory_stats":{"usage":1000,"limit":4000,"stats":{"inactive_file":250,"anon":700}}}"#,
    );
    assert_eq!(compute_memory(&v), (750, 4000));
}

#[test]
fn memory_falls_back_to_raw_usage_and_never_underflows() {
    let bare = json(r#"{"memory_stats":{"usage":1000,"limit":4000}}"#);
    assert_eq!(compute_memory(&bare), (1000, 4000));

    // Cache larger than usage: the two were sampled at different moments.
    let skewed = json(r#"{"memory_stats":{"usage":100,"limit":4000,"stats":{"cache":500}}}"#);
    assert_eq!(compute_memory(&skewed), (100, 4000));

    assert_eq!(compute_memory(&json("{}")), (0, 0));
}

#[test]
fn memory_percent_is_derived_from_the_working_set() {
    let v = json(r#"{"memory_stats":{"usage":600,"limit":2000,"stats":{"cache":100}}}"#);
    let s = ContainerStats::from_json(&v);
    assert_eq!(s.memory_bytes, 500);
    assert_eq!(s.memory_percent, 25.0);
    assert_eq!(s.to_json().get("memory_percent").unwrap().as_f64(), Some(25.0));
}

// ==========================================================================
// Log demultiplexing
// ==========================================================================

fn drain(stream: &mut DemuxReader<impl Read>) -> Vec<Frame> {
    let mut out = Vec::new();
    while let Some(f) = stream.next_frame().expect("frame") {
        out.push(f);
    }
    out
}

#[test]
fn demux_splits_real_stdout_and_stderr_frames() {
    let mut r = DemuxReader::new(std::io::Cursor::new(LOG_BYTES_MUX));
    let frames = drain(&mut r);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].stream, StreamKind::Stdout);
    assert_eq!(frames[0].data, b"out\n");
    assert_eq!(frames[1].stream, StreamKind::Stderr);
    assert_eq!(frames[1].data, b"err\n");
}

/// A reader that hands out at most `chunk` bytes per call, so a frame header
/// lands across two `read()`s the way it does on a real socket.
struct Trickle<'a> {
    data: &'a [u8],
    pos: usize,
    chunk: usize,
}

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.chunk.min(buf.len()).min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn demux_reassembles_a_header_split_across_reads() {
    // Three bytes at a time: every 8-byte header spans three reads.
    let mut r = DemuxReader::new(Trickle { data: LOG_BYTES_MUX, pos: 0, chunk: 3 });
    let frames = drain(&mut r);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].data, b"out\n");
    assert_eq!(frames[1].data, b"err\n");
}

#[test]
fn demux_reassembles_a_payload_split_across_reads() {
    let mut r = DemuxReader::new(Trickle { data: LOG_BYTES_MUX, pos: 0, chunk: 1 });
    let frames = drain(&mut r);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[1].data, b"err\n");
}

#[test]
fn demux_accepts_a_zero_length_frame() {
    // An empty write still produces a header, and it is not end-of-stream.
    let bytes: &[u8] = &[
        0x01, 0, 0, 0, 0, 0, 0, 0x00, // stdout, length 0
        0x02, 0, 0, 0, 0, 0, 0, 0x02, b'h', b'i',
    ];
    let mut r = DemuxReader::new(std::io::Cursor::new(bytes));
    let frames = drain(&mut r);
    assert_eq!(frames.len(), 2);
    assert!(frames[0].data.is_empty());
    assert_eq!(frames[1].data, b"hi");
}

#[test]
fn demux_reports_a_truncated_header() {
    let mut r = DemuxReader::new(std::io::Cursor::new(&[0x01u8, 0, 0, 0][..]));
    let err = r.next_frame().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn demux_reports_a_truncated_payload() {
    let bytes: &[u8] = &[0x01, 0, 0, 0, 0, 0, 0, 0x10, b's', b'h', b'o', b'r', b't'];
    let mut r = DemuxReader::new(std::io::Cursor::new(bytes));
    let err = r.next_frame().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

#[test]
fn demux_refuses_an_absurd_frame_size() {
    // 0xFFFFFFFF would be a 4 GiB allocation from a corrupt or hostile stream.
    let bytes: &[u8] = &[0x01, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF];
    let mut r = DemuxReader::new(std::io::Cursor::new(bytes));
    let err = r.next_frame().unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn demux_returns_none_at_a_clean_end_of_stream() {
    let mut r = DemuxReader::new(std::io::Cursor::new(&[][..]));
    assert!(r.next_frame().unwrap().is_none());
    assert!(r.next_frame().unwrap().is_none(), "and stays ended");
}

#[test]
fn stream_kinds_map_to_their_wire_bytes() {
    assert_eq!(StreamKind::from_byte(0), StreamKind::Stdin);
    assert_eq!(StreamKind::from_byte(1), StreamKind::Stdout);
    assert_eq!(StreamKind::from_byte(2), StreamKind::Stderr);
    assert_eq!(StreamKind::from_byte(9), StreamKind::Unknown(9));
    assert_eq!(StreamKind::Stderr.as_str(), "stderr");
}

#[test]
fn a_tty_stream_is_passed_through_unframed() {
    // Real bytes from a `-t` container: no headers, and CRLF line endings.
    let raw = b"ttyline\r\n".to_vec();
    let mut s = LogStream::new(Box::new(std::io::Cursor::new(raw)), true);
    let f = s.next_frame().unwrap().unwrap();
    assert_eq!(f.stream, StreamKind::Stdout);
    assert_eq!(f.data, b"ttyline\r\n");
    assert!(s.next_frame().unwrap().is_none());
}

#[test]
fn log_stream_reads_out_payload_bytes_with_headers_removed() {
    let mut s = LogStream::new(Box::new(std::io::Cursor::new(LOG_BYTES_MUX.to_vec())), false);
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    assert_eq!(out, "out\nerr\n");
}

// ==========================================================================
// Log lines
// ==========================================================================

fn frames_of(bytes: &[u8]) -> Vec<Frame> {
    let mut r = DemuxReader::new(std::io::Cursor::new(bytes.to_vec()));
    drain(&mut r)
}

#[test]
fn frames_become_lines_tagged_with_their_stream() {
    let lines = frames_to_lines(&frames_of(LOG_BYTES_MUX), false);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].stream, StreamKind::Stdout);
    assert_eq!(lines[0].message, "out");
    assert_eq!(lines[0].timestamp, None);
    assert_eq!(lines[1].stream, StreamKind::Stderr);
    assert_eq!(lines[1].message, "err");
}

#[test]
fn a_line_split_across_frames_is_rejoined() {
    let frames = vec![
        Frame { stream: StreamKind::Stdout, data: b"hello ".to_vec() },
        Frame { stream: StreamKind::Stderr, data: b"interleaved\n".to_vec() },
        Frame { stream: StreamKind::Stdout, data: b"world\nnext\n".to_vec() },
    ];
    let lines = frames_to_lines(&frames, false);
    assert_eq!(lines.len(), 3);
    // The stderr line completes first; the stdout halves still join correctly.
    assert_eq!(lines[0].message, "interleaved");
    assert_eq!(lines[1].message, "hello world");
    assert_eq!(lines[2].message, "next");
}

#[test]
fn a_trailing_line_without_a_newline_is_still_emitted() {
    let frames = vec![Frame { stream: StreamKind::Stdout, data: b"no newline".to_vec() }];
    let lines = frames_to_lines(&frames, false);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].message, "no newline");
}

#[test]
fn timestamps_are_split_off_the_front_of_the_line() {
    let lines = frames_to_lines(&frames_of(LOG_BYTES_TS), true);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].message, "out");
    assert_eq!(lines[0].timestamp, Some(1_789_200_759));

    let v = lines[0].to_json();
    assert_eq!(v.get("stream").unwrap().as_str(), Some("stdout"));
    assert_eq!(v.get("message").unwrap().as_str(), Some("out"));
}

#[test]
fn a_line_that_is_not_timestamped_keeps_its_whole_text() {
    // Asked for timestamps but the line does not start with one: do not eat
    // the first word.
    let frames = vec![Frame { stream: StreamKind::Stdout, data: b"plain line here\n".to_vec() }];
    let lines = frames_to_lines(&frames, true);
    assert_eq!(lines[0].message, "plain line here");
    assert_eq!(lines[0].timestamp, None);
}

#[test]
fn carriage_returns_from_a_tty_are_stripped() {
    let frames = vec![Frame { stream: StreamKind::Stdout, data: b"ttyline\r\n".to_vec() }];
    assert_eq!(frames_to_lines(&frames, false)[0].message, "ttyline");
}

#[test]
fn non_utf8_output_is_kept_rather_than_dropped() {
    let frames = vec![Frame { stream: StreamKind::Stdout, data: vec![0xff, 0xfe, b'\n'] }];
    let lines = frames_to_lines(&frames, false);
    assert_eq!(lines.len(), 1);
    assert!(!lines[0].message.is_empty());
}

// ==========================================================================
// Images, volumes, networks
// ==========================================================================

#[test]
fn images_map_a_real_entry() {
    let images = parse_images(&json(FIXTURE_IMAGES)).unwrap();
    assert_eq!(images.len(), 1);
    let i = &images[0];
    assert_eq!(i.short_id(), "9a0cea180511", "the sha256: prefix is dropped");
    assert_eq!(i.repo_tags, vec!["serveros-test:base"]);
    assert_eq!(i.repository.as_deref(), Some("serveros-test"));
    assert_eq!(i.tag.as_deref(), Some("base"));
    assert_eq!(i.size_bytes, 3_857_897);
    assert_eq!(i.created_at, Some(1_789_200_756));
    assert!(!i.dangling);
    // Containers: -1 is "did not compute", not "none".
    assert_eq!(i.containers, None);
    assert!(i.to_json().get("containers").is_none());
}

#[test]
fn an_untagged_image_is_reported_as_dangling() {
    let v = json(r#"[{"Id":"sha256:abc","RepoTags":["<none>:<none>"],"Size":10,"Containers":2}]"#);
    let i = &parse_images(&v).unwrap()[0];
    assert!(i.dangling);
    assert!(i.repo_tags.is_empty(), "the <none> placeholder is not a real tag");
    assert_eq!(i.repository, None);
    assert_eq!(i.tag, None);
    assert_eq!(i.containers, Some(2));

    let null_tags = json(r#"[{"Id":"sha256:abc","RepoTags":null,"Size":0}]"#);
    assert!(parse_images(&null_tags).unwrap()[0].dangling);
}

#[test]
fn repository_and_tag_split_on_the_right_colon() {
    assert_eq!(
        split_repo_tag("nginx:alpine"),
        (Some("nginx".into()), Some("alpine".into()))
    );
    assert_eq!(
        split_repo_tag("ghcr.io/acme/api:1.4"),
        (Some("ghcr.io/acme/api".into()), Some("1.4".into()))
    );
    // A registry port is not a tag separator.
    assert_eq!(
        split_repo_tag("registry.local:5000/team/app"),
        (Some("registry.local:5000/team/app".into()), None)
    );
    assert_eq!(
        split_repo_tag("registry.local:5000/team/app:2.0"),
        (Some("registry.local:5000/team/app".into()), Some("2.0".into()))
    );
    assert_eq!(split_repo_tag("postgres"), (Some("postgres".into()), None));
    assert_eq!(split_repo_tag(""), (None, None));
}

#[test]
fn images_reject_a_non_array_payload() {
    assert!(matches!(parse_images(&json("{}")), Err(DockerError::Decode(_))));
}

#[test]
fn volumes_map_a_real_entry() {
    let volumes = parse_volumes(&json(FIXTURE_VOLUMES)).unwrap();
    assert_eq!(volumes.len(), 1);
    let v = &volumes[0];
    assert_eq!(v.name, "serveros-testvol");
    assert_eq!(v.driver, "local");
    assert_eq!(v.mountpoint, "/var/lib/docker/volumes/serveros-testvol/_data");
    assert_eq!(v.created_at, Some(1_789_200_830));
    assert!(v.labels.is_empty(), "Labels: null must not panic");
    // Docker no longer returns UsageData from the list endpoint.
    assert_eq!(v.size_bytes, None);
    assert_eq!(v.in_use, None);
}

#[test]
fn volumes_read_usage_data_when_the_daemon_supplies_it() {
    let v = json(
        r#"{"Volumes":[{"Name":"pgdata","Driver":"local","Mountpoint":"/m",
            "UsageData":{"Size":41943040,"RefCount":2}}]}"#,
    );
    let vol = &parse_volumes(&v).unwrap()[0];
    assert_eq!(vol.size_bytes, Some(41_943_040));
    assert_eq!(vol.in_use, Some(true));

    // -1 means "did not compute", which is not the same as zero.
    let unknown = json(r#"{"Volumes":[{"Name":"x","UsageData":{"Size":-1,"RefCount":-1}}]}"#);
    let vol = &parse_volumes(&unknown).unwrap()[0];
    assert_eq!(vol.size_bytes, None);
    assert_eq!(vol.in_use, None);
}

#[test]
fn an_empty_volume_list_is_null_not_an_array() {
    // Verified against the live daemon: `{"Volumes":[],"Warnings":null}` when
    // empty on 29.x, but older daemons send `"Volumes": null`.
    assert!(parse_volumes(&json(r#"{"Volumes":null}"#)).unwrap().is_empty());
    assert!(parse_volumes(&json(r#"{"Volumes":[]}"#)).unwrap().is_empty());
    assert!(matches!(parse_volumes(&json("[]")), Err(DockerError::Decode(_))));
}

#[test]
fn volume_usage_is_derived_from_container_mounts() {
    let mut volumes = parse_volumes(&json(FIXTURE_VOLUMES)).unwrap();
    volumes.push(Volume::from_json(&json(r#"{"Name":"unused","Driver":"local"}"#)));

    // A *stopped* container still holds its volume.
    let containers = json(
        r#"[{"Id":"a","State":"exited",
             "Mounts":[{"Type":"volume","Name":"serveros-testvol","Destination":"/data"},
                       {"Type":"bind","Source":"/etc/hostname","Destination":"/h"}]}]"#,
    );
    apply_volume_usage(&mut volumes, &containers);
    assert_eq!(volumes[0].in_use, Some(true));
    assert_eq!(volumes[1].in_use, Some(false));
}

#[test]
fn networks_map_real_entries() {
    let networks = parse_networks(&json(FIXTURE_NETWORKS)).unwrap();
    assert_eq!(networks.len(), 2);

    let none = &networks[0];
    assert_eq!(none.name, "none");
    assert_eq!(none.driver, "null");
    assert_eq!(none.scope, "local");
    assert!(!none.internal);
    // IPAM.Config is null on the null driver.
    assert_eq!(none.subnet, None);
    assert_eq!(none.gateway, None);

    let bridge = &networks[1];
    assert_eq!(bridge.name, "serveros-testnet");
    assert_eq!(bridge.short_id(), "6feed715e796");
    assert_eq!(bridge.subnet.as_deref(), Some("172.17.0.0/16"));
    assert_eq!(bridge.gateway.as_deref(), Some("172.17.0.1"));
    // Docker 25+ omits the Containers map from the list endpoint.
    assert_eq!(bridge.container_count, None);
}

#[test]
fn networks_use_the_containers_map_when_the_daemon_sends_one() {
    let v = json(r#"[{"Name":"bridge","Id":"x","Containers":{"a":{},"b":{},"c":{}}}]"#);
    assert_eq!(parse_networks(&v).unwrap()[0].container_count, Some(3));
}

#[test]
fn network_membership_is_counted_from_the_container_list() {
    let mut networks = parse_networks(&json(FIXTURE_NETWORKS)).unwrap();
    let containers = json(FIXTURE_LIST);
    apply_network_counts(&mut networks, &containers);
    assert_eq!(networks[0].container_count, Some(0), "nothing is on `none`");
    assert_eq!(networks[1].container_count, Some(1));

    let v = networks[1].to_json();
    assert_eq!(v.get("container_count").unwrap().as_u64(), Some(1));
    assert_eq!(v.get("subnet").unwrap().as_str(), Some("172.17.0.0/16"));
}

#[test]
fn networks_reject_a_non_array_payload() {
    assert!(matches!(parse_networks(&json("{}")), Err(DockerError::Decode(_))));
}

#[test]
fn a_network_with_no_fields_at_all_still_parses() {
    let n = Network::from_json(&json("{}"));
    assert_eq!(n.scope, "local");
    assert_eq!(n.name, "");
    assert!(!n.internal);
}

#[test]
fn an_image_with_no_fields_at_all_still_parses() {
    let i = Image::from_json(&json("{}"));
    assert_eq!(i.size_bytes, 0);
    assert!(i.dangling);
}

// ==========================================================================
// Daemon info
// ==========================================================================

#[test]
fn info_summarises_a_real_daemon() {
    let i = DaemonInfo::from_json(&json(FIXTURE_INFO), &json(FIXTURE_VERSION), "1.43");
    assert_eq!(i.version, "29.4.3");
    // The negotiated version, not the daemon's maximum of 1.54.
    assert_eq!(i.api_version, "1.43");
    assert_eq!(i.root_dir, "/var/lib/docker");
    assert_eq!(i.storage_driver, "overlayfs");
    assert_eq!(i.containers_total, 4);
    assert_eq!(i.containers_running, 3);
    assert_eq!(i.containers_stopped, 1);
    assert_eq!(i.containers_paused, 0);
    assert_eq!(i.images, 1);
    assert_eq!(i.cpus, 2);
    assert_eq!(i.memory_bytes, 8_413_380_608);
    assert_eq!(i.cgroup_version.as_deref(), Some("1"));
    assert!(!i.live_restore);
    assert_eq!(i.warnings.len(), 2);
    assert!(i.warnings[1].contains("IPv4 forwarding"));
}

#[test]
fn info_falls_back_to_server_version_without_a_version_document() {
    let i = DaemonInfo::from_json(&json(FIXTURE_INFO), &Value::Null, "1.41");
    assert_eq!(i.version, "29.4.3");
    assert_eq!(i.api_version, "1.41");
}

#[test]
fn info_survives_a_daemon_that_reports_almost_nothing() {
    let i = DaemonInfo::from_json(&json("{}"), &json("{}"), "1.41");
    assert_eq!(i.version, "");
    assert_eq!(i.containers_total, 0);
    assert_eq!(i.cgroup_version, None);
    assert!(i.warnings.is_empty());
    assert_eq!(i.to_json().get("warnings").unwrap().as_array().unwrap().len(), 0);
}

#[test]
fn info_json_has_the_documented_shape() {
    let v = DaemonInfo::from_json(&json(FIXTURE_INFO), &json(FIXTURE_VERSION), "1.43").to_json();
    for key in [
        "version",
        "api_version",
        "root_dir",
        "storage_driver",
        "containers_total",
        "containers_running",
        "containers_stopped",
        "containers_paused",
        "images",
        "cpus",
        "memory_bytes",
        "cgroup_version",
        "live_restore",
        "warnings",
    ] {
        assert!(v.get(key).is_some(), "{key} must be present");
    }
}

// ==========================================================================
// Compose projects
// ==========================================================================

fn container_with(project: Option<&str>, service: &str, state: &str) -> Container {
    let labels = match project {
        Some(p) => format!(
            r#"{{"com.docker.compose.project":"{p}",
                 "com.docker.compose.service":"{service}",
                 "com.docker.compose.project.working_dir":"/srv/{p}"}}"#
        ),
        None => "{}".to_string(),
    };
    Container::from_list_entry(&json(&format!(
        r#"{{"Id":"{service}-id","Names":["/{service}"],"State":"{state}",
             "Status":"x","Labels":{labels}}}"#
    )))
}

#[test]
fn containers_group_into_a_project_by_their_compose_labels() {
    let containers = vec![
        container_with(Some("estatify"), "api", "running"),
        container_with(Some("estatify"), "worker", "running"),
        container_with(Some("estatify"), "db", "running"),
    ];
    let projects = group_projects(&containers);
    assert_eq!(projects.len(), 1);

    let p = &projects[0];
    assert_eq!(p.name, "estatify");
    assert_eq!(p.service_count(), 3);
    assert_eq!(p.container_count(), 3);
    assert_eq!(p.running(), 3);
    assert_eq!(p.state(), "running");
    assert_eq!(p.working_dir.as_deref(), Some("/srv/estatify"));
    assert_eq!(p.services, vec!["api", "db", "worker"], "services are sorted");
}

#[test]
fn a_half_running_project_is_partial_not_stopped() {
    // The state worth designing for: a deployment that only half came up.
    let containers = vec![
        container_with(Some("estatify"), "api", "running"),
        container_with(Some("estatify"), "worker", "exited"),
    ];
    let p = &group_projects(&containers)[0];
    assert_eq!(p.state(), "partial");
    assert_eq!(p.running(), 1);
}

#[test]
fn a_project_with_nothing_running_is_stopped() {
    let containers = vec![
        container_with(Some("estatify"), "api", "exited"),
        container_with(Some("estatify"), "worker", "created"),
    ];
    assert_eq!(group_projects(&containers)[0].state(), "stopped");
}

#[test]
fn standalone_containers_do_not_invent_a_project() {
    let containers = vec![
        container_with(None, "redis", "running"),
        container_with(Some("estatify"), "api", "running"),
    ];
    let projects = group_projects(&containers);
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].name, "estatify");
}

#[test]
fn projects_and_their_containers_come_back_sorted() {
    let containers = vec![
        container_with(Some("zebra"), "web", "running"),
        container_with(Some("alpha"), "worker", "running"),
        container_with(Some("alpha"), "api", "running"),
    ];
    let projects = group_projects(&containers);
    assert_eq!(projects.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["alpha", "zebra"]);
    assert_eq!(
        projects[0].containers.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        vec!["api", "worker"]
    );
}

#[test]
fn a_project_without_a_working_dir_label_reports_none() {
    let c = Container::from_list_entry(&json(
        r#"{"Id":"x","Names":["/x"],"State":"running","Status":"Up",
            "Labels":{"com.docker.compose.project":"legacy"}}"#,
    ));
    let p = &group_projects(&[c])[0];
    assert_eq!(p.working_dir, None);
    assert!(p.services.is_empty());
    assert!(p.to_json().get("working_dir").is_none());
}

#[test]
fn project_json_has_the_documented_shape() {
    let containers = vec![
        container_with(Some("estatify"), "api", "running"),
        container_with(Some("estatify"), "db", "exited"),
    ];
    let v = group_projects(&containers)[0].to_json();
    assert_eq!(v.get("name").unwrap().as_str(), Some("estatify"));
    assert_eq!(v.get("service_count").unwrap().as_u64(), Some(2));
    assert_eq!(v.get("container_count").unwrap().as_u64(), Some(2));
    assert_eq!(v.get("running").unwrap().as_u64(), Some(1));
    assert_eq!(v.get("state").unwrap().as_str(), Some("partial"));
    assert_eq!(v.get("containers").unwrap().as_array().unwrap().len(), 2);
}

// ==========================================================================
// Live tests — skipped gracefully when there is no daemon
// ==========================================================================

/// Whether a real daemon is listening on the conventional socket.
fn daemon_available() -> bool {
    DockerClient::connect(socket_path()).is_ok()
}

/// The socket the live tests use.
///
/// Overridable so the *skip* path can itself be exercised:
/// `SERVEROS_DOCKER_SOCKET=/nonexistent cargo test` must leave the suite green.
fn socket_path() -> String {
    std::env::var("SERVEROS_DOCKER_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.to_string())
}

/// A client, or `None` when there is no daemon to talk to.
fn live_client() -> Option<DockerClient> {
    if !daemon_available() {
        return None;
    }
    DockerClient::connect(socket_path()).ok()
}

macro_rules! require_daemon {
    () => {
        match live_client() {
            Some(c) => c,
            None => {
                eprintln!("skipping: no docker daemon");
                return;
            }
        }
    };
}

/// An image to build test containers from.
///
/// Image pulls are not assumed to work (an air-gapped box has no registry), so
/// this uses whatever is already local — preferring the fixture image created
/// by `docker import` — and skips when the daemon has none.
fn test_image(client: &DockerClient) -> Option<String> {
    let images = client.images().ok()?;
    if let Some(i) = images.iter().find(|i| i.repo_tags.iter().any(|t| t.starts_with("serveros-test")))
    {
        return i.repo_tags.first().cloned();
    }
    images.iter().find(|i| !i.dangling).and_then(|i| i.repo_tags.first().cloned())
}

/// A container created for one test, removed when the test ends — including on
/// panic, so a failing assertion does not leave rubbish on the daemon.
struct Scratch<'a> {
    client: &'a DockerClient,
    id: String,
}

impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        let _ = self.client.remove(&self.id, true, true);
    }
}

/// Create and start a container. Returns `None` if the daemon has no usable
/// image, which is a skip rather than a failure.
fn scratch<'a>(client: &'a DockerClient, name: &str, cmd: &[&str]) -> Option<Scratch<'a>> {
    let image = test_image(client)?;

    // Idempotent: a previous interrupted run may have left this name in use.
    let _ = client.remove(name, true, true);

    let body = Value::Object(
        Object::new()
            .set("Image", image)
            .set("Cmd", Value::array(cmd.to_vec()))
            .set("Tty", false)
            .set(
                "Labels",
                Value::Object(
                    Object::new()
                        .set("com.docker.compose.project", "serveros-selftest")
                        .set("com.docker.compose.service", name)
                        .set("com.docker.compose.project.working_dir", "/srv/selftest"),
                ),
            ),
    );

    let resp = client
        .http()
        .post_json(&client.url(&format!("/containers/create?name={name}")), &body)
        .ok()?;
    if !resp.is_success() {
        eprintln!("skipping: could not create container: {}", resp.text());
        return None;
    }
    let id = resp.json().ok()?.get("Id")?.as_str()?.to_string();
    let scratch = Scratch { client, id };
    client.start(&scratch.id).ok()?;
    Some(scratch)
}

macro_rules! require_scratch {
    ($client:expr, $name:expr, $cmd:expr) => {
        match scratch(&$client, $name, $cmd) {
            Some(s) => s,
            None => {
                eprintln!("skipping: no usable local image");
                return;
            }
        }
    };
}

#[test]
fn live_negotiates_a_version_the_daemon_accepts() {
    let client = require_daemon!();
    let version = client.api_version().to_string();
    // Printed under --nocapture: the first thing worth knowing when this crate
    // misbehaves on someone else's daemon.
    eprintln!("negotiated Docker API version: {version}");
    assert!(parse_version(&version).is_some(), "negotiated {version}");
    // Whatever we negotiated, the daemon must answer on that prefix.
    assert!(client.info().is_ok(), "daemon rejected /v{version}");
    assert!(client.is_available());
}

#[test]
fn live_info_reports_a_plausible_daemon() {
    let client = require_daemon!();
    let info = client.info().unwrap();
    assert!(!info.version.is_empty());
    assert!(!info.root_dir.is_empty());
    assert!(!info.storage_driver.is_empty());
    assert!(info.cpus >= 1);
    assert!(info.memory_bytes > 0);
    assert_eq!(info.api_version, client.api_version());
    assert!(
        info.containers_total >= info.containers_running,
        "{info:?}"
    );
}

#[test]
fn live_lists_and_inspects_a_real_container() {
    let client = require_daemon!();
    let s = require_scratch!(client, "serveros-live-list", &["/bin/sh", "-c", "sleep 30"]);

    let listed = client.list(true).unwrap();
    let found = listed.iter().find(|c| c.id == s.id).expect("our container must be listed");
    assert_eq!(found.name, "serveros-live-list");
    assert_eq!(found.state, "running");
    assert!(found.created_at.unwrap() > 1_600_000_000);
    assert_eq!(found.compose_project.as_deref(), Some("serveros-selftest"));

    let detail = client.inspect(&s.id).unwrap();
    assert_eq!(detail.container.id, s.id);
    assert_eq!(detail.command, vec!["/bin/sh", "-c", "sleep 30"]);
    assert!(!detail.tty);
    assert_eq!(detail.container.restart_count, Some(0));
    assert!(detail.container.started_at.is_some());
    // Whatever the daemon put in Env, none of it may leak unmasked.
    for var in detail.env() {
        if var.masked {
            assert_eq!(var.value, None);
        }
    }
}

#[test]
fn live_lifecycle_verbs_move_a_container_between_states() {
    let client = require_daemon!();
    let s = require_scratch!(client, "serveros-live-cycle", &["/bin/sh", "-c", "sleep 60"]);

    assert_eq!(client.inspect(&s.id).unwrap().container.state, "running");

    client.pause(&s.id).unwrap();
    assert_eq!(client.inspect(&s.id).unwrap().container.state, "paused");
    client.unpause(&s.id).unwrap();
    assert_eq!(client.inspect(&s.id).unwrap().container.state, "running");

    client.restart(&s.id, Some(1)).unwrap();
    assert_eq!(client.inspect(&s.id).unwrap().container.state, "running");

    client.stop(&s.id, Some(1)).unwrap();
    let stopped = client.inspect(&s.id).unwrap();
    assert_eq!(stopped.container.state, "exited");
    assert!(stopped.finished_at.is_some());

    // Stopping twice is not an error: Docker answers 304, which means the
    // requested state has been reached.
    client.stop(&s.id, Some(1)).unwrap();

    client.start(&s.id).unwrap();
    assert_eq!(client.inspect(&s.id).unwrap().container.state, "running");
    client.start(&s.id).unwrap();
}

#[test]
fn live_reads_and_demultiplexes_real_container_logs() {
    let client = require_daemon!();
    let s = require_scratch!(
        client,
        "serveros-live-logs",
        &["/bin/sh", "-c", "echo out; echo err >&2; sleep 30"]
    );
    // Give the shell a moment to write both lines.
    std::thread::sleep(std::time::Duration::from_millis(600));

    let lines = client.logs(&s.id, 100, None, false).unwrap();
    assert!(lines.len() >= 2, "got {lines:?}");
    assert!(
        lines.iter().any(|l| l.stream == StreamKind::Stdout && l.message == "out"),
        "stdout line missing from {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.stream == StreamKind::Stderr && l.message == "err"),
        "stderr line missing from {lines:?}"
    );
    for l in &lines {
        assert_eq!(l.timestamp, None, "timestamps were not requested");
    }

    let stamped = client.logs(&s.id, 100, None, true).unwrap();
    assert!(stamped.iter().all(|l| l.timestamp.is_some()), "got {stamped:?}");
    assert!(stamped.iter().any(|l| l.message == "out"), "the stamp must be split off");
    assert!(stamped[0].timestamp.unwrap() > 1_600_000_000);
}

#[test]
fn live_follows_a_log_stream() {
    let client = require_daemon!();
    let s = require_scratch!(
        client,
        "serveros-live-follow",
        &["/bin/sh", "-c", "echo first; sleep 30"]
    );
    std::thread::sleep(std::time::Duration::from_millis(600));

    let mut stream = client.logs_frames(&s.id, 10, None, false).unwrap();
    let frame = stream.next_frame().unwrap().expect("at least one frame");
    assert_eq!(frame.stream, StreamKind::Stdout);
    assert_eq!(String::from_utf8_lossy(&frame.data).trim(), "first");
}

#[test]
fn live_stats_produce_a_usable_sample() {
    let client = require_daemon!();
    let s = require_scratch!(client, "serveros-live-stats", &["/bin/sh", "-c", "sleep 30"]);

    let stats = client.stats_once(&s.id).unwrap();
    assert_eq!(stats.id, s.id);
    assert!(stats.online_cpus >= 1);
    assert!(stats.memory_limit_bytes > 0, "the host memory limit must be reported");
    assert!(stats.memory_bytes > 0, "a running container uses some memory");
    // A sleeping shell uses almost nothing, but the number must be sane.
    assert!(
        (0.0..=100.0 * stats.online_cpus as f64).contains(&stats.cpu_percent),
        "implausible cpu {}",
        stats.cpu_percent
    );
    assert!(stats.read_at.is_some(), "one-shot=false must give a real read time");

    let mut c = client.inspect(&s.id).unwrap().container;
    c.apply_stats(&stats);
    assert!(c.to_json().get("cpu_percent").is_some());
}

#[test]
fn live_lists_images_volumes_and_networks() {
    let client = require_daemon!();

    let images = client.images().unwrap();
    for i in &images {
        assert!(!i.id.is_empty());
        assert_eq!(i.dangling, i.repo_tags.is_empty());
    }

    // Volumes and networks may be empty on a fresh daemon; the contract is that
    // the call succeeds and every entry is fully populated.
    for v in client.volumes().unwrap() {
        assert!(!v.name.is_empty());
        assert!(v.in_use.is_some(), "usage must be resolved one way or another");
    }
    let networks = client.networks().unwrap();
    assert!(!networks.is_empty(), "every daemon has at least `none` and `host`");
    for n in &networks {
        assert!(!n.id.is_empty());
        assert!(n.container_count.is_some());
    }
}

#[test]
fn live_groups_containers_into_a_project() {
    let client = require_daemon!();
    let s = require_scratch!(client, "serveros-live-project", &["/bin/sh", "-c", "sleep 30"]);
    let _ = &s;

    let projects = client.projects().unwrap();
    let p = projects
        .iter()
        .find(|p| p.name == "serveros-selftest")
        .expect("our labelled container must form a project");
    assert_eq!(p.working_dir.as_deref(), Some("/srv/selftest"));
    assert!(p.services.iter().any(|s| s == "serveros-live-project"));
    assert!(matches!(p.state(), "running" | "partial"));
}

#[test]
fn live_missing_container_is_a_not_found_with_dockers_message() {
    let client = require_daemon!();
    let err = client.inspect("serveros-definitely-not-here").unwrap_err();
    match err {
        DockerError::NotFound(m) => assert!(m.contains("No such container"), "got {m}"),
        other => panic!("expected NotFound, got {other:?}"),
    }
    assert!(matches!(
        client.start("serveros-definitely-not-here"),
        Err(DockerError::NotFound(_))
    ));
}

#[test]
fn connecting_to_a_missing_socket_reports_unavailable() {
    // Does not need a daemon: the point is the absence of one.
    let err = DockerClient::connect("/tmp/serveros-no-such-docker.sock").unwrap_err();
    assert!(err.is_unavailable(), "got {err:?}");
    assert_eq!(err.to_string(), "the Docker daemon is not reachable");
}
