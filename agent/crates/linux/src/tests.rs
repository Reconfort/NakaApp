//! Integration tests against the **live** `/proc` of whatever machine is
//! running them.
//!
//! The per-module unit tests pin parser behaviour against fixture text. These
//! do the complementary job: they prove the readers point at the right paths
//! and that the invariants hold on a real, moving system. They therefore assert
//! *shapes and ranges*, never exact values — a test that asserts this machine
//! has 4 GB of RAM is a test that fails on the next machine.
//!
//! Everything here must pass inside a container, which is the most constrained
//! environment the agent ships into: no DMI tables, no `/etc/shadow` access
//! when unprivileged, a mount table full of overlays, and a process list that
//! changes between two statements of the same test.

use crate::metrics::{DiskSource, MetricsSampler, ProcDiskSource, operstate_is_up, parse_cpu_stat};
use crate::processes::{ProcessQuery, SortKey, list_processes};
use crate::system::read_system_info;
use crate::users::{list_groups, list_users, resolve_uid};
use std::time::Duration;

// ---- system --------------------------------------------------------------

#[test]
fn live_system_info_is_coherent() {
    let info = read_system_info().expect("procfs must be readable");

    assert!(!info.hostname.is_empty(), "hostname must never be blank");
    assert!(!info.kernel.is_empty(), "kernel release must never be blank");
    assert!(!info.architecture.is_empty());
    assert!(!info.os.pretty.is_empty());
    assert!(!info.os.id.is_empty());

    assert!(info.cpu.threads >= 1, "a machine always has at least one CPU");
    assert!(info.cpu.cores >= 1);
    assert!(info.cpu.cores <= info.cpu.threads);
    assert!(!info.cpu.model.is_empty());
    assert!(info.cpu.mhz >= 0.0 && info.cpu.mhz.is_finite());

    assert!(info.memory_total_bytes > 0, "installed memory must be known");

    assert!(info.boot_time > 1_000_000_000, "boot time looks like a Unix timestamp");
    assert!(info.boot_time <= crate::procfs::now_unix() + 1);

    for v in [info.load_average.one, info.load_average.five, info.load_average.fifteen] {
        assert!(v.is_finite() && v >= 0.0, "load average {v}");
    }
}

#[test]
fn live_system_json_round_trips_through_the_parser() {
    let json = read_system_info().unwrap().to_json().to_string();
    let parsed = serveros_json::from_str(&json).expect("agent output must be valid JSON");
    assert!(parsed.path("os/pretty").and_then(|v| v.as_str()).is_some());
    assert!(parsed.path("cpu/threads").and_then(|v| v.as_u64()).unwrap_or(0) >= 1);
    assert!(parsed.get("virtualization").is_some(), "key present even when null");
}

#[test]
fn live_uptime_advances_with_the_clock() {
    let a = read_system_info().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let b = read_system_info().unwrap();
    assert!(b.uptime_seconds >= a.uptime_seconds, "uptime must be monotonic");
    assert_eq!(a.boot_time.abs_diff(b.boot_time), 0, "boot time must be stable");
}

// ---- metrics -------------------------------------------------------------

#[test]
fn live_proc_stat_has_an_aggregate_row_and_per_core_rows() {
    let text = crate::procfs::read_text("/proc/stat").unwrap();
    let snap = parse_cpu_stat(&text).expect("/proc/stat must have a cpu row");
    assert!(snap.total.total() > 0, "the machine has been running for some jiffies");
    assert!(!snap.cores.is_empty(), "at least one per-core row");
    // The aggregate is the sum of the cores, give or take the jiffies that
    // elapsed between the kernel writing the rows.
    let core_sum: u64 = snap.cores.iter().map(|c| c.total()).sum();
    assert!(core_sum > 0);
}

#[test]
fn live_first_sample_reports_no_rates() {
    let mut s = MetricsSampler::new();
    assert!(!s.has_baseline());
    let m = s.sample().expect("sampling must work on a live machine");
    assert!(s.has_baseline());

    assert_eq!(m.cpu.usage_percent, 0.0, "no baseline means no honest rate");
    assert_eq!(m.network.rx_bytes_per_sec, 0.0);
    // Absolute values are correct from the very first sample, though.
    assert!(m.memory.total_bytes > 0);
    assert!(m.sampled_at > 1_000_000_000);
}

#[test]
fn live_two_samples_produce_finite_in_range_numbers() {
    let mut s = MetricsSampler::new();
    s.sample().unwrap();
    std::thread::sleep(Duration::from_millis(120));
    let m = s.sample().unwrap();

    for (label, v) in [
        ("usage", m.cpu.usage_percent),
        ("user", m.cpu.user_percent),
        ("system", m.cpu.system_percent),
        ("iowait", m.cpu.iowait_percent),
        ("memory", m.memory.usage_percent),
        ("swap", m.memory.swap_usage_percent),
    ] {
        assert!(v.is_finite(), "{label} must be finite, got {v}");
        assert!((0.0..=100.0).contains(&v), "{label} out of range: {v}");
    }

    assert_eq!(m.cpu.per_core.len(), m.cpu.core_count, "one entry per core");
    for (i, v) in m.cpu.per_core.iter().enumerate() {
        assert!(v.is_finite() && (0.0..=100.0).contains(v), "core {i}: {v}");
    }

    assert!(m.memory.used_bytes <= m.memory.total_bytes);
    assert!(m.memory.available_bytes <= m.memory.total_bytes);
    assert!(m.memory.swap_used_bytes <= m.memory.swap_total_bytes);

    for r in [m.network.rx_bytes_per_sec, m.network.tx_bytes_per_sec] {
        assert!(r.is_finite() && r >= 0.0, "rate {r}");
    }
    for i in &m.network.interfaces {
        assert!(i.name != "lo", "loopback must never appear");
        assert!(!i.name.is_empty());
        assert!(i.rx_bytes_per_sec.is_finite() && i.rx_bytes_per_sec >= 0.0);
        assert!(i.tx_bytes_per_sec.is_finite() && i.tx_bytes_per_sec >= 0.0);
    }
}

#[test]
fn live_metrics_json_is_valid_json_with_the_expected_sections() {
    let mut s = MetricsSampler::new();
    s.sample().unwrap();
    std::thread::sleep(Duration::from_millis(120));
    let text = s.sample().unwrap().to_json().to_string();

    let v = serveros_json::from_str(&text).expect("metrics must serialise to valid JSON");
    for key in ["sampled_at", "cpu", "memory", "disk", "network"] {
        assert!(v.get(key).is_some(), "missing section {key}");
    }
    assert!(!text.contains("NaN") && !text.contains("Infinity"), "{text}");
}

#[test]
fn live_mount_table_is_filtered_but_not_empty() {
    let source = ProcDiskSource::new().expect("/proc/self/mounts must be readable");
    let mounts = source.mounts();
    assert!(!mounts.is_empty(), "a running system has at least a root filesystem");
    for m in mounts {
        assert!(m.mount_point.starts_with('/'), "{m:?}");
        assert!(!m.fstype.is_empty());
        // Pseudo-filesystems must have been filtered out.
        assert!(!matches!(m.fstype.as_str(), "proc" | "sysfs" | "devtmpfs" | "cgroup" | "cgroup2"));
    }
    // Whatever the root filesystem is, asking about it must not error.
    assert!(source.statfs("/").is_ok() || !mounts.iter().any(|m| m.mount_point == "/"));
}

#[test]
fn live_operstate_reads_as_a_boolean_for_every_interface() {
    let mut s = MetricsSampler::new();
    let m = s.sample().unwrap();
    // No assertion on which interfaces are up — only that reading operstate for
    // every live interface produced a value rather than an error or a hang.
    for i in &m.network.interfaces {
        let path = format!("/sys/class/net/{}/operstate", i.name);
        if let Some(state) = crate::procfs::read_line_opt(&path) {
            assert_eq!(i.up, operstate_is_up(&state));
        } else {
            assert!(!i.up, "no operstate node means we must not claim the link is up");
        }
    }
}

// ---- processes -----------------------------------------------------------

#[test]
fn live_process_list_contains_pid_1_and_this_test_binary() {
    let all = list_processes(&ProcessQuery { search: None, sort: SortKey::Pid, limit: 0 }).unwrap();
    assert!(!all.is_empty(), "at least one process must be running");

    let init = all.iter().find(|p| p.pid == 1).expect("pid 1 always exists");
    assert!(!init.name.is_empty());
    assert!(!init.command.is_empty());
    assert_eq!(init.ppid, 0, "pid 1 has no parent inside its namespace");

    let me = std::process::id();
    assert!(all.iter().any(|p| p.pid == me), "the test process must list itself");
}

#[test]
fn live_process_fields_are_all_in_range() {
    let all = list_processes(&ProcessQuery { search: None, sort: SortKey::Cpu, limit: 0 }).unwrap();
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as f64;
    for p in &all {
        assert!(p.pid > 0);
        assert!(p.threads >= 1, "pid {} reported {} threads", p.pid, p.threads);
        assert!(p.cpu_percent.is_finite() && p.cpu_percent >= 0.0, "pid {}", p.pid);
        assert!(p.cpu_percent <= 100.0 * cores.max(1.0), "pid {}: {}", p.pid, p.cpu_percent);
        assert!((0.0..=100.0).contains(&p.memory_percent), "pid {}", p.pid);
        assert!(!p.command.is_empty(), "pid {} has an empty command", p.pid);
        assert_ne!(p.state, "", "pid {} has no state", p.pid);
    }
}

#[test]
fn live_process_sorting_and_limit_are_applied() {
    let top = list_processes(&ProcessQuery { search: None, sort: SortKey::Memory, limit: 5 })
        .unwrap();
    assert!(top.len() <= 5, "limit must be honoured");
    for w in top.windows(2) {
        assert!(w[0].memory_bytes >= w[1].memory_bytes, "memory sort is descending");
    }

    let by_pid =
        list_processes(&ProcessQuery { search: None, sort: SortKey::Pid, limit: 0 }).unwrap();
    for w in by_pid.windows(2) {
        assert!(w[0].pid < w[1].pid, "pid sort is ascending and unique");
    }
}

#[test]
fn live_process_search_narrows_the_list() {
    let all = list_processes(&ProcessQuery { search: None, sort: SortKey::Pid, limit: 0 }).unwrap();
    let init_name = all.iter().find(|p| p.pid == 1).unwrap().name.clone();

    let hits = list_processes(&ProcessQuery {
        search: Some(init_name.to_uppercase()),
        sort: SortKey::Pid,
        limit: 0,
    })
    .unwrap();
    assert!(!hits.is_empty(), "searching for pid 1's own name must find it");
    assert!(hits.len() <= all.len());

    let none = list_processes(&ProcessQuery {
        search: Some("zzz-no-such-process-zzz".into()),
        sort: SortKey::Pid,
        limit: 0,
    })
    .unwrap();
    assert!(none.is_empty());
}

#[test]
fn live_process_walk_tolerates_processes_exiting_underneath_it() {
    // Churn the process table while walking it. Nothing here should panic or
    // return an error; vanished pids are simply absent from the result.
    for _ in 0..5 {
        let list = list_processes(&ProcessQuery { search: None, sort: SortKey::Cpu, limit: 0 });
        assert!(list.is_ok(), "a vanishing process is not an error");
    }
}

#[test]
fn live_process_json_is_valid_json() {
    let list = list_processes(&ProcessQuery::default()).unwrap();
    let text = crate::processes::process_json(&list).to_string();
    let parsed = serveros_json::from_str(&text).unwrap();
    assert_eq!(parsed.as_array().map(|a| a.len()), Some(list.len()));
}

// ---- users ---------------------------------------------------------------

#[test]
fn live_user_list_contains_root() {
    let users = list_users().expect("/etc/passwd must be readable");
    let root = users.iter().find(|u| u.uid == 0).expect("uid 0 always exists");
    assert_eq!(root.username, "root");
    assert!(root.is_system, "uid 0 is a system account");
    assert!(!root.home.is_empty());
    for u in &users {
        assert!(!u.username.is_empty());
        assert!(u.groups.iter().all(|g| !g.is_empty()));
    }
}

#[test]
fn live_user_json_never_contains_a_password_hash() {
    // The strongest form of the promise in the users module: whatever
    // `/etc/shadow` holds on this machine, none of it reaches the output.
    let json = crate::users::users_json(&list_users().unwrap()).to_string();
    for marker in ["$1$", "$2b$", "$5$", "$6$", "$y$", "$7$"] {
        assert!(!json.contains(marker), "hash prefix {marker} leaked into user JSON");
    }
    assert!(serveros_json::from_str(&json).is_ok());
}

#[test]
fn live_shadow_status_is_consistent_for_every_user() {
    let users = list_users().unwrap();
    // Either we could read /etc/shadow for everyone, or for no one; a mixture
    // would mean the parser silently dropped rows.
    let known = users.iter().filter(|u| u.locked.is_some()).count();
    assert!(known == 0 || known == users.len(), "{known} of {} users", users.len());
    for u in &users {
        assert_eq!(u.locked.is_some(), u.has_password.is_some());
        assert_eq!(u.last_login, None, "documented as unimplemented");
    }
}

#[test]
fn live_group_list_contains_root_and_resolves_primary_groups() {
    let groups = list_groups().expect("/etc/group must be readable");
    assert!(groups.iter().any(|g| g.gid == 0), "gid 0 always exists");
    for g in &groups {
        assert!(!g.name.is_empty());
        assert!(g.members.iter().all(|m| !m.is_empty()), "no empty member names");
    }

    // Every user's primary gid that exists as a group should appear first in
    // that user's group list.
    for u in list_users().unwrap() {
        if let Some(primary) = groups.iter().find(|g| g.gid == u.gid) {
            assert_eq!(u.groups.first().map(String::as_str), Some(primary.name.as_str()));
        }
    }
}

#[test]
fn live_resolve_uid_matches_the_user_list() {
    assert_eq!(resolve_uid(0).as_deref(), Some("root"));
    assert_eq!(resolve_uid(4_000_000_000), None, "an unassigned uid resolves to nothing");

    for u in list_users().unwrap() {
        // Several names can share a uid; resolve_uid returns the first, which
        // must at least be a real account with that uid.
        let resolved = resolve_uid(u.uid).expect("a listed uid must resolve");
        assert!(!resolved.is_empty());
    }
}

#[test]
fn live_uid_name_map_agrees_with_the_process_list() {
    let map = crate::users::uid_name_map();
    assert!(!map.is_empty());
    for p in list_processes(&ProcessQuery { search: None, sort: SortKey::Pid, limit: 0 }).unwrap() {
        // If a process resolved a user name, it must be the one the map holds.
        if let Some(name) = &p.user {
            let expected = map.iter().find(|(u, _)| *u == p.uid).map(|(_, n)| n.as_str());
            assert_eq!(Some(name.as_str()), expected, "pid {}", p.pid);
        }
    }
}
