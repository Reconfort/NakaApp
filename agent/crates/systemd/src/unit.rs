//! The product's view of a systemd unit.
//!
//! systemd describes a unit with two orthogonal strings — `ActiveState` and
//! `SubState` — plus a `LoadState` that says whether the unit file was even
//! found. That is exactly right for systemd and exactly wrong for a status
//! badge, so [`rollup_state`] flattens the pair into the six words the UI
//! actually renders. The raw strings are kept in the JSON as well: the product
//! brief is explicit that technical depth must stay reachable, just not first.

use std::collections::BTreeMap;

use serveros_json::{Object, Value};

use crate::dbus::DValue;
use crate::error::SystemdError;
use crate::names::display_name;

/// A unit as returned by `ListUnits`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Unit {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    /// The unit this one is "following" — systemd's alias mechanism. Usually
    /// empty; surfaced because a following unit's state is not its own.
    pub followed: String,
    pub object_path: String,
    pub job_id: u32,
    pub job_type: String,
    pub job_object_path: String,
    /// `UnitFileState`: `enabled`, `disabled`, `static`, `masked`, ... `None`
    /// when it was not looked up.
    pub enabled: Option<String>,
}

/// Flatten systemd's `(ActiveState, SubState)` into one word for the UI.
///
/// The mapping the product uses:
///
/// | systemd `ActiveState`      | product `state` |
/// |----------------------------|-----------------|
/// | `active` + `running`       | `running`       |
/// | `active` + anything else   | `running`       |
/// | `activating`               | `starting`      |
/// | `reloading`                | `starting`      |
/// | `deactivating`             | `stopping`      |
/// | `inactive`                 | `stopped`       |
/// | `failed`                   | `failed`        |
/// | anything else              | `unknown`       |
///
/// Two judgement calls worth knowing about:
///
///   * **`active` + `exited`** — a `Type=oneshot` unit that ran and finished —
///     maps to `running`. systemd considers it active and `systemctl is-active`
///     agrees; inventing a seventh state for it would mean the UI has a badge
///     no one can explain.
///   * **`reloading`** maps to `starting` rather than `running`, because it is
///     a transient state and the UI's transitional treatment (spinner, actions
///     disabled) is the honest rendering of "ask again in a second".
pub fn rollup_state(active_state: &str, sub_state: &str) -> &'static str {
    match (active_state, sub_state) {
        ("active", "running") => "running",
        ("active", _) => "running",
        ("activating", _) => "starting",
        ("reloading", _) => "starting",
        ("deactivating", _) => "stopping",
        ("inactive", _) => "stopped",
        ("failed", _) => "failed",
        _ => "unknown",
    }
}

impl Unit {
    /// Decode one element of `ListUnits`' `a(ssssssouso)` reply.
    pub fn from_list_entry(v: &DValue) -> Result<Unit, SystemdError> {
        let f = v.as_struct().ok_or_else(|| {
            SystemdError::Parse("ListUnits returned a non-struct element".to_owned())
        })?;
        if f.len() != 10 {
            return Err(SystemdError::Parse(format!(
                "ListUnits element has {} field(s), expected 10",
                f.len()
            )));
        }
        let s = |i: usize| f[i].as_str().unwrap_or_default().to_owned();
        Ok(Unit {
            name: s(0),
            description: s(1),
            load_state: s(2),
            active_state: s(3),
            sub_state: s(4),
            followed: s(5),
            object_path: s(6),
            job_id: f[7].as_u32().unwrap_or(0),
            job_type: s(8),
            job_object_path: s(9),
            enabled: None,
        })
    }

    /// The product-level rollup state.
    pub fn state(&self) -> &'static str {
        rollup_state(&self.active_state, &self.sub_state)
    }

    /// `nginx.service` -> `nginx`.
    pub fn display_name(&self) -> &str {
        display_name(&self.name)
    }

    /// True when systemd has the unit file and it is not masked.
    ///
    /// This is a *capability* flag, not a "would this do anything right now"
    /// flag — a running service still reports `can_start: true`. The UI decides
    /// which button to offer from `state`; these three say whether the backend
    /// can carry out the operation at all. A masked or missing unit reports
    /// false for everything, which is the case that actually matters.
    pub fn is_actionable(&self) -> bool {
        self.load_state.is_empty() || self.load_state == "loaded"
    }

    /// The JSON the agent's HTTP layer returns for a service row.
    pub fn to_json(&self) -> Value {
        let actionable = self.is_actionable();
        Value::Object(
            Object::new()
                .set("name", self.name.as_str())
                .set("display_name", self.display_name())
                .set("description", self.description.as_str())
                .set("load_state", self.load_state.as_str())
                .set("active_state", self.active_state.as_str())
                .set("sub_state", self.sub_state.as_str())
                .set("state", self.state())
                .set("enabled", self.enabled.clone())
                .set("can_start", actionable)
                .set("can_stop", actionable)
                .set("can_restart", actionable),
        )
    }
}

/// Everything the unit detail screen shows, on top of [`Unit`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UnitDetail {
    pub unit: Unit,
    pub main_pid: Option<u32>,
    pub memory_bytes: Option<u64>,
    pub cpu_usage_nsec: Option<u64>,
    pub tasks_current: Option<u64>,
    pub tasks_max: Option<u64>,
    /// `NRestarts`. Zero is kept as zero — see the note on sentinels below.
    pub restart_count: Option<u32>,
    /// `ActiveEnterTimestamp`, converted from microseconds to **seconds** since
    /// the epoch. systemd reports every timestamp in microseconds; leaving that
    /// unconverted is how a client ends up rendering the year 56000.
    pub active_since: Option<u64>,
    pub fragment_path: Option<String>,
    pub unit_file_state: Option<String>,
    pub result: Option<String>,
    pub exec_main_status: Option<i32>,
    pub documentation: Vec<String>,
    pub triggered_by: Vec<String>,
    pub requires: Vec<String>,
    pub wants: Vec<String>,
    /// systemd's own `CanStart`/`CanStop`/`CanReload`, when the properties were
    /// readable. These are authoritative and override the derived flags.
    pub can_start: Option<bool>,
    pub can_stop: Option<bool>,
    pub can_reload: Option<bool>,
}

/// systemd's "no value here" encodings.
///
/// A `t` property that is not being accounted reads as `0` **or** as
/// `(uint64) -1` depending on the property and the version, and a `s` property
/// that is unset reads as `""`. All three must become `null`, or the UI shows
/// "0 B of memory" for a service with no memory accounting and a support
/// ticket follows.
fn metric(v: Option<u64>) -> Option<u64> {
    match v {
        Some(0) | Some(u64::MAX) | None => None,
        some => some,
    }
}

fn text(v: Option<&str>) -> Option<String> {
    match v {
        Some("") | None => None,
        Some(s) => Some(s.to_owned()),
    }
}

impl UnitDetail {
    /// Build from the two `GetAll` property bags: `org.freedesktop.systemd1.Unit`
    /// and `org.freedesktop.systemd1.Service`.
    ///
    /// Missing properties are normal, not exceptional. `MemoryCurrent` is absent
    /// without `MemoryAccounting=yes`, `CPUUsageNSec` without cgroup v2, and the
    /// whole `Service` bag is absent for a `.socket`. Each costs one field.
    pub fn from_properties(name: &str, unit: &DValue, service: &DValue) -> UnitDetail {
        let u = |k: &str| unit.dict_get(k);
        let s = |k: &str| service.dict_get(k);

        let load_state = u("LoadState").and_then(DValue::as_str).unwrap_or_default();
        let active_state = u("ActiveState").and_then(DValue::as_str).unwrap_or_default();
        let sub_state = u("SubState").and_then(DValue::as_str).unwrap_or_default();
        let unit_file_state = text(u("UnitFileState").and_then(DValue::as_str));

        let base = Unit {
            name: u("Id").and_then(DValue::as_str).unwrap_or(name).to_owned(),
            description: u("Description").and_then(DValue::as_str).unwrap_or_default().to_owned(),
            load_state: load_state.to_owned(),
            active_state: active_state.to_owned(),
            sub_state: sub_state.to_owned(),
            followed: u("Following").and_then(DValue::as_str).unwrap_or_default().to_owned(),
            object_path: String::new(),
            job_id: 0,
            job_type: String::new(),
            job_object_path: String::new(),
            enabled: unit_file_state.clone(),
        };

        let strings = |v: Option<&DValue>| {
            v.and_then(DValue::as_string_vec).unwrap_or_default()
        };

        UnitDetail {
            unit: base,
            main_pid: s("MainPID")
                .and_then(DValue::as_u32)
                .filter(|p| *p != 0),
            memory_bytes: metric(s("MemoryCurrent").and_then(DValue::as_u64)),
            cpu_usage_nsec: metric(s("CPUUsageNSec").and_then(DValue::as_u64)),
            tasks_current: metric(s("TasksCurrent").and_then(DValue::as_u64)),
            tasks_max: metric(s("TasksMax").and_then(DValue::as_u64)),
            // NRestarts is a *count*, so 0 stays 0: "restarted 0 times" is a
            // fact and the product explicitly wants to show restart churn.
            restart_count: s("NRestarts").and_then(DValue::as_u32),
            active_since: u("ActiveEnterTimestamp")
                .and_then(DValue::as_u64)
                .filter(|t| *t != 0 && *t != u64::MAX)
                .map(|micros| micros / 1_000_000),
            fragment_path: text(u("FragmentPath").and_then(DValue::as_str)),
            unit_file_state,
            result: text(s("Result").and_then(DValue::as_str)),
            exec_main_status: s("ExecMainStatus").and_then(|v| {
                v.as_i64().and_then(|n| i32::try_from(n).ok())
            }),
            documentation: strings(u("Documentation")),
            triggered_by: strings(u("TriggeredBy")),
            requires: strings(u("Requires")),
            wants: strings(u("Wants")),
            can_start: u("CanStart").and_then(DValue::as_bool),
            can_stop: u("CanStop").and_then(DValue::as_bool),
            can_reload: u("CanReload").and_then(DValue::as_bool),
        }
    }

    /// Build from `systemctl show`'s `Key=Value` output.
    ///
    /// The same sentinel rules as [`UnitDetail::from_properties`] apply, plus
    /// two that only the textual form has: `[not set]`, which older systemd
    /// prints for an unaccounted metric, and `infinity`, which it prints for an
    /// unlimited `TasksMax`. Both mean "no number", so both become `null`.
    pub fn from_show_properties(name: &str, p: &BTreeMap<String, String>) -> UnitDetail {
        let get = |k: &str| p.get(k).map(String::as_str);
        let num = |k: &str| -> Option<u64> { metric(get(k).and_then(|v| v.parse::<u64>().ok())) };
        let list = |k: &str| -> Vec<String> {
            get(k)
                .unwrap_or_default()
                .split_whitespace()
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        };
        let yesno = |k: &str| -> Option<bool> {
            match get(k) {
                Some("yes") => Some(true),
                Some("no") => Some(false),
                _ => None,
            }
        };

        let unit_file_state = text(get("UnitFileState"));
        let base = Unit {
            name: get("Id").unwrap_or(name).to_owned(),
            description: get("Description").unwrap_or_default().to_owned(),
            load_state: get("LoadState").unwrap_or_default().to_owned(),
            active_state: get("ActiveState").unwrap_or_default().to_owned(),
            sub_state: get("SubState").unwrap_or_default().to_owned(),
            followed: get("Following").unwrap_or_default().to_owned(),
            object_path: String::new(),
            job_id: 0,
            job_type: String::new(),
            job_object_path: String::new(),
            enabled: unit_file_state.clone(),
        };

        UnitDetail {
            unit: base,
            main_pid: get("MainPID").and_then(|v| v.parse::<u32>().ok()).filter(|p| *p != 0),
            memory_bytes: num("MemoryCurrent"),
            cpu_usage_nsec: num("CPUUsageNSec"),
            tasks_current: num("TasksCurrent"),
            tasks_max: num("TasksMax"),
            restart_count: get("NRestarts").and_then(|v| v.parse::<u32>().ok()),
            // `--timestamp=unix` renders this as `@<seconds>`. Anything else is
            // a formatted date we decline to parse; see `SystemctlCli::show`.
            active_since: get("ActiveEnterTimestamp")
                .and_then(|v| v.strip_prefix('@'))
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|t| *t != 0),
            fragment_path: text(get("FragmentPath")),
            unit_file_state,
            result: text(get("Result")),
            exec_main_status: get("ExecMainStatus").and_then(|v| v.parse::<i32>().ok()),
            documentation: list("Documentation"),
            triggered_by: list("TriggeredBy"),
            requires: list("Requires"),
            wants: list("Wants"),
            can_start: yesno("CanStart"),
            can_stop: yesno("CanStop"),
            can_reload: yesno("CanReload"),
        }
    }

    /// The product-level rollup state.
    pub fn state(&self) -> &'static str {
        self.unit.state()
    }

    /// Detail JSON: every field of [`Unit::to_json`], plus the deep ones.
    pub fn to_json(&self) -> Value {
        let mut o = match self.unit.to_json() {
            Value::Object(o) => o,
            other => return other,
        };
        // systemd's own answers win where we have them.
        let actionable = self.unit.is_actionable();
        o.insert("can_start", self.can_start.unwrap_or(actionable));
        o.insert("can_stop", self.can_stop.unwrap_or(actionable));
        o.insert("can_restart", actionable);
        o.insert("can_reload", self.can_reload.unwrap_or(false));

        o.insert("main_pid", self.main_pid);
        o.insert("memory_bytes", self.memory_bytes);
        o.insert("cpu_usage_nsec", self.cpu_usage_nsec);
        o.insert("tasks_current", self.tasks_current);
        o.insert("tasks_max", self.tasks_max);
        o.insert("restart_count", self.restart_count);
        o.insert("active_since", self.active_since);
        o.insert("fragment_path", self.fragment_path.clone());
        o.insert("unit_file_state", self.unit_file_state.clone());
        o.insert("result", self.result.clone());
        o.insert("exec_main_status", self.exec_main_status);
        o.insert("documentation", self.documentation.clone());
        o.insert("triggered_by", self.triggered_by.clone());
        o.insert("requires", self.requires.clone());
        o.insert("wants", self.wants.clone());
        Value::Object(o)
    }
}

/// Serialise a list of units for the API.
pub fn units_json(units: &[Unit]) -> Value {
    Value::Array(units.iter().map(Unit::to_json).collect())
}
