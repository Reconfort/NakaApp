//! The service manager: a native D-Bus backend, and a `systemctl` fallback.
//!
//! # Two backends, one of them reluctantly
//!
//! [`SystemdDbus`] is the product. It talks to `org.freedesktop.systemd1` over
//! the system bus, which is systemd's actual API: typed values, structured
//! error names, no `fork`, no locale, no column widths.
//!
//! [`SystemctlCli`] exists because some hosts genuinely have no reachable bus —
//! a container with `/run/dbus` unmounted, a distribution that ships
//! `dbus-broker` behind a policy that excludes our uid, a rescue environment.
//! On those, running `systemctl` is better than telling the user their server
//! cannot be managed. It is a fallback, never a default, and
//! [`ServiceManager::backend_name`] is surfaced in the API so the app can say
//! which one answered.
//!
//! # What `list_units` does and does not show
//!
//! `ListUnits` returns units systemd currently has *loaded*, which is what
//! `systemctl list-units --all` shows too. A unit file that exists on disk but
//! has never been referenced will not appear. We deliberately do not
//! synthesise rows for those from `ListUnitFiles`: we would have to invent an
//! `ActiveState`, and a made-up state in an infrastructure tool is worse than a
//! missing row. `ListUnitFiles` is used only to fill in the `enabled` column,
//! which is a fact about disk rather than about runtime.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

use crate::dbus::{DBusConnection, DBusError, DValue};
use crate::error::SystemdError;
use crate::names::{is_interesting_service, validate_unit_name};
use crate::unit::{Unit, UnitDetail};

/// systemd's bus name.
pub const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
/// The manager object.
pub const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
/// The manager interface.
pub const MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
/// Properties common to every unit type.
pub const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
/// Properties specific to `.service` units (PIDs, memory, task counts).
pub const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";

/// The job mode used for every state change.
///
/// `replace` cancels any conflicting queued job and installs ours. The
/// alternative, `fail`, makes "restart it again because the first restart is
/// still queued" an error, which is not what a person clicking Restart twice
/// means.
pub const JOB_MODE: &str = "replace";

/// True when this host is running systemd as PID 1.
///
/// `/run/systemd/system` is the documented marker (`sd_booted(3)`): it exists
/// only when systemd is the init system, and notably does *not* exist inside a
/// container that merely has the `systemctl` binary installed.
pub fn is_systemd_running() -> bool {
    Path::new("/run/systemd/system").exists()
}

/// The operations the product performs on a service.
pub trait ServiceManager: Send + Sync {
    /// Services worth showing a human. See [`is_interesting_service`].
    fn list_units(&self) -> Result<Vec<Unit>, SystemdError>;

    /// Every loaded unit whose name ends in `suffix` (`.timer`, `.socket`, ...),
    /// unfiltered. The escape hatch behind [`ServiceManager::list_units`].
    fn list_units_of_type(&self, suffix: &str) -> Result<Vec<Unit>, SystemdError>;

    fn unit(&self, name: &str) -> Result<UnitDetail, SystemdError>;
    fn start(&self, name: &str) -> Result<(), SystemdError>;
    fn stop(&self, name: &str) -> Result<(), SystemdError>;
    fn restart(&self, name: &str) -> Result<(), SystemdError>;
    fn reload(&self, name: &str) -> Result<(), SystemdError>;
    fn enable(&self, name: &str) -> Result<(), SystemdError>;
    fn disable(&self, name: &str) -> Result<(), SystemdError>;

    /// `"dbus"` or `"systemctl"`. Returned in the API so the app can tell the
    /// user which path answered, and so a support ticket says which one broke.
    fn backend_name(&self) -> &'static str;
}

/// Pick a backend: D-Bus if a bus is reachable, otherwise `systemctl`.
pub fn detect() -> Result<Box<dyn ServiceManager>, SystemdError> {
    if !is_systemd_running() {
        return Err(SystemdError::Unavailable(
            "/run/systemd/system does not exist, so systemd is not this host's init system"
                .to_owned(),
        ));
    }
    match SystemdDbus::connect() {
        Ok(m) => Ok(Box::new(m)),
        Err(dbus_err) => {
            if SystemctlCli::available() {
                Ok(Box::new(SystemctlCli::new()))
            } else {
                Err(SystemdError::Unavailable(format!(
                    "the system bus is unreachable ({dbus_err}) and `systemctl` is not installed"
                )))
            }
        }
    }
}

// ------------------------------------------------------------- D-Bus back end

/// The native backend.
pub struct SystemdDbus {
    // One connection, serialised. D-Bus replies are matched by serial, so
    // concurrent use of one socket would be correct in principle, but the
    // framed byte stream is not: two threads writing interleaved messages
    // corrupts it. A mutex is the honest answer for an agent that handles a
    // handful of service operations a minute.
    conn: Mutex<DBusConnection>,
}

impl SystemdDbus {
    /// Connect to the system bus.
    pub fn connect() -> Result<SystemdDbus, SystemdError> {
        Ok(SystemdDbus { conn: Mutex::new(DBusConnection::connect_system()?) })
    }

    /// Connect to an explicit bus address. Used by the test harness to talk to
    /// a private `dbus-daemon` with a mock systemd on it.
    pub fn connect_to(address: &str) -> Result<SystemdDbus, SystemdError> {
        Ok(SystemdDbus { conn: Mutex::new(DBusConnection::connect(address)?) })
    }

    /// The unique bus name of our connection, for diagnostics.
    pub fn unique_name(&self) -> String {
        self.with(|c| Ok(c.unique_name().to_owned())).unwrap_or_default()
    }

    fn with<T>(
        &self,
        f: impl FnOnce(&mut DBusConnection) -> Result<T, DBusError>,
    ) -> Result<T, DBusError> {
        // A panic elsewhere must not permanently disable service management.
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }

    fn manager_call(
        &self,
        member: &str,
        signature: &str,
        args: Vec<DValue>,
    ) -> Result<Vec<DValue>, DBusError> {
        self.with(|c| {
            c.call(SYSTEMD_DESTINATION, SYSTEMD_PATH, MANAGER_INTERFACE, member, signature, args)
        })
    }

    /// `name` -> `/org/freedesktop/systemd1/unit/nginx_2eservice`.
    ///
    /// We ask systemd rather than doing the escaping ourselves. The escaping
    /// rules are simple enough to reimplement and subtle enough to get wrong,
    /// and asking also gives us `NoSuchUnit` for free.
    fn unit_path(&self, name: &str) -> Result<String, SystemdError> {
        let reply = self
            .manager_call("GetUnit", "s", vec![DValue::str(name)])
            .map_err(|e| SystemdError::from_dbus(name, e))?;
        reply
            .first()
            .and_then(DValue::as_str)
            .map(str::to_owned)
            .ok_or_else(|| SystemdError::Parse("GetUnit returned no object path".to_owned()))
    }

    /// Shared implementation of Start/Stop/Restart/Reload.
    fn job(&self, member: &str, name: &str) -> Result<(), SystemdError> {
        validate_unit_name(name)?;
        self.manager_call(member, "ss", vec![DValue::str(name), DValue::str(JOB_MODE)])
            .map(|_| ())
            .map_err(|e| SystemdError::from_dbus(name, e))
    }

    /// `ListUnitFiles` -> map of unit name to `UnitFileState`.
    ///
    /// One call for the whole list. The alternative — reading `UnitFileState`
    /// per unit — is several hundred round trips to render one screen.
    fn unit_file_states(&self) -> BTreeMap<String, String> {
        let Ok(reply) = self.manager_call("ListUnitFiles", "", Vec::new()) else {
            return BTreeMap::new();
        };
        let mut out = BTreeMap::new();
        for entry in reply.first().and_then(DValue::as_array).unwrap_or(&[]) {
            let Some(f) = entry.as_struct() else { continue };
            let (Some(path), Some(state)) =
                (f.first().and_then(DValue::as_str), f.get(1).and_then(DValue::as_str))
            else {
                continue;
            };
            let base = path.rsplit('/').next().unwrap_or(path);
            out.insert(base.to_owned(), state.to_owned());
        }
        out
    }

    fn list_raw(&self) -> Result<Vec<Unit>, SystemdError> {
        let reply = self.manager_call("ListUnits", "", Vec::new())?;
        let items = reply
            .first()
            .and_then(DValue::as_array)
            .ok_or_else(|| SystemdError::Parse("ListUnits did not return an array".to_owned()))?;
        items.iter().map(Unit::from_list_entry).collect()
    }
}

impl ServiceManager for SystemdDbus {
    fn list_units(&self) -> Result<Vec<Unit>, SystemdError> {
        let mut units: Vec<Unit> = self
            .list_raw()?
            .into_iter()
            .filter(|u| is_interesting_service(&u.name) && u.load_state != "not-found")
            .collect();
        let states = self.unit_file_states();
        for u in &mut units {
            u.enabled = states.get(&u.name).cloned();
        }
        units.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(units)
    }

    fn list_units_of_type(&self, suffix: &str) -> Result<Vec<Unit>, SystemdError> {
        let mut units: Vec<Unit> =
            self.list_raw()?.into_iter().filter(|u| u.name.ends_with(suffix)).collect();
        let states = self.unit_file_states();
        for u in &mut units {
            u.enabled = states.get(&u.name).cloned();
        }
        units.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(units)
    }

    fn unit(&self, name: &str) -> Result<UnitDetail, SystemdError> {
        validate_unit_name(name)?;
        let path = self.unit_path(name)?;
        let unit_props = self
            .with(|c| c.get_all_properties(SYSTEMD_DESTINATION, &path, UNIT_INTERFACE))
            .map_err(|e| SystemdError::from_dbus(name, e))?;
        // The Service bag is absent for non-service units, and on some systemd
        // versions an unknown interface is an error rather than an empty dict.
        // Either way it costs us the process-level fields, not the request.
        let service_props = self
            .with(|c| c.get_all_properties(SYSTEMD_DESTINATION, &path, SERVICE_INTERFACE))
            .unwrap_or_else(|_| DValue::Array(Vec::new()));
        let mut detail = UnitDetail::from_properties(name, &unit_props, &service_props);
        detail.unit.object_path = path;
        Ok(detail)
    }

    fn start(&self, name: &str) -> Result<(), SystemdError> {
        self.job("StartUnit", name)
    }

    fn stop(&self, name: &str) -> Result<(), SystemdError> {
        self.job("StopUnit", name)
    }

    fn restart(&self, name: &str) -> Result<(), SystemdError> {
        self.job("RestartUnit", name)
    }

    fn reload(&self, name: &str) -> Result<(), SystemdError> {
        self.job("ReloadUnit", name)
    }

    fn enable(&self, name: &str) -> Result<(), SystemdError> {
        validate_unit_name(name)?;
        // runtime=false: persist across reboot. force=false: refuse to clobber
        // an existing symlink that points somewhere else, which is a
        // configuration conflict a person should see rather than lose.
        self.manager_call(
            "EnableUnitFiles",
            "asbb",
            vec![
                DValue::Array(vec![DValue::str(name)]),
                DValue::Bool(false),
                DValue::Bool(false),
            ],
        )
        .map(|_| ())
        .map_err(|e| SystemdError::from_dbus(name, e))
    }

    fn disable(&self, name: &str) -> Result<(), SystemdError> {
        validate_unit_name(name)?;
        self.manager_call(
            "DisableUnitFiles",
            "asb",
            vec![DValue::Array(vec![DValue::str(name)]), DValue::Bool(false)],
        )
        .map(|_| ())
        .map_err(|e| SystemdError::from_dbus(name, e))
    }

    fn backend_name(&self) -> &'static str {
        "dbus"
    }
}

// --------------------------------------------------------- systemctl back end

/// Properties requested from `systemctl show`. Kept in one list so the D-Bus
/// and CLI backends cannot drift apart on what a unit detail contains.
const SHOW_PROPERTIES: &[&str] = &[
    "Id",
    "Description",
    "LoadState",
    "ActiveState",
    "SubState",
    "Following",
    "FragmentPath",
    "UnitFileState",
    "ActiveEnterTimestamp",
    "Documentation",
    "TriggeredBy",
    "Requires",
    "Wants",
    "CanStart",
    "CanStop",
    "CanReload",
    "MainPID",
    "MemoryCurrent",
    "CPUUsageNSec",
    "TasksCurrent",
    "TasksMax",
    "NRestarts",
    "Result",
    "ExecMainStatus",
];

/// The fallback backend.
///
/// Every invocation is an argument vector — [`std::process::Command`] with
/// explicit `arg` calls, never a shell string. Combined with
/// [`validate_unit_name`], which runs before anything here, a unit name cannot
/// become a second command or an option.
pub struct SystemctlCli {
    program: String,
}

impl Default for SystemctlCli {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemctlCli {
    pub fn new() -> SystemctlCli {
        SystemctlCli { program: Self::program_path() }
    }

    /// Prefer an absolute path over `$PATH`.
    ///
    /// The agent runs privileged. Resolving a program name through an inherited
    /// `$PATH` is a well-known way to be handed someone else's binary, and
    /// costs nothing to avoid.
    fn program_path() -> String {
        for candidate in ["/usr/bin/systemctl", "/bin/systemctl", "/usr/sbin/systemctl"] {
            if Path::new(candidate).exists() {
                return candidate.to_owned();
            }
        }
        "systemctl".to_owned()
    }

    /// True when `systemctl` can be executed at all.
    pub fn available() -> bool {
        Command::new(Self::program_path())
            .arg("--version")
            .env("LC_ALL", "C")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Run `systemctl` with an argument vector. `LC_ALL=C` pins the message
    /// language so the phrases we match on below do not depend on the server's
    /// locale.
    fn run(&self, args: &[&str]) -> Result<(bool, String, String), SystemdError> {
        let out = Command::new(&self.program)
            .args(args)
            .env("LC_ALL", "C")
            .env("SYSTEMD_COLORS", "0")
            .output()?;
        Ok((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ))
    }

    fn command_line(&self, args: &[&str]) -> String {
        format!("{} {}", self.program, args.join(" "))
    }

    fn fail(&self, args: &[&str], name: &str, stderr: &str) -> SystemdError {
        let lower = stderr.to_ascii_lowercase();
        if lower.contains("not found") || lower.contains("no such file") {
            return SystemdError::NoSuchUnit(name.to_owned());
        }
        if lower.contains("access denied")
            || lower.contains("permission denied")
            || lower.contains("interactive authentication required")
        {
            return SystemdError::PermissionDenied(name.to_owned());
        }
        SystemdError::Cli {
            command: self.command_line(args),
            status: None,
            stderr: stderr.to_owned(),
        }
    }

    fn action(&self, verb: &str, name: &str) -> Result<(), SystemdError> {
        validate_unit_name(name)?;
        let args = [verb, "--no-pager", name];
        let (ok, _, stderr) = self.run(&args)?;
        if ok { Ok(()) } else { Err(self.fail(&args, name, &stderr)) }
    }

    /// `systemctl show`, as a `Key=Value` map.
    ///
    /// Deliberately **not** `--value`: with `--value` the output is bare values
    /// whose order is systemd's, not the order we asked in, so a version that
    /// drops or adds a property silently shifts every field by one. `Key=Value`
    /// is self-describing and cannot mis-align.
    ///
    /// `--timestamp=unix` (systemd 247+) makes `ActiveEnterTimestamp` print as
    /// `@1700000000` instead of a formatted date. If the flag is rejected we
    /// retry without it and give up on that one field rather than parsing dates.
    fn show(&self, name: &str) -> Result<BTreeMap<String, String>, SystemdError> {
        let props = SHOW_PROPERTIES.join(",");
        let prop_arg = format!("--property={props}");
        let with_ts = ["show", "--no-pager", "--timestamp=unix", &prop_arg, name];
        let (ok, stdout, stderr) = self.run(&with_ts)?;
        if ok {
            return Ok(parse_key_values(&stdout));
        }
        let plain = ["show", "--no-pager", &prop_arg, name];
        let (ok2, stdout2, stderr2) = self.run(&plain)?;
        if ok2 {
            return Ok(parse_key_values(&stdout2));
        }
        let detail = if stderr2.trim().is_empty() { stderr } else { stderr2 };
        Err(self.fail(&plain, name, &detail))
    }

    /// `enabled` state for every service unit file, in one invocation.
    fn unit_file_states(&self) -> BTreeMap<String, String> {
        let json_args =
            ["list-unit-files", "--type=service", "--no-pager", "--no-legend", "--output=json"];
        if let Ok((true, stdout, _)) = self.run(&json_args)
            && let Ok(v) = serveros_json::from_str(&stdout)
        {
            let mut out = BTreeMap::new();
            for row in v.as_array().unwrap_or(&[]) {
                // systemd calls the column `unit_file` here and `unit`
                // elsewhere; accept either rather than depending on the version.
                let name = row
                    .get("unit_file")
                    .or_else(|| row.get("unit"))
                    .and_then(serveros_json::Value::as_str);
                let state = row.get("state").and_then(serveros_json::Value::as_str);
                if let (Some(n), Some(s)) = (name, state) {
                    let base = n.rsplit('/').next().unwrap_or(n);
                    out.insert(base.to_owned(), s.to_owned());
                }
            }
            if !out.is_empty() {
                return out;
            }
        }

        let args =
            ["list-unit-files", "--type=service", "--no-pager", "--no-legend", "--plain"];
        let mut out = BTreeMap::new();
        if let Ok((true, stdout, _)) = self.run(&args) {
            for line in stdout.lines() {
                let mut cols = line.split_whitespace();
                if let (Some(name), Some(state)) = (cols.next(), cols.next()) {
                    let base = name.rsplit('/').next().unwrap_or(name);
                    out.insert(base.to_owned(), state.to_owned());
                }
            }
        }
        out
    }

    fn list_raw(&self, type_arg: &str) -> Result<Vec<Unit>, SystemdError> {
        let json_args = ["list-units", type_arg, "--all", "--no-pager", "--output=json"];
        if let Ok((true, stdout, _)) = self.run(&json_args)
            && let Ok(v) = serveros_json::from_str(&stdout)
            && let Some(rows) = v.as_array()
        {
            return Ok(rows.iter().map(unit_from_json_row).collect());
        }

        let args = ["list-units", type_arg, "--all", "--no-pager", "--no-legend", "--plain"];
        let (ok, stdout, stderr) = self.run(&args)?;
        if !ok {
            return Err(SystemdError::Cli {
                command: self.command_line(&args),
                status: None,
                stderr,
            });
        }
        Ok(parse_list_units_table(&stdout))
    }
}

/// One row of `systemctl list-units --output=json`.
fn unit_from_json_row(row: &serveros_json::Value) -> Unit {
    let s = |k: &str| {
        row.get(k).and_then(serveros_json::Value::as_str).unwrap_or_default().to_owned()
    };
    Unit {
        name: s("unit"),
        description: s("description"),
        load_state: s("load"),
        active_state: s("active"),
        sub_state: s("sub"),
        followed: s("following"),
        object_path: String::new(),
        job_id: 0,
        job_type: String::new(),
        job_object_path: String::new(),
        enabled: None,
    }
}

/// Parse the tabular `list-units` form: `UNIT LOAD ACTIVE SUB DESCRIPTION...`.
///
/// Exported for tests because this is the part of the CLI backend most likely
/// to be wrong on a systemd version we have not seen.
pub fn parse_list_units_table(stdout: &str) -> Vec<Unit> {
    let mut out = Vec::new();
    for raw in stdout.lines() {
        // A failed unit is prefixed with a status glyph unless `--plain` was
        // honoured. Strip it defensively; it is one character and its absence
        // is not something we want to depend on.
        let line = raw.trim_start_matches(['\u{25cf}', '*', '\u{2192}']).trim();
        if line.is_empty() || line.starts_with("LOAD ") || line.starts_with("UNIT ") {
            continue;
        }
        // Take four whitespace-separated columns and keep the remainder whole:
        // the description contains spaces, and the columns are separated by
        // *runs* of them, so `splitn` on a single whitespace char would leave
        // empty fields wherever systemd padded the table.
        let mut rest = line;
        let mut cols: [&str; 4] = [""; 4];
        for col in &mut cols {
            rest = rest.trim_start();
            match rest.find(char::is_whitespace) {
                Some(i) => {
                    *col = &rest[..i];
                    rest = &rest[i..];
                }
                None => {
                    *col = rest;
                    rest = "";
                }
            }
        }
        let [name, load, active, sub] = cols;
        if name.is_empty() || !name.contains('.') || sub.is_empty() {
            continue;
        }
        let description = rest.trim().to_owned();
        out.push(Unit {
            name: name.to_owned(),
            description,
            load_state: load.to_owned(),
            active_state: active.to_owned(),
            sub_state: sub.to_owned(),
            followed: String::new(),
            object_path: String::new(),
            job_id: 0,
            job_type: String::new(),
            job_object_path: String::new(),
            enabled: None,
        });
    }
    out
}

/// Parse `Key=Value` lines from `systemctl show`.
///
/// Values may contain `=`, so only the first one splits. Keys never do.
pub fn parse_key_values(stdout: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in stdout.lines() {
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.trim().to_owned(), v.to_owned());
        }
    }
    out
}

impl ServiceManager for SystemctlCli {
    fn list_units(&self) -> Result<Vec<Unit>, SystemdError> {
        let mut units: Vec<Unit> = self
            .list_raw("--type=service")?
            .into_iter()
            .filter(|u| is_interesting_service(&u.name) && u.load_state != "not-found")
            .collect();
        let states = self.unit_file_states();
        for u in &mut units {
            u.enabled = states.get(&u.name).cloned();
        }
        units.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(units)
    }

    fn list_units_of_type(&self, suffix: &str) -> Result<Vec<Unit>, SystemdError> {
        let kind = suffix.trim_start_matches('.');
        // `--type=` takes a fixed vocabulary; anything else is not a unit type.
        if !crate::names::UNIT_SUFFIXES.iter().any(|s| &s[1..] == kind) {
            return Err(SystemdError::InvalidUnitName {
                name: suffix.to_owned(),
                reason: "not a known systemd unit type",
            });
        }
        let type_arg = format!("--type={kind}");
        let mut units = self.list_raw(&type_arg)?;
        let states = self.unit_file_states();
        for u in &mut units {
            u.enabled = states.get(&u.name).cloned();
        }
        units.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(units)
    }

    fn unit(&self, name: &str) -> Result<UnitDetail, SystemdError> {
        validate_unit_name(name)?;
        let props = self.show(name)?;
        // `systemctl show` answers for a unit that does not exist, with
        // LoadState=not-found. The D-Bus backend errors, so make them agree.
        if props.get("LoadState").map(String::as_str) == Some("not-found") {
            return Err(SystemdError::NoSuchUnit(name.to_owned()));
        }
        Ok(UnitDetail::from_show_properties(name, &props))
    }

    fn start(&self, name: &str) -> Result<(), SystemdError> {
        self.action("start", name)
    }

    fn stop(&self, name: &str) -> Result<(), SystemdError> {
        self.action("stop", name)
    }

    fn restart(&self, name: &str) -> Result<(), SystemdError> {
        self.action("restart", name)
    }

    fn reload(&self, name: &str) -> Result<(), SystemdError> {
        self.action("reload", name)
    }

    fn enable(&self, name: &str) -> Result<(), SystemdError> {
        self.action("enable", name)
    }

    fn disable(&self, name: &str) -> Result<(), SystemdError> {
        self.action("disable", name)
    }

    fn backend_name(&self) -> &'static str {
        "systemctl"
    }
}
