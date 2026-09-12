//! Integration tests against a **real** `dbus-daemon`.
//!
//! These are the tests that matter most. Everything in `src/tests.rs` proves
//! the codec agrees with itself; only an independent implementation can prove
//! it agrees with D-Bus. Two independent peers are used here:
//!
//!   * **`dbus-daemon`** (the reference implementation) is on the other end of
//!     every connection. It runs the SASL handshake, and it fully validates
//!     each message it routes — header fields, signature, and body — dropping
//!     the connection outright on a corrupt stream. So a message that survives
//!     a round trip through it has been checked by code we did not write.
//!   * **`busctl`** (systemd's own client) calls into the mock service below
//!     and decodes its replies, which checks our *reply* marshalling against a
//!     third implementation.
//!
//! The mock systemd service is a second client of the same bus. It speaks the
//! server side of the same methods `SystemdDbus` calls, so `ListUnits`,
//! `GetAll` and `StartUnit` are exercised end to end — with the reference
//! daemon sitting in the middle validating both directions.
//!
//! Every test **skips** rather than fails when `dbus-daemon` is not installed.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serveros_systemd::dbus::message::MessageType;
use serveros_systemd::dbus::{DBusConnection, DBusError, DValue, Message};
use serveros_systemd::{ServiceManager, SystemdDbus};

const SYSTEMD_NAME: &str = "org.freedesktop.systemd1";
const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_IFACE: &str = "org.freedesktop.systemd1.Manager";
const NGINX_PATH: &str = "/org/freedesktop/systemd1/unit/nginx_2eservice";

const LIST_UNITS_SIG: &str = "a(ssssssouso)";

// ------------------------------------------------------------------ fixture

fn have_dbus_daemon() -> bool {
    Command::new("dbus-daemon")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Skip-or-run guard. Returns `None` (and prints why) when the bus is absent.
macro_rules! require_daemon {
    () => {
        if !have_dbus_daemon() {
            eprintln!("SKIP: dbus-daemon is not installed");
            return;
        }
    };
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A private `dbus-daemon`, killed when the fixture drops.
struct Bus {
    child: Child,
    address: String,
    dir: PathBuf,
}

impl Bus {
    fn start() -> Bus {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        // Keep the path short: a unix socket path is capped near 108 bytes.
        let dir = std::env::temp_dir().join(format!("sos-dbus-{}-{n}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create fixture dir");

        let socket = dir.join("bus");
        let config = dir.join("bus.conf");
        // A self-contained session bus: EXTERNAL only (which is what our client
        // implements), and a permissive policy so the mock may own a name.
        let xml = format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*"/>
    <allow own="*"/>
    <allow receive_sender="*"/>
  </policy>
</busconfig>
"#,
            socket.display()
        );
        std::fs::write(&config, xml).expect("write bus config");

        let mut child = Command::new("dbus-daemon")
            .arg("--nofork")
            .arg("--print-address")
            .arg(format!("--config-file={}", config.display()))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn dbus-daemon");

        let stdout = child.stdout.take().expect("daemon stdout");
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).expect("read bus address");
        let address = line.trim().to_owned();
        assert!(!address.is_empty(), "dbus-daemon printed no address");

        Bus { child, address, dir }
    }

    fn address(&self) -> &str {
        &self.address
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// -------------------------------------------------------- the mock systemd

/// Stand-in for `org.freedesktop.systemd1`, serving the subset
/// [`SystemdDbus`] calls. Runs on its own connection to the same bus, so every
/// message it exchanges with the client is routed and validated by
/// `dbus-daemon`.
struct MockSystemd {
    handle: Option<thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

fn unit_tuple(
    name: &str,
    description: &str,
    load: &str,
    active: &str,
    sub: &str,
    path: &str,
) -> DValue {
    DValue::Struct(vec![
        DValue::str(name),
        DValue::str(description),
        DValue::str(load),
        DValue::str(active),
        DValue::str(sub),
        DValue::str(""),
        DValue::ObjectPath(path.to_owned()),
        DValue::Uint32(0),
        DValue::str(""),
        DValue::ObjectPath("/".to_owned()),
    ])
}

fn mock_units() -> DValue {
    DValue::Array(vec![
        unit_tuple(
            "nginx.service",
            "A high performance web server",
            "loaded",
            "active",
            "running",
            NGINX_PATH,
        ),
        unit_tuple(
            "postgresql.service",
            "PostgreSQL RDBMS",
            "loaded",
            "failed",
            "failed",
            "/org/freedesktop/systemd1/unit/postgresql_2eservice",
        ),
        unit_tuple(
            "ghost.service",
            "",
            "not-found",
            "inactive",
            "dead",
            "/org/freedesktop/systemd1/unit/ghost_2eservice",
        ),
        // Noise that `is_interesting_service` must filter out.
        unit_tuple(
            "systemd-fsck@dev-sda1.service",
            "File System Check on /dev/sda1",
            "loaded",
            "inactive",
            "dead",
            "/org/freedesktop/systemd1/unit/x1",
        ),
        unit_tuple(
            "multi-user.target",
            "Multi-User System",
            "loaded",
            "active",
            "active",
            "/org/freedesktop/systemd1/unit/x2",
        ),
        unit_tuple(
            "apt-daily.timer",
            "Daily apt download activities",
            "loaded",
            "active",
            "waiting",
            "/org/freedesktop/systemd1/unit/x3",
        ),
    ])
}

fn prop(key: &str, v: DValue) -> DValue {
    DValue::DictEntry(Box::new(DValue::str(key)), Box::new(DValue::variant(v)))
}

fn unit_properties() -> DValue {
    DValue::Array(vec![
        prop("Id", DValue::str("nginx.service")),
        prop("Description", DValue::str("A high performance web server")),
        prop("LoadState", DValue::str("loaded")),
        prop("ActiveState", DValue::str("active")),
        prop("SubState", DValue::str("running")),
        prop("Following", DValue::str("")),
        prop("FragmentPath", DValue::str("/lib/systemd/system/nginx.service")),
        prop("UnitFileState", DValue::str("enabled")),
        prop("ActiveEnterTimestamp", DValue::Uint64(1_700_000_000_000_000)),
        prop(
            "Documentation",
            DValue::Array(vec![
                DValue::str("man:nginx(8)"),
                DValue::str("https://nginx.org/en/docs/"),
            ]),
        ),
        prop("Requires", DValue::Array(vec![DValue::str("system.slice")])),
        prop("Wants", DValue::Array(vec![DValue::str("network.target")])),
        prop("TriggeredBy", DValue::Array(vec![DValue::str("nginx.socket")])),
        prop("CanStart", DValue::Bool(true)),
        prop("CanStop", DValue::Bool(true)),
        prop("CanReload", DValue::Bool(true)),
    ])
}

fn service_properties() -> DValue {
    DValue::Array(vec![
        prop("MainPID", DValue::Uint32(4242)),
        prop("MemoryCurrent", DValue::Uint64(12_582_912)),
        prop("CPUUsageNSec", DValue::Uint64(4_200_000_000)),
        prop("TasksCurrent", DValue::Uint64(5)),
        prop("TasksMax", DValue::Uint64(4915)),
        prop("NRestarts", DValue::Uint32(17)),
        prop("Result", DValue::str("success")),
        prop("ExecMainStatus", DValue::Int32(0)),
    ])
}

const INTROSPECT_XML: &str = r#"<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node>
 <interface name="org.freedesktop.systemd1.Manager">
  <method name="ListUnits">
   <arg type="a(ssssssouso)" direction="out"/>
  </method>
  <method name="GetUnit">
   <arg type="s" direction="in"/>
   <arg type="o" direction="out"/>
  </method>
  <method name="StartUnit">
   <arg type="s" direction="in"/>
   <arg type="s" direction="in"/>
   <arg type="o" direction="out"/>
  </method>
 </interface>
</node>
"#;

impl MockSystemd {
    fn start(address: &str) -> MockSystemd {
        let address = address.to_owned();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
        let handle = thread::spawn(move || {
            let mut conn = match DBusConnection::connect(&address) {
                Ok(c) => c,
                Err(e) => {
                    let _ = ready_tx.send(Err(format!("mock could not connect: {e}")));
                    return;
                }
            };
            // A short read timeout turns the blocking receive into a poll, so
            // shutdown costs one tick instead of one timeout. The client's
            // `read_exact` only retires a connection on a *partial* read, so
            // idling through timeouts like this is safe.
            let _ = conn.set_read_timeout(Some(Duration::from_millis(100)));
            if let Err(e) = conn.request_name(SYSTEMD_NAME, 0) {
                let _ = ready_tx.send(Err(format!("mock could not own the name: {e}")));
                return;
            }
            let _ = ready_tx.send(Ok(()));

            while !thread_stop.load(Ordering::Relaxed) {
                let call = match conn.receive_message() {
                    Ok(m) => m,
                    Err(DBusError::Timeout) => continue,
                    // The bus went away: the test finished.
                    Err(_) => return,
                };
                if call.kind != MessageType::MethodCall {
                    continue;
                }
                let reply = Self::dispatch(&call);
                if conn.send_message(&reply).is_err() {
                    return;
                }
            }
        });

        match ready_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => panic!("{e}"),
            Err(e) => panic!("mock systemd never became ready: {e}"),
        }
        MockSystemd { handle: Some(handle), stop }
    }

    fn dispatch(call: &Message) -> Message {
        let iface = call.interface.as_deref().unwrap_or("");
        let member = call.member.as_deref().unwrap_or("");
        let ret = |sig: &str, body: Vec<DValue>| Message::method_return(call).with_body(sig, body);

        match (iface, member) {
            ("org.freedesktop.DBus.Introspectable", "Introspect") => {
                ret("s", vec![DValue::str(INTROSPECT_XML)])
            }
            ("org.freedesktop.DBus.Peer", "Ping") => ret("", Vec::new()),
            (MANAGER_IFACE, "ListUnits") => ret(LIST_UNITS_SIG, vec![mock_units()]),
            (MANAGER_IFACE, "ListUnitFiles") => ret(
                "a(ss)",
                vec![DValue::Array(vec![
                    DValue::Struct(vec![
                        DValue::str("/lib/systemd/system/nginx.service"),
                        DValue::str("enabled"),
                    ]),
                    DValue::Struct(vec![
                        DValue::str("/lib/systemd/system/postgresql.service"),
                        DValue::str("disabled"),
                    ]),
                ])],
            ),
            (MANAGER_IFACE, "GetUnit") => {
                match call.body.first().and_then(DValue::as_str) {
                    Some("nginx.service") => {
                        ret("o", vec![DValue::ObjectPath(NGINX_PATH.to_owned())])
                    }
                    other => Message::error_reply(
                        call,
                        "org.freedesktop.systemd1.NoSuchUnit",
                        format!("Unit {} not found.", other.unwrap_or("?")),
                    ),
                }
            }
            (MANAGER_IFACE, "StartUnit" | "StopUnit" | "RestartUnit" | "ReloadUnit") => {
                // Assert the client sent exactly (name, mode) as two strings.
                let name = call.body.first().and_then(DValue::as_str).unwrap_or("");
                let mode = call.body.get(1).and_then(DValue::as_str).unwrap_or("");
                if call.signature.as_deref() != Some("ss") || mode != "replace" {
                    return Message::error_reply(
                        call,
                        "org.freedesktop.DBus.Error.InvalidArgs",
                        format!("expected (s name, s \"replace\"), got {name:?}/{mode:?}"),
                    );
                }
                if name == "denied.service" {
                    return Message::error_reply(
                        call,
                        "org.freedesktop.DBus.Error.AccessDenied",
                        "Permission denied",
                    );
                }
                ret("o", vec![DValue::ObjectPath("/org/freedesktop/systemd1/job/1".to_owned())])
            }
            (MANAGER_IFACE, "EnableUnitFiles") => {
                let files = call.body.first().and_then(DValue::as_string_vec).unwrap_or_default();
                if call.signature.as_deref() != Some("asbb") || files.is_empty() {
                    return Message::error_reply(
                        call,
                        "org.freedesktop.DBus.Error.InvalidArgs",
                        "expected (as files, b runtime, b force)",
                    );
                }
                ret(
                    "ba(sss)",
                    vec![
                        DValue::Bool(true),
                        DValue::Array(vec![DValue::Struct(vec![
                            DValue::str("symlink"),
                            DValue::str("/etc/systemd/system/multi-user.target.wants/nginx.service"),
                            DValue::str("/lib/systemd/system/nginx.service"),
                        ])]),
                    ],
                )
            }
            (MANAGER_IFACE, "DisableUnitFiles") => {
                if call.signature.as_deref() != Some("asb") {
                    return Message::error_reply(
                        call,
                        "org.freedesktop.DBus.Error.InvalidArgs",
                        "expected (as files, b runtime)",
                    );
                }
                // An empty `a(sss)`: the case a value-driven marshaller cannot
                // encode, and therefore the one worth round-tripping live.
                ret("a(sss)", vec![DValue::Array(Vec::new())])
            }
            ("org.freedesktop.DBus.Properties", "GetAll") => {
                let want = call.body.first().and_then(DValue::as_str).unwrap_or("");
                if call.path.as_deref() != Some(NGINX_PATH) {
                    return Message::error_reply(
                        call,
                        "org.freedesktop.systemd1.NoSuchUnit",
                        "no such object",
                    );
                }
                match want {
                    "org.freedesktop.systemd1.Unit" => ret("a{sv}", vec![unit_properties()]),
                    "org.freedesktop.systemd1.Service" => {
                        ret("a{sv}", vec![service_properties()])
                    }
                    other => Message::error_reply(
                        call,
                        "org.freedesktop.DBus.Error.UnknownInterface",
                        format!("no interface {other}"),
                    ),
                }
            }
            _ => Message::error_reply(
                call,
                "org.freedesktop.DBus.Error.UnknownMethod",
                format!("mock systemd does not implement {iface}.{member}"),
            ),
        }
    }
}

impl Drop for MockSystemd {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ------------------------------------------------- transport / handshake

#[test]
fn live_auth_and_hello_against_a_real_daemon() {
    require_daemon!();
    let bus = Bus::start();
    // This single assertion validates the whole transport: the NUL byte, the
    // AUTH EXTERNAL line with a hex uid the daemon checks against SO_PEERCRED,
    // NEGOTIATE_UNIX_FD, BEGIN, our marshalled Hello header, and our parse of
    // the reply.
    let conn = DBusConnection::connect(bus.address()).expect("connect to the reference daemon");
    assert!(
        conn.unique_name().starts_with(':'),
        "the bus should have assigned a unique name, got {:?}",
        conn.unique_name()
    );
    assert!(!conn.server_guid().is_empty(), "the OK line carries the bus GUID");
}

#[test]
fn live_list_names_returns_an_array_of_strings() {
    require_daemon!();
    let bus = Bus::start();
    let mut conn = DBusConnection::connect(bus.address()).unwrap();
    let names = conn.list_names().expect("ListNames");
    assert!(names.iter().any(|n| n == "org.freedesktop.DBus"));
    assert!(
        names.iter().any(|n| n == conn.unique_name()),
        "our own unique name should be listed"
    );
}

#[test]
fn live_unknown_method_surfaces_a_remote_error() {
    require_daemon!();
    let bus = Bus::start();
    let mut conn = DBusConnection::connect(bus.address()).unwrap();
    let err = conn
        .call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "ThisMethodDoesNotExist",
            "",
            Vec::new(),
        )
        .expect_err("the daemon should refuse");
    match err {
        DBusError::Remote { ref name, .. } => {
            assert!(name.starts_with("org.freedesktop.DBus.Error."), "got {name}");
        }
        other => panic!("expected a Remote error, got {other:?}"),
    }
    assert!(!err.is_unreachable(), "a refusal is not an unreachable bus");
    // The connection must still be usable after an error reply.
    assert!(!conn.list_names().unwrap().is_empty());
}

#[test]
fn live_unknown_destination_surfaces_a_remote_error() {
    require_daemon!();
    let bus = Bus::start();
    let mut conn = DBusConnection::connect(bus.address()).unwrap();
    let err = conn
        .call("org.example.NotRunning", "/x", "org.example.X", "Y", "", Vec::new())
        .expect_err("nobody owns that name");
    assert_eq!(err.error_name(), Some("org.freedesktop.DBus.Error.ServiceUnknown"));
}

#[test]
fn live_string_arguments_are_understood_by_the_daemon() {
    require_daemon!();
    let bus = Bus::start();
    let mut conn = DBusConnection::connect(bus.address()).unwrap();
    // NameHasOwner(s) -> b. If our string marshalling were wrong the daemon
    // would either answer about the wrong name or drop us for a corrupt body.
    let mine = conn.unique_name().to_owned();
    let reply = conn
        .call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            "s",
            vec![DValue::str(&mine)],
        )
        .unwrap();
    assert_eq!(reply[0].as_bool(), Some(true));

    let reply = conn
        .call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            "s",
            vec![DValue::str("org.example.Absent")],
        )
        .unwrap();
    assert_eq!(reply[0].as_bool(), Some(false));
}

#[test]
fn live_get_connection_credentials_decodes_a_real_dictionary() {
    require_daemon!();
    let bus = Bus::start();
    let mut conn = DBusConnection::connect(bus.address()).unwrap();
    let mine = conn.unique_name().to_owned();
    // `a{sv}` produced by the reference implementation, containing a `u` and
    // (usually) an `ay`. This is the same decode path as systemd's GetAll.
    let reply = conn
        .call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetConnectionCredentials",
            "s",
            vec![DValue::str(&mine)],
        )
        .unwrap();
    let dict = &reply[0];
    assert!(dict.as_array().is_some(), "expected a{{sv}}");
    let uid = dict.dict_get("UnixUserID").and_then(DValue::as_u32);
    assert!(uid.is_some(), "credentials should carry UnixUserID");
    let pid = dict.dict_get("ProcessID").and_then(DValue::as_u32);
    assert_eq!(pid, Some(std::process::id()), "the bus sees our real pid");
}

#[test]
fn live_properties_get_all_decodes_the_daemons_own_properties() {
    require_daemon!();
    let bus = Bus::start();
    let mut conn = DBusConnection::connect(bus.address()).unwrap();
    // dbus-daemon implements org.freedesktop.DBus.Properties with `Features`
    // and `Interfaces`, both `as` inside a variant: exactly the shape systemd
    // returns for a unit.
    let dict = conn
        .get_all_properties("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus")
        .expect("GetAll on the daemon");
    let features = dict.dict_get("Features").and_then(DValue::as_string_vec);
    assert!(features.is_some(), "expected a Features array, got {dict:?}");
}

#[test]
fn live_introspection_returns_xml() {
    require_daemon!();
    let bus = Bus::start();
    let mut conn = DBusConnection::connect(bus.address()).unwrap();
    let reply = conn
        .call(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.Introspectable",
            "Introspect",
            "",
            Vec::new(),
        )
        .unwrap();
    assert!(reply[0].as_str().unwrap_or("").contains("<node"));
}

#[test]
fn live_request_name_is_visible_to_busctl() {
    require_daemon!();
    let bus = Bus::start();
    let mut conn = DBusConnection::connect(bus.address()).unwrap();
    // "su" arguments marshalled by us, parsed by dbus-daemon.
    let code = conn.request_name("org.serveros.LiveTest", 0).expect("RequestName");
    assert_eq!(code, 1, "we should be the primary owner");

    let names = conn.list_names().unwrap();
    assert!(names.iter().any(|n| n == "org.serveros.LiveTest"));

    // And a completely independent client agrees.
    let out = Command::new("busctl")
        .arg(format!("--address={}", bus.address()))
        .arg("list")
        .arg("--no-pager")
        .output();
    if let Ok(out) = out
        && out.status.success()
    {
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("org.serveros.LiveTest"),
            "busctl did not see the name we claimed:\n{text}"
        );
    } else {
        eprintln!("NOTE: busctl unavailable; skipped the third-party cross-check");
    }
}

#[test]
fn live_signals_are_queued_and_not_mistaken_for_replies() {
    require_daemon!();
    let bus = Bus::start();
    let mut conn = DBusConnection::connect(bus.address()).unwrap();
    conn.call(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "AddMatch",
        "s",
        vec![DValue::str("type='signal',interface='org.freedesktop.DBus'")],
    )
    .expect("AddMatch");

    // A second connection claiming a name makes the daemon emit
    // NameOwnerChanged to us, interleaved with our own traffic.
    let mut other = DBusConnection::connect(bus.address()).unwrap();
    other.request_name("org.serveros.SignalSource", 0).unwrap();

    // The reply must still be matched correctly despite the signal in flight.
    let names = conn.list_names().expect("ListNames past a pending signal");
    assert!(names.iter().any(|n| n == "org.serveros.SignalSource"));

    let signals = conn.take_signals();
    assert!(
        signals.iter().any(|m| m.member.as_deref() == Some("NameOwnerChanged")),
        "expected a queued NameOwnerChanged, got {:?}",
        signals.iter().map(|m| m.member.clone()).collect::<Vec<_>>()
    );
    assert!(
        signals.iter().all(|m| m.kind == MessageType::Signal),
        "only signals belong in the signal queue"
    );
}

// ------------------------------------------------- end-to-end against a mock

#[test]
fn live_list_units_end_to_end() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());
    let mgr = SystemdDbus::connect_to(bus.address()).expect("client connect");
    assert_eq!(mgr.backend_name(), "dbus");

    let units = mgr.list_units().expect("ListUnits");
    let names: Vec<&str> = units.iter().map(|u| u.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["nginx.service", "postgresql.service"],
        "filtering should drop the target, timer, template instance and not-found unit"
    );

    assert_eq!(units[0].state(), "running");
    assert_eq!(units[0].description, "A high performance web server");
    assert_eq!(units[0].enabled.as_deref(), Some("enabled"), "joined from ListUnitFiles");
    assert_eq!(units[1].state(), "failed");
    assert_eq!(units[1].enabled.as_deref(), Some("disabled"));

    let json = units[0].to_json();
    assert_eq!(json.get("display_name").and_then(|v| v.as_str()), Some("nginx"));
    assert_eq!(json.get("state").and_then(|v| v.as_str()), Some("running"));
}

#[test]
fn live_list_units_of_type_is_unfiltered() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());
    let mgr = SystemdDbus::connect_to(bus.address()).unwrap();

    let timers = mgr.list_units_of_type(".timer").unwrap();
    assert_eq!(timers.len(), 1);
    assert_eq!(timers[0].name, "apt-daily.timer");

    let services = mgr.list_units_of_type(".service").unwrap();
    assert_eq!(services.len(), 4, "the escape hatch keeps the noise");
}

#[test]
fn live_unit_detail_end_to_end() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());
    let mgr = SystemdDbus::connect_to(bus.address()).unwrap();

    let d = mgr.unit("nginx.service").expect("unit detail");
    assert_eq!(d.unit.name, "nginx.service");
    assert_eq!(d.unit.object_path, NGINX_PATH);
    assert_eq!(d.state(), "running");
    assert_eq!(d.main_pid, Some(4242));
    assert_eq!(d.memory_bytes, Some(12_582_912));
    assert_eq!(d.cpu_usage_nsec, Some(4_200_000_000));
    assert_eq!(d.tasks_current, Some(5));
    assert_eq!(d.tasks_max, Some(4915));
    assert_eq!(d.restart_count, Some(17));
    assert_eq!(d.active_since, Some(1_700_000_000), "microseconds -> seconds");
    assert_eq!(d.unit_file_state.as_deref(), Some("enabled"));
    assert_eq!(d.documentation.len(), 2);
    assert_eq!(d.triggered_by, vec!["nginx.socket".to_owned()]);
    assert_eq!(d.can_reload, Some(true));

    let j = d.to_json();
    assert_eq!(j.get("main_pid").and_then(|v| v.as_u64()), Some(4242));
    assert_eq!(j.get("restart_count").and_then(|v| v.as_u64()), Some(17));
    assert_eq!(j.get("active_since").and_then(|v| v.as_u64()), Some(1_700_000_000));
}

#[test]
fn live_unknown_unit_becomes_a_no_such_unit_error() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());
    let mgr = SystemdDbus::connect_to(bus.address()).unwrap();

    let Err(e) = mgr.unit("absent.service") else { panic!("expected a failure") };
    assert_eq!(e.http_status(), 404, "got: {e}");
    assert!(e.user_message().contains("no service called"), "got: {}", e.user_message());
}

#[test]
fn live_lifecycle_operations_send_the_documented_arguments() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());
    let mgr = SystemdDbus::connect_to(bus.address()).unwrap();

    // The mock rejects anything that is not ("<name>", "replace") as `ss`.
    mgr.start("nginx.service").expect("StartUnit");
    mgr.stop("nginx.service").expect("StopUnit");
    mgr.restart("nginx.service").expect("RestartUnit");
    mgr.reload("nginx.service").expect("ReloadUnit");
}

#[test]
fn live_enable_and_disable_round_trip_their_reply_shapes() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());
    let mgr = SystemdDbus::connect_to(bus.address()).unwrap();

    // `asbb` out, `ba(sss)` back.
    mgr.enable("nginx.service").expect("EnableUnitFiles");
    // `asb` out, an *empty* `a(sss)` back — only a signature-driven codec can
    // encode that, which is the point of the test.
    mgr.disable("nginx.service").expect("DisableUnitFiles");
}

#[test]
fn live_permission_denied_becomes_a_product_error() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());
    let mgr = SystemdDbus::connect_to(bus.address()).unwrap();

    let Err(e) = mgr.start("denied.service") else { panic!("expected a refusal") };
    assert_eq!(e.http_status(), 403, "got: {e}");
    assert!(e.user_message().contains("isn't allowed"), "got: {}", e.user_message());
}

#[test]
fn live_invalid_unit_names_never_reach_the_bus() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());
    let mgr = SystemdDbus::connect_to(bus.address()).unwrap();

    for bad in ["nginx.service; rm -rf /", "../../etc/passwd", "-h.service", "a\nb.service"] {
        let Err(e) = mgr.start(bad) else { panic!("{bad:?} should have been rejected") };
        assert_eq!(e.http_status(), 400, "{bad:?} -> {e}");
    }
    // The connection is untouched and still works.
    mgr.start("nginx.service").expect("a valid call still works");
}

#[test]
fn live_busctl_can_call_our_mock_and_decode_the_reply() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());

    // A third implementation (systemd's own busctl) calls the mock and decodes
    // the `a(ssssssouso)` reply our marshaller produced. If our array, struct
    // or object-path encoding were wrong, busctl would say so.
    let out = Command::new("busctl")
        .arg(format!("--address={}", bus.address()))
        .arg("call")
        .args([SYSTEMD_NAME, SYSTEMD_PATH, MANAGER_IFACE, "ListUnits"])
        .arg("--no-pager")
        .output();
    let Ok(out) = out else {
        eprintln!("SKIP: busctl is not installed");
        return;
    };
    if !out.status.success() {
        panic!(
            "busctl could not decode our reply:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("nginx.service"), "busctl output was:\n{text}");
    assert!(text.contains("A high performance web server"), "busctl output was:\n{text}");
    assert!(
        text.contains("/org/freedesktop/systemd1/unit/nginx_2eservice"),
        "busctl output was:\n{text}"
    );
}

#[test]
fn live_busctl_can_call_our_mock_with_string_arguments() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());

    // busctl marshals the argument; our reader decodes it. The inverse of the
    // previous test, so both directions are checked against a third party.
    let out = Command::new("busctl")
        .arg(format!("--address={}", bus.address()))
        .arg("call")
        .args([SYSTEMD_NAME, SYSTEMD_PATH, MANAGER_IFACE, "GetUnit", "s", "nginx.service"])
        .arg("--no-pager")
        .output();
    let Ok(out) = out else {
        eprintln!("SKIP: busctl is not installed");
        return;
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains(NGINX_PATH), "busctl output was:\n{stdout}");
}

#[test]
fn live_busctl_sees_our_error_replies_as_errors() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());

    let out = Command::new("busctl")
        .arg(format!("--address={}", bus.address()))
        .arg("call")
        .args([SYSTEMD_NAME, SYSTEMD_PATH, MANAGER_IFACE, "GetUnit", "s", "absent.service"])
        .arg("--no-pager")
        .output();
    let Ok(out) = out else {
        eprintln!("SKIP: busctl is not installed");
        return;
    };
    assert!(!out.status.success(), "busctl should report our ERROR reply as a failure");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NoSuchUnit") || stderr.contains("not found"),
        "busctl stderr was:\n{stderr}"
    );
}

#[test]
fn live_connection_survives_many_sequential_calls() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());
    let mgr = SystemdDbus::connect_to(bus.address()).unwrap();

    // Serials increment; framing must stay in step across many messages.
    for _ in 0..50 {
        let units = mgr.list_units().unwrap();
        assert_eq!(units.len(), 2);
    }
}

#[test]
fn live_manager_is_usable_from_several_threads() {
    require_daemon!();
    let bus = Bus::start();
    let _mock = MockSystemd::start(bus.address());
    let mgr = std::sync::Arc::new(SystemdDbus::connect_to(bus.address()).unwrap());

    // `ServiceManager: Send + Sync` is a promise the agent's HTTP layer relies
    // on. One socket, serialised by the mutex inside SystemdDbus.
    let mut handles = Vec::new();
    for _ in 0..4 {
        let m = std::sync::Arc::clone(&mgr);
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                assert_eq!(m.list_units().unwrap().len(), 2);
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread");
    }
}

#[test]
fn live_a_timeout_with_nothing_pending_does_not_retire_the_connection() {
    require_daemon!();
    let bus = Bus::start();
    let mut conn = DBusConnection::connect(bus.address()).unwrap();
    conn.set_read_timeout(Some(Duration::from_millis(100))).unwrap();

    // The daemon volunteers a `NameAcquired` signal for our unique name
    // immediately after Hello, without being asked. Drain whatever is pending,
    // then confirm the next read is a clean timeout.
    let mut saw_name_acquired = false;
    let e = loop {
        match conn.receive_message() {
            Ok(m) => {
                assert_eq!(m.kind, MessageType::Signal, "only signals are unsolicited");
                saw_name_acquired |= m.member.as_deref() == Some("NameAcquired");
            }
            Err(e) => break e,
        }
    };
    assert!(saw_name_acquired, "the daemon announces the unique name it assigned");
    assert!(matches!(e, DBusError::Timeout), "got: {e}");

    // A timeout before the first byte consumed nothing, so the framing is
    // still intact and the connection remains usable.
    conn.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    assert!(!conn.list_names().expect("connection still works").is_empty());
}

#[test]
fn live_bad_address_fails_without_hanging() {
    let err = DBusConnection::connect("unix:path=/nonexistent/serveros/bus")
        .expect_err("there is no socket there");
    assert!(err.is_unreachable(), "got: {err}");
    let err = DBusConnection::connect("tcp:host=localhost,port=1").expect_err("unsupported");
    assert!(matches!(err, DBusError::Address(_)), "got: {err}");
}
