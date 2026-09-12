//! Bus addresses, the Unix socket, and the SASL handshake.
//!
//! # EXTERNAL authentication, and why there is no libc here
//!
//! D-Bus over a Unix socket authenticates with SASL `EXTERNAL`: the client
//! sends its uid, the kernel tells the server the *real* uid via
//! `SO_PEERCRED`, and the server compares them. So the uid we send is not a
//! secret and cannot be used to impersonate anyone — it only has to be right.
//!
//! Getting it without `libc::getuid()` is the fun part: `/proc/self` is owned
//! by the process's own effective uid, so `metadata("/proc/self").uid()` is
//! exactly the number we need, from safe `std` only. That keeps
//! `#![forbid(unsafe_code)]` intact for the whole crate.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::DBusError;

/// Where the system bus lives when `$DBUS_SYSTEM_BUS_ADDRESS` is unset.
pub const DEFAULT_SYSTEM_BUS: &str = "unix:path=/run/dbus/system_bus_socket";

/// How long to wait for a reply before giving up.
///
/// systemd can genuinely take seconds to answer `StartUnit` for a unit with a
/// slow `ExecStartPre`, so this is generous; it exists to stop a wedged bus
/// hanging an agent worker thread forever, not to enforce latency.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(25);
/// Write timeout. A blocked write means the peer has stopped reading.
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest SASL line we will read before declaring the peer broken.
const MAX_AUTH_LINE: usize = 8192;

/// A bus address we know how to connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BusAddress {
    /// `unix:path=/run/dbus/system_bus_socket`
    Path(String),
    /// `unix:abstract=/tmp/dbus-AbCdEf` — a Linux abstract socket, which lives
    /// in a namespace rather than the filesystem and is written on the wire
    /// with a leading NUL byte. `std` handles that NUL for us.
    Abstract(String),
}

/// The system bus address, honouring `$DBUS_SYSTEM_BUS_ADDRESS`.
pub fn system_bus_address() -> String {
    std::env::var("DBUS_SYSTEM_BUS_ADDRESS").unwrap_or_else(|_| DEFAULT_SYSTEM_BUS.to_owned())
}

/// The session bus address, if the environment names one. Only used by tests —
/// the agent is a system service and has no session.
pub fn session_bus_address() -> Option<String> {
    std::env::var("DBUS_SESSION_BUS_ADDRESS").ok().filter(|s| !s.is_empty())
}

/// Parse an address string into the alternatives it offers.
///
/// The grammar is `transport:k=v,k=v;transport:k=v`, values percent-escaped.
/// A real `dbus-daemon --print-address` emits, for example,
/// `unix:abstract=/tmp/dbus-8Xk2,guid=6f1a...`; the `guid=` key is advisory and
/// is ignored here. Transports we cannot use (tcp, nonce-tcp, launchd,
/// unixexec) are skipped rather than fatal, so an address list that contains
/// one usable entry still works.
pub fn parse_address(addr: &str) -> Result<Vec<BusAddress>, DBusError> {
    let mut out = Vec::new();
    let mut saw_entry = false;
    for entry in addr.split(';').filter(|s| !s.trim().is_empty()) {
        saw_entry = true;
        let (transport, rest) = match entry.split_once(':') {
            Some(pair) => pair,
            None => {
                return Err(DBusError::Address(format!(
                    "address entry `{entry}` has no `transport:` prefix"
                )));
            }
        };
        if transport != "unix" {
            continue;
        }
        let mut path = None;
        let mut abstract_name = None;
        for kv in rest.split(',').filter(|s| !s.is_empty()) {
            let Some((k, v)) = kv.split_once('=') else {
                return Err(DBusError::Address(format!(
                    "address key `{kv}` is not `key=value`"
                )));
            };
            let v = unescape(v)?;
            match k {
                "path" => path = Some(v),
                "abstract" => abstract_name = Some(v),
                // `guid` is the server identity, `tmpdir`/`dir` are
                // server-side listen hints. None affect how we connect.
                _ => {}
            }
        }
        match (path, abstract_name) {
            (Some(p), None) => out.push(BusAddress::Path(p)),
            (None, Some(a)) => out.push(BusAddress::Abstract(a)),
            (Some(_), Some(_)) => {
                return Err(DBusError::Address(
                    "address entry sets both `path` and `abstract`".to_owned(),
                ));
            }
            (None, None) => {
                return Err(DBusError::Address(
                    "unix address entry has neither `path` nor `abstract`".to_owned(),
                ));
            }
        }
    }
    if out.is_empty() {
        return Err(DBusError::Address(if saw_entry {
            format!("no usable unix transport in address `{addr}`")
        } else {
            "bus address is empty".to_owned()
        }));
    }
    Ok(out)
}

/// Decode `%XX` escapes.
fn unescape(v: &str) -> Result<String, DBusError> {
    if !v.contains('%') {
        return Ok(v.to_owned());
    }
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b
                .get(i + 1..i + 3)
                .ok_or_else(|| DBusError::Address(format!("truncated `%` escape in `{v}`")))?;
            let s = std::str::from_utf8(hex)
                .map_err(|_| DBusError::Address(format!("invalid `%` escape in `{v}`")))?;
            let byte = u8::from_str_radix(s, 16)
                .map_err(|_| DBusError::Address(format!("invalid `%` escape `%{s}` in `{v}`")))?;
            out.push(byte);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out)
        .map_err(|_| DBusError::Address(format!("address `{v}` decodes to invalid UTF-8")))
}

/// Connect to the first address in `addr` that works.
pub fn connect_stream(addr: &str) -> Result<UnixStream, DBusError> {
    let candidates = parse_address(addr)?;
    let mut last: Option<DBusError> = None;
    for c in &candidates {
        match connect_one(c) {
            Ok(s) => {
                s.set_read_timeout(Some(DEFAULT_READ_TIMEOUT))?;
                s.set_write_timeout(Some(DEFAULT_WRITE_TIMEOUT))?;
                return Ok(s);
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| DBusError::Address(format!("no usable address in `{addr}`"))))
}

#[cfg(target_os = "linux")]
fn connect_one(c: &BusAddress) -> Result<UnixStream, DBusError> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr;

    match c {
        BusAddress::Path(p) => Ok(UnixStream::connect(p)?),
        BusAddress::Abstract(name) => {
            // `from_abstract_name` prepends the NUL byte that marks the address
            // as abstract. Doing it by hand would need a raw `sockaddr_un`.
            let sa = SocketAddr::from_abstract_name(name.as_bytes())?;
            Ok(UnixStream::connect_addr(&sa)?)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn connect_one(c: &BusAddress) -> Result<UnixStream, DBusError> {
    match c {
        BusAddress::Path(p) => Ok(UnixStream::connect(p)?),
        BusAddress::Abstract(_) => Err(DBusError::Address(
            "abstract unix sockets are a Linux feature".to_owned(),
        )),
    }
}

/// The effective uid of this process, read from the owner of `/proc/self`.
pub fn current_uid() -> Result<u32, DBusError> {
    let md = fs::metadata("/proc/self").map_err(|e| {
        DBusError::Auth(format!("cannot read /proc/self to determine our uid: {e}"))
    })?;
    Ok(md.uid())
}

/// Run the SASL handshake and leave the stream positioned at the first byte of
/// the binary message stream.
///
/// Returns the server's GUID, which is how a client recognises two addresses as
/// the same bus. We do not use it for anything yet, but throwing it away would
/// mean re-doing the handshake to get it later.
pub fn authenticate(stream: &mut UnixStream) -> Result<String, DBusError> {
    let uid = current_uid()?;

    // The leading NUL is not part of SASL; it exists so the kernel attaches
    // credentials to *something* on transports that need a byte to hang them
    // on. It must be sent before the first command and outside any line.
    stream.write_all(&[0u8])?;

    // EXTERNAL's "initial response" is the uid rendered as ASCII decimal and
    // then hex-encoded — uid 0 is "0" is "30".
    let auth = format!("AUTH EXTERNAL {}\r\n", hex_encode(uid.to_string().as_bytes()));
    stream.write_all(auth.as_bytes())?;
    stream.flush()?;

    let line = read_line(stream)?;
    let guid = match first_word(&line) {
        "OK" => line["OK".len()..].trim().to_owned(),
        "REJECTED" => {
            let mechs = line["REJECTED".len()..].trim();
            return Err(DBusError::Auth(format!(
                "the bus rejected EXTERNAL authentication (it offers: {}). \
                 This usually means the agent's uid is not permitted on this bus.",
                if mechs.is_empty() { "nothing" } else { mechs }
            )));
        }
        "ERROR" => {
            return Err(DBusError::Auth(format!("the bus returned: {}", line.trim())));
        }
        _ => {
            return Err(DBusError::Auth(format!(
                "unexpected reply to AUTH: {:?}",
                truncate(&line)
            )));
        }
    };

    // Ask for fd passing. We never send or accept fds, but a bus that supports
    // it expects the negotiation, and a bus that does not answers ERROR, which
    // is fine and not fatal.
    stream.write_all(b"NEGOTIATE_UNIX_FD\r\n")?;
    stream.flush()?;
    let line = read_line(stream)?;
    match first_word(&line) {
        "AGREE_UNIX_FD" | "ERROR" => {}
        _ => {
            return Err(DBusError::Auth(format!(
                "unexpected reply to NEGOTIATE_UNIX_FD: {:?}",
                truncate(&line)
            )));
        }
    }

    stream.write_all(b"BEGIN\r\n")?;
    stream.flush()?;
    Ok(guid)
}

/// Read one CRLF-terminated SASL line.
///
/// One byte at a time, deliberately. `BEGIN` switches the socket from a line
/// protocol to a binary one with no framing in between, so a buffered reader
/// that over-read by even one byte would eat the front of the first message.
fn read_line(stream: &mut UnixStream) -> Result<String, DBusError> {
    let mut out = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            return Err(DBusError::Auth(
                "the bus closed the connection during authentication".to_owned(),
            ));
        }
        out.push(byte[0]);
        if out.ends_with(b"\r\n") {
            out.truncate(out.len() - 2);
            break;
        }
        if out.len() > MAX_AUTH_LINE {
            return Err(DBusError::Auth(format!(
                "authentication line exceeded {MAX_AUTH_LINE} bytes"
            )));
        }
    }
    String::from_utf8(out)
        .map_err(|_| DBusError::Auth("authentication line is not valid UTF-8".to_owned()))
}

fn first_word(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or("")
}

fn truncate(s: &str) -> String {
    s.chars().take(120).collect()
}

/// Lower-case hex, as SASL requires.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
