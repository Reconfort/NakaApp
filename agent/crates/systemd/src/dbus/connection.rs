//! A blocking D-Bus client connection.
//!
//! Blocking on purpose. The agent handles one management operation per request
//! thread; a reactor would buy nothing and cost a great deal of machinery in a
//! crate that is allowed no dependencies. The read timeout in
//! [`super::transport`] is what keeps a wedged bus from pinning a thread.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::DBusError;
use super::message::{FLAG_NO_REPLY_EXPECTED, Message, MessageType};
use super::transport::{self, session_bus_address, system_bus_address};
use super::value::DValue;

/// The bus daemon's own well-known name, path and interface.
pub const BUS_NAME: &str = "org.freedesktop.DBus";
pub const BUS_PATH: &str = "/org/freedesktop/DBus";
pub const BUS_INTERFACE: &str = "org.freedesktop.DBus";
/// The standard properties interface, used for systemd unit properties.
pub const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";

/// How many unsolicited signals to retain before dropping the oldest.
///
/// We do not subscribe to anything, so this should stay empty; it exists
/// because a bus may deliver `NameOwnerChanged` and similar before our reply,
/// and those must be consumed off the socket rather than mistaken for it.
const MAX_QUEUED_SIGNALS: usize = 256;

/// Upper bound on messages read while waiting for one reply. With the read
/// timeout this is belt-and-braces against a peer that streams signals forever.
const MAX_MESSAGES_PER_CALL: usize = 4096;

/// An authenticated connection to a message bus.
pub struct DBusConnection {
    stream: UnixStream,
    serial: u32,
    unique_name: String,
    server_guid: String,
    signals: VecDeque<Message>,
    /// Set when a read or write failed part-way. The byte stream has no
    /// resynchronisation point, so once framing is lost the only correct move
    /// is to refuse further use of this connection.
    broken: bool,
}

impl std::fmt::Debug for DBusConnection {
    /// Deliberately hand-written: the socket and the queued signal bodies have
    /// no place in a diagnostic, and a derived `Debug` would dump both.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DBusConnection")
            .field("unique_name", &self.unique_name)
            .field("server_guid", &self.server_guid)
            .field("serial", &self.serial)
            .field("queued_signals", &self.signals.len())
            .field("broken", &self.broken)
            .finish()
    }
}

impl DBusConnection {
    /// Connect, authenticate and say `Hello`.
    ///
    /// `Hello` is mandatory: until the bus answers it, the connection has no
    /// unique name and the bus will reject every other method call.
    pub fn connect(address: &str) -> Result<DBusConnection, DBusError> {
        let mut stream = transport::connect_stream(address)?;
        let server_guid = transport::authenticate(&mut stream)?;
        let mut conn = DBusConnection {
            stream,
            serial: 0,
            unique_name: String::new(),
            server_guid,
            signals: VecDeque::new(),
            broken: false,
        };
        let reply = conn.call(BUS_NAME, BUS_PATH, BUS_INTERFACE, "Hello", "", Vec::new())?;
        conn.unique_name = reply
            .first()
            .and_then(DValue::as_str)
            .ok_or_else(|| DBusError::protocol("Hello did not return a unique name"))?
            .to_owned();
        Ok(conn)
    }

    /// Connect to the system bus (`$DBUS_SYSTEM_BUS_ADDRESS`, else
    /// `/run/dbus/system_bus_socket`). This is where systemd lives.
    pub fn connect_system() -> Result<DBusConnection, DBusError> {
        DBusConnection::connect(&system_bus_address())
    }

    /// Connect to the session bus. Tests only — a system agent has no session.
    pub fn connect_session() -> Result<DBusConnection, DBusError> {
        let addr = session_bus_address()
            .ok_or_else(|| DBusError::Address("DBUS_SESSION_BUS_ADDRESS is not set".to_owned()))?;
        DBusConnection::connect(&addr)
    }

    /// The unique name the bus assigned us, e.g. `:1.42`.
    pub fn unique_name(&self) -> &str {
        &self.unique_name
    }

    /// The bus's GUID, from the SASL `OK` line.
    pub fn server_guid(&self) -> &str {
        &self.server_guid
    }

    /// Override the read timeout, for tests that need to fail fast.
    pub fn set_read_timeout(&self, t: Option<Duration>) -> Result<(), DBusError> {
        self.stream.set_read_timeout(t)?;
        Ok(())
    }

    /// Signals received while waiting for replies, oldest first.
    pub fn take_signals(&mut self) -> Vec<Message> {
        self.signals.drain(..).collect()
    }

    fn next_serial(&mut self) -> u32 {
        // Serials start at 1 and must never be 0. Wrapping back to 1 rather
        // than 0 keeps a very long-lived agent legal.
        self.serial = self.serial.checked_add(1).unwrap_or(1);
        if self.serial == 0 {
            self.serial = 1;
        }
        self.serial
    }

    /// Send a message, assigning a serial if it does not have one.
    pub fn send_message(&mut self, msg: &Message) -> Result<u32, DBusError> {
        self.check_usable()?;
        let mut msg = msg.clone();
        if msg.serial == 0 {
            msg.serial = self.next_serial();
        }
        let bytes = msg.to_bytes()?;
        if let Err(e) = self.stream.write_all(&bytes) {
            self.broken = true;
            return Err(e.into());
        }
        if let Err(e) = self.stream.flush() {
            self.broken = true;
            return Err(e.into());
        }
        Ok(msg.serial)
    }

    /// Read exactly one message off the wire.
    pub fn receive_message(&mut self) -> Result<Message, DBusError> {
        self.check_usable()?;
        let mut head = [0u8; 16];
        self.read_exact(&mut head)?;
        let total = Message::expected_len(&head)?
            .ok_or_else(|| DBusError::protocol("short read on message header"))?;
        if total < 16 {
            self.broken = true;
            return Err(DBusError::protocol(format!(
                "message claims a total length of {total} bytes"
            )));
        }
        let mut buf = Vec::with_capacity(total);
        buf.extend_from_slice(&head);
        buf.resize(total, 0);
        self.read_exact(&mut buf[16..])?;
        Message::parse(&buf)
    }

    /// Fill `dst`, tracking how much was consumed.
    ///
    /// Not [`std::io::Read::read_exact`], which hides that number. The
    /// distinction is load-bearing: a read timeout that fires before the first
    /// byte arrives leaves the stream perfectly intact and the caller may
    /// simply try again, while a timeout *part way through a message* has
    /// desynchronised the framing for good. Only the second case may mark the
    /// connection broken — conflating them would retire a healthy connection
    /// every time a peer was briefly slow.
    fn read_exact(&mut self, dst: &mut [u8]) -> Result<(), DBusError> {
        let mut filled = 0;
        while filled < dst.len() {
            match self.stream.read(&mut dst[filled..]) {
                Ok(0) => {
                    self.broken = true;
                    return Err(DBusError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "the bus closed the connection",
                    )));
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    if filled > 0 {
                        self.broken = true;
                    }
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }

    fn check_usable(&self) -> Result<(), DBusError> {
        if self.broken {
            return Err(DBusError::protocol(
                "this D-Bus connection is no longer usable after an earlier framing error",
            ));
        }
        Ok(())
    }

    /// Call a method and wait for its reply.
    ///
    /// Replies are matched by `REPLY_SERIAL`, not by arrival order: a bus is
    /// free to interleave signals, and an activatable destination may generate
    /// `NameOwnerChanged` before the reply we asked for.
    pub fn call(
        &mut self,
        destination: &str,
        path: &str,
        interface: &str,
        member: &str,
        signature: &str,
        args: Vec<DValue>,
    ) -> Result<Vec<DValue>, DBusError> {
        let msg = Message::method_call(destination, path, interface, member)
            .with_body(signature, args);
        let serial = self.send_message(&msg)?;

        for _ in 0..MAX_MESSAGES_PER_CALL {
            let reply = self.receive_message()?;
            match reply.kind {
                MessageType::MethodReturn if reply.reply_serial == Some(serial) => {
                    return Ok(reply.body);
                }
                MessageType::Error if reply.reply_serial == Some(serial) => {
                    return Err(DBusError::Remote {
                        name: reply.error_name.clone().unwrap_or_default(),
                        message: reply.error_text(),
                    });
                }
                MessageType::Signal => {
                    if self.signals.len() >= MAX_QUEUED_SIGNALS {
                        self.signals.pop_front();
                    }
                    self.signals.push_back(reply);
                }
                MessageType::MethodCall => {
                    // Somebody is calling us. We export nothing, so decline
                    // politely rather than leaving them waiting.
                    if reply.flags & FLAG_NO_REPLY_EXPECTED == 0 {
                        let err = Message::error_reply(
                            &reply,
                            "org.freedesktop.DBus.Error.UnknownMethod",
                            "this connection does not export any objects",
                        );
                        self.send_message(&err)?;
                    }
                }
                // A reply to a serial we are not waiting for: only possible if
                // a previous call timed out. Drop it and keep waiting.
                _ => {}
            }
        }
        Err(DBusError::protocol(format!(
            "no reply to {interface}.{member} after {MAX_MESSAGES_PER_CALL} messages"
        )))
    }

    /// Ask the bus for a well-known name. Returns the reply code
    /// (1 = primary owner). Used by the test harness's mock systemd.
    pub fn request_name(&mut self, name: &str, flags: u32) -> Result<u32, DBusError> {
        let reply = self.call(
            BUS_NAME,
            BUS_PATH,
            BUS_INTERFACE,
            "RequestName",
            "su",
            vec![DValue::str(name), DValue::Uint32(flags)],
        )?;
        reply
            .first()
            .and_then(DValue::as_u32)
            .ok_or_else(|| DBusError::protocol("RequestName returned no result code"))
    }

    /// `org.freedesktop.DBus.ListNames`.
    pub fn list_names(&mut self) -> Result<Vec<String>, DBusError> {
        let reply =
            self.call(BUS_NAME, BUS_PATH, BUS_INTERFACE, "ListNames", "", Vec::new())?;
        reply
            .first()
            .and_then(DValue::as_string_vec)
            .ok_or_else(|| DBusError::protocol("ListNames did not return an array of strings"))
    }

    /// `org.freedesktop.DBus.Properties.GetAll` on an arbitrary object.
    pub fn get_all_properties(
        &mut self,
        destination: &str,
        path: &str,
        interface: &str,
    ) -> Result<DValue, DBusError> {
        let mut reply = self.call(
            destination,
            path,
            PROPERTIES_INTERFACE,
            "GetAll",
            "s",
            vec![DValue::str(interface)],
        )?;
        if reply.is_empty() {
            return Err(DBusError::protocol("GetAll returned an empty body"));
        }
        Ok(reply.remove(0))
    }
}
