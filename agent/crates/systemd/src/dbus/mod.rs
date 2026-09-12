//! A D-Bus client, implemented from the specification.
//!
//! # Why we speak the wire protocol instead of running `systemctl`
//!
//! systemd's real API is D-Bus. `systemctl` is a *client* of that API, and its
//! textual output is explicitly documented as unstable: column widths change
//! with terminal size, status glyphs change with locale and unicode support,
//! `--no-pager` is load-bearing, and the exit codes conflate "unit is stopped"
//! with "unit does not exist". Parsing it means inheriting every one of those
//! as a bug surface, on every distribution, forever.
//!
//! Speaking D-Bus gives us typed values instead of text, a real error channel
//! (`org.freedesktop.systemd1.NoSuchUnit` rather than exit status 4 plus a
//! sentence on stderr), no `fork`/`exec` per operation, and no `$PATH`. It is
//! also the only way to get properties like `CPUUsageNSec` without a second
//! parse pass. The `systemctl` backend still exists in this crate, but as a
//! *fallback* for hosts with no accessible bus — not as the architecture.
//!
//! # The part everyone gets wrong: alignment
//!
//! Every D-Bus value is padded so that it starts at an offset which is a
//! multiple of its own alignment, **counted from the first byte of the
//! message** — not from the start of the body, and not from the start of the
//! enclosing container. The alignments are:
//!
//! | type                          | align | notes                              |
//! |-------------------------------|-------|------------------------------------|
//! | `y` byte, `g` signature, `v` variant | 1 | signature/variant length is a `u8` |
//! | `n` int16, `q` uint16         | 2     |                                    |
//! | `b` bool, `i` int32, `u` uint32 | 4   | a bool is a `u32` of 0 or 1        |
//! | `s` string, `o` object path   | 4     | `u32` length, bytes, then NUL      |
//! | `a` array                     | 4     | `u32` **byte** length, see below   |
//! | `x` int64, `t` uint64, `d` double | 8 |                                    |
//! | `(` struct, `{` dict entry    | 8     | even a struct of one byte          |
//!
//! Two consequences bite hard:
//!
//! 1. **An array's length prefix is 4-aligned, but its elements are aligned to
//!    the element type.** `at` (array of uint64) is `u32` length, then four
//!    bytes of padding, then the first `u64`. That padding is **not** counted
//!    in the length. It is present **even when the array is empty**, so an
//!    empty `at` occupies eight bytes, not four.
//! 2. **The body is marshalled as if it started at offset 0.** The header ends
//!    with padding to an 8-byte boundary and 8 is the maximum alignment, so
//!    body offsets are congruent either way. That is why [`marshal::Writer`]
//!    can build the body into its own buffer and simply concatenate.
//!
//! Everything in [`marshal`] is driven by a parsed [`signature::SigType`]
//! rather than by inspecting the value, because the value alone is not enough:
//! an empty `DValue::Array` does not know what it is an array *of*.

#![allow(clippy::module_inception)]

use std::fmt;
use std::io;

pub mod connection;
pub mod marshal;
pub mod message;
pub mod signature;
pub mod transport;
pub mod value;

pub use connection::DBusConnection;
pub use marshal::{Endian, Reader, Writer};
pub use message::{MAX_MESSAGE_SIZE, Message, MessageType};
pub use signature::{SigType, parse_signature};
pub use transport::BusAddress;
pub use value::DValue;

/// Everything that can go wrong between "open a socket" and "here is a reply".
///
/// The split matters to the product: [`DBusError::Remote`] is the peer saying
/// "no" in a structured way and is shown to the user as a real message, while
/// [`DBusError::Io`] and [`DBusError::Address`] mean "there is no bus here" and
/// drive the fallback to `systemctl`.
#[derive(Debug)]
pub enum DBusError {
    /// Socket-level failure: connect, read or write.
    Io(io::Error),
    /// The bus address string was absent or unparseable.
    Address(String),
    /// SASL handshake failed (`REJECTED`, unexpected reply, EOF mid-handshake).
    Auth(String),
    /// The peer sent bytes that are not a valid D-Bus message, or we were asked
    /// to marshal something that cannot be represented.
    Protocol(String),
    /// A well-formed `ERROR` reply. `name` is a D-Bus error name such as
    /// `org.freedesktop.systemd1.NoSuchUnit`.
    Remote { name: String, message: String },
    /// The read timeout elapsed with no reply.
    Timeout,
    /// A message (or array) exceeded the size cap. Guards against a hostile or
    /// broken peer pushing us into an allocation the agent cannot survive.
    TooLarge { size: usize, max: usize },
}

impl DBusError {
    pub(crate) fn protocol(msg: impl Into<String>) -> Self {
        DBusError::Protocol(msg.into())
    }

    /// True when the failure means "there is no usable bus", as opposed to
    /// "the bus answered and said no". [`crate::detect`] switches backends on
    /// exactly this distinction.
    pub fn is_unreachable(&self) -> bool {
        matches!(
            self,
            DBusError::Io(_) | DBusError::Address(_) | DBusError::Auth(_) | DBusError::Timeout
        )
    }

    /// The D-Bus error name, for `Remote` errors only.
    pub fn error_name(&self) -> Option<&str> {
        match self {
            DBusError::Remote { name, .. } => Some(name),
            _ => None,
        }
    }
}

impl fmt::Display for DBusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DBusError::Io(e) => write!(f, "D-Bus I/O error: {e}"),
            DBusError::Address(s) => write!(f, "D-Bus address error: {s}"),
            DBusError::Auth(s) => write!(f, "D-Bus authentication failed: {s}"),
            DBusError::Protocol(s) => write!(f, "D-Bus protocol error: {s}"),
            DBusError::Remote { name, message } => {
                if message.is_empty() {
                    write!(f, "{name}")
                } else {
                    write!(f, "{name}: {message}")
                }
            }
            DBusError::Timeout => f.write_str("timed out waiting for a D-Bus reply"),
            DBusError::TooLarge { size, max } => {
                write!(f, "D-Bus message of {size} bytes exceeds the {max} byte limit")
            }
        }
    }
}

impl std::error::Error for DBusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DBusError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for DBusError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => DBusError::Timeout,
            _ => DBusError::Io(e),
        }
    }
}
