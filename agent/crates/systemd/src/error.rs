//! Errors, shaped for a UI rather than for a log file.
//!
//! The product rule is that a user never sees `ECONNREFUSED` or
//! `org.freedesktop.systemd1.NoSuchUnit` as the headline. So every failure
//! carries two renderings: [`SystemdError::user_message`], which is a sentence
//! a person can act on, and [`SystemdError::technical_detail`], which is what
//! an engineer needs and the UI hides behind "View technical details".

use std::fmt;
use std::io;

use crate::dbus::DBusError;

/// Anything that can go wrong managing services.
#[derive(Debug)]
pub enum SystemdError {
    /// The bus itself failed.
    Dbus(DBusError),
    /// The `systemctl` fallback failed: non-zero exit, or unparseable output.
    Cli { command: String, status: Option<i32>, stderr: String },
    /// A unit name was rejected before it reached any backend.
    InvalidUnitName { name: String, reason: &'static str },
    /// systemd has no unit by that name.
    NoSuchUnit(String),
    /// Polkit or DAC said no.
    PermissionDenied(String),
    /// No backend is usable on this host.
    Unavailable(String),
    /// A backend answered, but not in a shape we understand.
    Parse(String),
    /// Local I/O — spawning `systemctl`, reading `/run/systemd/system`.
    Io(io::Error),
}

impl SystemdError {
    /// Translate a D-Bus reply into a product-level error.
    ///
    /// Worth doing precisely: "that unit does not exist" and "you are not
    /// allowed to do that" are completely different screens, and both arrive
    /// as a `Remote` error with only the name to tell them apart.
    pub fn from_dbus(unit: &str, e: DBusError) -> SystemdError {
        match e.error_name() {
            Some("org.freedesktop.systemd1.NoSuchUnit")
            | Some("org.freedesktop.systemd1.LoadFailed")
            | Some("org.freedesktop.DBus.Error.FileNotFound") => {
                SystemdError::NoSuchUnit(unit.to_owned())
            }
            Some("org.freedesktop.DBus.Error.AccessDenied")
            | Some("org.freedesktop.DBus.Error.AuthFailed")
            | Some("org.freedesktop.DBus.Error.InteractiveAuthorizationRequired") => {
                SystemdError::PermissionDenied(unit.to_owned())
            }
            Some("org.freedesktop.DBus.Error.ServiceUnknown")
            | Some("org.freedesktop.DBus.Error.NameHasNoOwner") => SystemdError::Unavailable(
                "systemd is not registered on the system bus".to_owned(),
            ),
            _ => SystemdError::Dbus(e),
        }
    }

    /// A sentence for the user. No error codes, no jargon.
    pub fn user_message(&self) -> String {
        match self {
            SystemdError::Dbus(e) if e.is_unreachable() => {
                "ServerOS couldn't reach the service manager on this server.".to_owned()
            }
            SystemdError::Dbus(_) => "The service manager rejected that operation.".to_owned(),
            SystemdError::Cli { .. } => "The service manager rejected that operation.".to_owned(),
            SystemdError::InvalidUnitName { name, .. } => {
                format!("\u{201c}{name}\u{201d} is not a valid service name.")
            }
            SystemdError::NoSuchUnit(n) => format!("There is no service called \u{201c}{n}\u{201d} on this server."),
            SystemdError::PermissionDenied(n) => {
                format!("ServerOS isn't allowed to manage \u{201c}{n}\u{201d} on this server.")
            }
            SystemdError::Unavailable(_) => {
                "This server doesn't appear to use systemd, so services can't be managed here."
                    .to_owned()
            }
            SystemdError::Parse(_) => {
                "ServerOS couldn't understand the service manager's response.".to_owned()
            }
            SystemdError::Io(_) => {
                "ServerOS couldn't reach the service manager on this server.".to_owned()
            }
        }
    }

    /// The detail an engineer wants, shown behind a disclosure.
    pub fn technical_detail(&self) -> String {
        self.to_string()
    }

    /// Suggested HTTP status for the agent's API layer.
    pub fn http_status(&self) -> u16 {
        match self {
            SystemdError::InvalidUnitName { .. } => 400,
            SystemdError::NoSuchUnit(_) => 404,
            SystemdError::PermissionDenied(_) => 403,
            SystemdError::Unavailable(_) => 503,
            _ => 500,
        }
    }
}

impl fmt::Display for SystemdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemdError::Dbus(e) => write!(f, "{e}"),
            SystemdError::Cli { command, status, stderr } => {
                write!(f, "`{command}` failed")?;
                if let Some(s) = status {
                    write!(f, " with exit status {s}")?;
                }
                if !stderr.is_empty() {
                    write!(f, ": {}", stderr.trim())?;
                }
                Ok(())
            }
            SystemdError::InvalidUnitName { name, reason } => {
                write!(f, "invalid unit name {name:?}: {reason}")
            }
            SystemdError::NoSuchUnit(n) => write!(f, "no such unit: {n}"),
            SystemdError::PermissionDenied(n) => {
                write!(f, "permission denied managing unit: {n}")
            }
            SystemdError::Unavailable(s) => write!(f, "no service manager available: {s}"),
            SystemdError::Parse(s) => write!(f, "could not parse service manager output: {s}"),
            SystemdError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for SystemdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SystemdError::Dbus(e) => Some(e),
            SystemdError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DBusError> for SystemdError {
    fn from(e: DBusError) -> Self {
        SystemdError::Dbus(e)
    }
}

impl From<io::Error> for SystemdError {
    fn from(e: io::Error) -> Self {
        SystemdError::Io(e)
    }
}
