//! The one error type this crate hands back.
//!
//! Three variants, because the caller only ever makes three decisions:
//!   * `Io` — the file was not there, or we were not allowed to read it. The
//!     HTTP layer turns this into 404/403 and the app shows "ServerOS could not
//!     read this". Recoverable by fixing permissions.
//!   * `Parse` — the file was there but did not look like we expect. This is
//!     always a bug report, never a user action, so the message names the file.
//!   * `NotSupported` — the kernel or the container does not expose the thing
//!     at all (no `/proc`, no `/sys/block`). The app should hide the feature
//!     rather than show a failure.
//!
//! Note what is *absent*: there is no `Other(String)`. Every failure mode in a
//! `/proc` reader is one of the three above, and a catch-all variant is how
//! error taxonomies rot.

use std::fmt;

/// Anything that can go wrong while inspecting the local Linux system.
#[derive(Debug)]
pub enum LinuxError {
    /// A system file could not be opened or read. The message carries the path.
    Io(std::io::Error),
    /// A system file was readable but malformed. The message names the source.
    Parse(String),
    /// The kernel does not expose the interface this call needs.
    NotSupported(&'static str),
}

impl LinuxError {
    /// Build a `Parse` error naming the file and what went wrong with it.
    pub fn parse(source: &str, detail: impl fmt::Display) -> Self {
        LinuxError::Parse(format!("{source}: {detail}"))
    }

    /// Re-wrap an `io::Error` so the message carries the path.
    ///
    /// `std::fs` deliberately omits the path from its errors (it would allocate
    /// on every failed open). We are reporting to a human through a UI, so the
    /// path is the single most useful thing in the message.
    pub fn io(path: &str, err: std::io::Error) -> Self {
        LinuxError::Io(std::io::Error::new(err.kind(), format!("{path}: {err}")))
    }
}

impl fmt::Display for LinuxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinuxError::Io(e) => write!(f, "{e}"),
            LinuxError::Parse(what) => write!(f, "unexpected system file contents: {what}"),
            LinuxError::NotSupported(what) => {
                write!(f, "this kernel does not expose {what}")
            }
        }
    }
}

impl std::error::Error for LinuxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LinuxError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for LinuxError {
    fn from(e: std::io::Error) -> Self {
        LinuxError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io::ErrorKind;

    #[test]
    fn io_error_carries_the_path() {
        let e = LinuxError::io("/proc/nope", std::io::Error::from(ErrorKind::NotFound));
        assert!(e.to_string().contains("/proc/nope"), "{e}");
        assert!(e.source().is_some());
    }

    #[test]
    fn parse_error_names_the_source() {
        let e = LinuxError::parse("/proc/stat", "no cpu line");
        assert!(e.to_string().contains("/proc/stat"));
        assert!(e.to_string().contains("no cpu line"));
        assert!(e.source().is_none());
    }

    #[test]
    fn not_supported_reads_as_a_sentence() {
        let e = LinuxError::NotSupported("/proc");
        assert_eq!(e.to_string(), "this kernel does not expose /proc");
    }

    #[test]
    fn converts_from_io_error() {
        let e: LinuxError = std::io::Error::from(ErrorKind::PermissionDenied).into();
        assert!(matches!(e, LinuxError::Io(_)));
    }
}
