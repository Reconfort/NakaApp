//! The one error type this crate hands back — and the one place where the
//! wording of a failure is decided.
//!
//! Two rules govern this file.
//!
//! **Every message is safe to put in front of a user.** The app shows these
//! verbatim (product rule: *errors must be human*), so no variant carries a
//! bare `ECONNREFUSED`/`EACCES` as its primary text. The raw `io::Error` is
//! kept in [`FsError::Io`] and surfaced as `detail` in JSON, which is where
//! "View technical details" reads from.
//!
//! **A refusal is never confused with a failure.** [`FsError::Denied`] means
//! *policy said no* and [`FsError::RefusedDangerous`] means *we could have done
//! it and chose not to*; neither is an I/O problem. The app reacts differently
//! to each — a denial is final, an I/O error offers a retry — so they cannot
//! share a variant. There is deliberately no `Other(String)`: an error taxonomy
//! with a catch-all rots into one.

use serveros_json::{Object, Value};
use std::fmt;
use std::io::ErrorKind;
use std::path::Path;

/// Anything that can go wrong while inspecting or changing the filesystem.
#[derive(Debug)]
pub enum FsError {
    /// The path policy refused this path. `reason` is a complete sentence and
    /// is safe to display; it never quotes the contents of a secret.
    Denied {
        /// User-facing explanation of the refusal.
        reason: String,
    },
    /// The operation is possible but too dangerous to perform through a GUI
    /// (deleting `/`, a configured root, or a critical system directory).
    RefusedDangerous {
        /// The path that was refused.
        path: String,
        /// Why it is refused, as a complete sentence.
        reason: String,
    },
    /// Nothing exists at that path.
    NotFound {
        /// The path that does not exist.
        path: String,
    },
    /// Something already exists where the caller wanted to create.
    AlreadyExists {
        /// The path that is occupied.
        path: String,
    },
    /// A directory was required and the path is not one.
    NotADirectory {
        /// The path that is not a directory.
        path: String,
    },
    /// A file was required and the path is a directory.
    IsADirectory {
        /// The path that is a directory.
        path: String,
    },
    /// A non-recursive delete found a directory with children in it.
    NotEmpty {
        /// The directory that still has children.
        path: String,
    },
    /// The file is not text, so it cannot be opened in the editor.
    NotText {
        /// The file that failed the text sniff.
        path: String,
        /// Which part of the heuristic rejected it.
        reason: String,
    },
    /// The file is larger than the limit for this operation.
    TooLarge {
        /// The oversized file.
        path: String,
        /// Its size in bytes.
        size: u64,
        /// The limit it exceeded, in bytes.
        limit: u64,
    },
    /// A caller-supplied log filter pattern was rejected by the compiler.
    InvalidPattern {
        /// Which rule of the supported subset the pattern broke.
        reason: String,
    },
    /// The server does not provide the facility at all (no systemd journal).
    Unsupported {
        /// The facility, named the way a user would name it.
        feature: &'static str,
        /// Why it is missing on this host.
        reason: &'static str,
    },
    /// Everything else the kernel told us, with the path it happened to.
    Io {
        /// The path the syscall was about.
        path: String,
        /// The underlying error, kept for "View technical details".
        source: std::io::Error,
    },
}

impl FsError {
    /// Build a policy refusal from a complete, user-safe sentence.
    pub fn denied(reason: impl Into<String>) -> FsError {
        FsError::Denied { reason: reason.into() }
    }

    /// Build a "we will not do that" refusal for a dangerous target.
    pub fn refused(path: &Path, reason: impl Into<String>) -> FsError {
        FsError::RefusedDangerous { path: show(path), reason: reason.into() }
    }

    /// Wrap an `io::Error`, mapping the kinds that have a better variant here.
    ///
    /// `std::fs` deliberately omits the path from its errors. We report to a
    /// human through a UI, where the path is the most useful thing in the
    /// message, so every I/O failure is re-wrapped with the path it concerns.
    pub fn io(path: &Path, err: std::io::Error) -> FsError {
        let p = show(path);
        match err.kind() {
            ErrorKind::NotFound => FsError::NotFound { path: p },
            ErrorKind::PermissionDenied => FsError::Denied {
                reason: format!("ServerOS does not have permission to open {p} on this server."),
            },
            ErrorKind::AlreadyExists => FsError::AlreadyExists { path: p },
            ErrorKind::NotADirectory => FsError::NotADirectory { path: p },
            ErrorKind::IsADirectory => FsError::IsADirectory { path: p },
            ErrorKind::DirectoryNotEmpty => FsError::NotEmpty { path: p },
            _ => FsError::Io { path: p, source: err },
        }
    }

    /// Stable machine-readable discriminant, for the HTTP layer and for tests.
    pub fn kind(&self) -> &'static str {
        match self {
            FsError::Denied { .. } => "denied",
            FsError::RefusedDangerous { .. } => "refused_dangerous",
            FsError::NotFound { .. } => "not_found",
            FsError::AlreadyExists { .. } => "already_exists",
            FsError::NotADirectory { .. } => "not_a_directory",
            FsError::IsADirectory { .. } => "is_a_directory",
            FsError::NotEmpty { .. } => "not_empty",
            FsError::NotText { .. } => "not_text",
            FsError::TooLarge { .. } => "too_large",
            FsError::InvalidPattern { .. } => "invalid_pattern",
            FsError::Unsupported { .. } => "unsupported",
            FsError::Io { .. } => "io",
        }
    }

    /// The HTTP status the agent should answer with.
    pub fn http_status(&self) -> u16 {
        match self {
            FsError::Denied { .. } | FsError::RefusedDangerous { .. } => 403,
            FsError::NotFound { .. } => 404,
            FsError::AlreadyExists { .. } | FsError::NotEmpty { .. } => 409,
            FsError::NotADirectory { .. }
            | FsError::IsADirectory { .. }
            | FsError::NotText { .. }
            | FsError::InvalidPattern { .. } => 400,
            FsError::TooLarge { .. } => 413,
            FsError::Unsupported { .. } => 501,
            FsError::Io { .. } => 500,
        }
    }

    /// The path this error is about, when it is about one.
    pub fn path(&self) -> Option<&str> {
        match self {
            FsError::RefusedDangerous { path, .. }
            | FsError::NotFound { path }
            | FsError::AlreadyExists { path }
            | FsError::NotADirectory { path }
            | FsError::IsADirectory { path }
            | FsError::NotEmpty { path }
            | FsError::NotText { path, .. }
            | FsError::TooLarge { path, .. }
            | FsError::Io { path, .. } => Some(path),
            FsError::Denied { .. } | FsError::InvalidPattern { .. } | FsError::Unsupported { .. } => None,
        }
    }

    /// The technical detail behind the human message, if there is one. This is
    /// what the app hides behind "View technical details".
    pub fn detail(&self) -> Option<String> {
        match self {
            FsError::Io { source, .. } => Some(source.to_string()),
            FsError::NotText { reason, .. } => Some(reason.clone()),
            _ => None,
        }
    }

    /// `{"kind":"denied","message":"…","path":"/etc/shadow","detail":null}`
    pub fn to_json(&self) -> Value {
        Object::new()
            .set("kind", self.kind())
            .set("message", self.to_string())
            .set_opt("path", self.path())
            .set_opt("detail", self.detail())
            .into()
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FsError::Denied { reason } => f.write_str(reason),
            FsError::RefusedDangerous { path, reason } => {
                write!(f, "ServerOS will not do that to {path}. {reason}")
            }
            FsError::NotFound { path } => write!(f, "There is nothing at {path} on this server."),
            FsError::AlreadyExists { path } => write!(f, "{path} already exists."),
            FsError::NotADirectory { path } => write!(f, "{path} is not a folder."),
            FsError::IsADirectory { path } => write!(f, "{path} is a folder, not a file."),
            FsError::NotEmpty { path } => {
                write!(f, "{path} is not empty. Delete its contents first, or delete it recursively.")
            }
            FsError::NotText { path, .. } => {
                write!(f, "{path} does not look like a text file, so it cannot be opened in the editor.")
            }
            FsError::TooLarge { path, size, limit } => write!(
                f,
                "{path} is {} and the limit for this operation is {}.",
                human_bytes(*size),
                human_bytes(*limit)
            ),
            FsError::InvalidPattern { reason } => {
                write!(f, "That search pattern is not supported: {reason}")
            }
            FsError::Unsupported { feature, reason } => {
                write!(f, "{feature} is not available on this server: {reason}")
            }
            FsError::Io { path, source } => {
                write!(f, "ServerOS could not complete that operation on {path}: {source}")
            }
        }
    }
}

impl std::error::Error for FsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FsError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Render a path for a message.
///
/// Linux paths are bytes, not UTF-8. A name the agent cannot represent is
/// shown lossily rather than hidden — the user needs to see that the entry is
/// there even when the agent cannot address it by name over a JSON API.
pub(crate) fn show(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Size for humans. Deliberately coarse: an error message is not a dashboard.
pub(crate) fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} bytes");
    }
    let mut value = n as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{} {}", serveros_json::round(value, 1), UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn io_not_found_becomes_not_found() {
        let e = FsError::io(Path::new("/tmp/nope"), io::Error::from(ErrorKind::NotFound));
        assert_eq!(e.kind(), "not_found");
        assert_eq!(e.http_status(), 404);
        assert_eq!(e.path(), Some("/tmp/nope"));
    }

    #[test]
    fn io_permission_denied_becomes_a_human_denial() {
        let e = FsError::io(Path::new("/etc/shadow"), io::Error::from(ErrorKind::PermissionDenied));
        assert_eq!(e.kind(), "denied");
        let msg = e.to_string();
        assert!(msg.contains("/etc/shadow"), "{msg}");
        assert!(!msg.contains("os error"), "raw errno must not reach the user: {msg}");
    }

    #[test]
    fn unknown_io_keeps_the_technical_detail_out_of_the_kind() {
        let e = FsError::io(Path::new("/x"), io::Error::other("weird"));
        assert_eq!(e.kind(), "io");
        assert_eq!(e.http_status(), 500);
        assert!(e.detail().unwrap().contains("weird"));
    }

    #[test]
    fn json_shape_is_stable() {
        let e = FsError::TooLarge { path: "/a".into(), size: 4 * 1024 * 1024, limit: 2 * 1024 * 1024 };
        let j = e.to_json();
        assert_eq!(j.get("kind").and_then(|v| v.as_str()), Some("too_large"));
        assert_eq!(j.get("path").and_then(|v| v.as_str()), Some("/a"));
        assert!(j.get("message").and_then(|v| v.as_str()).unwrap().contains("4 MB"));
        assert!(j.get("detail").is_none(), "absent detail is omitted, not null");
    }

    #[test]
    fn human_bytes_is_readable() {
        assert_eq!(human_bytes(0), "0 bytes");
        assert_eq!(human_bytes(1023), "1023 bytes");
        assert_eq!(human_bytes(1024), "1 KB");
        assert_eq!(human_bytes(2 * 1024 * 1024), "2 MB");
        assert_eq!(human_bytes(1536), "1.5 KB");
    }
}
