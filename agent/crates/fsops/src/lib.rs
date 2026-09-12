//! `serveros-fsops` — remote file management and log reading for the agent.
//!
//! This is the agent's most security-sensitive crate. Every other module
//! manages a *named thing*: a container, a unit, a database. This one can read
//! and write **any byte on the customer's server**, from a path a caller
//! supplied over the network. Path containment is therefore not a feature of
//! this crate, it is the crate; see [`path`] for the argument in full.
//!
//! | module      | question it answers                                    |
//! |-------------|--------------------------------------------------------|
//! | [`path`]    | may we touch this path at all?                         |
//! | [`listing`] | what is in this directory, and what is this entry?     |
//! | [`read`]    | what does this file say?                               |
//! | [`ops`]     | change it — safely, atomically, recoverably            |
//! | [`logs`]    | what has this server been saying?                      |
//! | [`pattern`] | a bounded regex subset for filtering log lines         |
//! | [`error`]   | one error type, with messages fit to show a human      |
//!
//! # The shape every entry point has
//!
//! ```text
//! caller's &str ──► PathPolicy::resolve ──► canonical PathBuf ──► syscall
//!                         │
//!                         └──► FsError::Denied (never a leak, never a guess)
//! ```
//!
//! No function in this crate takes a `&Path` from outside except
//! [`ops::copy_from`]'s spool file, which is a path the *agent* chose. Every
//! caller-supplied path is a `&str` that goes through the policy exactly once,
//! and the resolved `PathBuf` is what the syscall then uses.
//!
//! # What this crate deliberately does not do
//!
//! * **No `unsafe`, no libc.** Consequences are documented where they bite:
//!   permissions are computed from mode bits rather than `access(2)`
//!   ([`listing`]), following a log file polls rather than using `inotify`
//!   ([`logs`]), and there is no `openat2(2)` to close the last TOCTOU gap.
//! * **No shelling out**, with exactly one documented exception —
//!   [`logs::journal_tail`] runs `journalctl --output=json`, systemd's
//!   documented machine-readable interface, with an argv and a validated unit
//!   name.
//! * **No "execute this command" entry point.** There is nowhere in this crate
//!   that a caller-supplied string becomes a program to run.

#![forbid(unsafe_code)]

pub mod error;
pub mod ids;
pub mod listing;
pub mod logs;
pub mod ops;
pub mod path;
pub mod pattern;
pub mod read;

#[cfg(test)]
mod testutil;

#[cfg(test)]
mod tests;

pub use error::FsError;
pub use listing::{Entry, EntryKind, ListOptions, Listing, SortBy, list_directory, stat_entry};
pub use logs::{
    LogBatch, LogFollower, LogLine, LogQuery, LogSource, Level, follow_file, journal_available,
    journal_tail, parse_line, tail_file,
};
pub use ops::{
    DeleteReport, copy_from, create_directory, create_file, delete, move_to_trash, rename,
    set_mode, write_file,
};
pub use path::PathPolicy;
pub use pattern::{Matcher, Pattern};
pub use read::{MAX_TEXT_BYTES, TextFile, detect_line_ending, open_download, read_text, sniff_is_text};

/// Seconds since the unix epoch.
///
/// Clamped at zero rather than returning a `Result`: a server whose clock is
/// before 1970 has a problem this crate cannot fix, and every caller here is
/// stamping a filename or a synthetic log line, where a zero is harmless and a
/// propagated error would be noise.
pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
