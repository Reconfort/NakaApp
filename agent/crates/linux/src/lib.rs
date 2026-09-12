//! `serveros-linux` — the agent's window onto the machine it runs on.
//!
//! This crate answers four questions about a Linux host and nothing else:
//!
//! | question                     | module              | source                     |
//! |------------------------------|---------------------|----------------------------|
//! | what machine is this?        | [`system`]          | `/proc`, `/etc/os-release` |
//! | what is it doing right now?  | [`metrics`]         | `/proc`, `/sys`            |
//! | what is running on it?       | [`processes`]       | `/proc/<pid>/`             |
//! | who can log into it?         | [`users`]           | `/etc/passwd` & friends    |
//!
//! # Read files, do not run programs
//!
//! Nothing here shells out. Not to `ps`, not to `df`, not to `free`. That is
//! not asceticism — it is the whole architectural bet of the ServerOS agent:
//! the app must translate *user intent* into a *safe, structured operation*,
//! never into a command line. A crate that parses `ps` output has already lost
//! that argument, and inherits `ps`'s locale handling, column truncation and
//! exit codes as a bonus. Reading `/proc` is faster, has no fork cost, cannot
//! be influenced by `$PATH`, and produces the same bytes on every distribution.
//!
//! # Everything degrades, nothing panics
//!
//! Every public function returns `Result<_, LinuxError>` or an infallible
//! value, and there is not an `unwrap` on parsed system data anywhere in this
//! crate. Real servers have surprising `/proc` content: kernels old enough to
//! lack `MemAvailable`, containers with no `/sys/class/dmi`, processes named
//! `a (weird) name`, filesystems no syscall-free code can measure. Each of
//! those costs *one field*, which degrades to a documented default or to
//! `null`. None of them takes down the agent, because an agent that crashes is
//! an unmanageable server.
//!
//! # Reading these numbers
//!
//! Two limitations are load-bearing for anyone integrating this crate, and both
//! are documented where they live rather than hidden:
//!   * **Disk used/available is not reported** without `statvfs(2)`, which
//!     needs libc. See the [`metrics`] module docs — those JSON fields are
//!     omitted rather than faked.
//!   * **`last_login` is always null**; `wtmp` is a binary struct array whose
//!     layout varies by architecture. See [`users::list_users`].

#![forbid(unsafe_code)]

pub mod error;
pub mod metrics;
pub mod procfs;
pub mod processes;
pub mod system;
pub mod users;

pub use error::LinuxError;
pub use metrics::{
    DiskMetrics, DiskSource, FilesystemUsage, FsUsage, Metrics, MetricsSampler, MountEntry,
    ProcDiskSource,
};
pub use processes::{Process, ProcessQuery, SortKey, list_processes, process_json};
pub use system::{CpuInfo, LoadAverage, OsInfo, SystemInfo, read_system_info};
pub use users::{
    LocalGroup, LocalUser, groups_json, list_groups, list_users, resolve_uid, users_json,
};

#[cfg(test)]
mod tests;
