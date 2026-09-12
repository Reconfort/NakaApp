//! A PostgreSQL client that speaks the v3 wire protocol directly, for
//! reporting database health and inventory.
//!
//! # Why a hand-written driver
//!
//! The agent takes no third-party crates (see the workspace `Cargo.toml`), so
//! `postgres` and `tokio-postgres` are off the table. That is a smaller loss
//! than it sounds: the agent's entire relationship with PostgreSQL is *look,
//! never touch*. It opens one connection, authenticates, runs a fixed set of
//! catalogue queries, renders JSON, and hangs up. None of the hard parts of a
//! general driver — the extended query protocol, binary formats, prepared
//! statement caches, COPY, async notification, connection pooling, replication
//! — are on that path.
//!
//! What owning the codec buys, beyond the dependency count, is that the crate
//! can be *structurally* read-only. A driver that accepts arbitrary SQL cannot
//! promise that; this one routes every caller through
//! [`client::is_read_only`] and keeps the bypass `pub(crate)`.
//!
//! # Layout
//!
//! | module           | what it owns                                          |
//! |------------------|-------------------------------------------------------|
//! | [`protocol`]     | v3 message framing, encode and decode                 |
//! | [`auth`]         | SCRAM-SHA-256, legacy `md5`, cleartext, SASLprep      |
//! | [`client`]       | connecting, the read-only guard, Simple Query          |
//! | [`inventory`]    | discovery and the JSON the Databases screen renders    |
//! | [`error`]        | one error type, and the rules that keep secrets out    |
//!
//! # The three postures worth knowing about
//!
//! **No TLS, and no remote hosts.** The agent runs on the database host and
//! connects over loopback or a unix socket, where TLS protects nothing an
//! attacker in the same network namespace could not already do. Rather than
//! leave that as an implicit assumption, [`client::PgConnection::connect`]
//! *enforces* it: a non-loopback TCP host is refused with
//! [`error::PgError::RemoteHostNotAllowed`] before a socket is opened. Managing
//! a remote database means running an agent next to it.
//!
//! **Read-only.** [`client::PgConnection::query`] accepts a single `SELECT`,
//! `SHOW`, or `WITH ... SELECT` and nothing else. The inventory feature exists
//! to show an operator their data estate; without this guard the same endpoint
//! would be an arbitrary-SQL hole wearing a dashboard.
//!
//! **Secrets stay out of the error path.** [`client::PgConfig`] has a
//! hand-written `Debug`, [`client::PgConnection`] never stores a password at
//! all, and a rejected statement is reported by its leading keyword rather than
//! its text — so a refused `ALTER USER ... PASSWORD '...'` cannot end up in a
//! log line.
//!
//! # Using it
//!
//! ```no_run
//! use serveros_pg::{PgConfig, PgConnection, inventory};
//!
//! let mut cfg = PgConfig::local("serveros", "postgres");
//! cfg.password = Some(std::env::var("PGPASSWORD").unwrap());
//!
//! let mut conn = PgConnection::connect(&cfg)?;
//! let overview = inventory::instance_overview(&mut conn)?;
//! println!("{}", overview.to_string_pretty());
//! conn.close();
//! # Ok::<(), serveros_pg::PgError>(())
//! ```

#![forbid(unsafe_code)]

pub mod auth;
pub mod client;
pub mod error;
pub mod inventory;
pub mod protocol;

pub use client::{PgConfig, PgConnection, PgHost, QueryResult, is_read_only};
pub use error::{PgError, ServerError};
pub use inventory::{DiscoveredInstance, QueryTextPolicy, discover_instances};

#[cfg(test)]
mod tests;
