//! ServerOS agent — the process that runs on a managed Linux host.
//!
//! # What this is
//!
//! A small HTTP service exposing *structured, enumerable capabilities* over the
//! host: metrics, processes, users, services, containers, files, logs and
//! PostgreSQL inventory. It is explicitly **not** a remote shell. There is no
//! `POST /execute`. Every operation the agent can perform is a named route with
//! its own validation, its own authorisation and its own audit record, which is
//! what makes permissions, error handling and auditing tractable.
//!
//! # How it is reached
//!
//! ```text
//!   macOS app ──SSH (direct-tcpip)──▶ 127.0.0.1:8723 on the server ──▶ agent
//! ```
//!
//! The agent binds loopback and a Unix socket. Nothing listens on a routable
//! interface, so there is no port to firewall, no certificate to provision or
//! renew, and no TLS termination to get wrong. The desktop app already holds an
//! authenticated SSH channel to the host — forwarding a local port through it is
//! strictly less attack surface than adding a second TLS endpoint.
//!
//! # How requests are authorised
//!
//! Enrollment writes a 32-byte secret to `/etc/serveros/agent.key` (mode 0600)
//! and prints it once; the desktop app stores it in the macOS Keychain. The
//! secret is never transmitted afterwards. Each request carries a short-lived
//! token the client mints and signs with it:
//!
//! ```text
//!   serveros.<base64url(payload)>.<base64url(HMAC-SHA256(secret, signing_input))>
//! ```
//!
//! The agent verifies the MAC, the lifetime (≤ 5 minutes), and that the token's
//! `jti` has not been seen before. A captured token is therefore useless within
//! minutes and cannot be replayed even within them.
//!
//! See `docs/SECURITY.md` for the full threat model.

#![forbid(unsafe_code)]

pub mod activity;
pub mod api;
pub mod auth;
pub mod config;
pub mod enroll;
pub mod logging;
pub mod state;
pub mod stream;

/// Agent version, surfaced in `/v1/health` so the desktop app can tell the user
/// when a server is running an agent older than the app expects.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Wire-protocol version. Bumped only on a breaking change to the API shape;
/// the app refuses to talk to a major version it does not understand.
pub const API_VERSION: &str = "1";
