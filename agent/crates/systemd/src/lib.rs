//! `serveros-systemd` — service management, over systemd's real API.
//!
//! # Why a D-Bus client and not `systemctl`
//!
//! The product's central architectural bet is that user intent becomes a *safe,
//! structured operation*, never a command line. "Restart nginx" must resolve to
//! a method call with a typed argument and a typed error, not to a string that
//! a shell, a locale and a terminal width all get a say in.
//!
//! systemd already offers that: `org.freedesktop.systemd1.Manager` is the
//! interface, and `systemctl` is merely one of its clients. Speaking to it
//! directly buys:
//!
//!   * **Typed data.** `MemoryCurrent` arrives as a `u64`, not as the string
//!     `"412.3M"` that we would have to un-round.
//!   * **A real error channel.** `org.freedesktop.systemd1.NoSuchUnit` is
//!     distinguishable from "you lack permission", which is distinguishable
//!     from "the unit failed to start". With the CLI all three are a non-zero
//!     exit and a sentence on stderr that changes between releases.
//!   * **No process per operation.** Rendering one services screen is a
//!     handful of method calls on one socket, not several hundred `fork`s.
//!   * **No `$PATH`, no shell, no quoting.** A unit name cannot become an
//!     argument to something else, because there is no argv.
//!
//! The cost is that we implement the D-Bus wire protocol ourselves — see
//! [`dbus`], and in particular its notes on alignment, which is where every
//! hand-written implementation goes wrong. The agent takes no third-party
//! dependencies by policy (a privileged binary on a customer's server is not
//! the place for a supply chain), so this is the price of the right
//! architecture, paid once.
//!
//! [`SystemctlCli`] still exists as a fallback for hosts with no reachable bus.
//! It is explicitly the degraded path, and the API reports which backend
//! answered so nobody has to guess.
//!
//! # Shape of the crate
//!
//! | module      | responsibility                                            |
//! |-------------|-----------------------------------------------------------|
//! | [`dbus`]    | the wire protocol: addresses, SASL, marshalling, messages |
//! | [`systemd`] | the two backends and the [`ServiceManager`] trait          |
//! | [`unit`]    | the product's view of a unit, and its JSON                 |
//! | [`names`]   | unit-name validation (a security boundary) and filtering   |
//! | [`error`]   | failures, rendered for a person and for an engineer        |
//!
//! # Example
//!
//! ```no_run
//! let manager = serveros_systemd::detect()?;
//! for unit in manager.list_units()? {
//!     println!("{:<40} {}", unit.name, unit.state());
//! }
//! manager.restart("nginx.service")?;
//! # Ok::<(), serveros_systemd::SystemdError>(())
//! ```

#![forbid(unsafe_code)]

pub mod dbus;
pub mod error;
pub mod names;
pub mod systemd;
pub mod unit;

pub use dbus::{DBusConnection, DBusError, DValue, Message, MessageType};
pub use error::SystemdError;
pub use names::{
    MAX_UNIT_NAME_LEN, UNIT_SUFFIXES, display_name, is_interesting_service, unit_suffix,
    validate_unit_name,
};
pub use systemd::{
    JOB_MODE, MANAGER_INTERFACE, SERVICE_INTERFACE, ServiceManager, SYSTEMD_DESTINATION,
    SYSTEMD_PATH, SystemctlCli, SystemdDbus, UNIT_INTERFACE, detect, is_systemd_running,
};
pub use unit::{Unit, UnitDetail, rollup_state, units_json};

#[cfg(test)]
mod tests;
