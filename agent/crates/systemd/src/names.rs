//! Unit-name validation and the "is this worth showing a human" filter.
//!
//! # This module is a security boundary
//!
//! Unit names arrive from HTTP path parameters: `POST /services/{name}/restart`.
//! With the D-Bus backend a hostile name is merely a failed method call, but the
//! `systemctl` fallback turns it into an argument of a program running as root.
//! We never use a shell, so `;` and `|` cannot chain commands — but an argument
//! vector is not immune on its own:
//!
//!   * A name beginning with `-` is read by `systemctl` as an **option**.
//!     `systemctl start --version` is not a service operation. That is why
//!     [`validate_unit_name`] rejects a leading `-` even though `-` is a legal
//!     character elsewhere in a unit name.
//!   * A name containing `/` would let `systemctl` load a unit from an
//!     arbitrary path.
//!   * Whitespace and NUL break every downstream parser we hand the name to.
//!
//! So validation happens **before** a name reaches either backend, it is a
//! whitelist rather than a blacklist, and it is tested against the things an
//! attacker actually sends.

use crate::error::SystemdError;

/// Unit type suffixes systemd currently defines.
pub const UNIT_SUFFIXES: &[&str] = &[
    ".service",
    ".socket",
    ".target",
    ".device",
    ".mount",
    ".automount",
    ".swap",
    ".path",
    ".timer",
    ".slice",
    ".scope",
];

/// Longest unit name systemd will accept (`UNIT_NAME_MAX`).
pub const MAX_UNIT_NAME_LEN: usize = 255;

/// The unit-type suffix of `name`, including the dot.
pub fn unit_suffix(name: &str) -> Option<&'static str> {
    UNIT_SUFFIXES.iter().copied().find(|s| name.ends_with(s))
}

/// The name without its unit-type suffix: `nginx.service` -> `nginx`.
///
/// This is what the UI puts in the title; `.service` on every row is noise.
pub fn display_name(name: &str) -> &str {
    match unit_suffix(name) {
        Some(suffix) => &name[..name.len() - suffix.len()],
        None => name,
    }
}

/// Reject anything that is not a well-formed systemd unit name.
///
/// Accepted: 1..=255 characters drawn from `A-Z a-z 0-9 : _ . - @ \`, ending in
/// a known unit-type suffix, with a non-empty stem that does not begin with
/// `-`.
///
/// Note that the stem may contain further dots. Requiring a single dot would
/// reject real units — `dbus-org.freedesktop.resolve1.service` and
/// `plymouth-quit-wait.service` both ship on stock distributions — so what is
/// enforced is "exactly one recognised *suffix*", not "exactly one dot".
pub fn validate_unit_name(name: &str) -> Result<(), SystemdError> {
    let reject = |reason: &'static str| {
        Err(SystemdError::InvalidUnitName { name: name.to_owned(), reason })
    };

    if name.is_empty() {
        return reject("a unit name cannot be empty");
    }
    if name.len() > MAX_UNIT_NAME_LEN {
        return reject("a unit name cannot be longer than 255 characters");
    }
    if name.starts_with('-') {
        // Would be parsed as an option by `systemctl`. See the module docs.
        return reject("a unit name cannot begin with `-`");
    }

    for c in name.chars() {
        if c == '\0' {
            return reject("a unit name cannot contain a NUL byte");
        }
        if c.is_whitespace() {
            return reject("a unit name cannot contain whitespace");
        }
        if c == '/' {
            return reject("a unit name cannot contain `/`");
        }
        let ok = c.is_ascii_alphanumeric()
            || matches!(c, ':' | '_' | '.' | '-' | '@' | '\\');
        if !ok {
            return reject(
                "a unit name may only contain letters, digits and `: _ . - @ \\`",
            );
        }
    }

    let Some(suffix) = unit_suffix(name) else {
        return reject("a unit name must end in a known unit type, such as `.service`");
    };

    let stem = &name[..name.len() - suffix.len()];
    if stem.is_empty() {
        return reject("a unit name must have something before its type suffix");
    }
    if stem.chars().all(|c| c == '.') {
        return reject("a unit name cannot consist only of dots");
    }

    Ok(())
}

/// Should this unit appear in the product's "Services" list?
///
/// `ListUnits` on a stock Ubuntu box returns roughly 400 units, of which maybe
/// 30 are things a person installed and thinks of as a service. The rest are
/// systemd's own bookkeeping. Showing all 400 is the "wall of numbers" failure
/// mode the product brief warns about, so the default list is filtered and
/// [`crate::ServiceManager::list_units_of_type`] is the escape hatch for
/// callers that want timers or sockets later.
///
/// The rules, and why each one earns its place:
///
///  1. **`.service` only.** `.scope`, `.slice`, `.mount`, `.device`, `.target`,
///     `.socket`, `.timer`, `.path`, `.swap` and `.automount` are all real
///     units, but none of them is what a person means by "a service".
///  2. **No template unit files** (`getty@.service`). These are patterns, not
///     runnable units; starting one is an error.
///  3. **No `systemd-*` template instances** (`systemd-fsck@dev-sda1.service`,
///     `systemd-backlight@backlight:acpi_video0.service`). One per block device
///     or per display, churning on every hotplug event.
///  4. **No per-login units** (`user@1000.service`, `user-runtime-dir@1000.service`,
///     `session-3.scope`). These appear and vanish as people log in.
///
/// Named systemd services that are *not* templates — `systemd-resolved.service`,
/// `systemd-journald.service` — deliberately stay visible: restarting resolved
/// is a genuine thing an administrator does.
pub fn is_interesting_service(name: &str) -> bool {
    if name.is_empty() || name.contains('/') {
        return false;
    }
    if !name.ends_with(".service") {
        return false;
    }
    // Rule 2: a template unit file has an empty instance part.
    if name.ends_with("@.service") {
        return false;
    }
    let stem = &name[..name.len() - ".service".len()];
    if stem.is_empty() {
        return false;
    }
    // Rule 3.
    if stem.starts_with("systemd-") && stem.contains('@') {
        return false;
    }
    // Rule 4.
    if stem == "user" || stem.starts_with("user@") || stem.starts_with("user-runtime-dir@") {
        return false;
    }
    if stem.starts_with("session-") {
        return false;
    }
    true
}
