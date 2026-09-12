//! Turning numeric uids and gids into the names a human recognises.
//!
//! A file listing that says `1000` instead of `deploy` is a listing the user
//! has to decode. `getpwuid(3)` would do this properly, including LDAP and
//! SSSD, but it is libc, therefore `unsafe`, therefore out of scope; and this
//! crate deliberately does not depend on `serveros-linux` either, so that file
//! management stays standalone and testable on its own. So: `/etc/passwd` and
//! `/etc/group`, parsed here, cached here.
//!
//! The cache has a short TTL rather than being computed once. A listing is
//! taken right after the operator adds a user through the same app, and a name
//! that stays stale until the agent restarts looks like a bug. Thirty seconds
//! is short enough that nobody notices and long enough that listing a directory
//! of 1 000 files re-reads nothing.
//!
//! Unresolvable ids fall back to their number as a string — never to "unknown",
//! which would hide the one piece of information we do have.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// How long a parsed `/etc/passwd` or `/etc/group` is trusted.
const TTL: Duration = Duration::from_secs(30);

struct Maps {
    users: BTreeMap<u32, String>,
    groups: BTreeMap<u32, String>,
    loaded_at: Instant,
}

fn cache() -> &'static Mutex<Option<Maps>> {
    static CACHE: OnceLock<Mutex<Option<Maps>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

fn with_maps<R>(f: impl FnOnce(&Maps) -> R) -> R {
    // A poisoned mutex here means another thread panicked mid-parse. The data
    // is a name cache; recovering it is strictly better than propagating the
    // panic into a file listing.
    let mut guard = match cache().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let stale = guard.as_ref().is_none_or(|m| m.loaded_at.elapsed() > TTL);
    if stale {
        *guard = Some(Maps {
            users: parse_passwd(&read("/etc/passwd")),
            groups: parse_group(&read("/etc/group")),
            loaded_at: Instant::now(),
        });
    }
    f(guard.as_ref().expect("just populated"))
}

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Drop the cached maps. Only useful in tests and after the agent itself
/// creates a user.
pub fn invalidate() {
    if let Ok(mut g) = cache().lock() {
        *g = None;
    }
}

/// Name for a uid, falling back to the number.
pub fn owner_name(uid: u32) -> String {
    with_maps(|m| m.users.get(&uid).cloned()).unwrap_or_else(|| uid.to_string())
}

/// Name for a gid, falling back to the number.
pub fn group_name(gid: u32) -> String {
    with_maps(|m| m.groups.get(&gid).cloned()).unwrap_or_else(|| gid.to_string())
}

/// `name:x:uid:…` → `uid → name`. Malformed lines are skipped, not fatal:
/// `/etc/passwd` on a long-lived server accumulates oddities.
fn parse_passwd(text: &str) -> BTreeMap<u32, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut f = line.split(':');
        let (Some(name), Some(_), Some(uid)) = (f.next(), f.next(), f.next()) else { continue };
        if let Ok(uid) = uid.parse::<u32>() {
            out.entry(uid).or_insert_with(|| name.to_owned());
        }
    }
    out
}

/// `name:x:gid:members` → `gid → name`.
fn parse_group(text: &str) -> BTreeMap<u32, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let mut f = line.split(':');
        let (Some(name), Some(_), Some(gid)) = (f.next(), f.next(), f.next()) else { continue };
        if let Ok(gid) = gid.parse::<u32>() {
            out.entry(gid).or_insert_with(|| name.to_owned());
        }
    }
    out
}

/// The agent's effective uid.
///
/// Read from the ownership of `/proc/self`, which the kernel keeps equal to the
/// process's effective uid. That avoids `geteuid(2)` (libc) for a value we only
/// need in order to decide whether to show a padlock in the UI.
///
/// If `/proc` is unavailable the value is `u32::MAX`, a uid that matches no
/// file, so permission answers fall back to the "other" bits — pessimistic,
/// which is the right direction for a permission display.
pub fn euid() -> u32 {
    static EUID: OnceLock<u32> = OnceLock::new();
    *EUID.get_or_init(|| {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(u32::MAX)
    })
}

/// The agent's effective gid, from the same place.
pub fn egid() -> u32 {
    static EGID: OnceLock<u32> = OnceLock::new();
    *EGID.get_or_init(|| {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").map(|m| m.gid()).unwrap_or(u32::MAX)
    })
}

/// Every gid the agent has, primary and supplementary.
///
/// `/proc/self/status` carries the supplementary set on its `Groups:` line,
/// which is the only way to get it without `getgroups(2)`.
pub fn gids() -> &'static [u32] {
    static GIDS: OnceLock<Vec<u32>> = OnceLock::new();
    GIDS.get_or_init(|| {
        let mut out = vec![egid()];
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Groups:") {
                    for tok in rest.split_whitespace() {
                        if let Ok(g) = tok.parse::<u32>() {
                            if !out.contains(&g) {
                                out.push(g);
                            }
                        }
                    }
                }
            }
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_is_parsed() {
        let m = parse_passwd("root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/sh\n");
        assert_eq!(m.get(&0).unwrap(), "root");
        assert_eq!(m.get(&1000).unwrap(), "deploy");
    }

    #[test]
    fn malformed_passwd_lines_are_skipped_not_fatal() {
        let m = parse_passwd("garbage\n\nroot:x:0:0:::\nnouid:x:abc:0:::\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m.get(&0).unwrap(), "root");
    }

    #[test]
    fn group_is_parsed() {
        let m = parse_group("root:x:0:\ndocker:x:998:deploy,ci\n");
        assert_eq!(m.get(&998).unwrap(), "docker");
    }

    #[test]
    fn first_entry_for_a_uid_wins() {
        // Two names for uid 0 is legal and common (root / toor).
        let m = parse_passwd("root:x:0:0:::\ntoor:x:0:0:::\n");
        assert_eq!(m.get(&0).unwrap(), "root");
    }

    #[test]
    fn live_root_resolves_to_a_name() {
        assert_eq!(owner_name(0), "root");
        assert_eq!(group_name(0), "root");
    }

    #[test]
    fn an_unknown_id_falls_back_to_its_number() {
        assert_eq!(owner_name(4_294_967_290), "4294967290");
        assert_eq!(group_name(4_294_967_290), "4294967290");
    }

    #[test]
    fn euid_is_readable_on_this_host() {
        // Any real value is fine; u32::MAX would mean /proc is missing, which
        // would be a broken container rather than a broken crate.
        assert_ne!(euid(), u32::MAX, "/proc/self must be readable");
        assert!(gids().contains(&egid()));
    }

    #[test]
    fn invalidate_forces_a_reload() {
        let before = owner_name(0);
        invalidate();
        assert_eq!(owner_name(0), before);
    }
}
