//! Local accounts and groups, from the flat files that define them.
//!
//! `/etc/passwd`, `/etc/group` and `/etc/shadow` are the whole source of truth
//! here. That is a deliberate limit: NSS (LDAP, SSSD, `systemd-homed`) can
//! define users these files never mention, and enumerating those requires
//! `getpwent(3)` — libc, therefore `unsafe`, therefore out of scope for this
//! crate. The agent describes the accounts that live *on the server*, which is
//! what a server-management UI is actually about; a directory-backed estate is
//! managed from the directory.
//!
//! # The one rule that matters
//!
//! **No password hash ever leaves this module.** [`parse_shadow_status`]
//! returns two booleans per user and nothing else — the hash is examined in a
//! local `&str` and dropped. There is no field on [`LocalUser`] that could hold
//! it, so it cannot reach a struct, a log line, a JSON body or a crash dump
//! even by accident. That is a type-level guarantee, not a convention, and it
//! should stay that way.

use crate::error::LinuxError;
use crate::procfs;
use serveros_json::{Object, Value};

/// UIDs below this are the distribution's, not a person's. Debian, Ubuntu, RHEL
/// and SUSE all agree on 1000 as the first human account.
const FIRST_HUMAN_UID: u32 = 1000;

/// Shells that mean "this account cannot log in interactively".
const NOLOGIN_SHELLS: &[&str] =
    &["/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/bin/sync", ""];

/// Groups that grant administrative rights on the distributions we support:
/// Debian-family uses `sudo`, RHEL-family and Arch use `wheel`.
const ADMIN_GROUPS: &[&str] = &["sudo", "wheel"];

/// One row of `/etc/passwd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswdEntry {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    /// The raw GECOS field, commas and all.
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

/// A local group and the users that name it as a supplementary group.
///
/// Note that `members` holds only `/etc/group`'s member list. A user whose
/// *primary* gid is this group does not appear there — that is how the file
/// works, and [`list_users`] compensates when building each user's group list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalGroup {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

impl LocalGroup {
    /// `{"name":"docker","gid":998,"members":["deploy"]}`
    pub fn to_json(&self) -> Value {
        Object::new()
            .set("name", self.name.as_str())
            .set("gid", self.gid)
            .set("members", self.members.clone())
            .into()
    }
}

/// What `/etc/shadow` says about an account, with the hash discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowStatus {
    /// The hash field is prefixed with `!` or is `*`: no password login.
    pub locked: bool,
    /// A hash is actually set (possibly behind a lock prefix).
    pub has_password: bool,
}

/// A local account as the app renders it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalUser {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    /// First comma-separated part of GECOS; `None` when unset.
    pub full_name: Option<String>,
    pub home: String,
    pub shell: String,
    /// Primary group first, then supplementary groups in `/etc/group` order.
    pub groups: Vec<String>,
    pub is_system: bool,
    pub can_sudo: bool,
    /// `None` when `/etc/shadow` could not be read (we are not root).
    pub locked: Option<bool>,
    /// `None` when `/etc/shadow` could not be read.
    pub has_password: Option<bool>,
    /// `None` when the home directory or key file is unreadable.
    pub ssh_key_count: Option<u64>,
    /// Always `None` — see [`list_users`].
    pub last_login: Option<u64>,
}

impl LocalUser {
    /// Serialise in the exact shape the macOS app decodes.
    ///
    /// Unknown values are explicit `null`s rather than omitted keys: "we could
    /// not read `/etc/shadow`" is a state the UI renders ("run the agent as
    /// root to see lock status"), and an absent key would be indistinguishable
    /// from a missing field.
    pub fn to_json(&self) -> Value {
        Object::new()
            .set("username", self.username.as_str())
            .set("uid", self.uid)
            .set("gid", self.gid)
            .set("full_name", Value::from(self.full_name.clone()))
            .set("home", self.home.as_str())
            .set("shell", self.shell.as_str())
            .set("groups", self.groups.clone())
            .set("is_system", self.is_system)
            .set("can_sudo", self.can_sudo)
            .set("locked", Value::from(self.locked))
            .set("has_password", Value::from(self.has_password))
            .set("ssh_key_count", Value::from(self.ssh_key_count))
            .set("last_login", Value::from(self.last_login))
            .into()
    }
}

/// `[{...}, {...}]` for a list of users.
pub fn users_json(users: &[LocalUser]) -> Value {
    Value::Array(users.iter().map(LocalUser::to_json).collect())
}

/// `[{...}, {...}]` for a list of groups.
pub fn groups_json(groups: &[LocalGroup]) -> Value {
    Value::Array(groups.iter().map(LocalGroup::to_json).collect())
}

/// Read every local account.
///
/// `last_login` is always `None`. The data lives in `/var/log/wtmp` and
/// `/var/log/lastlog`, which are arrays of fixed-layout C structs whose field
/// widths differ by architecture and glibc version; decoding them by hand is a
/// reliable way to report a plausible wrong date. It belongs in a later
/// iteration backed by `utmpx` parsing or `lastlog2`'s SQLite database.
pub fn list_users() -> Result<Vec<LocalUser>, LinuxError> {
    let passwd = procfs::read_text("/etc/passwd")?;
    let group = procfs::read_text_opt("/etc/group").unwrap_or_default();
    // Unreadable unless we are root. That is normal, not an error.
    let shadow = procfs::read_text_opt("/etc/shadow").map(|t| parse_shadow_status(&t));

    let entries = parse_passwd(&passwd);
    let groups = parse_group(&group);
    let mut users = build_users(&entries, &groups, shadow.as_deref());

    for user in &mut users {
        user.ssh_key_count = read_authorized_key_count(&user.home);
    }
    Ok(users)
}

/// Read every local group.
pub fn list_groups() -> Result<Vec<LocalGroup>, LinuxError> {
    Ok(parse_group(&procfs::read_text("/etc/group")?))
}

/// Map a uid to a username.
///
/// Reads `/etc/passwd` on every call, which is right for the occasional lookup
/// and wrong in a loop — [`crate::processes::list_processes`] builds a map once
/// per walk instead of calling this a thousand times.
pub fn resolve_uid(uid: u32) -> Option<String> {
    let text = procfs::read_text_opt("/etc/passwd")?;
    parse_passwd(&text).into_iter().find(|e| e.uid == uid).map(|e| e.username)
}

/// uid -> username for every local account, for callers resolving many uids.
pub fn uid_name_map() -> Vec<(u32, String)> {
    procfs::read_text_opt("/etc/passwd")
        .map(|t| parse_passwd(&t).into_iter().map(|e| (e.uid, e.username)).collect())
        .unwrap_or_default()
}

// ---- parsers (pure, so they can be tested against fixtures) ---------------

/// Parse `/etc/passwd`: seven colon-separated fields per line.
///
/// Rows with too few fields, a non-numeric uid, or a leading `+`/`-` (the NIS
/// netgroup syntax, which is not an account) are skipped rather than guessed
/// at. A malformed line should cost one row, never the whole user list.
pub fn parse_passwd(text: &str) -> Vec<PasswdEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() || line.starts_with('#') || line.starts_with('+') || line.starts_with('-')
        {
            continue;
        }
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let (Some(uid), Some(gid)) = (procfs::parse_u64(f[2]), procfs::parse_u64(f[3])) else {
            continue;
        };
        if f[0].is_empty() {
            continue;
        }
        out.push(PasswdEntry {
            username: f[0].to_string(),
            uid: uid as u32,
            gid: gid as u32,
            gecos: f[4].to_string(),
            home: f[5].to_string(),
            shell: f[6].to_string(),
        });
    }
    out
}

/// Parse `/etc/group`: `name:password:gid:member,member,...`.
pub fn parse_group(text: &str) -> Vec<LocalGroup> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() || line.starts_with('#') || line.starts_with('+') {
            continue;
        }
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 3 || f[0].is_empty() {
            continue;
        }
        let Some(gid) = procfs::parse_u64(f[2]) else {
            continue;
        };
        let members = f
            .get(3)
            .map(|m| m.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect())
            .unwrap_or_default();
        out.push(LocalGroup { name: f[0].to_string(), gid: gid as u32, members });
    }
    out
}

/// Reduce `/etc/shadow` to `(username, lock/password state)`.
///
/// The hash is inspected inside this function and never returned. The rules are
/// those of `shadow(5)`:
///   * empty field — the account has no password at all;
///   * `*` or `!` alone — login disabled, no usable hash;
///   * `!`-prefixed hash — the account has a password but it is locked
///     (`passwd -l` prepends the bang and `passwd -u` removes it);
///   * anything else — a usable hash.
pub fn parse_shadow_status(text: &str) -> Vec<(String, ShadowStatus)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split(':');
        let (Some(user), Some(hash)) = (f.next(), f.next()) else {
            continue;
        };
        if user.is_empty() {
            continue;
        }
        let stripped = hash.trim_start_matches('!');
        let locked = hash.starts_with('!') || stripped == "*";
        let has_password = !stripped.is_empty() && stripped != "*";
        out.push((user.to_string(), ShadowStatus { locked, has_password }));
    }
    out
}

/// The display name from a GECOS field: everything before the first comma.
///
/// GECOS is `full name,room,work phone,home phone,other`. Only the first part
/// is a name, and an all-comma field (`,,,`) means no name was set.
pub fn full_name_from_gecos(gecos: &str) -> Option<String> {
    let name = gecos.split(',').next().unwrap_or("").trim();
    if name.is_empty() { None } else { Some(name.to_string()) }
}

/// Count usable keys in an `authorized_keys` file.
///
/// Blank lines and `#` comments do not authorise anyone. Every other line is
/// counted without being parsed: validating key formats here would mean
/// tracking every algorithm OpenSSH adds, and an unparseable line is still a
/// line the administrator should know about.
pub fn count_authorized_keys(text: &str) -> u64 {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .count() as u64
}

/// Combine the three files into the user list the app renders.
///
/// `shadow` is `None` when `/etc/shadow` was unreadable, which propagates to
/// `locked`/`has_password` as `None` rather than as a guess.
pub fn build_users(
    passwd: &[PasswdEntry],
    groups: &[LocalGroup],
    shadow: Option<&[(String, ShadowStatus)]>,
) -> Vec<LocalUser> {
    passwd
        .iter()
        .map(|e| {
            let primary = groups.iter().find(|g| g.gid == e.gid).map(|g| g.name.clone());
            let mut group_names: Vec<String> = Vec::new();
            if let Some(p) = primary {
                group_names.push(p);
            }
            for g in groups {
                if g.members.iter().any(|m| m == &e.username) && !group_names.contains(&g.name) {
                    group_names.push(g.name.clone());
                }
            }

            // Membership of `sudo`/`wheel` is the 99% case and the only one we
            // can answer from these files. Parsing `/etc/sudoers` (and its
            // `.d/` fragments, aliases, `NOPASSWD:` specs and host patterns) is
            // out of scope: a half-parse would report "cannot sudo" for a user
            // who can, which is the dangerous direction to be wrong in.
            let can_sudo = group_names.iter().any(|g| ADMIN_GROUPS.contains(&g.as_str()));

            let status = shadow.and_then(|s| s.iter().find(|(u, _)| u == &e.username)).map(|(_, s)| *s);

            LocalUser {
                username: e.username.clone(),
                uid: e.uid,
                gid: e.gid,
                full_name: full_name_from_gecos(&e.gecos),
                home: e.home.clone(),
                shell: e.shell.clone(),
                groups: group_names,
                is_system: is_system_account(e.uid, &e.shell),
                can_sudo,
                locked: status.map(|s| s.locked),
                has_password: status.map(|s| s.has_password),
                // Filled in by `list_users`, which has a filesystem to read.
                ssh_key_count: None,
                last_login: None,
            }
        })
        .collect()
}

/// Is this the distribution's account rather than a person's?
///
/// Two signals, either of which is enough: a reserved uid, or a shell that
/// cannot be logged into. The second catches accounts an administrator created
/// above 1000 for a service.
pub fn is_system_account(uid: u32, shell: &str) -> bool {
    uid < FIRST_HUMAN_UID || NOLOGIN_SHELLS.contains(&shell.trim())
}

/// Count the keys in `<home>/.ssh/authorized_keys`, or `None` if unreadable.
fn read_authorized_key_count(home: &str) -> Option<u64> {
    // Service accounts point at `/nonexistent`; do not even try.
    if home.is_empty() || home == "/nonexistent" {
        return None;
    }
    let path = format!("{}/.ssh/authorized_keys", home.trim_end_matches('/'));
    procfs::read_text_opt(&path).map(|t| count_authorized_keys(&t))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `/etc/passwd` rows from an Ubuntu 24.04 host.
    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
postgres:x:102:104:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
deploy:x:1001:1001:Deploy User,,,:/home/deploy:/bin/bash
";

    const GROUP: &str = "\
root:x:0:
adm:x:4:ubuntu
sudo:x:27:ubuntu,deploy
www-data:x:33:
ubuntu:x:1000:
deploy:x:1001:
docker:x:998:deploy
postgres:x:104:
";

    /// Shape-accurate `/etc/shadow`. The hashes are obvious fakes; the point is
    /// the prefix handling, and nothing here ever leaves the parser.
    const SHADOW: &str = "\
root:*:20553:0:99999:7:::
daemon:*:20553:0:99999:7:::
ubuntu:$6$abcdefgh$0123456789:20553:0:99999:7:::
deploy:$y$j9T$xxxxxx:20553:0:99999:7:::
locked:!$6$abcdefgh$0123456789:20553:0:99999:7:::
banged:!:20553:0:99999:7:::
nopass::20553:0:99999:7:::
doublebang:!!$6$zz$yy:20553:0:99999:7:::
";

    // ---- passwd ----------------------------------------------------------

    #[test]
    fn passwd_parses_every_field() {
        let e = parse_passwd(PASSWD);
        let deploy = e.iter().find(|u| u.username == "deploy").unwrap();
        assert_eq!(deploy.uid, 1001);
        assert_eq!(deploy.gid, 1001);
        assert_eq!(deploy.home, "/home/deploy");
        assert_eq!(deploy.shell, "/bin/bash");
        assert_eq!(deploy.gecos, "Deploy User,,,");
        assert_eq!(e.len(), 10);
    }

    #[test]
    fn passwd_skips_malformed_rows_without_losing_good_ones() {
        let text = "\
# a comment
root:x:0:0:root:/root:/bin/bash
truncated:x:1
bad-uid:x:notanumber:0:x:/x:/bin/sh
+@netgroup
-blocked
:x:5:5:no name:/x:/bin/sh
good:x:1001:1001::/home/good:/bin/bash
";
        let e = parse_passwd(text);
        let names: Vec<&str> = e.iter().map(|u| u.username.as_str()).collect();
        assert_eq!(names, vec!["root", "good"]);
    }

    #[test]
    fn passwd_on_empty_input() {
        assert!(parse_passwd("").is_empty());
        assert!(parse_passwd("\n\n\n").is_empty());
    }

    #[test]
    fn passwd_keeps_extra_trailing_fields() {
        // Some systems append fields; the first seven are what matters.
        let e = parse_passwd("x:x:1:1:g:/h:/bin/sh:extra\n");
        assert_eq!(e[0].shell, "/bin/sh");
    }

    // ---- group -----------------------------------------------------------

    #[test]
    fn group_parses_members() {
        let g = parse_group(GROUP);
        let sudo = g.iter().find(|g| g.name == "sudo").unwrap();
        assert_eq!(sudo.gid, 27);
        assert_eq!(sudo.members, vec!["ubuntu", "deploy"]);
        let root = g.iter().find(|g| g.name == "root").unwrap();
        assert!(root.members.is_empty(), "empty member list is empty, not [\"\"]");
    }

    #[test]
    fn group_skips_malformed_rows() {
        let g = parse_group("ok:x:1:a\nbroken\nbad:x:notanumber:\n:x:9:\n");
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].name, "ok");
    }

    // ---- shadow ----------------------------------------------------------

    #[test]
    fn shadow_status_classifies_every_prefix() {
        let s = parse_shadow_status(SHADOW);
        let get = |name: &str| s.iter().find(|(u, _)| u == name).map(|(_, st)| *st).unwrap();

        assert_eq!(get("ubuntu"), ShadowStatus { locked: false, has_password: true });
        // `*` means "no password login", which the UI shows as locked.
        assert_eq!(get("root"), ShadowStatus { locked: true, has_password: false });
        // A real hash behind a bang: password exists, login disabled.
        assert_eq!(get("locked"), ShadowStatus { locked: true, has_password: true });
        assert_eq!(get("banged"), ShadowStatus { locked: true, has_password: false });
        assert_eq!(get("nopass"), ShadowStatus { locked: false, has_password: false });
        // `!!` is Red Hat's "never set", still locked.
        assert_eq!(get("doublebang"), ShadowStatus { locked: true, has_password: true });
    }

    #[test]
    fn shadow_status_returns_no_hash_material_at_all() {
        // The type cannot hold a hash; this asserts the *serialised* output of
        // a user built from it is clean, which is the property that matters.
        let users = build_users(
            &parse_passwd(PASSWD),
            &parse_group(GROUP),
            Some(&parse_shadow_status(SHADOW)),
        );
        let json = users_json(&users).to_string();
        for secret in ["$6$", "$y$", "abcdefgh", "0123456789", "j9T"] {
            assert!(!json.contains(secret), "hash material leaked into JSON: {secret}");
        }
    }

    #[test]
    fn shadow_status_skips_junk() {
        assert!(parse_shadow_status("").is_empty());
        assert!(parse_shadow_status("# comment\n").is_empty());
        assert!(parse_shadow_status("no-colon-line\n").is_empty());
        assert_eq!(parse_shadow_status(":x:1\n").len(), 0);
    }

    // ---- GECOS / keys / system detection ---------------------------------

    #[test]
    fn gecos_takes_the_first_comma_field() {
        assert_eq!(full_name_from_gecos("Deploy User,,,").as_deref(), Some("Deploy User"));
        assert_eq!(
            full_name_from_gecos("PostgreSQL administrator,,,").as_deref(),
            Some("PostgreSQL administrator")
        );
        assert_eq!(full_name_from_gecos(",,,"), None);
        assert_eq!(full_name_from_gecos(""), None);
        assert_eq!(full_name_from_gecos("   "), None);
        assert_eq!(full_name_from_gecos("Solo").as_deref(), Some("Solo"));
    }

    #[test]
    fn authorized_keys_counts_only_real_entries() {
        let text = "\
# my laptop
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 alice@laptop

ssh-rsa AAAAB3NzaC1yc2EAAAA bob@desktop

# ssh-ed25519 commented-out-key
";
        assert_eq!(count_authorized_keys(text), 2);
        assert_eq!(count_authorized_keys(""), 0);
        assert_eq!(count_authorized_keys("\n\n#only a comment\n"), 0);
    }

    #[test]
    fn system_accounts_are_detected_by_uid_or_shell() {
        assert!(is_system_account(0, "/bin/bash"));
        assert!(is_system_account(999, "/bin/bash"));
        assert!(is_system_account(33, "/usr/sbin/nologin"));
        // Created above 1000 but deliberately not loginable.
        assert!(is_system_account(1500, "/usr/sbin/nologin"));
        assert!(is_system_account(1500, "/bin/false"));
        assert!(is_system_account(1500, ""));
        assert!(!is_system_account(1000, "/bin/bash"));
        assert!(!is_system_account(1001, "/bin/zsh"));
    }

    // ---- assembly --------------------------------------------------------

    fn built() -> Vec<LocalUser> {
        build_users(&parse_passwd(PASSWD), &parse_group(GROUP), Some(&parse_shadow_status(SHADOW)))
    }

    #[test]
    fn user_groups_list_primary_first_then_supplementary() {
        let users = built();
        let deploy = users.iter().find(|u| u.username == "deploy").unwrap();
        assert_eq!(deploy.groups, vec!["deploy", "sudo", "docker"]);
    }

    #[test]
    fn sudo_membership_is_detected_from_either_admin_group() {
        let users = built();
        assert!(users.iter().find(|u| u.username == "deploy").unwrap().can_sudo);
        assert!(users.iter().find(|u| u.username == "ubuntu").unwrap().can_sudo);
        assert!(!users.iter().find(|u| u.username == "www-data").unwrap().can_sudo);

        // RHEL-family uses `wheel` instead of `sudo`.
        let wheel = build_users(
            &parse_passwd("admin:x:1000:1000::/home/admin:/bin/bash\n"),
            &parse_group("wheel:x:10:admin\n"),
            None,
        );
        assert!(wheel[0].can_sudo);
    }

    #[test]
    fn a_user_whose_primary_group_is_missing_still_lists_the_rest() {
        let users = build_users(
            &parse_passwd("x:x:1000:4242::/home/x:/bin/bash\n"),
            &parse_group("docker:x:998:x\n"),
            None,
        );
        assert_eq!(users[0].groups, vec!["docker"]);
    }

    #[test]
    fn shadow_unavailable_yields_null_not_false() {
        let users = build_users(&parse_passwd(PASSWD), &parse_group(GROUP), None);
        let u = &users[0];
        assert_eq!(u.locked, None);
        assert_eq!(u.has_password, None);
        let json = u.to_json();
        assert!(json.get("locked").unwrap().is_null());
        assert!(json.get("has_password").unwrap().is_null());
    }

    #[test]
    fn user_json_has_the_documented_shape() {
        let users = built();
        let deploy = users.iter().find(|u| u.username == "deploy").unwrap();
        let v = deploy.to_json();
        assert_eq!(v.get("username").and_then(|v| v.as_str()), Some("deploy"));
        assert_eq!(v.get("uid").and_then(|v| v.as_u64()), Some(1001));
        assert_eq!(v.get("full_name").and_then(|v| v.as_str()), Some("Deploy User"));
        assert_eq!(v.get("home").and_then(|v| v.as_str()), Some("/home/deploy"));
        assert_eq!(v.get("is_system").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(v.get("can_sudo").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(v.get("locked").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(v.get("has_password").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(v.get("groups").and_then(|v| v.as_array()).map(|a| a.len()), Some(3));
        // Documented as always null until wtmp parsing exists.
        assert!(v.get("last_login").unwrap().is_null());
        assert!(v.get("ssh_key_count").unwrap().is_null());
    }

    #[test]
    fn json_helpers_emit_arrays() {
        assert!(users_json(&built()).as_array().is_some());
        assert_eq!(users_json(&built()).as_array().unwrap().len(), 10);
        let groups = parse_group(GROUP);
        let v = groups_json(&groups);
        assert_eq!(v.as_array().unwrap().len(), 8);
        assert_eq!(v.as_array().unwrap()[2].get("name").and_then(|v| v.as_str()), Some("sudo"));
    }

    #[test]
    fn nonexistent_homes_are_not_probed() {
        assert_eq!(read_authorized_key_count("/nonexistent"), None);
        assert_eq!(read_authorized_key_count(""), None);
    }
}
