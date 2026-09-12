//! Local accounts, groups and SSH authorised keys.
//!
//! # Reading is parsing, writing is `useradd`
//!
//! Reading accounts means parsing `/etc/passwd`, `/etc/group` and (when we are
//! root) `/etc/shadow` — `serveros-linux` does that with no process spawned and
//! no `unsafe`.
//!
//! Writing them is different. Creating a Linux user is not one file edit: it
//! allocates a uid, creates a primary group, writes four files that must stay
//! consistent, copies `/etc/skel`, creates and chowns a home directory, and
//! takes the `/etc/passwd` lock while doing it. Re-implementing that is how you
//! corrupt an account database. `useradd` and its siblings are the interface
//! the distribution actually supports, so that is what we drive — with every
//! rule that keeps it closer to an API call than to a command line:
//!
//!   * **argv, never a shell**, and never `$PATH` — absolute allow-listed paths
//!     (see [`crate::api::find_binary`]).
//!   * **Every input validated here first**, against the charset `useradd`
//!     itself accepts, before it can become an argument. A name that would need
//!     quoting is refused, not quoted.
//!   * **Passwords go in on stdin, never in argv.** `/proc/<pid>/cmdline` is
//!     world-readable: an argv password is visible to every user on the box for
//!     as long as the process lives. `chpasswd` exists precisely so it does not
//!     have to be.
//!   * **A missing binary is a capability, not a crash** — 503 with a sentence,
//!     because a minimal container genuinely has no `useradd`.
//!
//! # Refusals that are not configurable
//!
//! `root` and every account below uid 1000 are readable but not writable
//! through this API, and neither is the account the agent itself runs as. Those
//! are the accounts that own the system and the agent's own identity; a GUI
//! that can delete them is a GUI one mis-click away from an unrecoverable
//! server. The escape hatch for genuinely needing that is SSH, which is a
//! deliberate and appropriate amount of friction.

use crate::activity::Event;
use crate::api::{
    bad_request, collection, collection_with, find_binary, internal, json_body, not_found, record,
    required_str, unavailable,
};
use crate::auth::Principal;
use crate::state::AgentState;
use serveros_crypto::{b64_decode, b64_encode, sha256};
use serveros_http::{Request, Response, Status};
use serveros_json::{Object, Value};
use serveros_linux::LocalUser;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Below this, an account belongs to the distribution, not to a person.
///
/// Every mutating route in this module refuses to touch anything under it.
pub const MIN_MANAGED_UID: u32 = 1000;

/// Longest username `useradd` will accept on Linux.
const MAX_USERNAME_LEN: usize = 32;

/// Key types a caller may add.
///
/// Ed25519 first because it is what anyone should be using. `ssh-dss` is absent
/// on purpose: 1024-bit DSA has been disabled by default in OpenSSH for years,
/// and accepting it here would mean the agent is the reason a weak key works.
const ALLOWED_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
];

const USERADD: &[&str] = &["/usr/sbin/useradd", "/sbin/useradd", "/usr/bin/useradd"];
const USERMOD: &[&str] = &["/usr/sbin/usermod", "/sbin/usermod", "/usr/bin/usermod"];
const USERDEL: &[&str] = &["/usr/sbin/userdel", "/sbin/userdel", "/usr/bin/userdel"];
const CHPASSWD: &[&str] = &["/usr/sbin/chpasswd", "/sbin/chpasswd", "/usr/bin/chpasswd"];

/// The sentence every "we have no shadow-suite" answer uses.
const NO_TOOLS_REASON: &str =
    "the shadow-utils programs (useradd, usermod, userdel) are not installed on this host";

// ------------------------------------------------------------------ reading --

/// `GET /v1/users` — every local account.
///
/// `?include_system=false` hides accounts below uid 1000. They are included by
/// default: hiding rows by default makes a count in the UI disagree with the
/// same count taken over SSH, and that is the kind of small dishonesty that
/// costs trust in an infrastructure tool.
pub fn list(_state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let users = match serveros_linux::list_users() {
        Ok(users) => users,
        Err(e) => return internal("ServerOS couldn't read the accounts on this server.", e),
    };

    let include_system = match req.query_str("include_system") {
        Some(v) => !matches!(v.as_str(), "false" | "0"),
        None => true,
    };

    let people = users.iter().filter(|u| !u.is_system).count();
    let shown: Vec<&LocalUser> =
        users.iter().filter(|u| include_system || !u.is_system).collect();

    let items = shown.iter().map(|u| u.to_json()).collect::<Vec<Value>>();
    collection_with(
        items,
        Object::new().set("people", people).set("system", users.len() - people),
    )
}

/// `GET /v1/groups` — every local group.
pub fn groups(_state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    match serveros_linux::list_groups() {
        Ok(groups) => {
            let items = match serveros_linux::groups_json(&groups) {
                Value::Array(items) => items,
                _ => Vec::new(),
            };
            collection(items)
        }
        Err(e) => internal("ServerOS couldn't read the groups on this server.", e),
    }
}

/// `GET /v1/users/{name}` — one account.
pub fn get(_state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let name = req.param("name").unwrap_or_default().to_string();
    match lookup(&name) {
        Ok(Some(user)) => Response::json(user.to_json()),
        Ok(None) => not_found("user", &name),
        Err(response) => response,
    }
}

// ------------------------------------------------------------------ writing --

/// `POST /v1/users` — create a local account.
///
/// Body: `{"username", "full_name"?, "shell"?, "groups"?: [..],
/// "create_home"?: true, "password"?}`.
///
/// The password, if present, is set in a second step through `chpasswd`'s
/// stdin. It is never logged, never echoed back, and never reaches the audit
/// record — the record says *that* a password was set, not what it was.
pub fn create(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let body = match json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let username = match required_str(&body, "username") {
        Ok(name) => name,
        Err(response) => return response,
    };

    let (response, ok, summary) = create_inner(&body, &username);
    record(
        state,
        req,
        principal,
        // Whether a password was set belongs in the sentence, not in metadata:
        // any key containing "pass" is rewritten to "[redacted]" on the way to
        // the log, which would turn a useful boolean into noise.
        Event::new("user.create", "user", &username).summary(summary).outcome(ok),
    );
    response
}

fn create_inner(body: &Value, username: &str) -> (Response, bool, String) {
    if let Err(reason) = validate_username(username) {
        return (bad_request(reason), false, format!("Refused to create user {username}"));
    }
    match lookup(username) {
        Ok(Some(_)) => {
            return (
                Response::error(
                    Status::CONFLICT,
                    "already_exists",
                    format!("There is already an account called \u{201c}{username}\u{201d} on this server."),
                ),
                false,
                format!("Refused to create user {username}: the name is taken"),
            );
        }
        Ok(None) => {}
        Err(response) => {
            return (response, false, format!("Refused to create user {username}"));
        }
    }

    let shell = match optional_shell(body) {
        Ok(shell) => shell,
        Err(response) => return (response, false, format!("Refused to create user {username}")),
    };
    let full_name = match optional_full_name(body) {
        Ok(name) => name,
        Err(response) => return (response, false, format!("Refused to create user {username}")),
    };
    let groups = match optional_groups(body) {
        Ok(groups) => groups,
        Err(response) => return (response, false, format!("Refused to create user {username}")),
    };
    let password = body.get("password").and_then(Value::as_str).map(str::to_string);
    if let Some(p) = &password {
        if let Err(reason) = validate_password(p) {
            return (bad_request(reason), false, format!("Refused to create user {username}"));
        }
    }

    let Some(useradd) = find_binary(USERADD) else {
        return (
            unavailable("User management", NO_TOOLS_REASON),
            false,
            format!("Could not create user {username}: no account tools on this server"),
        );
    };

    let mut args: Vec<String> = Vec::new();
    // Default to creating a home directory: an account without one cannot hold
    // an authorised key, which is the reason most of these accounts exist.
    if body.get("create_home").and_then(Value::as_bool).unwrap_or(true) {
        args.push("-m".into());
    } else {
        args.push("-M".into());
    }
    if let Some(shell) = &shell {
        args.push("-s".into());
        args.push(shell.clone());
    }
    if let Some(full_name) = &full_name {
        args.push("-c".into());
        args.push(full_name.clone());
    }
    if !groups.is_empty() {
        args.push("-G".into());
        args.push(groups.join(","));
    }
    args.push(username.to_string());

    if let Err((response, detail)) = run(useradd, &args, "create that account") {
        return (
            response,
            false,
            format!("Failed to create user {username}: {detail}"),
        );
    }

    // The account exists now. A password failure past this point is reported,
    // but the account is not rolled back: deleting a just-created account
    // because its password did not take would be a worse surprise than an
    // account that needs its password set again.
    if let Some(password) = &password {
        if let Err((response, detail)) = set_password(username, password) {
            return (
                response,
                false,
                format!("Created user {username} but could not set its password: {detail}"),
            );
        }
    }

    let created = match lookup(username) {
        Ok(Some(user)) => user.to_json(),
        _ => Object::new().set("username", username).into(),
    };
    let summary = if password.is_some() {
        format!("Created user {username} with a password")
    } else {
        format!("Created user {username}")
    };
    (Response::json_status(Status::CREATED, created), true, summary)
}

/// `PATCH /v1/users/{name}` — change an existing account.
///
/// Body: any of `{"full_name", "shell", "groups": [..], "locked": bool,
/// "password"}`. Absent fields are left alone.
pub fn update(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let username = req.param("name").unwrap_or_default().to_string();
    let body = match json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };

    let (response, ok, summary) = update_inner(&body, &username);
    record(
        state,
        req,
        principal,
        Event::new("user.update", "user", &username).summary(summary).outcome(ok),
    );
    response
}

fn update_inner(body: &Value, username: &str) -> (Response, bool, String) {
    let user = match require_managed(username, "change") {
        Ok(user) => user,
        Err(response) => return (response, false, format!("Refused to change user {username}")),
    };

    let shell = match optional_shell(body) {
        Ok(shell) => shell,
        Err(response) => return (response, false, format!("Refused to change user {username}")),
    };
    let full_name = match optional_full_name(body) {
        Ok(name) => name,
        Err(response) => return (response, false, format!("Refused to change user {username}")),
    };
    let groups = match optional_groups(body) {
        Ok(groups) => groups,
        Err(response) => return (response, false, format!("Refused to change user {username}")),
    };
    let locked = body.get("locked").and_then(Value::as_bool);
    let password = body.get("password").and_then(Value::as_str).map(str::to_string);
    if let Some(p) = &password {
        if let Err(reason) = validate_password(p) {
            return (bad_request(reason), false, format!("Refused to change user {username}"));
        }
    }

    let mut args: Vec<String> = Vec::new();
    let mut changed: Vec<&str> = Vec::new();
    if let Some(shell) = &shell {
        args.push("-s".into());
        args.push(shell.clone());
        changed.push("shell");
    }
    if let Some(full_name) = &full_name {
        args.push("-c".into());
        args.push(full_name.clone());
        changed.push("full name");
    }
    if body.get("groups").is_some() {
        // `-G` with the full list replaces supplementary group membership. That
        // is the operation a checkbox list in the UI means; incremental add and
        // remove would need their own routes and their own audit records.
        args.push("-G".into());
        args.push(groups.join(","));
        changed.push("groups");
    }
    if let Some(locked) = locked {
        args.push(if locked { "-L".into() } else { "-U".into() });
        changed.push(if locked { "lock" } else { "unlock" });
    }

    if args.is_empty() && password.is_none() {
        return (
            bad_request(
                "Nothing to change. Send at least one of \"full_name\", \"shell\", \"groups\", \
                 \"locked\" or \"password\".",
            ),
            false,
            format!("Nothing to change on user {username}"),
        );
    }

    if !args.is_empty() {
        let Some(usermod) = find_binary(USERMOD) else {
            return (
                unavailable("User management", NO_TOOLS_REASON),
                false,
                format!("Could not change user {username}: no account tools on this server"),
            );
        };
        args.push(username.to_string());
        if let Err((response, detail)) = run(usermod, &args, "change that account") {
            return (response, false, format!("Failed to change user {username}: {detail}"));
        }
    }

    if let Some(password) = &password {
        if let Err((response, detail)) = set_password(username, password) {
            return (
                response,
                false,
                format!("Failed to set the password for {username}: {detail}"),
            );
        }
        changed.push("password");
    }

    let updated = lookup(username).ok().flatten().map(|u| u.to_json()).unwrap_or(user.to_json());
    (
        Response::json(updated),
        true,
        format!("Updated {} for {username}", changed.join(", ")),
    )
}

/// `DELETE /v1/users/{name}` — remove an account.
///
/// `?remove_home=true` also deletes the home directory and mail spool. It is
/// opt-in: the files are usually the only thing anyone actually wanted to keep.
pub fn delete(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let username = req.param("name").unwrap_or_default().to_string();
    let remove_home = req.query_flag("remove_home");

    let (response, ok, summary) = delete_inner(&username, remove_home);
    record(
        state,
        req,
        principal,
        Event::new("user.delete", "user", &username)
            .summary(summary)
            .meta("remove_home", remove_home)
            .outcome(ok),
    );
    response
}

fn delete_inner(username: &str, remove_home: bool) -> (Response, bool, String) {
    if let Err(response) = require_managed(username, "delete") {
        return (response, false, format!("Refused to delete user {username}"));
    }
    if Some(username) == agent_username().as_deref() {
        return (
            refused(format!(
                "ServerOS will not delete \u{201c}{username}\u{201d}. That is the account this \
                 agent runs as, and removing it would leave this server unmanageable."
            )),
            false,
            format!("Refused to delete the agent's own account {username}"),
        );
    }

    let Some(userdel) = find_binary(USERDEL) else {
        return (
            unavailable("User management", NO_TOOLS_REASON),
            false,
            format!("Could not delete user {username}: no account tools on this server"),
        );
    };

    let mut args: Vec<String> = Vec::new();
    if remove_home {
        args.push("-r".into());
    }
    args.push(username.to_string());

    match run(userdel, &args, "delete that account") {
        Ok(()) => (
            Response::json(
                Object::new()
                    .set("username", username)
                    .set("deleted", true)
                    .set("home_removed", remove_home),
            ),
            true,
            format!("Deleted user {username}"),
        ),
        Err((response, detail)) => {
            (response, false, format!("Failed to delete user {username}: {detail}"))
        }
    }
}

// ------------------------------------------------------------- ssh keys ------

/// `GET /v1/users/{name}/keys` — the account's authorised SSH keys.
///
/// Only the key type, comment and SHA-256 fingerprint are returned. The key
/// material itself is public by nature, but the fingerprint is what anyone
/// actually compares against (`ssh-keygen -lf`), and a list of full keys is a
/// screen nobody can read.
pub fn list_keys(_state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let username = req.param("name").unwrap_or_default().to_string();
    let user = match lookup(&username) {
        Ok(Some(user)) => user,
        Ok(None) => return not_found("user", &username),
        Err(response) => return response,
    };

    let path = authorized_keys_path(&user);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        // No file is not an error: it is an account with no keys yet, which is
        // an empty state the app already knows how to draw.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return internal(
                format!("ServerOS couldn't read the authorised keys for {username}."),
                e,
            );
        }
    };

    let items: Vec<Value> = parse_authorized_keys(&text).iter().map(SshKey::to_json).collect();
    collection_with(items, Object::new().set("path", path.display().to_string()))
}

/// `POST /v1/users/{name}/keys` — add one authorised key.
///
/// Body: `{"key": "ssh-ed25519 AAAA… laptop"}`.
pub fn add_key(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let username = req.param("name").unwrap_or_default().to_string();
    let body = match json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let key = match required_str(&body, "key") {
        Ok(key) => key,
        Err(response) => return response,
    };

    let (response, ok, summary, fingerprint) = add_key_inner(&username, &key);
    record(
        state,
        req,
        principal,
        Event::new("user.key.add", "user", &username)
            .summary(summary)
            .meta("fingerprint", fingerprint)
            .outcome(ok),
    );
    response
}

fn add_key_inner(username: &str, raw: &str) -> (Response, bool, String, String) {
    let user = match require_managed(username, "add an SSH key to") {
        Ok(user) => user,
        Err(response) => {
            return (response, false, format!("Refused to add an SSH key to {username}"), String::new());
        }
    };

    let key = match parse_one_key(raw) {
        Ok(key) => key,
        Err(reason) => {
            return (
                bad_request(reason),
                false,
                format!("Rejected a malformed SSH key for {username}"),
                String::new(),
            );
        }
    };
    let fingerprint = key.fingerprint.clone();

    let existing_path = authorized_keys_path(&user);
    let existing = std::fs::read_to_string(&existing_path).unwrap_or_default();
    if parse_authorized_keys(&existing).iter().any(|k| k.fingerprint == key.fingerprint) {
        return (
            Response::error(
                Status::CONFLICT,
                "already_exists",
                format!("{username} already has that key."),
            ),
            false,
            format!("That SSH key is already authorised for {username}"),
            fingerprint,
        );
    }

    if let Err(response) = ensure_ssh_dir(&user) {
        return (
            response,
            false,
            format!("Could not add an SSH key for {username}"),
            fingerprint,
        );
    }

    // Rewrite the whole file rather than appending blind: it guarantees the new
    // key starts on its own line even when the existing file has no trailing
    // newline, which is the usual way a hand-edited authorized_keys ends.
    let mut contents = existing;
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(&key.line);
    contents.push('\n');

    if let Err(e) = write_owned(&existing_path, contents.as_bytes(), 0o600, user.uid, user.gid) {
        return (
            internal(format!("ServerOS couldn't add that key for {username}."), e),
            false,
            format!("Could not add an SSH key for {username}"),
            fingerprint,
        );
    }

    (
        Response::json_status(Status::CREATED, key.to_json()),
        true,
        format!("Added an SSH key for {username}"),
        fingerprint,
    )
}

/// `DELETE /v1/users/{name}/keys/{fingerprint}` — remove one authorised key.
///
/// Matched on the SHA-256 fingerprint rather than on the key text, because the
/// key text is 400 characters that cannot survive a URL, and because two
/// records of the same key can differ in their comment while being the same
/// key. The `SHA256:` prefix is optional in the path.
pub fn remove_key(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let username = req.param("name").unwrap_or_default().to_string();
    let fingerprint = req.param("fingerprint").unwrap_or_default().to_string();

    let (response, ok, summary) = remove_key_inner(&username, &fingerprint);
    record(
        state,
        req,
        principal,
        Event::new("user.key.remove", "user", &username)
            .summary(summary)
            .meta("fingerprint", fingerprint.as_str())
            .outcome(ok),
    );
    response
}

fn remove_key_inner(username: &str, fingerprint: &str) -> (Response, bool, String) {
    let user = match require_managed(username, "remove an SSH key from") {
        Ok(user) => user,
        Err(response) => {
            return (response, false, format!("Refused to remove an SSH key from {username}"));
        }
    };

    let wanted = normalise_fingerprint(fingerprint);
    let path = authorized_keys_path(&user);
    let contents = std::fs::read_to_string(&path).unwrap_or_default();
    let keys = parse_authorized_keys(&contents);
    if !keys.iter().any(|k| k.fingerprint == wanted) {
        return (
            not_found("authorised key", fingerprint),
            false,
            format!("No such SSH key on {username}"),
        );
    }

    let kept: Vec<String> = contents
        .lines()
        .filter(|line| match parse_one_key(line) {
            Ok(key) => key.fingerprint != wanted,
            // Comments, blank lines and anything unparseable are preserved
            // verbatim: this API removes one key, it does not tidy the file.
            Err(_) => true,
        })
        .map(str::to_string)
        .collect();

    let mut rewritten = kept.join("\n");
    if !rewritten.is_empty() {
        rewritten.push('\n');
    }
    if let Err(e) = write_owned(&path, rewritten.as_bytes(), 0o600, user.uid, user.gid) {
        return (
            internal(format!("ServerOS couldn't remove that key from {username}."), e),
            false,
            format!("Could not remove an SSH key from {username}"),
        );
    }

    (
        Response::json(Object::new().set("fingerprint", wanted).set("removed", true)),
        true,
        format!("Removed an SSH key from {username}"),
    )
}

// ------------------------------------------------------------- validation ----

/// `^[a-z_][a-z0-9_-]{0,31}$`, spelled out rather than regexed.
///
/// This is `useradd`'s own `NAME_REGEX`, minus the trailing `$` form that
/// permits a leading digit. Enforcing it here means no username can ever be a
/// string that needs escaping to be safe as an argument.
pub fn validate_username(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("A username is required.".into());
    }
    if name.len() > MAX_USERNAME_LEN {
        return Err(format!("A username can be at most {MAX_USERNAME_LEN} characters."));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap_or(' ');
    if !(first.is_ascii_lowercase() || first == '_') {
        return Err(
            "A username has to start with a lower-case letter or an underscore.".into()
        );
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-') {
        return Err(
            "A username can only contain lower-case letters, digits, underscores and hyphens."
                .into(),
        );
    }
    if name == "root" {
        return Err("\u{201c}root\u{201d} is this server's administrator account and cannot be created here.".into());
    }
    Ok(())
}

/// A password that would break the `chpasswd` line format, or that is empty.
///
/// `chpasswd` reads `user:password` lines, so a colon-free, newline-free value
/// is not a style preference — a newline would let one field become two
/// records, which is exactly the injection this check exists to stop.
fn validate_password(password: &str) -> Result<(), String> {
    if password.is_empty() {
        return Err("A password cannot be empty.".into());
    }
    if password.contains('\n') || password.contains('\r') || password.contains('\0') {
        return Err("A password cannot contain line breaks.".into());
    }
    if password.len() > 512 {
        return Err("That password is too long.".into());
    }
    Ok(())
}

fn optional_shell(body: &Value) -> Result<Option<String>, Response> {
    let Some(shell) = body.get("shell").and_then(Value::as_str) else {
        return Ok(None);
    };
    let shell = shell.trim();
    if !shell.starts_with('/') || shell.contains(char::is_whitespace) || shell.contains(':') {
        return Err(bad_request("A login shell has to be an absolute path, such as /bin/bash."));
    }
    if !Path::new(shell).exists() {
        return Err(bad_request(format!("There is no {shell} on this server.")));
    }
    Ok(Some(shell.to_string()))
}

fn optional_full_name(body: &Value) -> Result<Option<String>, Response> {
    let Some(name) = body.get("full_name").and_then(Value::as_str) else {
        return Ok(None);
    };
    // GECOS is a colon-delimited field inside a colon-delimited file. A colon
    // or a newline here would corrupt /etc/passwd rather than merely look odd.
    if name.contains(':') || name.contains('\n') || name.contains('\r') {
        return Err(bad_request("A full name cannot contain a colon or a line break."));
    }
    if name.chars().count() > 128 {
        return Err(bad_request("That full name is too long."));
    }
    Ok(Some(name.trim().to_string()))
}

fn optional_groups(body: &Value) -> Result<Vec<String>, Response> {
    let Some(items) = body.get("groups").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let known = serveros_linux::list_groups().unwrap_or_default();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some(name) = item.as_str() else {
            return Err(bad_request("\"groups\" must be a list of group names."));
        };
        // Group names obey the same charset as usernames, so validating them
        // the same way keeps both out of argv-escaping territory.
        if validate_username(name).is_err() {
            return Err(bad_request(format!("\u{201c}{name}\u{201d} is not a valid group name.")));
        }
        if !known.iter().any(|g| g.name == name) {
            return Err(bad_request(format!(
                "There is no group called \u{201c}{name}\u{201d} on this server."
            )));
        }
        out.push(name.to_string());
    }
    Ok(out)
}

// ---------------------------------------------------------------- plumbing ---

/// Look one account up by name.
fn lookup(name: &str) -> Result<Option<LocalUser>, Response> {
    match serveros_linux::list_users() {
        Ok(users) => Ok(users.into_iter().find(|u| u.username == name)),
        Err(e) => Err(internal("ServerOS couldn't read the accounts on this server.", e)),
    }
}

/// The account must exist and must be one this API is allowed to change.
fn require_managed(name: &str, verb: &str) -> Result<LocalUser, Response> {
    let user = match lookup(name)? {
        Some(user) => user,
        None => return Err(not_found("user", name)),
    };
    if name == "root" || user.uid < MIN_MANAGED_UID {
        return Err(refused(format!(
            "ServerOS will not {verb} \u{201c}{name}\u{201d}. It is a system account (uid \
             {}), and those belong to the operating system rather than to a person.",
            user.uid
        )));
    }
    Ok(user)
}

/// 403 for something we could do and will not.
fn refused(message: String) -> Response {
    Response::error(Status::FORBIDDEN, "refused_dangerous", message)
}

/// Run one shadow-suite program with an argv, mapping its failure to a
/// response a person can read.
///
/// `useradd` and friends document their exit codes; the ones worth
/// distinguishing are 1 (permission), 9 (name in use) and 6 (no such user).
fn run(binary: &str, args: &[String], verb: &str) -> Result<(), (Response, String)> {
    let output = match Command::new(binary).args(args).output() {
        Ok(output) => output,
        Err(e) => {
            let detail = e.to_string();
            return Err((
                internal(format!("ServerOS couldn't {verb} on this server."), e),
                detail,
            ));
        }
    };
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let code = output.status.code().unwrap_or(-1);
    let (status, message) = match code {
        1 => (
            Status::FORBIDDEN,
            format!(
                "ServerOS isn't allowed to {verb} on this server. The agent has to run as root \
                 to manage accounts."
            ),
        ),
        6 => (Status::NOT_FOUND, "That account no longer exists on this server.".to_string()),
        9 => (
            Status::CONFLICT,
            "That name is already in use on this server.".to_string(),
        ),
        _ => (Status::INTERNAL, format!("ServerOS couldn't {verb} on this server.")),
    };
    let detail = if stderr.is_empty() {
        format!("{binary} exited with status {code}")
    } else {
        format!("{binary} exited with status {code}: {stderr}")
    };
    Err((Response::error_detail(status, "user_command_failed", message, detail.clone()), detail))
}

/// Set a password by feeding `chpasswd` one `user:password` line on **stdin**.
///
/// Never as an argument. `/proc/<pid>/cmdline` is world-readable on Linux, so
/// an argv password is readable by every local account for the lifetime of the
/// process — which is long enough. Nothing in this function logs, returns or
/// records the password.
fn set_password(username: &str, password: &str) -> Result<(), (Response, String)> {
    let Some(chpasswd) = find_binary(CHPASSWD) else {
        return Err((
            unavailable("Setting passwords", "the chpasswd program is not installed on this host"),
            "chpasswd is not installed".to_string(),
        ));
    };

    let child = Command::new(chpasswd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(child) => child,
        Err(e) => {
            let detail = e.to_string();
            return Err((internal("ServerOS couldn't set that password.", e), detail));
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        // Errors here are reported through the exit status below; writing the
        // line is the only place the password exists outside the request.
        let _ = stdin.write_all(format!("{username}:{password}\n").as_bytes());
        let _ = stdin.flush();
        // Dropping stdin closes the pipe, which is how chpasswd knows to stop
        // reading. Without this it waits for EOF forever and so do we.
        drop(stdin);
    }

    match child.wait_with_output() {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            // chpasswd echoes nothing sensitive, but be conservative: report
            // only its exit code, never its output.
            let detail = format!("chpasswd exited with status {}", output.status);
            Err((
                Response::error_detail(
                    Status::INTERNAL,
                    "password_failed",
                    "ServerOS couldn't set that password on this server.",
                    detail.clone(),
                ),
                detail,
            ))
        }
        Err(e) => {
            let detail = e.to_string();
            Err((internal("ServerOS couldn't set that password.", e), detail))
        }
    }
}

/// This agent's own account name, so it can refuse to delete itself.
///
/// `getuid(2)` needs libc; `/proc/self/status` does not, and is the same
/// number. The first field of the `Uid:` line is the real uid.
fn agent_username() -> Option<String> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    let uid: u32 = line.split_whitespace().nth(1)?.parse().ok()?;
    serveros_linux::resolve_uid(uid)
}

fn authorized_keys_path(user: &LocalUser) -> PathBuf {
    Path::new(&user.home).join(".ssh").join("authorized_keys")
}

/// Create `~/.ssh` with mode 0700 owned by the account, if it is missing.
///
/// `sshd` ignores an authorized_keys file whose directory is group- or
/// world-writable, or owned by someone else — silently. Getting the mode and
/// the owner right here is the difference between "key added" and "key added
/// and login still fails for no visible reason".
fn ensure_ssh_dir(user: &LocalUser) -> Result<(), Response> {
    let home = Path::new(&user.home);
    if !home.is_dir() {
        return Err(bad_request(format!(
            "{} has no home directory at {}, so it cannot hold an SSH key.",
            user.username, user.home
        )));
    }
    let dir = home.join(".ssh");
    if !dir.exists() {
        if let Err(e) = std::fs::create_dir(&dir) {
            return Err(internal(
                format!("ServerOS couldn't create {}.", dir.display()),
                e,
            ));
        }
    }
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)) {
        return Err(internal(format!("ServerOS couldn't secure {}.", dir.display()), e));
    }
    // `std::os::unix::fs::chown` exists precisely so this does not need libc.
    if let Err(e) = std::os::unix::fs::chown(&dir, Some(user.uid), Some(user.gid)) {
        return Err(internal(
            format!("ServerOS couldn't give {} to {}.", dir.display(), user.username),
            e,
        ));
    }
    Ok(())
}

/// Write a file, then fix its mode and owner.
///
/// Order matters: create, restrict, then hand over. A file that is briefly
/// world-readable is a file that was world-readable.
fn write_owned(
    path: &Path,
    contents: &[u8],
    mode: u32,
    uid: u32,
    gid: u32,
) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    file.write_all(contents)?;
    file.flush()?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
}

// ---------------------------------------------------------------- ssh keys ---

/// One line of an `authorized_keys` file that we could make sense of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKey {
    /// `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`, …
    pub key_type: String,
    /// Trailing free text, conventionally `user@host`.
    pub comment: Option<String>,
    /// `SHA256:<unpadded base64>` — what `ssh-keygen -lf` prints.
    pub fingerprint: String,
    /// Whether the line carried `command=`, `from=` or other options.
    pub has_options: bool,
    /// The line as it will be written, normalised to `type blob [comment]`.
    line: String,
}

impl SshKey {
    fn to_json(&self) -> Value {
        Object::new()
            .set("type", self.key_type.as_str())
            .set("comment", Value::from(self.comment.clone()))
            .set("fingerprint", self.fingerprint.as_str())
            .set("has_options", self.has_options)
            .into()
    }
}

/// Validate and parse exactly one key, as supplied by a caller.
///
/// Stricter than [`parse_authorized_keys`] on purpose. Two rules carry weight:
///
///   * **No embedded newline.** A field containing `\n` is how one "key" in the
///     request body becomes two authorised keys in the file, and the second one
///     is the one the caller did not show you.
///   * **The key type must come first.** An `authorized_keys` line may be
///     prefixed with options — `command="…"`, `environment="…"`, `from="…"` —
///     which change what the key can do. Accepting them through this route
///     would make "add a key" a way to install a forced command.
pub fn parse_one_key(raw: &str) -> Result<SshKey, String> {
    let line = raw.trim();
    if line.is_empty() {
        return Err("That key is empty.".into());
    }
    if raw.contains('\n') || raw.contains('\r') {
        return Err("An SSH key has to be a single line.".into());
    }

    let mut parts = line.split_whitespace();
    let key_type = parts.next().unwrap_or_default();
    if !ALLOWED_KEY_TYPES.contains(&key_type) {
        return Err(format!(
            "ServerOS accepts {} keys. \u{201c}{key_type}\u{201d} isn't one of them.",
            ALLOWED_KEY_TYPES.join(", ")
        ));
    }

    let blob = parts.next().unwrap_or_default();
    let comment: Vec<&str> = parts.collect();
    let Some(fingerprint) = fingerprint_of(key_type, blob) else {
        return Err("That doesn't look like an SSH public key — the key data is not valid.".into());
    };

    let comment = (!comment.is_empty()).then(|| comment.join(" "));
    Ok(SshKey {
        line: match &comment {
            Some(c) => format!("{key_type} {blob} {c}"),
            None => format!("{key_type} {blob}"),
        },
        key_type: key_type.to_string(),
        comment,
        fingerprint,
        has_options: false,
    })
}

/// Parse a whole `authorized_keys` file, tolerating what is really in one.
///
/// Unlike [`parse_one_key`] this accepts option prefixes, because they exist on
/// real servers and a key the user cannot see is a key the user cannot remove.
/// Such rows are flagged `has_options` so the UI can say so.
pub fn parse_authorized_keys(text: &str) -> Vec<SshKey> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(at) = tokens.iter().position(|t| ALLOWED_KEY_TYPES.contains(t)) else {
            continue;
        };
        let key_type = tokens[at];
        let Some(blob) = tokens.get(at + 1) else { continue };
        let Some(fingerprint) = fingerprint_of(key_type, blob) else { continue };
        let comment = tokens.get(at + 2..).filter(|c| !c.is_empty()).map(|c| c.join(" "));
        out.push(SshKey {
            line: line.to_string(),
            key_type: key_type.to_string(),
            comment,
            fingerprint,
            has_options: at > 0,
        });
    }
    out
}

/// `SHA256:<base64 of sha256(blob), unpadded>` — OpenSSH's own format.
///
/// The digest is over the raw key blob, and the base64 is printed without `=`
/// padding, which is exactly what `ssh-keygen -lf` shows. Matching it means a
/// fingerprint in our UI is a fingerprint the user can compare by eye.
fn fingerprint_of(key_type: &str, blob: &str) -> Option<String> {
    if blob.is_empty() {
        return None;
    }
    let decoded = b64_decode(blob)?;
    // The blob is an SSH wire string starting with its own type name; if that
    // does not match the declared type, the line is malformed or spliced.
    if !blob_declares(&decoded, key_type) {
        return None;
    }
    let digest = sha256(&decoded);
    Some(format!("SHA256:{}", b64_encode(&digest).trim_end_matches('=')))
}

/// The first field of an SSH key blob is a length-prefixed copy of its type.
fn blob_declares(decoded: &[u8], key_type: &str) -> bool {
    if decoded.len() < 4 {
        return false;
    }
    let len = u32::from_be_bytes([decoded[0], decoded[1], decoded[2], decoded[3]]) as usize;
    if len == 0 || len > 64 || decoded.len() < 4 + len {
        return false;
    }
    &decoded[4..4 + len] == key_type.as_bytes()
}

/// Accept a fingerprint with or without its `SHA256:` prefix.
fn normalise_fingerprint(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("SHA256:") {
        trimmed.to_string()
    } else {
        format!("SHA256:{trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real ed25519 public key, so the blob/type cross-check is exercised.
    const ED25519: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ1ZVQ5kJZ0y8qKQ4rH0m0mQ4Q1kzQ1e0rJQ9mYs0N1T abebe@mac";

    #[test]
    fn usernames_follow_useradds_own_rule() {
        for good in ["deploy", "_svc", "a", "web-01", "abebe_2"] {
            assert!(validate_username(good).is_ok(), "{good} should be valid");
        }
        for bad in [
            "",
            "Deploy",           // upper case
            "1web",             // leading digit
            "-web",             // leading hyphen
            "web user",         // space
            "web;rm -rf /",     // shell metacharacters
            "web\nroot",        // newline: two /etc/passwd records
            "root",
            "averyveryveryveryveryverylongusername12345",
        ] {
            assert!(validate_username(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn passwords_cannot_smuggle_a_second_chpasswd_record() {
        assert!(validate_password("hunter2").is_ok());
        assert!(validate_password("a:b").is_ok(), "a colon is only special in the username half");
        assert!(validate_password("").is_err());
        assert!(validate_password("hunter2\nroot:owned").is_err());
        assert!(validate_password("hunter2\rroot:owned").is_err());
    }

    #[test]
    fn a_good_key_parses_and_fingerprints() {
        let key = parse_one_key(ED25519).expect("valid ed25519 key");
        assert_eq!(key.key_type, "ssh-ed25519");
        assert_eq!(key.comment.as_deref(), Some("abebe@mac"));
        assert!(key.fingerprint.starts_with("SHA256:"));
        assert!(!key.fingerprint.ends_with('='), "OpenSSH prints unpadded base64");
        assert!(!key.has_options);
    }

    #[test]
    fn the_fingerprint_is_stable_and_comment_independent() {
        let with_comment = parse_one_key(ED25519).unwrap();
        let without = parse_one_key(&ED25519.replace(" abebe@mac", "")).unwrap();
        assert_eq!(with_comment.fingerprint, without.fingerprint);
    }

    #[test]
    fn a_newline_cannot_smuggle_a_second_key() {
        // The whole point of the check: one field, two authorised keys.
        let smuggled = format!("{ED25519}\n{ED25519}");
        assert!(parse_one_key(&smuggled).is_err());
    }

    #[test]
    fn option_prefixes_are_refused_on_add_but_survive_a_listing() {
        let with_options = format!("command=\"/bin/sh\",no-pty {ED25519}");
        assert!(
            parse_one_key(&with_options).is_err(),
            "adding a forced-command key through this API must be refused"
        );
        let listed = parse_authorized_keys(&with_options);
        assert_eq!(listed.len(), 1, "but it must still be visible and removable");
        assert!(listed[0].has_options);
    }

    #[test]
    fn weak_and_bogus_key_types_are_refused() {
        assert!(parse_one_key("ssh-dss AAAAB3NzaC1kc3M= old").is_err());
        assert!(parse_one_key("not-a-key AAAA").is_err());
        assert!(parse_one_key("ssh-ed25519 not-base64!!").is_err());
        // Right type name, wrong blob: the blob declares its own type.
        assert!(parse_one_key("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIJ1ZVQ5kJZ0y8qKQ4rH0m0mQ4Q1kzQ1e0rJQ9mYs0N1T").is_err());
    }

    #[test]
    fn a_file_with_comments_and_blanks_parses_cleanly() {
        let text = format!("# my keys\n\n{ED25519}\n\n# done\n");
        let keys = parse_authorized_keys(&text);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_type, "ssh-ed25519");
    }

    #[test]
    fn fingerprints_normalise_with_or_without_the_prefix() {
        assert_eq!(normalise_fingerprint("abc"), "SHA256:abc");
        assert_eq!(normalise_fingerprint("SHA256:abc"), "SHA256:abc");
        assert_eq!(normalise_fingerprint("  SHA256:abc  "), "SHA256:abc");
    }

    #[test]
    fn shells_have_to_be_absolute_paths_that_exist() {
        let ok = serveros_json::from_str(r#"{"shell":"/bin/sh"}"#).unwrap();
        assert!(optional_shell(&ok).unwrap().is_some());
        for bad in [r#"{"shell":"bash"}"#, r#"{"shell":"/bin/sh; rm -rf /"}"#, r#"{"shell":"/nope/nope"}"#] {
            let v = serveros_json::from_str(bad).unwrap();
            assert!(optional_shell(&v).is_err(), "{bad} should be rejected");
        }
        let absent = serveros_json::from_str("{}").unwrap();
        assert!(optional_shell(&absent).unwrap().is_none());
    }

    #[test]
    fn full_names_cannot_corrupt_etc_passwd() {
        let v = serveros_json::from_str(r#"{"full_name":"Abebe Bikila"}"#).unwrap();
        assert_eq!(optional_full_name(&v).unwrap().as_deref(), Some("Abebe Bikila"));
        for bad in [r#"{"full_name":"a:b"}"#, "{\"full_name\":\"a\\nroot::0:0\"}"] {
            let v = serveros_json::from_str(bad).unwrap();
            assert!(optional_full_name(&v).is_err(), "{bad} should be rejected");
        }
    }
}
