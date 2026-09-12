//! Path containment: the only thing standing between a caller-supplied string
//! and every byte on a customer's production server.
//!
//! # Why lexical checks are not enough
//!
//! The obvious implementation is to normalise the string (collapse `//`, fold
//! `.`, pop `..`) and then check that the result starts with an allowed root.
//! That implementation is wrong, and it is wrong in a way that looks right in
//! every test that does not create a symlink:
//!
//! ```text
//! ln -s /etc/shadow /srv/app/notes.txt
//! GET /files/read?path=/srv/app/notes.txt
//! ```
//!
//! `/srv/app/notes.txt` is lexically inside `/srv/app`. There is no `..` in it.
//! It passes every string check ever written, and `open(2)` hands back
//! `/etc/shadow`, because the kernel resolves symlinks and string matching does
//! not. The attacker does not even need write access to the agent's config —
//! any process that can create a file in a managed directory can plant the
//! link. On a server that runs a web app as `www-data` and is managed by
//! ServerOS as `root`, that is a privilege escalation.
//!
//! # The order that actually defends
//!
//! Every method here follows the same sequence, and the order is the whole
//! defence:
//!
//! 1. **Syntax.** Absolute, no NUL, within `PATH_MAX`, no `..` that escapes.
//!    Cheap, and it produces the clearest error messages.
//! 2. **Lexical deny check.** Purely so `/proc/1/environ` says "that path is
//!    off limits" instead of leaking whether it exists. Not a defence.
//! 3. **`canonicalize`.** `realpath(3)`: resolves every symlink, every `..`,
//!    every `.`, and fails if the path does not exist. The result is the file
//!    the kernel will actually open.
//! 4. **Containment and denial on the canonical path.** This is the defence. A
//!    symlink to `/etc/shadow` canonicalises *to* `/etc/shadow` and is denied
//!    on the way out.
//! 5. **Identity check.** Canonical paths still miss two tricks: a **hard link**
//!    to `/etc/shadow` has its own path, and a **bind mount** of `/proc` has its
//!    own path. Both share the `(st_dev, st_ino)` of the thing they alias, so
//!    the resolved path and its ancestors are compared against the device/inode
//!    identity of every denied entry.
//!
//! # The contract with callers
//!
//! `resolve` returns the `PathBuf` that was checked. **Callers must operate on
//! the returned path, never on the string they were given.** Re-deriving the
//! path from the original string throws away steps 3–5 and reintroduces a
//! time-of-check/time-of-use gap. Every function in this crate takes `&str`,
//! resolves once, and uses the result.
//!
//! A residual TOCTOU window remains — the kernel does not offer "open exactly
//! this inode" without `openat2(2)`, which needs libc — but it requires an
//! attacker to swap a component between our `canonicalize` and our `open`,
//! which is a far smaller target than a string comparison.

use crate::error::{FsError, show};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Longest path the agent will consider. `PATH_MAX` on Linux, which is also
/// the point past which every syscall would fail anyway.
pub const MAX_PATH_BYTES: usize = 4096;

/// Longest single component. `NAME_MAX` on every filesystem we support.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Paths the agent refuses to touch under **any** policy, root or not.
///
/// Three groups, for three different reasons:
///
/// * **Kernel interfaces** (`/proc`, `/sys`, `/dev`, `/run/udev`). These are not
///   files. Reading `/proc/kcore` means reading physical memory; writing
///   `/sys/power/state` suspends the machine; `/dev/sda` is the disk itself.
///   A file manager has no business here, and [`crate::listing`] would report
///   nonsense sizes for them anyway.
/// * **Credential stores** (`/etc/shadow`, `/etc/gshadow`, `/root/.ssh`,
///   `/etc/ssl/private`). Password hashes and private keys must not be
///   readable *through the agent* even when the agent runs as root — the
///   agent's job is to manage the server, not to exfiltrate its secrets.
/// * **The agent's own configuration** (`/etc/serveros`). This holds the
///   agent's enrolment key. If the file API could read it, a single directory
///   traversal would hand an attacker the agent's identity; if it could write
///   it, an attacker could re-point the agent at their own control plane.
///   Denying it makes the file API useless as a privilege-escalation path
///   *into the agent itself*.
///
/// `sudoers` is here because an editable `sudoers` is an editable root shell.
pub const ALWAYS_DENIED: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/run/udev",
    "/etc/serveros",
    "/etc/shadow",
    "/etc/shadow-",
    "/etc/gshadow",
    "/etc/gshadow-",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/root/.ssh",
    "/etc/ssl/private",
];

/// Directories whose contents are treated as key material, where a file with a
/// private-key-shaped name is denied even though the directory itself is not.
///
/// This is what makes `/home/deploy/.ssh/id_ed25519` unreadable while leaving
/// `/home/deploy/.ssh/authorized_keys` manageable — which is the operation a
/// server-management UI actually needs.
const SECRET_DIRS: &[&str] = &["/etc/ssl", "/etc/ssh", "/etc/pki"];

/// The set of roots the agent may touch, plus the paths it must never touch.
#[derive(Debug, Clone)]
pub struct PathPolicy {
    roots: Vec<PathBuf>,
    denied: Vec<PathBuf>,
    /// `(st_dev, st_ino)` of every denied entry that exists, so hard links and
    /// bind mounts cannot launder a denied file into an allowed path.
    denied_ids: Vec<(u64, u64)>,
    follow_symlinks: bool,
}

impl PathPolicy {
    /// Unrestricted view of the filesystem, minus the always-denied set.
    ///
    /// This is the default for a self-hosted agent: the operator owns the
    /// machine, and a file manager that cannot leave `/srv` is not a file
    /// manager. The denied set still applies, and always will.
    pub fn whole_filesystem() -> PathPolicy {
        PathPolicy::build(vec![PathBuf::from("/")])
    }

    /// Restrict the agent to the given roots (plus the always-denied set).
    ///
    /// Roots are canonicalised here, once, so that a root given through a
    /// symlink (`/srv/app` → `/mnt/data/app`) still matches the canonical
    /// paths that [`PathPolicy::resolve`] produces later. A root that does not
    /// exist is kept lexically and will simply never match.
    pub fn rooted_at(roots: Vec<PathBuf>) -> PathPolicy {
        PathPolicy::build(roots)
    }

    fn build(roots: Vec<PathBuf>) -> PathPolicy {
        let roots: Vec<PathBuf> = roots
            .into_iter()
            .map(|r| fs::canonicalize(&r).unwrap_or(r))
            .collect();
        let denied: Vec<PathBuf> = ALWAYS_DENIED.iter().map(PathBuf::from).collect();
        // One `lstat` per denied entry at construction. Cheap, and it is what
        // makes the hard-link and bind-mount checks possible later.
        let denied_ids = denied
            .iter()
            .filter_map(|p| fs::symlink_metadata(p).ok())
            .map(|m| (m.dev(), m.ino()))
            .collect();
        PathPolicy { roots, denied, denied_ids, follow_symlinks: true }
    }

    /// Refuse to traverse symbolic links at all.
    ///
    /// With this set, a request whose canonical form differs in any way from
    /// its lexical form is refused, which means callers must address files by
    /// their real paths. It is the strictest setting and it is off by default:
    /// real servers are full of legitimate links (`/var/log` on its own volume,
    /// `sites-enabled/*`), and the canonical-path checks already contain them.
    #[must_use]
    pub fn without_symlinks(mut self) -> PathPolicy {
        self.follow_symlinks = false;
        self
    }

    /// The canonicalised roots this policy allows.
    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    /// The always-denied prefixes.
    pub fn denied(&self) -> &[PathBuf] {
        &self.denied
    }

    /// Whether symbolic links may be traversed.
    pub fn follow_symlinks(&self) -> bool {
        self.follow_symlinks
    }

    /// Resolve a caller-supplied path to a real, contained absolute path.
    ///
    /// The path must exist. Symlinks are resolved and the **result** is what is
    /// checked; see the module docs for why that order is the whole defence.
    pub fn resolve(&self, requested: &str) -> Result<PathBuf, FsError> {
        let lexical = normalise(requested)?;
        self.check_denied(&lexical)?;
        let canonical = fs::canonicalize(&lexical).map_err(|e| FsError::io(&lexical, e))?;
        self.check_strict_symlinks(&lexical, &canonical)?;
        self.check_contained(&canonical)?;
        self.check_denied(&canonical)?;
        self.check_identity(&canonical)?;
        Ok(canonical)
    }

    /// Same, but the final component may not exist yet (create, upload, rename
    /// target).
    ///
    /// The parent is canonicalised and checked exactly as in
    /// [`PathPolicy::resolve`]; only the last component is taken on trust, and
    /// it is validated separately (no separator, not `.`, not `..`). If the
    /// target *does* already exist this falls through to the full resolve, so
    /// an existing symlink at the destination cannot be used to write through
    /// to a denied path.
    pub fn resolve_for_create(&self, requested: &str) -> Result<PathBuf, FsError> {
        let name = final_component(requested)?;
        let lexical = normalise(requested)?;
        self.check_denied(&lexical)?;

        match fs::symlink_metadata(&lexical) {
            Ok(md) => {
                if md.is_symlink() && fs::canonicalize(&lexical).is_err() {
                    // A dangling link: canonicalize cannot tell us where a
                    // write would land, so we refuse rather than guess.
                    return Err(FsError::denied(format!(
                        "{} is a broken symbolic link, and ServerOS will not write through it.",
                        show(&lexical)
                    )));
                }
                // Exists: nothing about this is a "create", so use the strict path.
                self.resolve(requested)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let parent = lexical.parent().ok_or_else(|| {
                    FsError::denied("The filesystem root already exists and cannot be created.")
                })?;
                let canonical_parent =
                    fs::canonicalize(parent).map_err(|e| FsError::io(parent, e))?;
                if !canonical_parent.is_dir() {
                    return Err(FsError::NotADirectory { path: show(&canonical_parent) });
                }
                self.check_strict_symlinks(parent, &canonical_parent)?;
                self.check_contained(&canonical_parent)?;
                self.check_denied(&canonical_parent)?;
                self.check_identity(&canonical_parent)?;

                let target = canonical_parent.join(name);
                self.check_denied(&target)?;
                Ok(target)
            }
            Err(e) => Err(FsError::io(&lexical, e)),
        }
    }

    /// Resolve an existing path **without** following a final symlink.
    ///
    /// This is what `delete` and `move_to_trash` use. `resolve` would hand back
    /// the link's target, and unlinking the target of `~/current -> /srv/app`
    /// instead of the link itself is a data-loss bug, not a containment bug —
    /// but it is just as expensive. The parent is still canonicalised and
    /// checked, so the link cannot live outside the policy.
    pub fn resolve_leaf(&self, requested: &str) -> Result<PathBuf, FsError> {
        let name = final_component(requested)?;
        let lexical = normalise(requested)?;
        self.check_denied(&lexical)?;

        let parent = lexical
            .parent()
            .ok_or_else(|| FsError::denied("The filesystem root itself cannot be used here."))?;
        let canonical_parent = fs::canonicalize(parent).map_err(|e| FsError::io(parent, e))?;
        self.check_strict_symlinks(parent, &canonical_parent)?;
        self.check_contained(&canonical_parent)?;
        self.check_denied(&canonical_parent)?;
        self.check_identity(&canonical_parent)?;

        let target = canonical_parent.join(name);
        let md = fs::symlink_metadata(&target).map_err(|e| FsError::io(&target, e))?;
        self.check_denied(&target)?;
        // Identity is checked against the link itself, not its target: removing
        // a symlink that happens to point at /etc/shadow harms nothing.
        if self.denied_ids.contains(&(md.dev(), md.ino())) {
            return Err(FsError::denied(format!(
                "{} is one of the paths ServerOS never touches.",
                show(&target)
            )));
        }
        Ok(target)
    }

    /// The deepest configured root containing `path`, if any.
    pub fn root_for<'a>(&'a self, path: &Path) -> Option<&'a Path> {
        self.roots
            .iter()
            .filter(|r| path.starts_with(r))
            .max_by_key(|r| r.components().count())
            .map(PathBuf::as_path)
    }

    /// Whether `path` *is* one of the configured roots (not merely inside one).
    pub fn is_root(&self, path: &Path) -> bool {
        self.roots.iter().any(|r| r == path)
    }

    /// Would this already-canonical path be allowed?
    ///
    /// For code that has resolved a path by other means — a directory entry
    /// during a listing, the target of a symlink — and needs the policy's
    /// answer without the error message. Never a substitute for
    /// [`PathPolicy::resolve`] on a caller-supplied string.
    pub fn allows(&self, canonical: &Path) -> bool {
        self.check_contained(canonical).is_ok()
            && self.check_denied(canonical).is_ok()
            && self.check_identity(canonical).is_ok()
    }

    // ---- the checks ------------------------------------------------------

    fn check_contained(&self, canonical: &Path) -> Result<(), FsError> {
        // `Path::starts_with` compares whole components, so `/srv/apple` does
        // not match the root `/srv/app`. A `str::starts_with` here would be a
        // containment bug.
        if self.roots.iter().any(|r| canonical.starts_with(r)) {
            return Ok(());
        }
        Err(FsError::denied(format!(
            "{} is outside the folders ServerOS is allowed to manage on this server.",
            show(canonical)
        )))
    }

    fn check_denied(&self, path: &Path) -> Result<(), FsError> {
        for d in &self.denied {
            if path.starts_with(d) {
                return Err(FsError::denied(format!(
                    "{} is inside {}, which ServerOS never reads or changes.",
                    show(path),
                    show(d)
                )));
            }
        }
        if is_key_material(path) {
            return Err(FsError::denied(format!(
                "{} looks like a private key. ServerOS does not open key material.",
                show(path)
            )));
        }
        Ok(())
    }

    /// Catch hard links and bind mounts, which have their own paths but share
    /// the identity of the thing they alias.
    fn check_identity(&self, canonical: &Path) -> Result<(), FsError> {
        if self.denied_ids.is_empty() {
            return Ok(());
        }
        // Walk the path and its ancestors: a bind mount of /proc at /mnt/p
        // makes /mnt/p/1/environ allowed by prefix but identical by inode at
        // the /mnt/p level. Depth is bounded by MAX_PATH_BYTES in practice.
        for ancestor in canonical.ancestors() {
            let Ok(md) = fs::symlink_metadata(ancestor) else { continue };
            if self.denied_ids.contains(&(md.dev(), md.ino())) {
                return Err(FsError::denied(format!(
                    "{} is another name for {}, which ServerOS never reads or changes.",
                    show(canonical),
                    show(ancestor)
                )));
            }
        }
        Ok(())
    }

    fn check_strict_symlinks(&self, lexical: &Path, canonical: &Path) -> Result<(), FsError> {
        if self.follow_symlinks || lexical == canonical {
            return Ok(());
        }
        Err(FsError::denied(format!(
            "{} is reached through a symbolic link, which this server's policy does not allow.",
            show(lexical)
        )))
    }
}

/// Validate and lexically normalise a caller-supplied path.
///
/// `..` is resolved by popping, and a `..` that would climb above `/` is an
/// error rather than a silent no-op: nothing legitimate produces one, so it is
/// always either an attack or a client bug, and both deserve to be told.
pub fn normalise(requested: &str) -> Result<PathBuf, FsError> {
    if requested.is_empty() {
        return Err(FsError::denied("No path was given."));
    }
    if requested.contains('\0') {
        return Err(FsError::denied("That path contains a NUL byte, which is never valid."));
    }
    if requested.len() > MAX_PATH_BYTES {
        return Err(FsError::denied(format!(
            "That path is {} bytes long; the limit is {MAX_PATH_BYTES}.",
            requested.len()
        )));
    }
    if !requested.starts_with('/') {
        return Err(FsError::denied(format!(
            "\"{requested}\" is not an absolute path. Paths must start with /."
        )));
    }

    let mut stack: Vec<&str> = Vec::new();
    for seg in requested.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                if stack.pop().is_none() {
                    return Err(FsError::denied(
                        "That path uses .. to climb above the filesystem root.",
                    ));
                }
            }
            s => {
                if s.len() > MAX_COMPONENT_BYTES {
                    return Err(FsError::denied(format!(
                        "One part of that path is {} bytes long; the limit is {MAX_COMPONENT_BYTES}.",
                        s.len()
                    )));
                }
                stack.push(s);
            }
        }
    }

    let mut out = String::with_capacity(requested.len());
    for seg in &stack {
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() {
        out.push('/');
    }
    Ok(PathBuf::from(out))
}

/// The last component of the *raw* request, validated as a name.
///
/// Deliberately taken before normalisation: `/srv/app/..` normalises to `/srv`,
/// and silently creating or deleting the parent directory because the client
/// sent a trailing `..` is exactly the kind of surprise this crate exists to
/// prevent. Splitting on `/` is also what guarantees the returned name contains
/// no separator.
fn final_component(requested: &str) -> Result<&str, FsError> {
    if requested.contains('\0') {
        return Err(FsError::denied("That path contains a NUL byte, which is never valid."));
    }
    let last = requested.split('/').rfind(|s| !s.is_empty());
    match last {
        None => Err(FsError::denied("The filesystem root is not a valid target for this operation.")),
        Some(".") | Some("..") => Err(FsError::denied(
            "The last part of that path must name a file or folder, not . or ..",
        )),
        Some(s) if s.len() > MAX_COMPONENT_BYTES => Err(FsError::denied(format!(
            "That name is {} bytes long; the limit is {MAX_COMPONENT_BYTES}.",
            s.len()
        ))),
        Some(s) => Ok(s),
    }
}

/// Does this path name key material we refuse to open?
///
/// Scoped to directories that hold keys (`/etc/ssl`, `/etc/ssh`, `/etc/pki`,
/// and any `.ssh`), so an application's `licence.key` under `/srv` stays
/// manageable while `~/.ssh/id_ed25519` does not.
fn is_key_material(path: &Path) -> bool {
    let in_secret_dir = SECRET_DIRS.iter().any(|d| path.starts_with(d))
        || path.components().any(|c| c.as_os_str() == ".ssh");
    if !in_secret_dir {
        return false;
    }
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return false;
    };
    matches!(name.as_str(), "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa")
        || name.ends_with(".key")
}

/// Number of components in an absolute path (`/etc/nginx` → 2).
pub(crate) fn depth(path: &Path) -> usize {
    path.components().filter(|c| matches!(c, Component::Normal(_))).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::symlink;

    fn open() -> PathPolicy {
        PathPolicy::whole_filesystem()
    }

    fn assert_denied(r: Result<PathBuf, FsError>) {
        match r {
            Err(e) => assert_eq!(e.kind(), "denied", "expected a denial, got {e}"),
            Ok(p) => panic!("expected a denial, resolved to {}", p.display()),
        }
    }

    // ---- syntax ----------------------------------------------------------

    #[test]
    fn empty_path_is_denied() {
        assert_denied(open().resolve(""));
    }

    #[test]
    fn relative_path_is_denied() {
        assert_denied(open().resolve("etc/passwd"));
    }

    #[test]
    fn dot_is_denied_because_it_is_relative() {
        assert_denied(open().resolve("."));
    }

    #[test]
    fn dot_dot_traversal_from_relative_is_denied() {
        assert_denied(open().resolve("../../etc/shadow"));
    }

    #[test]
    fn nul_byte_is_denied() {
        assert_denied(open().resolve("/etc/passwd\0.txt"));
    }

    #[test]
    fn five_thousand_character_path_is_denied() {
        let long = format!("/{}", "a".repeat(5000));
        assert_denied(open().resolve(&long));
    }

    #[test]
    fn over_long_single_component_is_denied() {
        let long = format!("/tmp/{}", "a".repeat(300));
        assert_denied(open().resolve(&long));
    }

    #[test]
    fn climbing_above_the_root_is_denied() {
        assert_denied(open().resolve("/.."));
        assert_denied(open().resolve("/tmp/../.."));
    }

    #[test]
    fn normalise_collapses_duplicate_slashes() {
        assert_eq!(normalise("//etc//passwd").unwrap(), PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn normalise_folds_single_dots() {
        assert_eq!(normalise("/etc/./nginx/./nginx.conf").unwrap(), PathBuf::from("/etc/nginx/nginx.conf"));
    }

    #[test]
    fn normalise_pops_dot_dot() {
        assert_eq!(normalise("/tmp/../etc/passwd").unwrap(), PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn normalise_of_root_is_root() {
        assert_eq!(normalise("/").unwrap(), PathBuf::from("/"));
        assert_eq!(normalise("///").unwrap(), PathBuf::from("/"));
    }

    #[test]
    fn trailing_slash_is_harmless() {
        assert_eq!(normalise("/etc/nginx/").unwrap(), PathBuf::from("/etc/nginx"));
    }

    // ---- the denied set --------------------------------------------------

    #[test]
    fn etc_passwd_is_allowed_under_whole_filesystem() {
        let p = open().resolve("/etc/passwd").expect("/etc/passwd must be readable");
        assert_eq!(p, PathBuf::from("/etc/passwd"));
    }

    #[test]
    fn etc_shadow_is_denied() {
        assert_denied(open().resolve("/etc/shadow"));
    }

    #[test]
    fn etc_gshadow_is_denied() {
        assert_denied(open().resolve("/etc/gshadow"));
    }

    #[test]
    fn sudoers_is_denied() {
        assert_denied(open().resolve("/etc/sudoers"));
        assert_denied(open().resolve("/etc/sudoers.d/90-cloud-init-users"));
    }

    #[test]
    fn dot_dot_into_shadow_is_denied_after_normalisation() {
        assert_denied(open().resolve("/tmp/../etc/shadow"));
        assert_denied(open().resolve("/tmp/./.././etc/shadow"));
    }

    #[test]
    fn proc_is_denied() {
        assert_denied(open().resolve("/proc/1/environ"));
        assert_denied(open().resolve("/proc"));
        assert_denied(open().resolve("/proc/self/status"));
    }

    #[test]
    fn sys_and_dev_are_denied() {
        assert_denied(open().resolve("/sys/power/state"));
        assert_denied(open().resolve("/dev/sda"));
        assert_denied(open().resolve("/dev/null"));
    }

    #[test]
    fn the_agents_own_secrets_are_denied() {
        assert_denied(open().resolve("/etc/serveros/agent.key"));
        assert_denied(open().resolve("/etc/serveros"));
    }

    #[test]
    fn root_ssh_directory_is_denied() {
        assert_denied(open().resolve("/root/.ssh/authorized_keys"));
    }

    #[test]
    fn ssl_private_is_denied() {
        assert_denied(open().resolve("/etc/ssl/private/server.key"));
    }

    #[test]
    fn private_key_names_under_a_dot_ssh_are_denied_but_authorized_keys_is_not() {
        let t = TempDir::new("keys");
        let home = t.path().join("home");
        let ssh = home.join(".ssh");
        fs::create_dir_all(&ssh).unwrap();
        fs::write(ssh.join("id_ed25519"), b"PRIVATE").unwrap();
        fs::write(ssh.join("authorized_keys"), b"ssh-ed25519 AAAA...").unwrap();

        let policy = PathPolicy::rooted_at(vec![t.path().to_path_buf()]);
        assert_denied(policy.resolve(ssh.join("id_ed25519").to_str().unwrap()));
        policy
            .resolve(ssh.join("authorized_keys").to_str().unwrap())
            .expect("authorized_keys is manageable; that is the point");
    }

    #[test]
    fn dot_key_files_outside_a_secret_directory_are_fine() {
        let t = TempDir::new("appkey");
        fs::write(t.path().join("licence.key"), b"not a private key").unwrap();
        let policy = PathPolicy::rooted_at(vec![t.path().to_path_buf()]);
        policy.resolve(t.path().join("licence.key").to_str().unwrap()).unwrap();
    }

    // ---- symlinks: the cases that only a real symlink can prove -----------

    #[test]
    fn a_real_symlink_to_etc_shadow_is_denied() {
        let t = TempDir::new("linkshadow");
        let link = t.path().join("link-to-shadow");
        symlink("/etc/shadow", &link).unwrap();
        // The link is lexically inside an allowed root and contains no "..".
        assert_denied(open().resolve(link.to_str().unwrap()));
        let rooted = PathPolicy::rooted_at(vec![t.path().to_path_buf()]);
        assert_denied(rooted.resolve(link.to_str().unwrap()));
    }

    #[test]
    fn a_symlink_pointing_outside_a_configured_root_is_denied() {
        let t = TempDir::new("escape");
        let inside = t.path().join("inside");
        let outside = t.path().join("outside");
        fs::create_dir_all(&inside).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), b"not yours").unwrap();
        symlink(outside.join("secret.txt"), inside.join("escape.txt")).unwrap();

        let policy = PathPolicy::rooted_at(vec![inside.clone()]);
        assert_denied(policy.resolve(inside.join("escape.txt").to_str().unwrap()));
    }

    #[test]
    fn a_symlink_that_stays_inside_the_root_is_allowed() {
        let t = TempDir::new("innerlink");
        fs::write(t.path().join("real.txt"), b"hello").unwrap();
        symlink(t.path().join("real.txt"), t.path().join("alias.txt")).unwrap();
        let policy = PathPolicy::rooted_at(vec![t.path().to_path_buf()]);
        let got = policy.resolve(t.path().join("alias.txt").to_str().unwrap()).unwrap();
        assert_eq!(got, t.path().join("real.txt"));
    }

    #[test]
    fn a_symlinked_directory_component_is_followed_and_checked() {
        let t = TempDir::new("dirlink");
        let real = t.path().join("real");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("f.txt"), b"x").unwrap();
        symlink(&real, t.path().join("alias")).unwrap();
        let policy = PathPolicy::rooted_at(vec![t.path().to_path_buf()]);
        let got = policy.resolve(t.path().join("alias/f.txt").to_str().unwrap()).unwrap();
        assert_eq!(got, real.join("f.txt"));
    }

    #[test]
    fn strict_mode_refuses_a_symlink_that_stays_inside_the_root() {
        let t = TempDir::new("strict");
        fs::write(t.path().join("real.txt"), b"hello").unwrap();
        symlink(t.path().join("real.txt"), t.path().join("alias.txt")).unwrap();
        let policy = PathPolicy::rooted_at(vec![t.path().to_path_buf()]).without_symlinks();
        assert!(!policy.follow_symlinks());
        assert_denied(policy.resolve(t.path().join("alias.txt").to_str().unwrap()));
        policy.resolve(t.path().join("real.txt").to_str().unwrap()).unwrap();
    }

    #[test]
    fn a_hard_link_to_a_denied_file_is_caught_by_inode_identity() {
        let t = TempDir::new("hardlink");
        let link = t.path().join("passwd-alias");
        // /etc/shadow may be unreadable to a non-root test runner; hard-link
        // whatever denied file we can, and skip cleanly if none is linkable
        // (a container may have /etc on a read-only or different filesystem).
        let mut linked = false;
        for candidate in ["/etc/shadow", "/etc/gshadow", "/etc/sudoers"] {
            if fs::hard_link(candidate, &link).is_ok() {
                linked = true;
                break;
            }
        }
        if !linked {
            return;
        }
        assert_denied(open().resolve(link.to_str().unwrap()));
    }

    // ---- containment -----------------------------------------------------

    #[test]
    fn root_itself_resolves_under_whole_filesystem() {
        assert_eq!(open().resolve("/").unwrap(), PathBuf::from("/"));
    }

    #[test]
    fn root_is_outside_a_configured_root() {
        let t = TempDir::new("contain");
        let policy = PathPolicy::rooted_at(vec![t.path().to_path_buf()]);
        assert_denied(policy.resolve("/"));
        assert_denied(policy.resolve("/etc/passwd"));
    }

    #[test]
    fn sibling_prefix_does_not_count_as_containment() {
        let t = TempDir::new("prefix");
        let app = t.path().join("app");
        let apple = t.path().join("apple");
        fs::create_dir_all(&app).unwrap();
        fs::create_dir_all(&apple).unwrap();
        fs::write(apple.join("f.txt"), b"x").unwrap();
        let policy = PathPolicy::rooted_at(vec![app]);
        // "/…/apple/f.txt" starts_with "/…/app" as a *string*, but not as a path.
        assert_denied(policy.resolve(apple.join("f.txt").to_str().unwrap()));
    }

    #[test]
    fn multiple_roots_are_all_honoured() {
        let a = TempDir::new("roota");
        let b = TempDir::new("rootb");
        fs::write(a.path().join("f"), b"x").unwrap();
        fs::write(b.path().join("f"), b"x").unwrap();
        let policy = PathPolicy::rooted_at(vec![a.path().to_path_buf(), b.path().to_path_buf()]);
        policy.resolve(a.path().join("f").to_str().unwrap()).unwrap();
        policy.resolve(b.path().join("f").to_str().unwrap()).unwrap();
    }

    #[test]
    fn dot_dot_inside_a_root_that_escapes_it_is_denied() {
        let t = TempDir::new("escape2");
        let inner = t.path().join("inner");
        fs::create_dir_all(&inner).unwrap();
        fs::write(t.path().join("outer.txt"), b"x").unwrap();
        let policy = PathPolicy::rooted_at(vec![inner.clone()]);
        let escaping = format!("{}/../outer.txt", inner.display());
        assert_denied(policy.resolve(&escaping));
    }

    #[test]
    fn dot_dot_inside_a_root_that_stays_inside_is_allowed() {
        let t = TempDir::new("stayin");
        let a = t.path().join("a");
        fs::create_dir_all(&a).unwrap();
        fs::write(t.path().join("b.txt"), b"x").unwrap();
        let policy = PathPolicy::rooted_at(vec![t.path().to_path_buf()]);
        let p = format!("{}/../b.txt", a.display());
        assert_eq!(policy.resolve(&p).unwrap(), t.path().join("b.txt"));
    }

    #[test]
    fn root_for_picks_the_deepest_matching_root() {
        let t = TempDir::new("deep");
        let inner = t.path().join("inner");
        fs::create_dir_all(&inner).unwrap();
        let policy =
            PathPolicy::rooted_at(vec![t.path().to_path_buf(), inner.clone()]);
        assert_eq!(policy.root_for(&inner.join("x")), Some(inner.as_path()));
    }

    #[test]
    fn is_root_distinguishes_the_root_from_its_children() {
        let t = TempDir::new("isroot");
        let policy = PathPolicy::rooted_at(vec![t.path().to_path_buf()]);
        assert!(policy.is_root(t.path()));
        assert!(!policy.is_root(&t.path().join("child")));
    }

    // ---- existence -------------------------------------------------------

    #[test]
    fn a_path_that_does_not_exist_is_not_found() {
        let t = TempDir::new("missing");
        let e = open().resolve(t.path().join("nope.txt").to_str().unwrap()).unwrap_err();
        assert_eq!(e.kind(), "not_found");
    }

    #[test]
    fn a_path_whose_parent_does_not_exist_is_not_found_for_create() {
        let t = TempDir::new("missingparent");
        let e = open()
            .resolve_for_create(t.path().join("nope/child.txt").to_str().unwrap())
            .unwrap_err();
        assert_eq!(e.kind(), "not_found");
    }

    // ---- resolve_for_create ---------------------------------------------

    #[test]
    fn create_target_in_an_existing_directory_resolves() {
        let t = TempDir::new("create");
        let want = t.path().join("new.txt");
        let got = open().resolve_for_create(want.to_str().unwrap()).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn create_target_named_dot_dot_is_denied() {
        let t = TempDir::new("createdotdot");
        let p = format!("{}/sub/..", t.path().display());
        assert_denied(open().resolve_for_create(&p));
    }

    #[test]
    fn create_target_named_dot_is_denied() {
        let t = TempDir::new("createdot");
        let p = format!("{}/.", t.path().display());
        assert_denied(open().resolve_for_create(&p));
    }

    #[test]
    fn create_target_at_the_filesystem_root_is_denied() {
        assert_denied(open().resolve_for_create("/"));
    }

    #[test]
    fn create_target_inside_a_denied_directory_is_denied() {
        assert_denied(open().resolve_for_create("/etc/serveros/new.conf"));
        assert_denied(open().resolve_for_create("/proc/evil"));
    }

    #[test]
    fn create_target_that_is_a_denied_file_is_denied() {
        assert_denied(open().resolve_for_create("/etc/shadow"));
    }

    #[test]
    fn create_through_an_existing_symlink_to_a_denied_file_is_denied() {
        let t = TempDir::new("createlink");
        let link = t.path().join("notes.txt");
        symlink("/etc/shadow", &link).unwrap();
        assert_denied(open().resolve_for_create(link.to_str().unwrap()));
    }

    #[test]
    fn create_through_a_symlinked_parent_is_resolved_to_the_real_parent() {
        let t = TempDir::new("createparent");
        let real = t.path().join("real");
        fs::create_dir_all(&real).unwrap();
        symlink(&real, t.path().join("alias")).unwrap();
        let got = open()
            .resolve_for_create(t.path().join("alias/new.txt").to_str().unwrap())
            .unwrap();
        assert_eq!(got, real.join("new.txt"));
    }

    #[test]
    fn create_through_a_broken_symlink_is_denied() {
        let t = TempDir::new("broken");
        let link = t.path().join("dangling");
        symlink(t.path().join("does-not-exist"), &link).unwrap();
        assert_denied(open().resolve_for_create(link.to_str().unwrap()));
    }

    #[test]
    fn create_outside_a_configured_root_is_denied() {
        let t = TempDir::new("createout");
        let inner = t.path().join("inner");
        fs::create_dir_all(&inner).unwrap();
        let policy = PathPolicy::rooted_at(vec![inner]);
        assert_denied(policy.resolve_for_create(t.path().join("outside.txt").to_str().unwrap()));
    }

    // ---- resolve_leaf ----------------------------------------------------

    #[test]
    fn resolve_leaf_does_not_follow_the_final_symlink() {
        let t = TempDir::new("leaf");
        fs::write(t.path().join("real.txt"), b"x").unwrap();
        let link = t.path().join("alias.txt");
        symlink(t.path().join("real.txt"), &link).unwrap();
        let got = open().resolve_leaf(link.to_str().unwrap()).unwrap();
        assert_eq!(got, link, "delete must act on the link, not its target");
    }

    #[test]
    fn resolve_leaf_requires_existence() {
        let t = TempDir::new("leafmissing");
        let e = open().resolve_leaf(t.path().join("nope").to_str().unwrap()).unwrap_err();
        assert_eq!(e.kind(), "not_found");
    }

    #[test]
    fn resolve_leaf_still_denies_denied_paths() {
        assert_denied(open().resolve_leaf("/etc/shadow"));
        assert_denied(open().resolve_leaf("/proc/1"));
    }

    #[test]
    fn depth_counts_components() {
        assert_eq!(depth(Path::new("/")), 0);
        assert_eq!(depth(Path::new("/etc")), 1);
        assert_eq!(depth(Path::new("/var/lib")), 2);
        assert_eq!(depth(Path::new("/var/lib/postgresql/16")), 4);
    }
}
