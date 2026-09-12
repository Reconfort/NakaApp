//! Changing the filesystem: create, write, rename, delete, chmod, upload.
//!
//! Everything here is a mutation on a production server, so every function
//! obeys three rules that are worth stating before the code.
//!
//! # 1. A write is atomic or it does not happen
//!
//! The naive save is `open(O_TRUNC)` then `write`. Between those two calls the
//! file is **empty**, and between the first and last `write` it is **half a
//! file**. If the process is killed, the disk fills, or the machine loses power
//! in that window — and the window is wide, because the app is saving over a
//! network — the customer is left with a truncated `nginx.conf` and a web
//! server that will not start. That is the single worst thing this crate could
//! do to someone.
//!
//! So [`write_file`] never touches the destination until the new contents are
//! on disk in full:
//!
//! ```text
//! .nginx.conf.serveros-tmp   ← create, write, fsync
//!          │ rename(2)          ← atomic: readers see old or new, never half
//!          ▼
//!   nginx.conf
//! ```
//!
//! The temp file is created **in the same directory** on purpose: `rename(2)`
//! is only atomic within a filesystem, and `/tmp` is very often a different
//! one. The directory itself is `fsync`ed after the rename, because the rename
//! is metadata and metadata is not durable until the directory is.
//!
//! Mode and ownership are copied from the file being replaced. A saved
//! `nginx.conf` that comes back as `root:root 0644` instead of `www-data:
//! www-data 0640` is a permission bug the user did not ask for and will not
//! find for weeks.
//!
//! # 2. Delete is recoverable by default
//!
//! [`move_to_trash`] — not [`delete`] — is what the app calls when a person
//! clicks "Delete". The file is moved to `<root>/.serveros-trash/` with a
//! timestamped name and can be dragged back. Deleting the wrong thing on a
//! server is not like deleting the wrong thing on a laptop: there is no Time
//! Machine, and the file may be the only copy of a customer's database dump.
//! An "are you sure?" dialog is not a safety net, it is a speed bump; a trash
//! directory is a safety net. [`delete`] stays available for the cases where
//! the user explicitly asks to delete permanently, and for the agent's own
//! housekeeping.
//!
//! # 3. Some things are simply refused
//!
//! `rm -rf /` is one typo away in every shell on earth. It is not one typo away
//! here: [`delete`] refuses the filesystem root, any configured policy root,
//! anything less than two components deep, and a list of directories whose
//! removal would end the server ([`CRITICAL_PATHS`]). The refusal is a distinct
//! error ([`FsError::RefusedDangerous`]) so the app can say *why* rather than
//! showing a permission error for something that was never a permission
//! problem.
//!
//! Recursive delete walks the tree itself rather than trusting a library to do
//! the right thing with symlinks: an entry that is a link is **unlinked**,
//! never descended into. Deleting `/srv/app/current` must not delete the
//! release directory it points at, and must never follow a link out of the
//! tree into `/etc`.

use crate::error::{FsError, show};
use crate::listing::{Entry, entry_at};
use crate::path::{PathPolicy, depth};
use crate::read::sniff_is_text;
use serveros_json::{Object, Value};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Directory name used for recoverable deletes, inside each policy root.
pub const TRASH_DIR_NAME: &str = ".serveros-trash";

/// Where trash goes when the policy root is the whole filesystem. `/` must not
/// accumulate a dot-directory, and `/var/tmp` is the FHS location for data that
/// should survive a reboot.
pub const WHOLE_FS_TRASH: &str = "/var/tmp/.serveros-trash";

/// Buffer used for every streaming copy. 64 KiB is large enough that syscall
/// overhead disappears and small enough to stay off the stack budget.
pub const COPY_BUFFER: usize = 64 * 1024;

/// Mode given to a file the agent creates when there is no previous file to
/// copy one from. Set explicitly so the result does not depend on the umask the
/// agent happens to have been started with.
pub const DEFAULT_FILE_MODE: u32 = 0o644;

/// Mode given to a directory the agent creates.
pub const DEFAULT_DIR_MODE: u32 = 0o755;

/// Directories whose deletion would end the server, refused at any depth.
///
/// The depth rule alone would allow `/var/lib`, and a UI that can delete
/// `/var/lib` is a UI that can destroy every database on the machine with one
/// mis-click.
pub const CRITICAL_PATHS: &[&str] = &[
    "/etc", "/var", "/var/lib", "/var/log", "/var/www", "/var/cache", "/var/spool", "/usr",
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local", "/usr/share", "/bin", "/sbin", "/lib",
    "/lib32", "/lib64", "/boot", "/home", "/root", "/opt", "/srv", "/tmp", "/run", "/mnt",
    "/media", "/snap",
];

/// What a delete actually removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeleteReport {
    /// Regular files and symlinks unlinked.
    pub files_deleted: u64,
    /// Directories removed.
    pub directories_deleted: u64,
    /// Sum of the sizes of the files removed. Symlinks count as zero: their
    /// `st_size` is the length of the target path, which would be a lie.
    pub bytes_freed: u64,
}

impl DeleteReport {
    /// `{"files_deleted":3,"directories_deleted":1,"bytes_freed":4096}`
    pub fn to_json(&self) -> Value {
        Object::new()
            .set("files_deleted", self.files_deleted)
            .set("directories_deleted", self.directories_deleted)
            .set("bytes_freed", self.bytes_freed)
            .into()
    }
}

/// Create a directory. The parent must already exist.
///
/// Deliberately not `create_dir_all`: a typo in a path the user typed should
/// produce "that folder does not exist", not four nested directories nobody
/// asked for.
pub fn create_directory(policy: &PathPolicy, path: &str) -> Result<Entry, FsError> {
    let target = policy.resolve_for_create(path)?;
    if target.exists() {
        return Err(FsError::AlreadyExists { path: show(&target) });
    }
    fs::create_dir(&target).map_err(|e| FsError::io(&target, e))?;
    let _ = fs::set_permissions(&target, Permissions::from_mode(DEFAULT_DIR_MODE));
    entry_at(policy, &target, true)
}

/// Create a new file. Fails if anything is already there.
///
/// `O_CREAT|O_EXCL` does the check in the kernel, so there is no window between
/// "does it exist?" and "create it" — and it refuses to follow a symlink at the
/// destination, which is the classic way to trick a privileged process into
/// writing somewhere else.
pub fn create_file(policy: &PathPolicy, path: &str, contents: &[u8]) -> Result<Entry, FsError> {
    let target = policy.resolve_for_create(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|e| FsError::io(&target, e))?;
    file.write_all(contents).map_err(|e| FsError::io(&target, e))?;
    file.sync_all().map_err(|e| FsError::io(&target, e))?;
    drop(file);
    let _ = fs::set_permissions(&target, Permissions::from_mode(DEFAULT_FILE_MODE));
    entry_at(policy, &target, true)
}

/// Replace a file's contents atomically. Creates it if it does not exist.
///
/// See the module docs: temp file in the same directory, `fsync`, `rename`,
/// `fsync` the directory. Mode and ownership are inherited from the file being
/// replaced.
pub fn write_file(policy: &PathPolicy, path: &str, contents: &[u8]) -> Result<Entry, FsError> {
    let target = policy.resolve_for_create(path)?;
    atomic_write(&target, |f| f.write_all(contents))?;
    entry_at(policy, &target, true)
}

/// Move or rename. Refuses to overwrite an existing destination.
///
/// `rename(2)` would happily clobber the destination file. The app should ask
/// first, so the clobber is a separate, explicit operation rather than a
/// silent side effect of a drag.
pub fn rename(policy: &PathPolicy, from: &str, to: &str) -> Result<Entry, FsError> {
    const WHY: &str = "Renaming it would break the server";
    refuse_dangerous_request(policy, from, WHY)?;
    // The source is resolved without following a final symlink: moving
    // `current -> releases/42` must move the link, not the release.
    let source = policy.resolve_leaf(from)?;
    refuse_dangerous(policy, &source, WHY)?;
    let dest = policy.resolve_for_create(to)?;
    if dest.exists() {
        return Err(FsError::AlreadyExists { path: show(&dest) });
    }
    if source == dest {
        return entry_at(policy, &source, true);
    }
    fs::rename(&source, &dest).map_err(|e| FsError::io(&source, e))?;
    entry_at(policy, &dest, true)
}

/// Delete permanently.
///
/// Prefer [`move_to_trash`] for anything a person initiated. A non-recursive
/// delete of a non-empty directory fails **before** removing anything, so it
/// can never half-delete a tree.
pub fn delete(policy: &PathPolicy, path: &str, recursive: bool) -> Result<DeleteReport, FsError> {
    const WHY: &str = "Deleting it would destroy the server";
    refuse_dangerous_request(policy, path, WHY)?;
    let target = policy.resolve_leaf(path)?;
    refuse_dangerous(policy, &target, WHY)?;

    let md = fs::symlink_metadata(&target).map_err(|e| FsError::io(&target, e))?;
    let mut report = DeleteReport::default();

    if md.is_symlink() {
        fs::remove_file(&target).map_err(|e| FsError::io(&target, e))?;
        report.files_deleted += 1;
        return Ok(report);
    }

    if md.is_dir() {
        if !recursive {
            // Check first, delete second: a partial delete is worse than a
            // refusal, and `remove_dir` failing half-way is not a thing we
            // want to explain to a customer.
            let mut children = fs::read_dir(&target).map_err(|e| FsError::io(&target, e))?;
            if children.next().is_some() {
                return Err(FsError::NotEmpty { path: show(&target) });
            }
            fs::remove_dir(&target).map_err(|e| FsError::io(&target, e))?;
            report.directories_deleted += 1;
            return Ok(report);
        }
        remove_tree(&target, &mut report)?;
        return Ok(report);
    }

    report.bytes_freed += md.len();
    fs::remove_file(&target).map_err(|e| FsError::io(&target, e))?;
    report.files_deleted += 1;
    Ok(report)
}

/// Move something into the trash instead of unlinking it.
///
/// The destination is `<root>/.serveros-trash/<unix-seconds>-<name>`, where
/// `<root>` is the deepest policy root containing the path (or
/// [`WHOLE_FS_TRASH`] when the policy is the whole filesystem). Nothing here
/// empties the trash: that is a deliberate, separate decision for the operator,
/// and a trash that empties itself is not a safety net.
///
/// Returns where the thing now lives, so the app can offer "Undo".
pub fn move_to_trash(policy: &PathPolicy, path: &str) -> Result<PathBuf, FsError> {
    const WHY: &str = "Deleting it would destroy the server";
    refuse_dangerous_request(policy, path, WHY)?;
    let target = policy.resolve_leaf(path)?;
    refuse_dangerous(policy, &target, WHY)?;

    let trash = trash_dir(policy, &target);
    if target.starts_with(&trash) {
        return Err(FsError::refused(
            &target,
            "It is already in the trash. Delete it permanently instead.",
        ));
    }
    fs::create_dir_all(&trash).map_err(|e| FsError::io(&trash, e))?;
    // The trash can hold anything the agent could read, so it is the agent's
    // alone.
    let _ = fs::set_permissions(&trash, Permissions::from_mode(0o700));

    let name = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let stamp = crate::now_secs();
    let mut dest = trash.join(format!("{stamp}-{name}"));
    let mut n = 1;
    while dest.exists() {
        dest = trash.join(format!("{stamp}-{n}-{name}"));
        n += 1;
    }

    match fs::rename(&target, &dest) {
        Ok(()) => Ok(dest),
        Err(e) if is_cross_device(&e) => {
            // `/home` on its own volume is the common case, not the exotic one,
            // so a trash that gives up at a mount boundary would be useless.
            copy_tree(&target, &dest)?;
            let mut report = DeleteReport::default();
            let md = fs::symlink_metadata(&target).map_err(|e| FsError::io(&target, e))?;
            if md.is_dir() {
                remove_tree(&target, &mut report)?;
            } else {
                fs::remove_file(&target).map_err(|e| FsError::io(&target, e))?;
            }
            Ok(dest)
        }
        Err(e) => Err(FsError::io(&target, e)),
    }
}

/// Change permission bits.
///
/// Follows symlinks, exactly as `chmod(1)` does — the mode of a link is
/// meaningless on Linux.
///
/// setuid and setgid are refused. A file manager that can set the setuid bit is
/// a one-click local privilege escalation, and no legitimate ServerOS workflow
/// needs it; the operator who genuinely does can use the terminal, where the
/// decision is at least deliberate.
pub fn set_mode(policy: &PathPolicy, path: &str, mode: u32) -> Result<Entry, FsError> {
    let target = policy.resolve(path)?;
    if mode > 0o7777 {
        return Err(FsError::denied(format!(
            "{mode:o} is not a valid permission mode; it must be four octal digits or fewer."
        )));
    }
    if mode & 0o6000 != 0 {
        return Err(FsError::refused(
            &target,
            "setuid and setgid turn a file into a way to gain another user's privileges.",
        ));
    }
    fs::set_permissions(&target, Permissions::from_mode(mode))
        .map_err(|e| FsError::io(&target, e))?;
    entry_at(policy, &target, true)
}

/// Land an uploaded file at its destination.
///
/// `spooled` is the agent's own temporary copy of the upload body and is **not**
/// policy-checked: it is a path the agent chose, not one a caller supplied.
/// `dest` is caller-supplied and goes through the policy like everything else.
///
/// The copy streams through a [`COPY_BUFFER`]-sized buffer. `read_to_end` on an
/// upload would mean the agent's memory ceiling is whatever the client decided
/// to send, which is not a ceiling at all.
pub fn copy_from(
    policy: &PathPolicy,
    spooled: &Path,
    dest: &str,
    overwrite: bool,
) -> Result<Entry, FsError> {
    let source_md = fs::symlink_metadata(spooled).map_err(|e| FsError::io(spooled, e))?;
    if !source_md.is_file() {
        return Err(FsError::denied(format!(
            "{} is not a regular file and cannot be uploaded.",
            show(spooled)
        )));
    }
    let target = policy.resolve_for_create(dest)?;
    match fs::symlink_metadata(&target) {
        Ok(md) if md.is_dir() => return Err(FsError::IsADirectory { path: show(&target) }),
        Ok(_) if !overwrite => return Err(FsError::AlreadyExists { path: show(&target) }),
        _ => {}
    }

    let mut source = File::open(spooled).map_err(|e| FsError::io(spooled, e))?;
    atomic_write(&target, |out| {
        let mut buf = vec![0u8; COPY_BUFFER];
        loop {
            let n = source.read(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            out.write_all(&buf[..n])?;
        }
    })?;
    entry_at(policy, &target, true)
}

// ---- internals ----------------------------------------------------------

/// Write via a temp file in the same directory, then `rename`.
fn atomic_write(
    target: &Path,
    fill: impl FnOnce(&mut File) -> io::Result<()>,
) -> Result<(), FsError> {
    let dir = target
        .parent()
        .ok_or_else(|| FsError::denied("The filesystem root is not a file."))?;
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| FsError::denied("That path does not name a file."))?;
    let tmp = dir.join(format!(".{name}.serveros-tmp"));

    let original = fs::symlink_metadata(target).ok().filter(|m| m.is_file());

    let mut file = match OpenOptions::new().write(true).create_new(true).open(&tmp) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            // A leftover temp file is the residue of a crashed write and has no
            // value to anyone. Remove it and try exactly once more, so a
            // genuine race still fails loudly instead of looping.
            fs::remove_file(&tmp).map_err(|e| FsError::io(&tmp, e))?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|e| FsError::io(&tmp, e))?
        }
        Err(e) => return Err(FsError::io(&tmp, e)),
    };

    let finish = (|| -> Result<(), FsError> {
        fill(&mut file).map_err(|e| FsError::io(&tmp, e))?;
        // Durability before visibility: the bytes must be on the platter before
        // the rename makes them the file everyone sees.
        file.sync_all().map_err(|e| FsError::io(&tmp, e))?;

        match &original {
            Some(md) => {
                fs::set_permissions(&tmp, Permissions::from_mode(md.mode() & 0o7777))
                    .map_err(|e| FsError::io(&tmp, e))?;
                preserve_ownership(&tmp, md)?;
            }
            None => {
                fs::set_permissions(&tmp, Permissions::from_mode(DEFAULT_FILE_MODE))
                    .map_err(|e| FsError::io(&tmp, e))?;
            }
        }
        fs::rename(&tmp, target).map_err(|e| FsError::io(target, e))?;
        // The rename is metadata; the directory entry is not durable until the
        // directory itself is synced. Best effort: some filesystems refuse to
        // fsync a directory, and failing the save at this point would be worse
        // than the residual risk.
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();

    if finish.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    finish
}

/// Copy uid/gid from the file being replaced onto its replacement.
///
/// A failure is only fatal if it would actually change the owner: a non-root
/// agent replacing its own file gets `EPERM` from `chown` for a no-op, and
/// failing that save would be absurd.
fn preserve_ownership(tmp: &Path, original: &fs::Metadata) -> Result<(), FsError> {
    let (uid, gid) = (original.uid(), original.gid());
    if std::os::unix::fs::chown(tmp, Some(uid), Some(gid)).is_ok() {
        return Ok(());
    }
    let now = fs::symlink_metadata(tmp).map_err(|e| FsError::io(tmp, e))?;
    if now.uid() == uid && now.gid() == gid {
        return Ok(());
    }
    Err(FsError::denied(format!(
        "Saving would change the owner of {} from {}:{} to {}:{}, so ServerOS stopped.",
        show(tmp),
        uid,
        gid,
        now.uid(),
        now.gid()
    )))
}

/// Is this the "different filesystem" error? Checked by errno as well as by
/// kind, because the mapping of `EXDEV` is a std detail and this decides
/// whether the trash works across a mount point.
fn is_cross_device(e: &io::Error) -> bool {
    e.raw_os_error() == Some(18) || e.kind() == io::ErrorKind::CrossesDevices
}

/// Refuse a dangerous path *before* it is resolved.
///
/// `/` has no final component and a policy root's parent is outside the policy,
/// so both would come back from `resolve_leaf` as a confusing "that path is not
/// valid here". They are not invalid — they are refused, and the user deserves
/// to be told which. The resolved path is checked again afterwards, because a
/// symlink can lexically look harmless and canonicalise to `/etc`.
fn refuse_dangerous_request(
    policy: &PathPolicy,
    requested: &str,
    what: &str,
) -> Result<(), FsError> {
    let lexical = crate::path::normalise(requested)?;
    refuse_dangerous(policy, &lexical, what)
}

/// Refuse the paths whose removal or rename would end the server.
fn refuse_dangerous(policy: &PathPolicy, target: &Path, what: &str) -> Result<(), FsError> {
    if target == Path::new("/") {
        return Err(FsError::refused(target, format!("{what}: it is the filesystem root.")));
    }
    if policy.is_root(target) {
        return Err(FsError::refused(
            target,
            format!("{what}: it is one of the folders ServerOS is configured to manage."),
        ));
    }
    if depth(target) < 2 {
        return Err(FsError::refused(
            target,
            format!("{what}: top-level system directories cannot be removed from ServerOS."),
        ));
    }
    if CRITICAL_PATHS.iter().any(|c| Path::new(c) == target) {
        return Err(FsError::refused(
            target,
            format!("{what}: it is a critical system directory."),
        ));
    }
    Ok(())
}

/// Post-order removal that never descends into a symlink.
///
/// An explicit stack rather than recursion: directory trees on a server can be
/// thousands deep (`node_modules`, a runaway backup loop), and a stack overflow
/// in the agent would take the whole process with it.
fn remove_tree(root: &Path, report: &mut DeleteReport) -> Result<(), FsError> {
    enum Step {
        Descend(PathBuf),
        Remove(PathBuf),
    }
    let mut stack = vec![Step::Descend(root.to_path_buf())];

    while let Some(step) = stack.pop() {
        match step {
            Step::Descend(dir) => {
                stack.push(Step::Remove(dir.clone()));
                let reader = fs::read_dir(&dir).map_err(|e| FsError::io(&dir, e))?;
                for item in reader {
                    let item = item.map_err(|e| FsError::io(&dir, e))?;
                    let path = item.path();
                    // `DirEntry::metadata` does not traverse symlinks, which is
                    // the whole point: a link to a directory must be unlinked,
                    // not walked. Following it would delete the contents of
                    // whatever it points at — possibly outside this tree.
                    let md = item.metadata().map_err(|e| FsError::io(&path, e))?;
                    if md.is_dir() {
                        stack.push(Step::Descend(path));
                    } else {
                        fs::remove_file(&path).map_err(|e| FsError::io(&path, e))?;
                        report.files_deleted += 1;
                        if !md.is_symlink() {
                            report.bytes_freed += md.len();
                        }
                    }
                }
            }
            Step::Remove(dir) => {
                fs::remove_dir(&dir).map_err(|e| FsError::io(&dir, e))?;
                report.directories_deleted += 1;
            }
        }
    }
    Ok(())
}

/// Copy a file, directory tree or symlink to a new location.
///
/// Only used for the cross-filesystem trash fallback. Symlinks are recreated as
/// symlinks rather than followed, for the same reason [`remove_tree`] does not
/// follow them.
fn copy_tree(from: &Path, to: &Path) -> Result<(), FsError> {
    let md = fs::symlink_metadata(from).map_err(|e| FsError::io(from, e))?;
    if md.is_symlink() {
        let link = fs::read_link(from).map_err(|e| FsError::io(from, e))?;
        return std::os::unix::fs::symlink(link, to).map_err(|e| FsError::io(to, e));
    }
    if !md.is_dir() {
        fs::copy(from, to).map_err(|e| FsError::io(from, e))?;
        return Ok(());
    }

    fs::create_dir_all(to).map_err(|e| FsError::io(to, e))?;
    let mut stack = vec![(from.to_path_buf(), to.to_path_buf())];
    while let Some((src, dst)) = stack.pop() {
        let reader = fs::read_dir(&src).map_err(|e| FsError::io(&src, e))?;
        for item in reader {
            let item = item.map_err(|e| FsError::io(&src, e))?;
            let md = item.metadata().map_err(|e| FsError::io(&item.path(), e))?;
            let target = dst.join(item.file_name());
            if md.is_symlink() {
                let link = fs::read_link(item.path()).map_err(|e| FsError::io(&item.path(), e))?;
                std::os::unix::fs::symlink(link, &target).map_err(|e| FsError::io(&target, e))?;
            } else if md.is_dir() {
                fs::create_dir_all(&target).map_err(|e| FsError::io(&target, e))?;
                stack.push((item.path(), target));
            } else {
                fs::copy(item.path(), &target).map_err(|e| FsError::io(&item.path(), e))?;
            }
        }
    }
    Ok(())
}

/// Where deleted things go for this policy and path.
fn trash_dir(policy: &PathPolicy, target: &Path) -> PathBuf {
    match policy.root_for(target) {
        Some(root) if root != Path::new("/") => root.join(TRASH_DIR_NAME),
        _ => PathBuf::from(WHOLE_FS_TRASH),
    }
}

/// Whether a byte slice would survive a round trip through the editor, used by
/// the HTTP layer to reject a "save" of something that is not text.
pub fn is_text_payload(contents: &[u8]) -> bool {
    sniff_is_text(contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::symlink;

    fn policy(t: &TempDir) -> PathPolicy {
        PathPolicy::rooted_at(vec![t.path().to_path_buf()])
    }

    // ---- create ----------------------------------------------------------

    #[test]
    fn creates_a_directory() {
        let t = TempDir::new("mkdir");
        let e = create_directory(&policy(&t), &t.s("sites")).unwrap();
        assert_eq!(e.kind.as_str(), "directory");
        assert_eq!(e.mode, "0755");
        assert!(t.path().join("sites").is_dir());
    }

    #[test]
    fn creating_an_existing_directory_is_a_conflict() {
        let t = TempDir::new("mkdirdup");
        create_directory(&policy(&t), &t.s("sites")).unwrap();
        let e = create_directory(&policy(&t), &t.s("sites")).unwrap_err();
        assert_eq!(e.kind(), "already_exists");
    }

    #[test]
    fn creating_a_directory_does_not_create_its_parents() {
        let t = TempDir::new("mkdirdeep");
        let e = create_directory(&policy(&t), &t.s("a/b/c")).unwrap_err();
        assert_eq!(e.kind(), "not_found");
        assert!(!t.path().join("a").exists());
    }

    #[test]
    fn creates_a_file_with_contents() {
        let t = TempDir::new("mkfile");
        let e = create_file(&policy(&t), &t.s("app.conf"), b"listen 8080;\n").unwrap();
        assert_eq!(e.size_bytes, 13);
        assert_eq!(e.mode, "0644");
        assert_eq!(fs::read(t.path().join("app.conf")).unwrap(), b"listen 8080;\n");
    }

    #[test]
    fn creating_an_existing_file_is_a_conflict() {
        let t = TempDir::new("mkfiledup");
        fs::write(t.path().join("a"), b"old").unwrap();
        let e = create_file(&policy(&t), &t.s("a"), b"new").unwrap_err();
        assert_eq!(e.kind(), "already_exists");
        assert_eq!(fs::read(t.path().join("a")).unwrap(), b"old", "the old file is untouched");
    }

    #[test]
    fn create_cannot_be_tricked_through_a_symlink() {
        let t = TempDir::new("mkfilelink");
        let outside = TempDir::new("mkfileout");
        fs::write(outside.path().join("victim"), b"original").unwrap();
        symlink(outside.path().join("victim"), t.path().join("bait")).unwrap();
        let e = create_file(&policy(&t), &t.s("bait"), b"attacker").unwrap_err();
        assert_eq!(e.kind(), "denied");
        assert_eq!(fs::read(outside.path().join("victim")).unwrap(), b"original");
    }

    // ---- atomic write ----------------------------------------------------

    #[test]
    fn write_replaces_contents() {
        let t = TempDir::new("write");
        fs::write(t.path().join("nginx.conf"), b"old config\n").unwrap();
        let e = write_file(&policy(&t), &t.s("nginx.conf"), b"new config\n").unwrap();
        assert_eq!(e.size_bytes, 11);
        assert_eq!(fs::read(t.path().join("nginx.conf")).unwrap(), b"new config\n");
    }

    #[test]
    fn write_creates_the_file_when_it_is_missing() {
        let t = TempDir::new("writenew");
        write_file(&policy(&t), &t.s("fresh.conf"), b"hello\n").unwrap();
        assert_eq!(fs::read(t.path().join("fresh.conf")).unwrap(), b"hello\n");
    }

    #[test]
    fn write_leaves_no_temp_file_behind() {
        let t = TempDir::new("writetmp");
        write_file(&policy(&t), &t.s("a.conf"), b"x").unwrap();
        let leftovers: Vec<String> = fs::read_dir(t.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("serveros-tmp"))
            .collect();
        assert!(leftovers.is_empty(), "left {leftovers:?}");
    }

    #[test]
    fn write_preserves_the_original_mode() {
        let t = TempDir::new("writemode");
        let p = t.path().join("secret.conf");
        fs::write(&p, b"old").unwrap();
        fs::set_permissions(&p, Permissions::from_mode(0o600)).unwrap();
        let e = write_file(&policy(&t), &t.s("secret.conf"), b"new").unwrap();
        assert_eq!(e.mode, "0600", "a 0600 config must not come back world-readable");
    }

    #[test]
    fn write_preserves_the_original_owner() {
        let t = TempDir::new("writeowner");
        let p = t.path().join("owned.conf");
        fs::write(&p, b"old").unwrap();
        let before = fs::metadata(&p).unwrap();
        write_file(&policy(&t), &t.s("owned.conf"), b"new").unwrap();
        let after = fs::metadata(&p).unwrap();
        assert_eq!((before.uid(), before.gid()), (after.uid(), after.gid()));
    }

    #[test]
    fn write_recovers_from_a_stale_temp_file() {
        let t = TempDir::new("writestale");
        fs::write(t.path().join("a.conf"), b"old").unwrap();
        fs::write(t.path().join(".a.conf.serveros-tmp"), b"crashed write").unwrap();
        write_file(&policy(&t), &t.s("a.conf"), b"new").unwrap();
        assert_eq!(fs::read(t.path().join("a.conf")).unwrap(), b"new");
        assert!(!t.path().join(".a.conf.serveros-tmp").exists());
    }

    #[test]
    fn write_keeps_the_old_file_intact_when_the_new_one_cannot_be_written() {
        // A directory where the temp file would go makes the create fail.
        let t = TempDir::new("writefail");
        fs::write(t.path().join("a.conf"), b"precious").unwrap();
        fs::create_dir(t.path().join(".a.conf.serveros-tmp")).unwrap();
        let e = write_file(&policy(&t), &t.s("a.conf"), b"replacement").unwrap_err();
        assert_ne!(e.kind(), "already_exists");
        assert_eq!(fs::read(t.path().join("a.conf")).unwrap(), b"precious");
    }

    #[test]
    fn write_is_denied_outside_the_policy() {
        let t = TempDir::new("writeout");
        let inner = t.path().join("inner");
        fs::create_dir(&inner).unwrap();
        let p = PathPolicy::rooted_at(vec![inner]);
        let e = write_file(&p, &t.s("escape.conf"), b"x").unwrap_err();
        assert_eq!(e.kind(), "denied");
    }

    #[test]
    fn write_cannot_reach_a_denied_file() {
        let e = write_file(&PathPolicy::whole_filesystem(), "/etc/shadow", b"x").unwrap_err();
        assert_eq!(e.kind(), "denied");
    }

    // ---- rename ----------------------------------------------------------

    #[test]
    fn renames_a_file() {
        let t = TempDir::new("rename");
        fs::write(t.path().join("a.txt"), b"x").unwrap();
        let e = rename(&policy(&t), &t.s("a.txt"), &t.s("b.txt")).unwrap();
        assert_eq!(e.name, "b.txt");
        assert!(!t.path().join("a.txt").exists());
    }

    #[test]
    fn rename_refuses_to_clobber() {
        let t = TempDir::new("renameclobber");
        fs::write(t.path().join("a"), b"a").unwrap();
        fs::write(t.path().join("b"), b"b").unwrap();
        let e = rename(&policy(&t), &t.s("a"), &t.s("b")).unwrap_err();
        assert_eq!(e.kind(), "already_exists");
        assert_eq!(fs::read(t.path().join("b")).unwrap(), b"b");
    }

    #[test]
    fn rename_moves_a_symlink_not_its_target() {
        let t = TempDir::new("renamelink");
        fs::write(t.path().join("real"), b"x").unwrap();
        symlink(t.path().join("real"), t.path().join("link")).unwrap();
        rename(&policy(&t), &t.s("link"), &t.s("moved")).unwrap();
        assert!(t.path().join("real").exists(), "the target must not move");
        assert!(fs::symlink_metadata(t.path().join("moved")).unwrap().is_symlink());
    }

    #[test]
    fn rename_refuses_a_dangerous_source() {
        let e = rename(&PathPolicy::whole_filesystem(), "/var/lib", "/var/lib2").unwrap_err();
        assert_eq!(e.kind(), "refused_dangerous");
    }

    // ---- delete ----------------------------------------------------------

    #[test]
    fn deletes_a_file_and_reports_it() {
        let t = TempDir::new("del");
        fs::write(t.path().join("a"), vec![b'x'; 100]).unwrap();
        let r = delete(&policy(&t), &t.s("a"), false).unwrap();
        assert_eq!(r.files_deleted, 1);
        assert_eq!(r.directories_deleted, 0);
        assert_eq!(r.bytes_freed, 100);
        assert!(!t.path().join("a").exists());
    }

    #[test]
    fn deletes_an_empty_directory() {
        let t = TempDir::new("delempty");
        fs::create_dir(t.path().join("d")).unwrap();
        let r = delete(&policy(&t), &t.s("d"), false).unwrap();
        assert_eq!(r.directories_deleted, 1);
    }

    #[test]
    fn non_recursive_delete_of_a_full_directory_fails_without_deleting_anything() {
        let t = TempDir::new("delfull");
        fs::create_dir(t.path().join("d")).unwrap();
        fs::write(t.path().join("d/keep"), b"x").unwrap();
        let e = delete(&policy(&t), &t.s("d"), false).unwrap_err();
        assert_eq!(e.kind(), "not_empty");
        assert!(t.path().join("d/keep").exists(), "nothing may be deleted on refusal");
    }

    #[test]
    fn recursive_delete_removes_a_whole_tree_and_counts_it() {
        let t = TempDir::new("deltree");
        fs::create_dir_all(t.path().join("a/b/c")).unwrap();
        fs::write(t.path().join("a/f1"), vec![b'x'; 10]).unwrap();
        fs::write(t.path().join("a/b/f2"), vec![b'x'; 20]).unwrap();
        fs::write(t.path().join("a/b/c/f3"), vec![b'x'; 30]).unwrap();
        let r = delete(&policy(&t), &t.s("a"), true).unwrap();
        assert_eq!(r.files_deleted, 3);
        assert_eq!(r.directories_deleted, 3);
        assert_eq!(r.bytes_freed, 60);
        assert!(!t.path().join("a").exists());
    }

    #[test]
    fn recursive_delete_unlinks_symlinks_and_spares_their_targets() {
        let t = TempDir::new("delsymlink");
        let precious = t.path().join("precious");
        fs::create_dir(&precious).unwrap();
        fs::write(precious.join("database.dump"), b"the only copy").unwrap();
        fs::write(precious.join("second.txt"), b"also important").unwrap();

        let doomed = t.path().join("doomed");
        fs::create_dir(&doomed).unwrap();
        fs::write(doomed.join("junk"), b"x").unwrap();
        symlink(&precious, doomed.join("link-to-precious")).unwrap();
        symlink(precious.join("database.dump"), doomed.join("link-to-file")).unwrap();

        let r = delete(&policy(&t), &t.s("doomed"), true).unwrap();
        assert!(!doomed.exists());
        assert_eq!(r.files_deleted, 3, "junk plus two links");
        assert_eq!(r.directories_deleted, 1, "the links must not be descended into");
        assert!(precious.join("database.dump").exists(), "the link target must survive");
        assert!(precious.join("second.txt").exists());
        assert_eq!(fs::read(precious.join("database.dump")).unwrap(), b"the only copy");
    }

    #[test]
    fn deleting_a_symlink_leaves_its_target_alone() {
        let t = TempDir::new("dellink");
        fs::write(t.path().join("real"), b"x").unwrap();
        symlink(t.path().join("real"), t.path().join("link")).unwrap();
        let r = delete(&policy(&t), &t.s("link"), false).unwrap();
        assert_eq!(r.files_deleted, 1);
        assert!(t.path().join("real").exists());
    }

    #[test]
    fn delete_refuses_the_filesystem_root() {
        let e = delete(&PathPolicy::whole_filesystem(), "/", true).unwrap_err();
        assert_eq!(e.kind(), "refused_dangerous");
    }

    #[test]
    fn delete_refuses_top_level_system_directories() {
        let p = PathPolicy::whole_filesystem();
        for path in ["/etc", "/home", "/usr", "/boot"] {
            let e = delete(&p, path, true).unwrap_err();
            assert_eq!(e.kind(), "refused_dangerous", "{path} must be refused");
        }
    }

    #[test]
    fn delete_refuses_critical_second_level_directories() {
        let p = PathPolicy::whole_filesystem();
        for path in ["/var/lib", "/var/log", "/usr/bin"] {
            let e = delete(&p, path, true).unwrap_err();
            assert_eq!(e.kind(), "refused_dangerous", "{path} must be refused");
        }
    }

    #[test]
    fn delete_refuses_a_configured_root_itself() {
        let t = TempDir::new("delroot");
        fs::create_dir(t.path().join("app")).unwrap();
        let p = PathPolicy::rooted_at(vec![t.path().join("app")]);
        let e = delete(&p, t.path().join("app").to_str().unwrap(), true).unwrap_err();
        assert_eq!(e.kind(), "refused_dangerous");
    }

    #[test]
    fn a_nested_path_is_deletable() {
        // The counter-example to all the refusals above: ordinary work must work.
        let t = TempDir::new("delnested");
        fs::create_dir_all(t.path().join("srv/app/cache")).unwrap();
        fs::write(t.path().join("srv/app/cache/x"), b"x").unwrap();
        delete(&policy(&t), &t.s("srv/app/cache"), true).unwrap();
        assert!(!t.path().join("srv/app/cache").exists());
        assert!(t.path().join("srv/app").exists());
    }

    #[test]
    fn delete_report_json_is_stable() {
        let r = DeleteReport { files_deleted: 3, directories_deleted: 1, bytes_freed: 4096 };
        let j = r.to_json();
        assert_eq!(j.get("files_deleted").and_then(|v| v.as_u64()), Some(3));
        assert_eq!(j.get("directories_deleted").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(j.get("bytes_freed").and_then(|v| v.as_u64()), Some(4096));
    }

    // ---- trash -----------------------------------------------------------

    #[test]
    fn trash_moves_instead_of_unlinking() {
        let t = TempDir::new("trash");
        fs::write(t.path().join("report.pdf"), b"contents").unwrap();
        let moved = move_to_trash(&policy(&t), &t.s("report.pdf")).unwrap();
        assert!(!t.path().join("report.pdf").exists());
        assert!(moved.exists(), "the file must still exist in the trash");
        assert_eq!(fs::read(&moved).unwrap(), b"contents");
        assert!(moved.starts_with(t.path().join(TRASH_DIR_NAME)));
        assert!(moved.file_name().unwrap().to_string_lossy().ends_with("-report.pdf"));
    }

    #[test]
    fn trash_moves_a_whole_directory() {
        let t = TempDir::new("trashdir");
        fs::create_dir_all(t.path().join("d/sub")).unwrap();
        fs::write(t.path().join("d/sub/f"), b"x").unwrap();
        let moved = move_to_trash(&policy(&t), &t.s("d")).unwrap();
        assert!(moved.join("sub/f").exists());
    }

    #[test]
    fn trashing_the_same_name_twice_does_not_collide() {
        let t = TempDir::new("trashtwice");
        fs::write(t.path().join("a"), b"first").unwrap();
        let one = move_to_trash(&policy(&t), &t.s("a")).unwrap();
        fs::write(t.path().join("a"), b"second").unwrap();
        let two = move_to_trash(&policy(&t), &t.s("a")).unwrap();
        assert_ne!(one, two);
        assert_eq!(fs::read(&one).unwrap(), b"first");
        assert_eq!(fs::read(&two).unwrap(), b"second");
    }

    #[test]
    fn the_trash_is_private_to_the_agent() {
        let t = TempDir::new("trashmode");
        fs::write(t.path().join("a"), b"x").unwrap();
        move_to_trash(&policy(&t), &t.s("a")).unwrap();
        let md = fs::metadata(t.path().join(TRASH_DIR_NAME)).unwrap();
        assert_eq!(md.mode() & 0o777, 0o700);
    }

    #[test]
    fn trashing_something_already_in_the_trash_is_refused() {
        let t = TempDir::new("trashagain");
        fs::write(t.path().join("a"), b"x").unwrap();
        let moved = move_to_trash(&policy(&t), &t.s("a")).unwrap();
        let e = move_to_trash(&policy(&t), moved.to_str().unwrap()).unwrap_err();
        assert_eq!(e.kind(), "refused_dangerous");
    }

    #[test]
    fn trash_refuses_dangerous_paths_too() {
        let e = move_to_trash(&PathPolicy::whole_filesystem(), "/etc").unwrap_err();
        assert_eq!(e.kind(), "refused_dangerous");
    }

    // ---- chmod -----------------------------------------------------------

    #[test]
    fn sets_the_mode() {
        let t = TempDir::new("chmod");
        fs::write(t.path().join("run.sh"), b"#!/bin/sh\n").unwrap();
        let e = set_mode(&policy(&t), &t.s("run.sh"), 0o750).unwrap();
        assert_eq!(e.mode, "0750");
        assert_eq!(e.mode_octal, 488);
        assert_eq!(fs::metadata(t.path().join("run.sh")).unwrap().mode() & 0o777, 0o750);
    }

    #[test]
    fn setuid_is_refused() {
        let t = TempDir::new("chmodsuid");
        fs::write(t.path().join("f"), b"x").unwrap();
        let e = set_mode(&policy(&t), &t.s("f"), 0o4755).unwrap_err();
        assert_eq!(e.kind(), "refused_dangerous");
        let e = set_mode(&policy(&t), &t.s("f"), 0o2755).unwrap_err();
        assert_eq!(e.kind(), "refused_dangerous");
    }

    #[test]
    fn the_sticky_bit_is_allowed() {
        let t = TempDir::new("chmodsticky");
        fs::create_dir(t.path().join("shared")).unwrap();
        let e = set_mode(&policy(&t), &t.s("shared"), 0o1777).unwrap();
        assert_eq!(e.mode, "1777");
    }

    #[test]
    fn an_out_of_range_mode_is_denied() {
        let t = TempDir::new("chmodrange");
        fs::write(t.path().join("f"), b"x").unwrap();
        let e = set_mode(&policy(&t), &t.s("f"), 0o10000).unwrap_err();
        assert_eq!(e.kind(), "denied");
    }

    // ---- upload ----------------------------------------------------------

    #[test]
    fn copies_a_spooled_upload_into_place() {
        let t = TempDir::new("upload");
        let spool = TempDir::new("uploadspool");
        let src = spool.path().join("body");
        fs::write(&src, vec![b'z'; 200_000]).unwrap();

        let e = copy_from(&policy(&t), &src, &t.s("archive.bin"), false).unwrap();
        assert_eq!(e.size_bytes, 200_000);
        assert_eq!(fs::metadata(t.path().join("archive.bin")).unwrap().len(), 200_000);
    }

    #[test]
    fn upload_refuses_to_overwrite_unless_asked() {
        let t = TempDir::new("uploaddup");
        let spool = TempDir::new("uploaddupspool");
        let src = spool.path().join("body");
        fs::write(&src, b"new").unwrap();
        fs::write(t.path().join("a"), b"old").unwrap();

        let e = copy_from(&policy(&t), &src, &t.s("a"), false).unwrap_err();
        assert_eq!(e.kind(), "already_exists");
        assert_eq!(fs::read(t.path().join("a")).unwrap(), b"old");

        copy_from(&policy(&t), &src, &t.s("a"), true).unwrap();
        assert_eq!(fs::read(t.path().join("a")).unwrap(), b"new");
    }

    #[test]
    fn upload_over_a_directory_is_refused() {
        let t = TempDir::new("uploaddir");
        let spool = TempDir::new("uploaddirspool");
        let src = spool.path().join("body");
        fs::write(&src, b"x").unwrap();
        fs::create_dir(t.path().join("d")).unwrap();
        let e = copy_from(&policy(&t), &src, &t.s("d"), true).unwrap_err();
        assert_eq!(e.kind(), "is_a_directory");
    }

    #[test]
    fn upload_respects_the_policy() {
        let t = TempDir::new("uploadpolicy");
        let spool = TempDir::new("uploadpolicyspool");
        let src = spool.path().join("body");
        fs::write(&src, b"x").unwrap();
        let e = copy_from(&PathPolicy::whole_filesystem(), &src, "/etc/serveros/agent.key", true)
            .unwrap_err();
        assert_eq!(e.kind(), "denied");
        let _ = t;
    }

    #[test]
    fn upload_preserves_the_mode_of_the_file_it_replaces() {
        let t = TempDir::new("uploadmode");
        let spool = TempDir::new("uploadmodespool");
        let src = spool.path().join("body");
        fs::write(&src, b"new").unwrap();
        let dest = t.path().join("cfg");
        fs::write(&dest, b"old").unwrap();
        fs::set_permissions(&dest, Permissions::from_mode(0o640)).unwrap();
        let e = copy_from(&policy(&t), &src, &t.s("cfg"), true).unwrap();
        assert_eq!(e.mode, "0640");
    }

    #[test]
    fn text_payload_detection_is_exposed_for_the_http_layer() {
        assert!(is_text_payload(b"server { }\n"));
        assert!(!is_text_payload(&[0u8, 1, 2, 3]));
    }
}
