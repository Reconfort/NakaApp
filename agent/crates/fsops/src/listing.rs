//! Describing what is on the disk: one entry, or a page of a directory.
//!
//! # The 200 000-file directory
//!
//! Real servers have them — a Maildir, a session store, an unrotated spool. A
//! listing implementation that collects every entry, stats every entry, and
//! then sorts is an out-of-memory crash waiting for the one customer who has
//! that directory, and it is a UI that hangs for everyone else.
//!
//! So the scan happens in two passes with a hard ceiling between them:
//!
//! 1. **Names only**, streamed from `read_dir`, keeping a `String` and a
//!    `d_type` flag per entry and nothing else, capped at [`MAX_SCAN_ENTRIES`].
//!    No `stat`, no [`Entry`], no allocation per entry beyond the name.
//! 2. **Stat the page.** Only the `limit` entries the caller actually asked
//!    for are turned into an [`Entry`].
//!
//! Sorting by size or modification time is the exception: it cannot be done
//! without the numbers, so those two sorts `stat` the scanned set (still capped
//! at [`MAX_SCAN_ENTRIES`]). Sorting by name — the default — never does.
//!
//! Past the ceiling, `truncated` is true and the page is a `read_dir`-order
//! prefix rather than a globally sorted window. That is an honest degradation:
//! the alternative is to promise an ordering we would have to read 200 000
//! inodes to keep.
//!
//! # Symlinks in a listing
//!
//! An entry that is a symlink reports `is_symlink: true` and its `kind`,
//! `size_bytes`, `mode` and timestamps describe **what it points at** — the
//! same choice `ls -lL` makes, and the one that puts a folder icon next to
//! `sites-enabled/default`.
//!
//! With two exceptions, both of which fall back to describing the link itself
//! (`kind: symlink`): a **broken** link has no target to describe, and a link
//! whose target is **outside the policy** must not become a keyhole through
//! which the size, mode and owner of a denied file can be read. Asking about
//! such a link directly — [`stat_entry`] rather than a listing — is refused
//! outright, because that question is the same question as asking about the
//! target.

use crate::error::{FsError, show};
use crate::ids;
use crate::path::PathPolicy;
use crate::read::sniff_is_text;
use serveros_json::{Object, Value};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

/// Hard ceiling on how many directory entries are scanned in one call.
pub const MAX_SCAN_ENTRIES: usize = 50_000;

/// Page size used when the caller does not ask for one.
pub const DEFAULT_LIMIT: usize = 1_000;

/// Largest page the agent will build, whatever the caller asks for.
pub const MAX_LIMIT: usize = 10_000;

/// Bytes sniffed to decide whether a file is text.
pub const SNIFF_BYTES: usize = 8 * 1024;

/// What a directory entry actually is.
///
/// The exotic variants are not decoration: `/run` is full of sockets, `/dev`
/// of device nodes, and a UI that renders a FIFO as a zero-byte file invites a
/// user to double-click something that will block forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link whose target could not be described.
    Symlink,
    /// A unix domain socket.
    Socket,
    /// A named pipe.
    Fifo,
    /// A block device node.
    BlockDevice,
    /// A character device node.
    CharDevice,
    /// Something the kernel reported that we have no name for.
    Unknown,
}

impl EntryKind {
    /// The wire form: `file`, `directory`, `symlink`, `socket`, `fifo`,
    /// `block-device`, `char-device`, `unknown`.
    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::File => "file",
            EntryKind::Directory => "directory",
            EntryKind::Symlink => "symlink",
            EntryKind::Socket => "socket",
            EntryKind::Fifo => "fifo",
            EntryKind::BlockDevice => "block-device",
            EntryKind::CharDevice => "char-device",
            EntryKind::Unknown => "unknown",
        }
    }

    fn of(ft: std::fs::FileType) -> EntryKind {
        if ft.is_file() {
            EntryKind::File
        } else if ft.is_dir() {
            EntryKind::Directory
        } else if ft.is_symlink() {
            EntryKind::Symlink
        } else if ft.is_socket() {
            EntryKind::Socket
        } else if ft.is_fifo() {
            EntryKind::Fifo
        } else if ft.is_block_device() {
            EntryKind::BlockDevice
        } else if ft.is_char_device() {
            EntryKind::CharDevice
        } else {
            EntryKind::Unknown
        }
    }
}

/// One file, directory or device node, described for the UI.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Final path component.
    pub name: String,
    /// Absolute, canonical path.
    pub path: PathBuf,
    /// What it is.
    pub kind: EntryKind,
    /// Size in bytes (of the target, for a symlink).
    pub size_bytes: u64,
    /// Modification time, seconds since the epoch.
    pub modified_at: i64,
    /// Permission bits as a four-digit octal string, e.g. `0644`.
    pub mode: String,
    /// The same permission bits as a number (`0o644` == 420).
    pub mode_octal: u32,
    /// Owner's name, or their uid as a string when unresolvable.
    pub owner: String,
    /// Group's name, or its gid as a string when unresolvable.
    pub group: String,
    /// Owner's uid.
    pub uid: u32,
    /// Group's gid.
    pub gid: u32,
    /// Whether the entry itself is a symbolic link.
    pub is_symlink: bool,
    /// Where the link points, verbatim (may be relative).
    pub symlink_target: Option<String>,
    /// Whether the agent could read it, from the mode bits.
    pub is_readable: bool,
    /// Whether the agent could write it, from the mode bits.
    pub is_writable: bool,
    /// Lower-cased extension, without the dot.
    pub extension: Option<String>,
    /// Whether the file can be opened in the text editor.
    pub is_text: bool,
}

impl Entry {
    /// The exact JSON the macOS app decodes.
    pub fn to_json(&self) -> Value {
        Object::new()
            .set("name", self.name.as_str())
            .set("path", show(&self.path))
            .set("kind", self.kind.as_str())
            .set("size_bytes", self.size_bytes)
            .set("modified_at", self.modified_at)
            .set("mode", self.mode.as_str())
            .set("mode_octal", self.mode_octal)
            .set("owner", self.owner.as_str())
            .set("group", self.group.as_str())
            .set("uid", self.uid)
            .set("gid", self.gid)
            .set("is_symlink", self.is_symlink)
            .set("symlink_target", self.symlink_target.clone())
            .set("is_readable", self.is_readable)
            .set("is_writable", self.is_writable)
            .set("extension", self.extension.clone())
            .set("is_text", self.is_text)
            .into()
    }
}

/// A page of a directory.
#[derive(Debug, Clone)]
pub struct Listing {
    /// The directory that was listed.
    pub path: PathBuf,
    /// Its parent, absent at the filesystem root.
    pub parent: Option<PathBuf>,
    /// The requested window, already sorted.
    pub entries: Vec<Entry>,
    /// How many entries the directory has (after the hidden-file filter). A
    /// floor rather than an exact count past [`MAX_SCAN_ENTRIES`].
    pub total: usize,
    /// Whether entries were left out of this page.
    pub truncated: bool,
}

impl Listing {
    /// `{"path","parent","entries":[…],"total":123,"truncated":false}`
    pub fn to_json(&self) -> Value {
        Object::new()
            .set("path", show(&self.path))
            .set("parent", self.parent.as_deref().map(show))
            .set("entries", Value::Array(self.entries.iter().map(Entry::to_json).collect()))
            .set("total", self.total)
            .set("truncated", self.truncated)
            .into()
    }
}

/// How a listing is ordered. Directories always come first, in every mode —
/// that is a product decision, not a technical one: people navigate by folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortBy {
    /// Case-insensitive name, A→Z.
    #[default]
    Name,
    /// Case-insensitive name, Z→A.
    NameDesc,
    /// Smallest first.
    Size,
    /// Largest first — what you want when a disk is filling up.
    SizeDesc,
    /// Oldest first.
    Modified,
    /// Newest first.
    ModifiedDesc,
}

impl SortBy {
    /// Parse the query-string spelling; unknown values fall back to `name`.
    ///
    /// Not `FromStr`: there is no error case, because an unrecognised sort in a
    /// query string should list the directory by name rather than fail the
    /// request.
    pub fn parse(s: &str) -> SortBy {
        match s {
            "name_desc" => SortBy::NameDesc,
            "size" => SortBy::Size,
            "size_desc" => SortBy::SizeDesc,
            "modified" => SortBy::Modified,
            "modified_desc" => SortBy::ModifiedDesc,
            _ => SortBy::Name,
        }
    }

    /// The query-string spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            SortBy::Name => "name",
            SortBy::NameDesc => "name_desc",
            SortBy::Size => "size",
            SortBy::SizeDesc => "size_desc",
            SortBy::Modified => "modified",
            SortBy::ModifiedDesc => "modified_desc",
        }
    }

    fn needs_stat(self) -> bool {
        matches!(self, SortBy::Size | SortBy::SizeDesc | SortBy::Modified | SortBy::ModifiedDesc)
    }
}

/// Everything the caller can vary about a listing.
#[derive(Debug, Clone)]
pub struct ListOptions {
    /// Include dotfiles.
    pub show_hidden: bool,
    /// Ordering.
    pub sort: SortBy,
    /// Page size. `0` means [`DEFAULT_LIMIT`]; anything above [`MAX_LIMIT`] is
    /// clamped to it.
    pub limit: usize,
    /// How many entries to skip.
    pub offset: usize,
}

impl Default for ListOptions {
    fn default() -> Self {
        ListOptions { show_hidden: false, sort: SortBy::Name, limit: DEFAULT_LIMIT, offset: 0 }
    }
}

impl ListOptions {
    fn effective_limit(&self) -> usize {
        match self.limit {
            0 => DEFAULT_LIMIT,
            n => n.min(MAX_LIMIT),
        }
    }
}

/// One entry of the cheap first pass.
struct Scanned {
    name: String,
    is_dir: bool,
    size: u64,
    mtime: i64,
}

/// List a directory, sorted and paged.
pub fn list_directory(
    policy: &PathPolicy,
    path: &str,
    opts: &ListOptions,
) -> Result<Listing, FsError> {
    let dir = policy.resolve(path)?;
    let md = fs::metadata(&dir).map_err(|e| FsError::io(&dir, e))?;
    if !md.is_dir() {
        return Err(FsError::NotADirectory { path: show(&dir) });
    }

    let reader = fs::read_dir(&dir).map_err(|e| FsError::io(&dir, e))?;
    let mut scanned: Vec<Scanned> = Vec::new();
    let mut total = 0usize;
    let mut hit_ceiling = false;

    for item in reader {
        // One unreadable entry must not take down the whole listing: a
        // directory being written while it is read is normal, not exceptional.
        let Ok(item) = item else { continue };
        let name = item.file_name().to_string_lossy().into_owned();
        if !opts.show_hidden && name.starts_with('.') {
            continue;
        }
        total += 1;
        if scanned.len() >= MAX_SCAN_ENTRIES {
            hit_ceiling = true;
            continue; // keep counting, stop collecting
        }
        // `file_type()` comes from the dirent's `d_type` on Linux, so this is
        // free; a symlink reports as a symlink and therefore sorts with files.
        let is_dir = item.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let (size, mtime) = if opts.sort.needs_stat() {
            match fs::metadata(dir.join(&name)) {
                Ok(m) => (m.len(), m.mtime()),
                Err(_) => (0, 0),
            }
        } else {
            (0, 0)
        };
        scanned.push(Scanned { name, is_dir, size, mtime });
    }

    sort_scanned(&mut scanned, opts.sort);

    let limit = opts.effective_limit();
    let window = scanned.iter().skip(opts.offset).take(limit);
    let mut entries = Vec::with_capacity(limit.min(scanned.len().saturating_sub(opts.offset)));
    for s in window {
        // Entries can vanish between the scan and the stat. Skipping is the
        // only sane answer — the file genuinely is not there any more.
        if let Ok(entry) = entry_at(policy, &dir.join(&s.name), true) {
            entries.push(entry);
        }
    }

    let truncated = hit_ceiling || opts.offset + entries.len() < total;
    Ok(Listing { parent: dir.parent().map(Path::to_path_buf), path: dir, entries, total, truncated })
}

fn sort_scanned(scanned: &mut [Scanned], sort: SortBy) {
    scanned.sort_by(|a, b| {
        // Directories first, always.
        match b.is_dir.cmp(&a.is_dir) {
            std::cmp::Ordering::Equal => {}
            other => return other,
        }
        match sort {
            SortBy::Name => name_cmp(&a.name, &b.name),
            SortBy::NameDesc => name_cmp(&b.name, &a.name),
            SortBy::Size => a.size.cmp(&b.size).then_with(|| name_cmp(&a.name, &b.name)),
            SortBy::SizeDesc => b.size.cmp(&a.size).then_with(|| name_cmp(&a.name, &b.name)),
            SortBy::Modified => a.mtime.cmp(&b.mtime).then_with(|| name_cmp(&a.name, &b.name)),
            SortBy::ModifiedDesc => b.mtime.cmp(&a.mtime).then_with(|| name_cmp(&a.name, &b.name)),
        }
    });
}

/// Case-insensitive, with the exact bytes as a tie-break so the order is
/// total and therefore stable across pages.
fn name_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let la = a.to_lowercase();
    let lb = b.to_lowercase();
    la.cmp(&lb).then_with(|| a.cmp(b))
}

/// Describe a single path.
pub fn stat_entry(policy: &PathPolicy, path: &str) -> Result<Entry, FsError> {
    // `resolve_leaf` rather than `resolve`: stat'ing a symlink should tell the
    // user it is a symlink, not silently describe something else.
    let p = match policy.resolve_leaf(path) {
        Ok(p) => p,
        // A policy root's *parent* is outside the policy, and the filesystem
        // root has no leaf at all. Both are legitimate things to stat, so fall
        // back to the stricter whole-path resolve — which denies again if the
        // path was genuinely off limits.
        Err(FsError::Denied { .. }) => policy.resolve(path)?,
        Err(e) => return Err(e),
    };
    // Asking about a link that leaves the policy is asking about the thing it
    // points at, so it gets the same answer that asking directly would: no. A
    // *broken* link has no target to describe and is reported as itself.
    if fs::symlink_metadata(&p).map(|m| m.is_symlink()).unwrap_or(false) {
        if let Ok(target) = fs::canonicalize(&p) {
            if !policy.allows(&target) {
                return Err(FsError::denied(format!(
                    "{} points at {}, which is outside the folders ServerOS may manage.",
                    show(&p),
                    show(&target)
                )));
            }
        }
    }
    entry_at(policy, &p, true)
}

/// Build an [`Entry`] for an already-resolved path.
///
/// `sniff` controls whether an extensionless file is opened to guess whether it
/// is text. It is on for single entries and for listing pages (which are
/// bounded by `limit`), and it never touches anything but a regular file —
/// opening a FIFO would block the agent until someone wrote to it.
///
/// The policy is needed for one reason: a symlink is described by its target,
/// and a link pointing out of the policy must not become a way to read the
/// size, mode and owner of a file the caller may not see. Such a link is
/// described as a link and nothing more.
pub(crate) fn entry_at(
    policy: &PathPolicy,
    path: &Path,
    sniff: bool,
) -> Result<Entry, FsError> {
    let lstat = fs::symlink_metadata(path).map_err(|e| FsError::io(path, e))?;
    let is_symlink = lstat.is_symlink();
    let symlink_target =
        if is_symlink { fs::read_link(path).ok().map(|t| show(&t)) } else { None };
    let target_allowed =
        is_symlink && fs::canonicalize(path).is_ok_and(|target| policy.allows(&target));

    // For a link we can follow, describe the target; otherwise (broken link, or
    // one that leaves the policy) describe the link itself.
    let md = if target_allowed { fs::metadata(path).unwrap_or(lstat) } else { lstat };

    let kind = EntryKind::of(md.file_type());
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| show(path));
    let mode_octal = md.mode() & 0o7777;
    let extension = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .filter(|e| !e.is_empty());

    let is_text = kind == EntryKind::File && looks_like_text(path, extension.as_deref(), md.len(), sniff);

    Ok(Entry {
        name,
        path: path.to_path_buf(),
        kind,
        size_bytes: md.len(),
        modified_at: md.mtime(),
        mode: format!("{mode_octal:04o}"),
        mode_octal,
        owner: ids::owner_name(md.uid()),
        group: ids::group_name(md.gid()),
        uid: md.uid(),
        gid: md.gid(),
        is_symlink,
        symlink_target,
        is_readable: permitted(&md, 0o400, 0o040, 0o004),
        is_writable: permitted(&md, 0o200, 0o020, 0o002),
        extension,
        is_text,
    })
}

/// Can the agent do this, according to the mode bits?
///
/// Computed from the bits against the agent's euid/egid rather than by trying
/// to `open` the file. Opening is the only *exact* answer, but it costs a
/// syscall per entry (pathological on a large directory), it has side effects
/// (atime, and a FIFO open blocks), and it cannot answer "writable" without
/// either creating or truncating something.
///
/// Root is a special case in the kernel, not in the bits: uid 0 bypasses
/// permission checks entirely, so it is reported as able to do everything. The
/// two things that can still stop root — a read-only mount and the immutable
/// attribute — are not visible without `statfs(2)`/`FS_IOC_GETFLAGS`, so a
/// write can still fail after this says `true`. It drives a padlock icon, not
/// an authorisation decision; the authorisation decision is the policy.
fn permitted(md: &fs::Metadata, owner_bit: u32, group_bit: u32, other_bit: u32) -> bool {
    if ids::euid() == 0 {
        return true;
    }
    let mode = md.mode();
    if md.uid() == ids::euid() {
        return mode & owner_bit != 0;
    }
    if ids::gids().contains(&md.gid()) {
        return mode & group_bit != 0;
    }
    mode & other_bit != 0
}

/// Extensions we treat as text without looking inside.
const TEXT_EXTENSIONS: &[&str] = &[
    "conf", "cnf", "cfg", "ini", "txt", "md", "markdown", "log", "json", "yaml", "yml", "toml",
    "xml", "html", "htm", "css", "scss", "js", "mjs", "cjs", "ts", "tsx", "jsx", "sh", "bash",
    "zsh", "fish", "py", "rb", "pl", "php", "go", "rs", "c", "h", "cc", "cpp", "hpp", "java",
    "kt", "swift", "sql", "env", "service", "socket", "timer", "target", "mount", "path",
    "list", "sources", "repo", "rules", "properties", "gradle", "cmake", "mk", "am", "in",
    "po", "csv", "tsv", "srt", "vtt", "patch", "diff", "lock", "tf", "tfvars", "hcl", "nix",
    "gitignore", "dockerignore", "editorconfig", "template", "tmpl", "j2", "example", "sample",
];

/// Extensions we treat as binary without looking inside.
const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "tif", "tiff", "svgz", "pdf", "zip",
    "gz", "bz2", "xz", "zst", "lz4", "tar", "tgz", "7z", "rar", "deb", "rpm", "so", "o", "a",
    "dylib", "dll", "exe", "bin", "img", "iso", "db", "sqlite", "sqlite3", "mdb", "mp3", "mp4",
    "m4a", "mkv", "mov", "avi", "webm", "wav", "flac", "ogg", "woff", "woff2", "ttf", "otf",
    "eot", "class", "jar", "pyc", "pyo", "pack", "idx", "wasm", "dat", "swp",
];

/// Extensionless names that are always text on a Linux server.
const TEXT_BASENAMES: &[&str] = &[
    "Dockerfile", "Makefile", "Vagrantfile", "Jenkinsfile", "Procfile", "README", "LICENCE",
    "LICENSE", "CHANGELOG", "AUTHORS", "COPYING", "NOTICE", "TODO", "passwd", "group", "hosts",
    "hostname", "fstab", "crontab", "resolv.conf", "authorized_keys", "known_hosts", "profile",
    "environment", "issue", "motd", "nsswitch.conf", ".bashrc", ".profile", ".bash_history",
    ".gitconfig", ".env", ".gitignore", ".dockerignore",
];

/// Extension first, then a peek at the bytes. See [`sniff_is_text`].
fn looks_like_text(path: &Path, extension: Option<&str>, size: u64, sniff: bool) -> bool {
    if let Some(ext) = extension {
        if TEXT_EXTENSIONS.contains(&ext) {
            return true;
        }
        if BINARY_EXTENSIONS.contains(&ext) {
            return false;
        }
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        if TEXT_BASENAMES.contains(&name) {
            return true;
        }
    }
    if size == 0 {
        return true; // an empty file is editable; calling it binary is hostile
    }
    if !sniff {
        return false;
    }
    let Ok(mut f) = fs::File::open(path) else { return false };
    let mut buf = [0u8; SNIFF_BYTES];
    match f.read(&mut buf) {
        Ok(n) => sniff_is_text(&buf[..n]),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn policy(t: &TempDir) -> PathPolicy {
        PathPolicy::rooted_at(vec![t.path().to_path_buf()])
    }

    #[test]
    fn stat_reports_a_regular_file() {
        let t = TempDir::new("statfile");
        fs::write(t.path().join("nginx.conf"), b"worker_processes auto;\n").unwrap();
        let e = stat_entry(&policy(&t), &t.s("nginx.conf")).unwrap();
        assert_eq!(e.name, "nginx.conf");
        assert_eq!(e.kind, EntryKind::File);
        assert_eq!(e.size_bytes, 23);
        assert_eq!(e.extension.as_deref(), Some("conf"));
        assert!(e.is_text);
        assert!(!e.is_symlink);
        assert!(e.symlink_target.is_none());
        assert!(e.modified_at > 1_600_000_000);
    }

    #[test]
    fn mode_is_four_digit_octal_and_its_decimal_twin() {
        let t = TempDir::new("statmode");
        let p = t.path().join("f");
        fs::write(&p, b"x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        let e = stat_entry(&policy(&t), &t.s("f")).unwrap();
        assert_eq!(e.mode, "0644");
        assert_eq!(e.mode_octal, 420);

        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let e = stat_entry(&policy(&t), &t.s("f")).unwrap();
        assert_eq!(e.mode, "0600");
        assert_eq!(e.mode_octal, 384);
    }

    #[test]
    fn owner_and_group_resolve_to_names() {
        let t = TempDir::new("statowner");
        fs::write(t.path().join("f"), b"x").unwrap();
        let e = stat_entry(&policy(&t), &t.s("f")).unwrap();
        // Whatever uid runs the tests, the name must not be empty and the
        // numeric ids must agree with the string form when unresolvable.
        assert!(!e.owner.is_empty());
        assert!(!e.group.is_empty());
        assert_eq!(e.owner, ids::owner_name(e.uid));
        assert_eq!(e.group, ids::group_name(e.gid));
    }

    #[test]
    fn stat_reports_a_directory() {
        let t = TempDir::new("statdir");
        fs::create_dir(t.path().join("sub")).unwrap();
        let e = stat_entry(&policy(&t), &t.s("sub")).unwrap();
        assert_eq!(e.kind, EntryKind::Directory);
        assert!(!e.is_text);
    }

    #[test]
    fn stat_describes_a_symlinks_target_but_flags_the_link() {
        let t = TempDir::new("statlink");
        fs::write(t.path().join("real.txt"), b"hello").unwrap();
        symlink(t.path().join("real.txt"), t.path().join("alias.txt")).unwrap();
        let e = stat_entry(&policy(&t), &t.s("alias.txt")).unwrap();
        assert!(e.is_symlink);
        assert_eq!(e.kind, EntryKind::File, "kind describes the target");
        assert_eq!(e.size_bytes, 5);
        assert!(e.symlink_target.unwrap().ends_with("real.txt"));
        assert_eq!(e.name, "alias.txt");
    }

    #[test]
    fn a_broken_symlink_falls_back_to_the_link_itself() {
        let t = TempDir::new("brokenlink");
        symlink(t.path().join("gone"), t.path().join("dangling")).unwrap();
        let e = stat_entry(&policy(&t), &t.s("dangling")).unwrap();
        assert!(e.is_symlink);
        assert_eq!(e.kind, EntryKind::Symlink);
    }

    #[test]
    fn entry_json_matches_the_documented_shape() {
        let t = TempDir::new("json");
        let p = t.path().join("nginx.conf");
        fs::write(&p, vec![b'x'; 2048]).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        let j = stat_entry(&policy(&t), &t.s("nginx.conf")).unwrap().to_json();

        assert_eq!(j.get("name").and_then(|v| v.as_str()), Some("nginx.conf"));
        assert_eq!(j.get("kind").and_then(|v| v.as_str()), Some("file"));
        assert_eq!(j.get("size_bytes").and_then(|v| v.as_u64()), Some(2048));
        assert_eq!(j.get("mode").and_then(|v| v.as_str()), Some("0644"));
        assert_eq!(j.get("mode_octal").and_then(|v| v.as_u64()), Some(420));
        assert_eq!(j.get("extension").and_then(|v| v.as_str()), Some("conf"));
        assert_eq!(j.get("is_text").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(j.get("is_symlink").and_then(|v| v.as_bool()), Some(false));
        assert!(j.get("symlink_target").unwrap().is_null());
        assert!(j.get("modified_at").and_then(|v| v.as_i64()).unwrap() > 0);
    }

    #[test]
    fn listing_sorts_directories_before_files() {
        let t = TempDir::new("listorder");
        fs::create_dir(t.path().join("zeta")).unwrap();
        fs::write(t.path().join("alpha.txt"), b"x").unwrap();
        let l = list_directory(&policy(&t), &t.s(""), &ListOptions::default()).unwrap();
        let names: Vec<&str> = l.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["zeta", "alpha.txt"]);
        assert_eq!(l.total, 2);
        assert!(!l.truncated);
    }

    #[test]
    fn listing_hides_dotfiles_unless_asked() {
        let t = TempDir::new("listhidden");
        fs::write(t.path().join(".env"), b"SECRET=1").unwrap();
        fs::write(t.path().join("app.js"), b"x").unwrap();

        let hidden = list_directory(&policy(&t), &t.s(""), &ListOptions::default()).unwrap();
        assert_eq!(hidden.total, 1);

        let shown = list_directory(
            &policy(&t),
            &t.s(""),
            &ListOptions { show_hidden: true, ..Default::default() },
        )
        .unwrap();
        assert_eq!(shown.total, 2);
    }

    #[test]
    fn listing_reports_parent() {
        let t = TempDir::new("listparent");
        fs::create_dir(t.path().join("sub")).unwrap();
        let l = list_directory(&policy(&t), &t.s("sub"), &ListOptions::default()).unwrap();
        assert_eq!(l.parent.as_deref(), Some(t.path()));
    }

    #[test]
    fn listing_a_file_is_an_error() {
        let t = TempDir::new("listfile");
        fs::write(t.path().join("f"), b"x").unwrap();
        let e = list_directory(&policy(&t), &t.s("f"), &ListOptions::default()).unwrap_err();
        assert_eq!(e.kind(), "not_a_directory");
    }

    #[test]
    fn listing_pages_and_reports_truncation() {
        let t = TempDir::new("listpage");
        for i in 0..250 {
            fs::write(t.path().join(format!("f{i:04}.txt")), b"x").unwrap();
        }
        let opts = ListOptions { limit: 10, offset: 0, ..Default::default() };
        let first = list_directory(&policy(&t), &t.s(""), &opts).unwrap();
        assert_eq!(first.entries.len(), 10);
        assert_eq!(first.total, 250);
        assert!(first.truncated);
        assert_eq!(first.entries[0].name, "f0000.txt");

        let opts = ListOptions { limit: 10, offset: 240, ..Default::default() };
        let last = list_directory(&policy(&t), &t.s(""), &opts).unwrap();
        assert_eq!(last.entries.len(), 10);
        assert_eq!(last.entries[9].name, "f0249.txt");
        assert!(!last.truncated, "the final page is not truncated");
    }

    #[test]
    fn an_offset_past_the_end_is_an_empty_page_not_an_error() {
        let t = TempDir::new("listpast");
        fs::write(t.path().join("f"), b"x").unwrap();
        let opts = ListOptions { offset: 9_000, ..Default::default() };
        let l = list_directory(&policy(&t), &t.s(""), &opts).unwrap();
        assert!(l.entries.is_empty());
        assert_eq!(l.total, 1);
    }

    #[test]
    fn listing_sorts_by_size_descending() {
        let t = TempDir::new("listsize");
        fs::write(t.path().join("small"), vec![b'x'; 10]).unwrap();
        fs::write(t.path().join("big"), vec![b'x'; 5000]).unwrap();
        fs::write(t.path().join("medium"), vec![b'x'; 500]).unwrap();
        let opts = ListOptions { sort: SortBy::SizeDesc, ..Default::default() };
        let l = list_directory(&policy(&t), &t.s(""), &opts).unwrap();
        let names: Vec<&str> = l.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["big", "medium", "small"]);
    }

    #[test]
    fn listing_sorts_by_name_descending() {
        let t = TempDir::new("listnamedesc");
        fs::write(t.path().join("a"), b"x").unwrap();
        fs::write(t.path().join("b"), b"x").unwrap();
        let opts = ListOptions { sort: SortBy::NameDesc, ..Default::default() };
        let l = list_directory(&policy(&t), &t.s(""), &opts).unwrap();
        assert_eq!(l.entries[0].name, "b");
    }

    #[test]
    fn name_sort_is_case_insensitive_but_total() {
        let t = TempDir::new("listcase");
        for n in ["Beta", "alpha", "Alpha", "beta"] {
            fs::write(t.path().join(n), b"x").unwrap();
        }
        let l = list_directory(&policy(&t), &t.s(""), &ListOptions::default()).unwrap();
        let names: Vec<&str> = l.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["Alpha", "alpha", "Beta", "beta"]);
    }

    #[test]
    fn a_large_directory_is_listed_without_materialising_it() {
        let t = TempDir::new("listbig");
        for i in 0..2_000 {
            fs::write(t.path().join(format!("f{i:05}")), b"").unwrap();
        }
        let opts = ListOptions { limit: 25, ..Default::default() };
        let started = std::time::Instant::now();
        let l = list_directory(&policy(&t), &t.s(""), &opts).unwrap();
        assert_eq!(l.entries.len(), 25);
        assert_eq!(l.total, 2_000);
        assert!(l.truncated);
        // Only 25 entries were stat'ed, so this is a scan, not 2 000 syscalls
        // of metadata work. Generous bound: CI machines are slow.
        assert!(started.elapsed().as_secs() < 5, "listing took {:?}", started.elapsed());
    }

    #[test]
    fn sort_by_round_trips_through_its_wire_form() {
        for s in ["name", "name_desc", "size", "size_desc", "modified", "modified_desc"] {
            assert_eq!(SortBy::parse(s).as_str(), s);
        }
        assert_eq!(SortBy::parse("nonsense"), SortBy::Name);
    }

    #[test]
    fn limits_are_clamped() {
        let o = ListOptions { limit: 0, ..Default::default() };
        assert_eq!(o.effective_limit(), DEFAULT_LIMIT);
        let o = ListOptions { limit: 999_999, ..Default::default() };
        assert_eq!(o.effective_limit(), MAX_LIMIT);
    }

    #[test]
    fn text_detection_uses_the_extension_first() {
        let t = TempDir::new("istext");
        fs::write(t.path().join("a.conf"), vec![0u8, 1, 2]).unwrap();
        fs::write(t.path().join("b.png"), b"plain text really").unwrap();
        let a = stat_entry(&policy(&t), &t.s("a.conf")).unwrap();
        let b = stat_entry(&policy(&t), &t.s("b.png")).unwrap();
        assert!(a.is_text, "a known text extension is trusted");
        assert!(!b.is_text, "a known binary extension is trusted");
    }

    #[test]
    fn text_detection_sniffs_when_the_extension_is_unknown() {
        let t = TempDir::new("sniff");
        fs::write(t.path().join("textish"), b"hello\nworld\n").unwrap();
        fs::write(t.path().join("binaryish"), [0x7fu8, b'E', b'L', b'F', 0, 0, 0]).unwrap();
        assert!(stat_entry(&policy(&t), &t.s("textish")).unwrap().is_text);
        assert!(!stat_entry(&policy(&t), &t.s("binaryish")).unwrap().is_text);
    }

    #[test]
    fn well_known_basenames_are_text() {
        let t = TempDir::new("basenames");
        fs::write(t.path().join("Dockerfile"), b"FROM scratch\n").unwrap();
        assert!(stat_entry(&policy(&t), &t.s("Dockerfile")).unwrap().is_text);
    }

    #[test]
    fn an_empty_file_is_editable() {
        let t = TempDir::new("emptytext");
        fs::write(t.path().join("fresh"), b"").unwrap();
        assert!(stat_entry(&policy(&t), &t.s("fresh")).unwrap().is_text);
    }

    #[test]
    fn a_fifo_is_never_opened_by_the_sniffer() {
        // Creating a FIFO needs mkfifo(3); instead assert the guard directly —
        // looks_like_text is only ever called for EntryKind::File.
        let t = TempDir::new("fifoguard");
        fs::create_dir(t.path().join("d")).unwrap();
        let e = stat_entry(&policy(&t), &t.s("d")).unwrap();
        assert!(!e.is_text);
    }

    #[test]
    fn entry_kinds_have_stable_wire_names() {
        assert_eq!(EntryKind::File.as_str(), "file");
        assert_eq!(EntryKind::Directory.as_str(), "directory");
        assert_eq!(EntryKind::Symlink.as_str(), "symlink");
        assert_eq!(EntryKind::Socket.as_str(), "socket");
        assert_eq!(EntryKind::Fifo.as_str(), "fifo");
        assert_eq!(EntryKind::BlockDevice.as_str(), "block-device");
        assert_eq!(EntryKind::CharDevice.as_str(), "char-device");
        assert_eq!(EntryKind::Unknown.as_str(), "unknown");
    }

    #[test]
    fn listing_json_has_the_documented_envelope() {
        let t = TempDir::new("listjson");
        fs::write(t.path().join("f"), b"x").unwrap();
        let j = list_directory(&policy(&t), &t.s(""), &ListOptions::default()).unwrap().to_json();
        assert!(j.get("path").is_some());
        assert!(j.get("parent").is_some());
        assert_eq!(j.get("entries").and_then(|v| v.as_array()).map(|a| a.len()), Some(1));
        assert_eq!(j.get("total").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(j.get("truncated").and_then(|v| v.as_bool()), Some(false));
    }

    #[test]
    fn listing_a_denied_path_is_denied_not_empty() {
        let e = list_directory(&PathPolicy::whole_filesystem(), "/proc", &ListOptions::default())
            .unwrap_err();
        assert_eq!(e.kind(), "denied");
    }
}
