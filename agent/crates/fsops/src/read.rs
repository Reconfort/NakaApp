//! Reading a file for the editor, and streaming one for download.
//!
//! The editor is the feature that makes a file browser worth having: the point
//! of ServerOS is that a user can fix `nginx.conf` without opening a terminal.
//! Two rules keep that from going wrong.
//!
//! **Never hand a binary to a text editor.** Loading `/usr/bin/nginx` into a
//! `String`, showing the user the replacement character 400 000 times and then
//! writing it back is how a working server becomes a broken one. So a file is
//! sniffed before it is read, and a failed sniff is a refusal with a name
//! ([`FsError::NotText`]) rather than a best effort.
//!
//! **Never read an unbounded amount.** The agent has no idea how much memory
//! the server can spare, and a 4 GB log opened into a `String` is a swap storm
//! at best and the OOM killer at worst. [`MAX_TEXT_BYTES`] is the ceiling, the
//! error says what the ceiling is, and the log viewer ([`crate::logs`]) exists
//! precisely so that large files have a bounded way to be read.

use crate::error::{FsError, show};
use crate::listing::{Entry, EntryKind, entry_at};
use crate::path::PathPolicy;
use serveros_json::{Object, Value};
use std::fs::File;
use std::io::Read;

/// Largest file the editor will open. Two megabytes is comfortably more than
/// any configuration file and comfortably less than a log.
pub const MAX_TEXT_BYTES: usize = 2 * 1024 * 1024;

/// How much of a file is examined to decide whether it is text.
pub const SNIFF_BYTES: usize = 8 * 1024;

/// Share of non-printable bytes above which a sample is considered binary.
pub const NON_PRINTABLE_LIMIT: f64 = 0.30;

/// A file's contents, ready for the editor.
#[derive(Debug, Clone)]
pub struct TextFile {
    /// The canonical path that was read.
    pub path: String,
    /// The decoded contents.
    pub content: String,
    /// `utf-8`, or `utf-8-lossy` when invalid sequences had to be replaced.
    pub encoding: &'static str,
    /// Number of lines.
    pub line_count: usize,
    /// Bytes returned (not necessarily the file's size, if truncated).
    pub size_bytes: u64,
    /// Whether the file was longer than what is returned.
    pub truncated: bool,
    /// `lf`, `crlf`, `cr` or `mixed`.
    pub line_ending: &'static str,
    /// Whether the agent would be unable to save changes back.
    pub readonly: bool,
}

impl TextFile {
    /// The JSON the editor decodes.
    pub fn to_json(&self) -> Value {
        Object::new()
            .set("path", self.path.as_str())
            .set("content", self.content.as_str())
            .set("encoding", self.encoding)
            .set("line_count", self.line_count)
            .set("size_bytes", self.size_bytes)
            .set("truncated", self.truncated)
            .set("line_ending", self.line_ending)
            .set("readonly", self.readonly)
            .into()
    }
}

/// Read a text file for the editor.
pub fn read_text(policy: &PathPolicy, path: &str) -> Result<TextFile, FsError> {
    let resolved = policy.resolve(path)?;
    let entry = entry_at(policy, &resolved, false)?;
    if entry.kind == EntryKind::Directory {
        return Err(FsError::IsADirectory { path: show(&resolved) });
    }
    if entry.kind != EntryKind::File {
        return Err(FsError::NotText {
            path: show(&resolved),
            reason: format!("it is a {}, not a regular file", entry.kind.as_str()),
        });
    }
    if entry.size_bytes > MAX_TEXT_BYTES as u64 {
        return Err(FsError::TooLarge {
            path: show(&resolved),
            size: entry.size_bytes,
            limit: MAX_TEXT_BYTES as u64,
        });
    }

    let mut file = File::open(&resolved).map_err(|e| FsError::io(&resolved, e))?;
    // One byte past the limit, so growth between the stat and the read is
    // detected rather than silently returning a partial file as if it were
    // whole.
    let mut bytes = Vec::with_capacity(entry.size_bytes as usize + 1);
    (&mut file)
        .take(MAX_TEXT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| FsError::io(&resolved, e))?;

    let truncated = bytes.len() > MAX_TEXT_BYTES;
    if truncated {
        bytes.truncate(MAX_TEXT_BYTES);
    }

    let sniff_len = bytes.len().min(SNIFF_BYTES);
    if !sniff_is_text(&bytes[..sniff_len]) {
        return Err(FsError::NotText {
            path: show(&resolved),
            reason: "the first 8 KiB contain a NUL byte or too many non-printable bytes"
                .to_owned(),
        });
    }

    // Lossy rather than an error: a config file with one stray Latin-1 byte in
    // a comment is still a config file the user needs to edit. The encoding
    // field tells the app that saving will normalise those bytes to U+FFFD.
    let (content, encoding) = match String::from_utf8(bytes) {
        Ok(s) => (s, "utf-8"),
        Err(e) => (String::from_utf8_lossy(e.as_bytes()).into_owned(), "utf-8-lossy"),
    };

    Ok(TextFile {
        path: show(&resolved),
        line_count: count_lines(&content),
        size_bytes: content.len() as u64,
        line_ending: detect_line_ending(&content),
        readonly: !entry.is_writable,
        truncated,
        encoding,
        content,
    })
}

/// Open a file for download, with its metadata.
///
/// The caller streams the `File`; nothing here reads it. That is deliberate —
/// download is the one operation with no size limit, and the only way to serve
/// a 4 GB backup without a 4 GB allocation is never to hold it.
pub fn open_download(policy: &PathPolicy, path: &str) -> Result<(File, Entry), FsError> {
    let resolved = policy.resolve(path)?;
    let entry = entry_at(policy, &resolved, false)?;
    if entry.kind == EntryKind::Directory {
        return Err(FsError::IsADirectory { path: show(&resolved) });
    }
    if entry.kind != EntryKind::File {
        return Err(FsError::denied(format!(
            "{} is a {} and cannot be downloaded.",
            show(&resolved),
            entry.kind.as_str()
        )));
    }
    let file = File::open(&resolved).map_err(|e| FsError::io(&resolved, e))?;
    Ok((file, entry))
}

/// Does this sample look like text?
///
/// Two rules, in the order a human would apply them:
///
/// * **A NUL byte means binary.** No text encoding the agent supports produces
///   one, and every binary format is full of them. This alone catches ELF,
///   images, archives and databases.
/// * **More than 30% non-printable means binary.** Control characters other
///   than tab, newline, carriage return and form feed are the signal. Bytes
///   ≥ 0x80 are *not* counted — they are UTF-8 continuation bytes, and counting
///   them would declare every non-English file binary.
///
/// An empty sample is text: a new file is the most editable thing there is.
pub fn sniff_is_text(sample: &[u8]) -> bool {
    if sample.is_empty() {
        return true;
    }
    let window = &sample[..sample.len().min(SNIFF_BYTES)];
    let mut non_printable = 0usize;
    for &b in window {
        if b == 0 {
            return false;
        }
        let printable = matches!(b, b'\t' | b'\n' | b'\r' | 0x0c) || (0x20..=0x7e).contains(&b) || b >= 0x80;
        if !printable {
            non_printable += 1;
        }
    }
    (non_printable as f64 / window.len() as f64) <= NON_PRINTABLE_LIMIT
}

/// Which line ending the file uses: `lf`, `crlf`, `cr` or `mixed`.
///
/// The editor needs this to write the file back the way it found it. Silently
/// converting a `crlf` file to `lf` is a 400-line diff in someone's git repo.
pub fn detect_line_ending(sample: &str) -> &'static str {
    let bytes = sample.as_bytes();
    let (mut lf, mut crlf, mut cr) = (0usize, 0usize, 0usize);
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' => {
                if bytes.get(i + 1) == Some(&b'\n') {
                    crlf += 1;
                    i += 1;
                } else {
                    cr += 1;
                }
            }
            b'\n' => lf += 1,
            _ => {}
        }
        i += 1;
    }
    match (lf > 0, crlf > 0, cr > 0) {
        (false, false, false) => "lf", // no line ending at all: the default
        (true, false, false) => "lf",
        (false, true, false) => "crlf",
        (false, false, true) => "cr",
        _ => "mixed",
    }
}

/// Lines in the editor's sense: a trailing newline does not open a new line.
fn count_lines(s: &str) -> usize {
    if s.is_empty() {
        return 0;
    }
    let n = s.lines().count();
    n.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::fs;

    fn policy(t: &TempDir) -> PathPolicy {
        PathPolicy::rooted_at(vec![t.path().to_path_buf()])
    }

    // ---- sniffing --------------------------------------------------------

    #[test]
    fn empty_is_text() {
        assert!(sniff_is_text(b""));
    }

    #[test]
    fn plain_ascii_is_text() {
        assert!(sniff_is_text(b"worker_processes auto;\nevents { }\n"));
    }

    #[test]
    fn utf8_is_text() {
        assert!(sniff_is_text("# café — naïve\nkey = «valeur»\n".as_bytes()));
    }

    #[test]
    fn a_nul_byte_means_binary() {
        assert!(!sniff_is_text(b"hello\0world"));
        assert!(!sniff_is_text(&[0x7f, b'E', b'L', b'F', 0, 0, 0, 0]));
    }

    #[test]
    fn mostly_control_bytes_mean_binary() {
        let mut sample = vec![0x01u8; 40];
        sample.extend_from_slice(b"text");
        assert!(!sniff_is_text(&sample));
    }

    #[test]
    fn a_few_control_bytes_are_tolerated() {
        // ANSI colour codes in a log file must not make it unreadable.
        let line = b"\x1b[31mERROR\x1b[0m something went wrong on the server today\n";
        assert!(sniff_is_text(line));
    }

    #[test]
    fn tabs_and_form_feeds_are_printable() {
        assert!(sniff_is_text(b"a\tb\x0cc\r\n"));
    }

    // ---- line endings ----------------------------------------------------

    #[test]
    fn line_endings_are_detected() {
        assert_eq!(detect_line_ending("a\nb\n"), "lf");
        assert_eq!(detect_line_ending("a\r\nb\r\n"), "crlf");
        assert_eq!(detect_line_ending("a\rb\r"), "cr");
        assert_eq!(detect_line_ending("a\r\nb\n"), "mixed");
        assert_eq!(detect_line_ending("no line endings"), "lf");
        assert_eq!(detect_line_ending(""), "lf");
    }

    #[test]
    fn a_lone_cr_next_to_crlf_is_mixed() {
        assert_eq!(detect_line_ending("a\r\nb\rc"), "mixed");
    }

    // ---- read_text -------------------------------------------------------

    #[test]
    fn reads_a_config_file() {
        let t = TempDir::new("readtext");
        fs::write(t.path().join("nginx.conf"), b"worker_processes auto;\nevents {\n}\n").unwrap();
        let f = read_text(&policy(&t), &t.s("nginx.conf")).unwrap();
        assert_eq!(f.line_count, 3);
        assert_eq!(f.encoding, "utf-8");
        assert_eq!(f.line_ending, "lf");
        assert!(!f.truncated);
        assert!(f.content.starts_with("worker_processes"));
        assert_eq!(f.size_bytes, 34);
    }

    #[test]
    fn json_shape_is_the_documented_one() {
        let t = TempDir::new("readjson");
        fs::write(t.path().join("a.txt"), b"one\ntwo\n").unwrap();
        let j = read_text(&policy(&t), &t.s("a.txt")).unwrap().to_json();
        assert_eq!(j.get("encoding").and_then(|v| v.as_str()), Some("utf-8"));
        assert_eq!(j.get("line_count").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(j.get("line_ending").and_then(|v| v.as_str()), Some("lf"));
        assert_eq!(j.get("truncated").and_then(|v| v.as_bool()), Some(false));
        assert!(j.get("readonly").is_some());
        assert!(j.get("content").is_some());
    }

    #[test]
    fn an_empty_file_reads_as_zero_lines() {
        let t = TempDir::new("readempty");
        fs::write(t.path().join("empty"), b"").unwrap();
        let f = read_text(&policy(&t), &t.s("empty")).unwrap();
        assert_eq!(f.line_count, 0);
        assert_eq!(f.content, "");
    }

    #[test]
    fn a_binary_file_is_refused_by_name() {
        let t = TempDir::new("readbin");
        fs::write(t.path().join("prog"), [0x7fu8, b'E', b'L', b'F', 0, 1, 2, 3]).unwrap();
        let e = read_text(&policy(&t), &t.s("prog")).unwrap_err();
        assert_eq!(e.kind(), "not_text");
        assert!(e.to_string().contains("text file"), "{e}");
    }

    #[test]
    fn an_over_large_file_is_refused_and_the_message_names_the_limit() {
        let t = TempDir::new("readbig");
        fs::write(t.path().join("huge"), vec![b'x'; MAX_TEXT_BYTES + 1]).unwrap();
        let e = read_text(&policy(&t), &t.s("huge")).unwrap_err();
        assert_eq!(e.kind(), "too_large");
        assert!(e.to_string().contains("2 MB"), "{e}");
    }

    #[test]
    fn a_file_exactly_at_the_limit_is_allowed() {
        let t = TempDir::new("readlimit");
        fs::write(t.path().join("edge"), vec![b'x'; MAX_TEXT_BYTES]).unwrap();
        let f = read_text(&policy(&t), &t.s("edge")).unwrap();
        assert!(!f.truncated);
        assert_eq!(f.size_bytes, MAX_TEXT_BYTES as u64);
    }

    #[test]
    fn invalid_utf8_is_read_lossily_and_labelled() {
        let t = TempDir::new("readlossy");
        // Latin-1 "é" in a comment, which is not valid UTF-8.
        fs::write(t.path().join("legacy.conf"), b"# caf\xe9\nkey = value\n").unwrap();
        let f = read_text(&policy(&t), &t.s("legacy.conf")).unwrap();
        assert_eq!(f.encoding, "utf-8-lossy");
        assert!(f.content.contains('\u{fffd}'));
        assert_eq!(f.line_count, 2);
    }

    #[test]
    fn a_directory_is_not_readable_as_text() {
        let t = TempDir::new("readdir");
        fs::create_dir(t.path().join("sub")).unwrap();
        let e = read_text(&policy(&t), &t.s("sub")).unwrap_err();
        assert_eq!(e.kind(), "is_a_directory");
    }

    #[test]
    fn a_denied_path_is_refused_before_it_is_read() {
        let e = read_text(&PathPolicy::whole_filesystem(), "/etc/shadow").unwrap_err();
        assert_eq!(e.kind(), "denied");
    }

    #[test]
    fn a_missing_file_is_not_found() {
        let t = TempDir::new("readmissing");
        let e = read_text(&policy(&t), &t.s("nope")).unwrap_err();
        assert_eq!(e.kind(), "not_found");
    }

    #[test]
    fn crlf_survives_the_round_trip_report() {
        let t = TempDir::new("readcrlf");
        fs::write(t.path().join("win.txt"), b"a\r\nb\r\n").unwrap();
        let f = read_text(&policy(&t), &t.s("win.txt")).unwrap();
        assert_eq!(f.line_ending, "crlf");
        assert_eq!(f.line_count, 2);
        assert!(f.content.contains("\r\n"), "content keeps the original bytes");
    }

    // ---- download --------------------------------------------------------

    #[test]
    fn download_opens_the_file_and_describes_it() {
        let t = TempDir::new("download");
        fs::write(t.path().join("backup.tar.gz"), vec![0u8; 4096]).unwrap();
        let (mut f, entry) = open_download(&policy(&t), &t.s("backup.tar.gz")).unwrap();
        assert_eq!(entry.size_bytes, 4096);
        assert!(!entry.is_text, "a .gz is not text");
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), 4096);
    }

    #[test]
    fn a_directory_cannot_be_downloaded() {
        let t = TempDir::new("downloaddir");
        fs::create_dir(t.path().join("sub")).unwrap();
        let e = open_download(&policy(&t), &t.s("sub")).unwrap_err();
        assert_eq!(e.kind(), "is_a_directory");
    }

    #[test]
    fn download_respects_the_policy() {
        let e = open_download(&PathPolicy::whole_filesystem(), "/proc/self/environ").unwrap_err();
        assert_eq!(e.kind(), "denied");
    }
}
