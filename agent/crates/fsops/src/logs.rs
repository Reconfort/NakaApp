//! Reading logs — the feature, not the utility.
//!
//! "Show me the logs" is the second thing anyone does after "is it running?",
//! and it is the operation where a naive implementation hurts most. Three
//! things make this module worth its length.
//!
//! # Tailing must not read the file
//!
//! An nginx access log is routinely four gigabytes. `read_to_string` then
//! `lines().rev().take(200)` is not slow, it is fatal: the agent allocates four
//! gigabytes on a server whose whole problem may be that it is out of memory.
//! [`tail_file`] instead seeks to the end and reads **backwards** in growing
//! chunks — 8 KiB, then 16, then 32 — until it has the newlines it needs. The
//! last 200 lines of a 4 GB file cost one or two reads of a few kilobytes.
//!
//! # Lines must be understood, not just shown
//!
//! A log viewer that shows grey monospace text is a terminal with extra steps.
//! [`parse_line`] pulls a timestamp and a severity out of the shapes real
//! software actually emits — nginx, syslog/systemd, Docker's JSON file driver,
//! Python's `logging`, Go's zap, logfmt — so the app can colour errors red,
//! filter to warnings and above, and say "this started 4 minutes ago". What it
//! cannot parse it leaves as `null`; `raw` always holds the original line, so
//! nothing is ever lost to a parser's opinion.
//!
//! # Following must survive rotation
//!
//! Logs rotate. If the follower holds an open file descriptor and `logrotate`
//! renames the file underneath it, the descriptor keeps pointing at the old
//! inode and the UI silently stops updating — the worst possible failure, since
//! it looks like "nothing is happening" exactly when something is. [`LogFollower`]
//! notices both rotation (the inode behind the path changed) and truncation
//! (`> file.log`), drains what is left of the old file first, emits a synthetic
//! line so the user can see what happened, and reopens.
//!
//! Following polls rather than using `inotify`: `inotify_init1(2)` needs libc,
//! which needs `unsafe`, which this workspace does not do. A 50 ms poll costs
//! one `stat` and one zero-byte `read` per interval and is indistinguishable
//! from instant to a human reading a log.

use crate::error::{FsError, show};
use crate::path::PathPolicy;
use crate::pattern::Matcher;
use serveros_json::{Object, Value};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// First backward read when tailing. Doubles until the request is satisfied.
pub const TAIL_CHUNK: usize = 8 * 1024;

/// Largest single backward read.
pub const MAX_TAIL_CHUNK: usize = 1024 * 1024;

/// Most bytes [`tail_file`] will scan backwards before giving up and returning
/// what it has. Bounds the work when a filter matches nothing.
pub const MAX_TAIL_BYTES: usize = 8 * 1024 * 1024;

/// Most lines any single call will return.
pub const MAX_LINES: usize = 10_000;

/// How often [`LogFollower::poll`] checks for new data.
pub const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Largest partial line held while following, before it is emitted unterminated.
pub const MAX_PENDING_LINE: usize = 1024 * 1024;

/// How far into a line a level token is looked for.
const LEVEL_WINDOW: usize = 96;

/// How far into the remainder a level may start and still be stripped from the
/// message. Beyond this it is assumed to be part of the text.
const LEVEL_STRIP_WINDOW: usize = 24;

/// Normalised severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Finest-grained tracing.
    Trace,
    /// Developer diagnostics.
    Debug,
    /// Normal operation.
    Info,
    /// Something to look at, but the system is working.
    Warn,
    /// Something failed.
    Error,
    /// Something failed and the process is probably gone.
    Fatal,
}

impl Level {
    /// The wire form: `trace`, `debug`, `info`, `warn`, `error`, `fatal`.
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "trace",
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
            Level::Fatal => "fatal",
        }
    }

    /// Map a token from any of the common vocabularies onto the six levels.
    ///
    /// `CRITICAL`, `EMERG` and `PANIC` all collapse into `fatal`: the UI has
    /// one "the process is gone" colour, and inventing three would not help
    /// anyone decide anything.
    pub fn parse(token: &str) -> Option<Level> {
        let t = token.to_ascii_lowercase();
        Some(match t.as_str() {
            "trace" | "trce" => Level::Trace,
            "debug" | "dbug" | "dbg" | "verbose" => Level::Debug,
            "info" | "information" | "notice" | "note" => Level::Info,
            "warn" | "warning" | "warns" => Level::Warn,
            "error" | "err" | "eror" => Level::Error,
            "fatal" | "critical" | "crit" | "emerg" | "emergency" | "alert" | "panic" => {
                Level::Fatal
            }
            _ => return None,
        })
    }

    /// Map a syslog priority (0–7) onto a level.
    pub fn from_priority(p: u8) -> Level {
        match p {
            0..=2 => Level::Fatal,
            3 => Level::Error,
            4 => Level::Warn,
            5 | 6 => Level::Info,
            _ => Level::Debug,
        }
    }
}

/// Where a line came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSource {
    /// A file on disk.
    File,
    /// The systemd journal.
    Journal,
    /// Synthesised by the agent (a rotation notice).
    Agent,
}

impl LogSource {
    /// The wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            LogSource::File => "file",
            LogSource::Journal => "journal",
            LogSource::Agent => "agent",
        }
    }
}

/// One parsed log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Unix seconds, when a timestamp could be parsed.
    pub timestamp: Option<i64>,
    /// Normalised severity, when one could be detected.
    pub level: Option<Level>,
    /// The line with its timestamp and level prefix removed.
    pub message: String,
    /// The original line, always.
    pub raw: String,
    /// Where it came from.
    pub source: LogSource,
}

impl LogLine {
    /// `{"timestamp":…,"level":"error","message":"…","raw":"…","source":"file"}`
    pub fn to_json(&self) -> Value {
        Object::new()
            .set("timestamp", self.timestamp)
            .set("level", self.level.map(Level::as_str))
            .set("message", self.message.as_str())
            .set("raw", self.raw.as_str())
            .set("source", self.source.as_str())
            .into()
    }

    /// A line the agent made up, to tell the user something about the stream.
    fn synthetic(message: &str) -> LogLine {
        LogLine {
            timestamp: Some(crate::now_secs()),
            level: Some(Level::Info),
            message: message.to_owned(),
            raw: message.to_owned(),
            source: LogSource::Agent,
        }
    }
}

/// What to read.
#[derive(Debug, Clone)]
pub struct LogQuery {
    /// How many lines to return, counted **after** filtering.
    pub lines: usize,
    /// Drop anything older than this (unix seconds).
    pub since: Option<i64>,
    /// Substring, or a pattern when `regex` is set.
    pub filter: Option<String>,
    /// Interpret `filter` as the bounded regex subset ([`crate::pattern`]).
    pub regex: bool,
}

impl Default for LogQuery {
    fn default() -> Self {
        LogQuery { lines: 200, since: None, filter: None, regex: false }
    }
}

impl LogQuery {
    fn want(&self) -> usize {
        self.lines.clamp(1, MAX_LINES)
    }

    fn matcher(&self) -> Result<Option<Matcher>, FsError> {
        Matcher::new(self.filter.as_deref(), self.regex)
    }
}

/// A page of log lines.
#[derive(Debug, Clone)]
pub struct LogBatch {
    /// Oldest first, which is the order a person reads.
    pub lines: Vec<LogLine>,
    /// File or journal.
    pub source: LogSource,
    /// The file that was read, if it was a file.
    pub path: Option<String>,
    /// The unit that was read, if it was the journal.
    pub unit: Option<String>,
    /// Whether the scan stopped before reaching the start of the file.
    pub truncated: bool,
}

impl LogBatch {
    /// `{"source","path","unit","lines":[…],"count","truncated"}`
    pub fn to_json(&self) -> Value {
        Object::new()
            .set("source", self.source.as_str())
            .set("path", self.path.clone())
            .set("unit", self.unit.clone())
            .set("lines", Value::Array(self.lines.iter().map(LogLine::to_json).collect()))
            .set("count", self.lines.len())
            .set("truncated", self.truncated)
            .into()
    }
}

/// Read the last N lines of a file without reading the whole file.
///
/// Seeks to the end and reads backwards in growing chunks. With a filter, the
/// scan keeps growing until it has N *matching* lines or hits
/// [`MAX_TAIL_BYTES`], so "the last 200 errors" works on a log that is mostly
/// access records.
pub fn tail_file(policy: &PathPolicy, path: &str, q: &LogQuery) -> Result<LogBatch, FsError> {
    // Validate the caller's input before touching the disk: a bad pattern is a
    // bad request, and it should say so rather than reporting whatever the
    // filesystem happened to think of the path.
    let matcher = q.matcher()?;
    let resolved = policy.resolve(path)?;
    let md = fs::metadata(&resolved).map_err(|e| FsError::io(&resolved, e))?;
    if md.is_dir() {
        return Err(FsError::IsADirectory { path: show(&resolved) });
    }
    if !md.is_file() {
        return Err(FsError::denied(format!("{} is not a regular file.", show(&resolved))));
    }
    let want = q.want();

    let mut file = File::open(&resolved).map_err(|e| FsError::io(&resolved, e))?;
    let len = md.len();

    let mut pos = len;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = TAIL_CHUNK;
    let mut lines: Vec<LogLine> = Vec::new();
    let mut truncated = false;

    while pos > 0 {
        let start = pos.saturating_sub(chunk as u64);
        let n = (pos - start) as usize;
        file.seek(SeekFrom::Start(start)).map_err(|e| FsError::io(&resolved, e))?;
        let mut head = vec![0u8; n];
        file.read_exact(&mut head).map_err(|e| FsError::io(&resolved, e))?;
        head.extend_from_slice(&buf);
        buf = head;
        pos = start;

        // The first line of the buffer is incomplete unless we reached the
        // start of the file — it began before the window.
        let text = String::from_utf8_lossy(&buf);
        lines = select_lines(&text, pos > 0, q, matcher.as_ref(), want);
        if lines.len() >= want {
            break;
        }
        if buf.len() >= MAX_TAIL_BYTES {
            truncated = true;
            break;
        }
        chunk = (chunk * 2).min(MAX_TAIL_CHUNK);
    }

    if pos == 0 && buf.is_empty() {
        // Empty file: nothing to decode, and the loop never ran.
        lines.clear();
    }
    let truncated = truncated || pos > 0;

    Ok(LogBatch {
        lines,
        source: LogSource::File,
        path: Some(show(&resolved)),
        unit: None,
        truncated,
    })
}

/// Turn a decoded window into the last `want` lines that pass the query.
///
/// `drop_first` discards the leading partial line when the window does not
/// start at the beginning of the file.
///
/// `since` treats an untimestamped line as a continuation of the line before
/// it: a Java stack trace or a wrapped nginx error has the timestamp only on
/// its first line, and dropping the rest would hide the actual error.
fn select_lines(
    text: &str,
    drop_first: bool,
    q: &LogQuery,
    matcher: Option<&Matcher>,
    want: usize,
) -> Vec<LogLine> {
    let mut out: Vec<LogLine> = Vec::new();
    let mut keeping = false;
    for (i, raw) in text.split('\n').enumerate() {
        if i == 0 && drop_first {
            continue;
        }
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if raw.is_empty() {
            continue;
        }
        let line = parse_line(raw);
        if let Some(since) = q.since {
            match line.timestamp {
                Some(ts) => {
                    keeping = ts >= since;
                    if !keeping {
                        continue;
                    }
                }
                None if !keeping => continue,
                None => {}
            }
        }
        if let Some(m) = matcher {
            if !m.is_match(&line.raw) {
                continue;
            }
        }
        out.push(line);
    }
    if out.len() > want {
        out.drain(..out.len() - want);
    }
    out
}

/// Follow a file, yielding new lines. Handles truncation and rotation.
pub fn follow_file(
    policy: &PathPolicy,
    path: &str,
    from_end: bool,
) -> Result<LogFollower, FsError> {
    let resolved = policy.resolve(path)?;
    let md = fs::metadata(&resolved).map_err(|e| FsError::io(&resolved, e))?;
    if !md.is_file() {
        return Err(FsError::denied(format!("{} is not a regular file.", show(&resolved))));
    }
    let file = File::open(&resolved).map_err(|e| FsError::io(&resolved, e))?;
    let pos = if from_end { md.len() } else { 0 };
    Ok(LogFollower {
        path: resolved,
        file: Some(file),
        pos,
        dev: md.dev(),
        ino: md.ino(),
        pending: Vec::new(),
        matcher: None,
    })
}

/// An open follow of one log file.
#[derive(Debug)]
pub struct LogFollower {
    path: PathBuf,
    file: Option<File>,
    pos: u64,
    dev: u64,
    ino: u64,
    pending: Vec<u8>,
    matcher: Option<Matcher>,
}

impl LogFollower {
    /// The file being followed.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Apply a filter to everything yielded from now on.
    pub fn set_filter(&mut self, q: &LogQuery) -> Result<(), FsError> {
        self.matcher = q.matcher()?;
        Ok(())
    }

    /// Blocking poll; returns new lines, or an empty vec on timeout.
    pub fn poll(&mut self, timeout: Duration) -> Result<Vec<LogLine>, FsError> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut out = Vec::new();
            self.drain(&mut out)?;
            if !out.is_empty() {
                return Ok(out);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(out);
            }
            std::thread::sleep(POLL_INTERVAL.min(deadline - now));
        }
    }

    /// One pass: read what is there, then check whether the file moved.
    fn drain(&mut self, out: &mut Vec<LogLine>) -> Result<(), FsError> {
        self.read_available(out)?;

        let md = match fs::metadata(&self.path) {
            Ok(md) => md,
            // The path is gone for a moment — `logrotate` between `rename` and
            // `create`. Keep the handle and try again next poll rather than
            // ending the stream.
            Err(_) => return Ok(()),
        };

        if md.ino() != self.ino || md.dev() != self.dev {
            // Everything still buffered on the old handle belongs to the user;
            // `read_available` above already took it.
            out.push(LogLine::synthetic("— log rotated; following the new file —"));
            self.reopen(&md, out)?;
        } else if md.len() < self.pos {
            out.push(LogLine::synthetic("— log truncated; reading from the start —"));
            self.pos = 0;
            self.pending.clear();
            if let Some(f) = self.file.as_mut() {
                f.seek(SeekFrom::Start(0)).map_err(|e| FsError::io(&self.path, e))?;
            }
            self.read_available(out)?;
        }
        Ok(())
    }

    fn reopen(&mut self, md: &fs::Metadata, out: &mut Vec<LogLine>) -> Result<(), FsError> {
        let file = File::open(&self.path).map_err(|e| FsError::io(&self.path, e))?;
        self.file = Some(file);
        self.dev = md.dev();
        self.ino = md.ino();
        self.pos = 0;
        self.pending.clear();
        self.read_available(out)
    }

    /// Read from `pos` to EOF, emitting only complete lines.
    fn read_available(&mut self, out: &mut Vec<LogLine>) -> Result<(), FsError> {
        let Some(file) = self.file.as_mut() else { return Ok(()) };
        file.seek(SeekFrom::Start(self.pos)).map_err(|e| FsError::io(&self.path, e))?;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buf).map_err(|e| FsError::io(&self.path, e))?;
            if n == 0 {
                break;
            }
            self.pos += n as u64;
            self.pending.extend_from_slice(&buf[..n]);
        }

        // A line with no newline yet is still being written; hold it — unless
        // it has grown absurd, in which case the writer is not line-oriented
        // and holding it forever would be a memory leak.
        let complete = match self.pending.iter().rposition(|b| *b == b'\n') {
            Some(last) => self.pending.drain(..=last).collect::<Vec<u8>>(),
            None => Vec::new(),
        };
        for line in complete.split(|b| *b == b'\n') {
            self.emit(line, out);
        }
        if self.pending.len() > MAX_PENDING_LINE {
            let held = std::mem::take(&mut self.pending);
            self.emit(&held, out);
        }
        Ok(())
    }

    fn emit(&self, bytes: &[u8], out: &mut Vec<LogLine>) {
        let text = String::from_utf8_lossy(bytes);
        let text = text.strip_suffix('\r').unwrap_or(&text);
        if text.is_empty() {
            return;
        }
        let line = parse_line(text);
        if let Some(m) = &self.matcher {
            if !m.is_match(&line.raw) {
                return;
            }
        }
        out.push(line);
    }
}

// ---- line parsing --------------------------------------------------------

/// Which timestamp shape a line began with, because the shape says what
/// follows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TsShape {
    /// `2026-09-12T09:15:00Z`, `2026-09-12 09:15:00,123`
    Iso,
    /// `2026/09/12 09:15:00` — nginx's error log
    Nginx,
    /// `Sep 12 09:15:00` — syslog, and therefore systemd's file output
    Syslog,
}

/// Parse one raw log line into a timestamp, a level and a message.
///
/// The message is the line with a **leading** timestamp and level removed and
/// nothing else: `raw` keeps the original, so a parser mistake costs nothing.
pub fn parse_line(raw: &str) -> LogLine {
    let trimmed = raw.trim_end_matches(['\n', '\r']);

    // Docker's json-file driver, zap's JSON encoder, and anything structured.
    if trimmed.starts_with('{') {
        if let Some(line) = parse_json_line(trimmed) {
            return line;
        }
    }

    let mut rest = trimmed;
    let mut level = None;

    // RFC 3164 priority: `<3>Sep 12 …`
    if let Some((lvl, consumed)) = parse_priority(rest) {
        level = Some(lvl);
        rest = &rest[consumed..];
    }

    let mut timestamp = None;
    if let Some((ts, consumed, shape)) = parse_timestamp_at(rest) {
        timestamp = Some(ts);
        rest = &rest[consumed..];
        if shape == TsShape::Syslog {
            rest = skip_host_and_tag(rest);
        }
    } else if let Some(ts) = find_clf_timestamp(rest) {
        // An access-log line: the timestamp sits in the middle and the rest of
        // the line is all payload, so nothing is stripped.
        timestamp = Some(ts);
    }

    let rest = rest.trim_start_matches([' ', '\t']);
    let mut message = rest.to_owned();
    if let Some((found, start, end)) = find_level(rest) {
        if level.is_none() {
            level = Some(found);
        }
        if start < LEVEL_STRIP_WINDOW {
            message = rest[end..].trim_start_matches([' ', '\t', '-', ':', '|', ',', ']']).to_owned();
        }
    }

    LogLine { timestamp, level, message, raw: trimmed.to_owned(), source: LogSource::File }
}

/// Structured lines: Docker's `{"log":…,"time":…}`, zap's `{"level":…,"ts":…}`,
/// and anything else that uses the same handful of key names.
fn parse_json_line(raw: &str) -> Option<LogLine> {
    let value = serveros_json::from_str(raw).ok()?;
    let obj = value.as_object()?;

    let message = ["log", "msg", "message", "MESSAGE", "event", "text"]
        .iter()
        .find_map(|k| obj.get(k).and_then(|v| v.as_str()))?
        .trim_end_matches(['\n', '\r'])
        .to_owned();

    let timestamp = ["time", "ts", "timestamp", "@timestamp", "t", "__REALTIME_TIMESTAMP"]
        .iter()
        .find_map(|k| obj.get(k).and_then(json_timestamp));

    let level = ["level", "lvl", "severity", "levelname", "PRIORITY", "log.level"]
        .iter()
        .find_map(|k| obj.get(k).and_then(json_level))
        .or_else(|| find_level(&message).map(|(l, _, _)| l));

    Some(LogLine { timestamp, level, message, raw: raw.to_owned(), source: LogSource::File })
}

/// A timestamp field may be an ISO string, seconds as a float (zap), or
/// microseconds as a numeric string (the journal).
fn json_timestamp(v: &Value) -> Option<i64> {
    if let Some(s) = v.as_str() {
        if let Some((ts, _, _)) = parse_timestamp_at(s) {
            return Some(ts);
        }
        // The journal sends microseconds in a string.
        if let Ok(n) = s.parse::<i64>() {
            return Some(scale_epoch(n as f64));
        }
        return None;
    }
    v.as_f64().map(scale_epoch)
}

/// Guess the unit of a numeric epoch by magnitude. Seconds until the year
/// 5138, so anything larger is milliseconds, then microseconds, then nanos.
fn scale_epoch(v: f64) -> i64 {
    let abs = v.abs();
    if abs >= 1e17 {
        (v / 1e9) as i64
    } else if abs >= 1e14 {
        (v / 1e6) as i64
    } else if abs >= 1e11 {
        (v / 1e3) as i64
    } else {
        v as i64
    }
}

fn json_level(v: &Value) -> Option<Level> {
    if let Some(s) = v.as_str() {
        if let Ok(p) = s.parse::<u8>() {
            return Some(Level::from_priority(p));
        }
        return Level::parse(s);
    }
    v.as_u64().map(|p| Level::from_priority(p.min(7) as u8))
}

/// `<3>` at the start of a syslog line.
fn parse_priority(s: &str) -> Option<(Level, usize)> {
    let rest = s.strip_prefix('<')?;
    let end = rest.find('>')?;
    if end == 0 || end > 3 {
        return None;
    }
    let n: u8 = rest[..end].parse().ok()?;
    // The low three bits are the severity; the rest is the facility.
    Some((Level::from_priority(n & 0x07), end + 2))
}

/// Try every leading timestamp shape. Returns the epoch, the bytes it occupied
/// and which shape matched.
fn parse_timestamp_at(s: &str) -> Option<(i64, usize, TsShape)> {
    parse_iso(s).or_else(|| parse_nginx(s)).or_else(|| parse_syslog(s))
}

/// `2026-09-12T09:15:00.123456789Z`, `2026-09-12 09:15:00,123`, `…+02:00`.
fn parse_iso(s: &str) -> Option<(i64, usize, TsShape)> {
    let b = s.as_bytes();
    let year = digits(b, 0, 4)?;
    if b.get(4)? != &b'-' {
        return None;
    }
    let month = digits(b, 5, 2)?;
    if b.get(7)? != &b'-' {
        return None;
    }
    let day = digits(b, 8, 2)?;
    if !matches!(b.get(10), Some(b'T') | Some(b't') | Some(b' ') | Some(b'_')) {
        return None;
    }
    let (h, m, sec) = clock(b, 11)?;
    let mut i = 19;
    if matches!(b.get(i), Some(b'.') | Some(b',')) {
        i += 1;
        while b.get(i).is_some_and(|c| c.is_ascii_digit()) {
            i += 1;
        }
    }
    let (offset, used) = zone(b, i);
    Some((epoch(year, month, day, h, m, sec) - offset, i + used, TsShape::Iso))
}

/// nginx's error log: `2026/09/12 09:15:00`.
fn parse_nginx(s: &str) -> Option<(i64, usize, TsShape)> {
    let b = s.as_bytes();
    let year = digits(b, 0, 4)?;
    if b.get(4)? != &b'/' {
        return None;
    }
    let month = digits(b, 5, 2)?;
    if b.get(7)? != &b'/' {
        return None;
    }
    let day = digits(b, 8, 2)?;
    if b.get(10)? != &b' ' {
        return None;
    }
    let (h, m, sec) = clock(b, 11)?;
    Some((epoch(year, month, day, h, m, sec), 19, TsShape::Nginx))
}

/// syslog: `Sep 12 09:15:00`, day space-padded to two columns.
///
/// There is no year in the format. The current year is assumed, and a
/// timestamp that lands more than a day in the future is pushed back a year —
/// which is what turns a December log read on the 2nd of January into December
/// rather than eleven months from now.
fn parse_syslog(s: &str) -> Option<(i64, usize, TsShape)> {
    let b = s.as_bytes();
    if b.len() < 15 {
        return None;
    }
    let month = month_from_name(&s[..3])?;
    if b[3] != b' ' {
        return None;
    }
    let day: i64 = s[4..6].trim().parse().ok()?;
    if b[6] != b' ' {
        return None;
    }
    let (h, m, sec) = clock(b, 7)?;
    let now = crate::now_secs();
    let (this_year, _, _) = civil_from_days(now.div_euclid(86_400));
    let mut ts = epoch(this_year, month, day, h, m, sec);
    if ts > now + 86_400 {
        ts = epoch(this_year - 1, month, day, h, m, sec);
    }
    Some((ts, 15, TsShape::Syslog))
}

/// The common-log-format timestamp inside an access-log line:
/// `[12/Sep/2026:09:15:00 +0000]`.
fn find_clf_timestamp(s: &str) -> Option<i64> {
    let open = s.find('[')?;
    if open > 120 {
        return None;
    }
    let rest = &s[open + 1..];
    let b = rest.as_bytes();
    let day = digits(b, 0, 2)?;
    if b.get(2)? != &b'/' {
        return None;
    }
    let month = month_from_name(rest.get(3..6)?)?;
    if b.get(6)? != &b'/' {
        return None;
    }
    let year = digits(b, 7, 4)?;
    if b.get(11)? != &b':' {
        return None;
    }
    let (h, m, sec) = clock(b, 12)?;
    let mut i = 20;
    if b.get(i) == Some(&b' ') {
        i += 1;
    }
    let (offset, _) = zone(b, i);
    Some(epoch(year, month, day, h, m, sec) - offset)
}

/// `HH:MM:SS` at `at`.
fn clock(b: &[u8], at: usize) -> Option<(i64, i64, i64)> {
    let h = digits(b, at, 2)?;
    if b.get(at + 2)? != &b':' {
        return None;
    }
    let m = digits(b, at + 3, 2)?;
    if b.get(at + 5)? != &b':' {
        return None;
    }
    let s = digits(b, at + 6, 2)?;
    if h > 23 || m > 59 || s > 60 {
        return None;
    }
    Some((h, m, s))
}

/// A zone suffix at `at`: `Z`, `+HH:MM`, `-HHMM`, `+HH`. Returns the offset in
/// seconds east of UTC and how many bytes it used.
///
/// A missing zone is read as UTC. The agent cannot know the host's local zone
/// without libc, and guessing wrong by a few hours on a syslog line is less
/// harmful than pretending to know.
fn zone(b: &[u8], at: usize) -> (i64, usize) {
    match b.get(at) {
        Some(b'Z') | Some(b'z') => (0, 1),
        Some(c @ (b'+' | b'-')) => {
            let sign = if *c == b'-' { -1 } else { 1 };
            let Some(h) = digits(b, at + 1, 2) else { return (0, 0) };
            let (m, used) = if b.get(at + 3) == Some(&b':') {
                (digits(b, at + 4, 2).unwrap_or(0), 6)
            } else if b.get(at + 3).is_some_and(|c| c.is_ascii_digit()) {
                (digits(b, at + 3, 2).unwrap_or(0), 5)
            } else {
                (0, 3)
            };
            (sign * (h * 3600 + m * 60), used)
        }
        _ => (0, 0),
    }
}

fn digits(b: &[u8], at: usize, n: usize) -> Option<i64> {
    let slice = b.get(at..at + n)?;
    let mut out: i64 = 0;
    for c in slice {
        if !c.is_ascii_digit() {
            return None;
        }
        out = out * 10 + (c - b'0') as i64;
    }
    Some(out)
}

fn month_from_name(s: &str) -> Option<i64> {
    Some(match s.to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    })
}

/// Civil date and time to unix seconds (Howard Hinnant's `days_from_civil`,
/// which is exact for every proleptic Gregorian date and needs no tables).
fn epoch(y: i64, m: i64, d: i64, h: i64, min: i64, s: i64) -> i64 {
    days_from_civil(y, m, d) * 86_400 + h * 3600 + min * 60 + s
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse, needed only to learn the current year for syslog lines.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Drop `host tag[pid]:` from a syslog line so the message is the message.
fn skip_host_and_tag(rest: &str) -> &str {
    let s = rest.trim_start();
    let Some(sp) = s.find(' ') else { return s };
    let after_host = s[sp + 1..].trim_start();
    match after_host.find(':') {
        // A tag is one token: `sshd[1234]:`, `kernel:`. A colon further along,
        // or one with a space before it, belongs to the message.
        Some(colon) if colon < 64 && !after_host[..colon].contains(' ') => &after_host[colon + 1..],
        _ => after_host,
    }
}

/// Find a level token that is *marked* as one.
///
/// A bare lower-case `error` in prose is not a level — "connection error while
/// retrying" would otherwise light up the UI red. Only four markings count:
/// bracketed (`[error]`), followed by a colon (`error:`), fully upper case
/// (`ERROR`), or a logfmt key (`level=error`). Returns the level and the byte
/// range it occupies, so the caller can strip it.
fn find_level(s: &str) -> Option<(Level, usize, usize)> {
    let b = s.as_bytes();
    let window = b.len().min(LEVEL_WINDOW);
    let mut i = 0usize;
    while i < window {
        if !is_word_byte(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_word_byte(b[i]) {
            i += 1;
        }
        let end = i;
        let token = &s[start..end];
        if let Some(level) = Level::parse(token) {
            let before = if start == 0 { None } else { Some(b[start - 1]) };
            let after = b.get(end).copied();
            let bracketed = before == Some(b'[') && after == Some(b']');
            let colon = after == Some(b':');
            let upper = token.chars().all(|c| !c.is_lowercase());
            let logfmt = before == Some(b'=') && is_level_key(&s[..start.saturating_sub(1)]);
            if bracketed {
                return Some((level, start - 1, end + 1));
            }
            if colon {
                return Some((level, start, end + 1));
            }
            if upper || logfmt {
                return Some((level, start, end));
            }
        }
    }
    None
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_level_key(before_equals: &str) -> bool {
    let lower = before_equals.to_ascii_lowercase();
    ["level", "lvl", "severity", "loglevel"].iter().any(|k| lower.ends_with(k))
}

// ---- the systemd journal -------------------------------------------------

/// Is there a journal to read on this host?
///
/// Both halves matter: the binary can be installed in a container that has no
/// journal at all (it comes with the systemd package), and a journal directory
/// is useless without the reader.
pub fn journal_available() -> bool {
    journalctl().is_some() && Path::new("/run/systemd/journal").exists()
}

fn journalctl() -> Option<&'static Path> {
    ["/usr/bin/journalctl", "/bin/journalctl", "/usr/sbin/journalctl"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.exists())
}

/// Read the tail of the journal, optionally for one unit.
///
/// This is the one place in the crate that runs another program, and it is
/// deliberate: `journalctl --output=json` is systemd's **documented
/// machine-readable interface** to the journal, and the alternative — parsing
/// the binary journal file format ourselves — would be a large, fragile,
/// version-coupled reimplementation of something systemd already offers as a
/// stable contract. The rules that make it safe are the ones that always apply
/// to running a program:
///
/// * an **argv**, never a shell string: nothing is word-split, globbed or
///   substituted, so a unit name containing `;` is a name, not a command;
/// * the unit name is validated against `[A-Za-z0-9:_.@-]+` before it is used
///   anyway, belt and braces;
/// * the binary is addressed by absolute path, so `$PATH` cannot redirect it;
/// * stdin is `/dev/null` and the output is captured, so it can never become
///   interactive or paged.
pub fn journal_tail(unit: Option<&str>, q: &LogQuery) -> Result<LogBatch, FsError> {
    let Some(binary) = journalctl() else {
        return Err(FsError::Unsupported {
            feature: "The systemd journal",
            reason: "journalctl is not installed",
        });
    };
    if !Path::new("/run/systemd/journal").exists() {
        return Err(FsError::Unsupported {
            feature: "The systemd journal",
            reason: "this server does not run systemd, or is inside a container without it",
        });
    }
    if let Some(unit) = unit {
        validate_unit(unit)?;
    }
    let matcher = q.matcher()?;

    let mut command = std::process::Command::new(binary);
    command
        .arg("--output=json")
        .arg("--no-pager")
        .arg(format!("--lines={}", q.want()))
        .stdin(std::process::Stdio::null());
    if let Some(unit) = unit {
        command.arg("--unit").arg(unit);
    }
    if let Some(since) = q.since {
        // systemd's time spec accepts `@<seconds since the epoch>`.
        command.arg("--since").arg(format!("@{since}"));
    }

    let output = command.output().map_err(|e| FsError::Io { path: "journalctl".into(), source: e })?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(FsError::Io {
            path: "journalctl".into(),
            source: std::io::Error::other(if detail.is_empty() {
                format!("journalctl exited with {}", output.status)
            } else {
                detail
            }),
        });
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = Vec::new();
    for raw in text.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let Some(line) = parse_journal_entry(raw) else { continue };
        if let Some(m) = &matcher {
            if !m.is_match(&line.raw) && !m.is_match(&line.message) {
                continue;
            }
        }
        lines.push(line);
    }

    Ok(LogBatch {
        lines,
        source: LogSource::Journal,
        path: None,
        unit: unit.map(str::to_owned),
        truncated: false,
    })
}

/// One `--output=json` record.
fn parse_journal_entry(raw: &str) -> Option<LogLine> {
    let value = serveros_json::from_str(raw).ok()?;
    let obj = value.as_object()?;

    let message = match obj.get("MESSAGE") {
        Some(Value::String(s)) => s.clone(),
        // A non-UTF-8 message is sent as an array of byte values.
        Some(Value::Array(bytes)) => {
            let collected: Vec<u8> =
                bytes.iter().filter_map(|v| v.as_u64()).map(|n| n as u8).collect();
            String::from_utf8_lossy(&collected).into_owned()
        }
        _ => return None,
    };

    let timestamp = obj.get("__REALTIME_TIMESTAMP").and_then(json_timestamp);
    let level = obj
        .get("PRIORITY")
        .and_then(json_level)
        .or_else(|| find_level(&message).map(|(l, _, _)| l));

    Some(LogLine { timestamp, level, message, raw: raw.to_owned(), source: LogSource::Journal })
}

/// Unit names are `[A-Za-z0-9:_.@-]+`, which is what systemd itself accepts.
fn validate_unit(unit: &str) -> Result<(), FsError> {
    if unit.is_empty() || unit.len() > 256 {
        return Err(FsError::denied("That is not a valid service name."));
    }
    let ok = unit
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'.' | b'@' | b'-'));
    if !ok {
        return Err(FsError::denied(format!(
            "\"{unit}\" is not a valid service name; service names use letters, digits and : _ . @ - only."
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::io::Write;

    fn policy(t: &TempDir) -> PathPolicy {
        PathPolicy::rooted_at(vec![t.path().to_path_buf()])
    }

    // 2026-09-12T09:15:00Z, computed by hand and cross-checked below.
    const NOON: i64 = 1_789_204_500;

    // ---- the calendar ----------------------------------------------------

    #[test]
    fn the_epoch_itself_round_trips() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn a_known_date_matches_hand_arithmetic() {
        // 56 years × 365 days + 14 leap days = 20 454 days to 2026-01-01,
        // plus 254 days to 12 September.
        assert_eq!(days_from_civil(2026, 1, 1), 20_454);
        assert_eq!(days_from_civil(2026, 9, 12), 20_708);
        assert_eq!(epoch(2026, 9, 12, 9, 15, 0), NOON);
    }

    #[test]
    fn leap_days_are_handled() {
        assert_eq!(days_from_civil(2024, 3, 1) - days_from_civil(2024, 2, 28), 2);
        assert_eq!(days_from_civil(2023, 3, 1) - days_from_civil(2023, 2, 28), 1);
        assert_eq!(days_from_civil(2000, 3, 1) - days_from_civil(2000, 2, 28), 2);
        assert_eq!(days_from_civil(1900, 3, 1) - days_from_civil(1900, 2, 28), 1);
    }

    #[test]
    fn civil_from_days_inverts_days_from_civil() {
        for (y, m, d) in [(1999, 12, 31), (2000, 1, 1), (2026, 9, 12), (2038, 1, 19)] {
            assert_eq!(civil_from_days(days_from_civil(y, m, d)), (y, m, d));
        }
    }

    // ---- timestamps ------------------------------------------------------

    #[test]
    fn iso_8601_with_zulu() {
        let (ts, used, shape) = parse_timestamp_at("2026-09-12T09:15:00Z rest").unwrap();
        assert_eq!(ts, NOON);
        assert_eq!(used, 20);
        assert_eq!(shape, TsShape::Iso);
    }

    #[test]
    fn iso_8601_with_nanoseconds_and_offset() {
        let (ts, used, _) = parse_timestamp_at("2026-09-12T11:15:00.123456789+02:00 x").unwrap();
        assert_eq!(ts, NOON, "the offset must be subtracted");
        assert_eq!(used, 35);
    }

    #[test]
    fn iso_8601_with_a_space_and_comma_milliseconds() {
        let (ts, used, _) = parse_timestamp_at("2026-09-12 09:15:00,123 - msg").unwrap();
        assert_eq!(ts, NOON);
        assert_eq!(used, 23);
    }

    #[test]
    fn a_compact_offset_is_understood() {
        let (ts, _, _) = parse_timestamp_at("2026-09-12T08:15:00-0100").unwrap();
        assert_eq!(ts, NOON);
    }

    #[test]
    fn nginx_slashes_are_understood() {
        let (ts, used, shape) = parse_timestamp_at("2026/09/12 09:15:00 [error]").unwrap();
        assert_eq!(ts, NOON);
        assert_eq!(used, 19);
        assert_eq!(shape, TsShape::Nginx);
    }

    #[test]
    fn syslog_dates_assume_the_current_year() {
        let now = crate::now_secs();
        let (year, month, day) = civil_from_days(now.div_euclid(86_400));
        let names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        let line = format!("{} {day:2} 09:15:00 host app: hi", names[(month - 1) as usize]);
        let (ts, used, shape) = parse_timestamp_at(&line).unwrap();
        assert_eq!(used, 15);
        assert_eq!(shape, TsShape::Syslog);
        assert_eq!(ts, epoch(year, month, day, 9, 15, 0));
    }

    #[test]
    fn a_syslog_date_in_the_future_rolls_back_a_year() {
        // Whatever today is, a date 60 days ahead must resolve to last year.
        let now = crate::now_secs();
        let (_, month, day) = civil_from_days(now.div_euclid(86_400) + 60);
        let names = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        let line = format!("{} {day:2} 09:15:00 host app: hi", names[(month - 1) as usize]);
        let (ts, _, _) = parse_timestamp_at(&line).unwrap();
        assert!(ts <= now + 86_400, "a log line cannot be 60 days in the future");
    }

    #[test]
    fn a_space_padded_syslog_day_parses() {
        let (_, used, shape) = parse_timestamp_at("Sep  2 09:15:00 host app: hi").unwrap();
        assert_eq!(used, 15);
        assert_eq!(shape, TsShape::Syslog);
    }

    #[test]
    fn nonsense_has_no_timestamp() {
        assert!(parse_timestamp_at("hello world").is_none());
        assert!(parse_timestamp_at("").is_none());
        assert!(parse_timestamp_at("9999-99-99T99:99:99Z").is_none());
        assert!(parse_timestamp_at("2026-09-12").is_none());
    }

    #[test]
    fn the_access_log_timestamp_is_found_in_the_middle() {
        let line = r#"10.0.0.1 - - [12/Sep/2026:09:15:00 +0000] "GET / HTTP/1.1" 200 612"#;
        assert_eq!(find_clf_timestamp(line), Some(NOON));
    }

    // ---- levels ----------------------------------------------------------

    #[test]
    fn level_vocabularies_normalise() {
        assert_eq!(Level::parse("WARNING"), Some(Level::Warn));
        assert_eq!(Level::parse("warn"), Some(Level::Warn));
        assert_eq!(Level::parse("CRITICAL"), Some(Level::Fatal));
        assert_eq!(Level::parse("emerg"), Some(Level::Fatal));
        assert_eq!(Level::parse("err"), Some(Level::Error));
        assert_eq!(Level::parse("notice"), Some(Level::Info));
        assert_eq!(Level::parse("nonsense"), None);
    }

    #[test]
    fn syslog_priorities_map_to_levels() {
        assert_eq!(Level::from_priority(0), Level::Fatal);
        assert_eq!(Level::from_priority(3), Level::Error);
        assert_eq!(Level::from_priority(4), Level::Warn);
        assert_eq!(Level::from_priority(6), Level::Info);
        assert_eq!(Level::from_priority(7), Level::Debug);
    }

    #[test]
    fn an_unmarked_lower_case_level_word_is_not_a_level() {
        let line = parse_line("connection error while retrying the upstream");
        assert_eq!(line.level, None, "prose must not light up the UI red");
        assert_eq!(line.message, "connection error while retrying the upstream");
    }

    #[test]
    fn a_logfmt_level_is_detected() {
        let line = parse_line(r#"time="2026-09-12T09:15:00Z" level=error msg="upstream down""#);
        assert_eq!(line.level, Some(Level::Error));
    }

    // ---- real log shapes -------------------------------------------------

    #[test]
    fn nginx_error_log() {
        let raw = "2026/09/12 09:15:00 [error] 1234#1234: *1 connect() failed (111: Connection refused) while connecting to upstream";
        let line = parse_line(raw);
        assert_eq!(line.timestamp, Some(NOON));
        assert_eq!(line.level, Some(Level::Error));
        assert!(line.message.starts_with("1234#1234: *1 connect() failed"), "{}", line.message);
        assert_eq!(line.raw, raw);
        assert_eq!(line.source, LogSource::File);
    }

    #[test]
    fn nginx_access_log() {
        let raw = r#"10.0.0.1 - - [12/Sep/2026:09:15:00 +0000] "GET /api/v1/servers HTTP/1.1" 502 166 "-" "ServerOS/1.0""#;
        let line = parse_line(raw);
        assert_eq!(line.timestamp, Some(NOON));
        assert_eq!(line.level, None, "an access log has no severity");
        assert_eq!(line.message, raw, "the whole line is the payload");
    }

    #[test]
    fn systemd_syslog_line() {
        let raw = "Sep 12 09:15:00 web-01 sshd[1234]: Accepted publickey for deploy from 10.0.0.5 port 54321";
        let line = parse_line(raw);
        assert!(line.timestamp.is_some());
        assert_eq!(line.message, "Accepted publickey for deploy from 10.0.0.5 port 54321");
    }

    #[test]
    fn syslog_with_a_priority_prefix() {
        let raw = "<3>Sep 12 09:15:00 web-01 kernel: Out of memory: Killed process 4242 (postgres)";
        let line = parse_line(raw);
        assert_eq!(line.level, Some(Level::Error), "priority 3 is err");
        assert_eq!(line.message, "Out of memory: Killed process 4242 (postgres)");
    }

    #[test]
    fn docker_json_file_line() {
        let raw = r#"{"log":"database timeout after 30s\n","stream":"stderr","time":"2026-09-12T09:15:00.123456789Z"}"#;
        let line = parse_line(raw);
        assert_eq!(line.timestamp, Some(NOON));
        assert_eq!(line.message, "database timeout after 30s");
        assert_eq!(line.raw, raw);
    }

    #[test]
    fn docker_json_file_line_with_an_embedded_level() {
        let raw = r#"{"log":"[ERROR] could not reach postgres\n","stream":"stderr","time":"2026-09-12T09:15:00Z"}"#;
        let line = parse_line(raw);
        assert_eq!(line.level, Some(Level::Error));
        assert_eq!(line.message, "[ERROR] could not reach postgres");
    }

    #[test]
    fn python_logging_default_format() {
        let raw = "2026-09-12 09:15:00,123 - myapp.db - ERROR - Database timeout";
        let line = parse_line(raw);
        assert_eq!(line.timestamp, Some(NOON));
        assert_eq!(line.level, Some(Level::Error));
        assert_eq!(line.message, "Database timeout");
    }

    #[test]
    fn python_logging_with_a_levelname_first() {
        let raw = "2026-09-12 09:15:00,123 WARNING Disk usage at 81%";
        let line = parse_line(raw);
        assert_eq!(line.level, Some(Level::Warn));
        assert_eq!(line.message, "Disk usage at 81%");
    }

    #[test]
    fn go_zap_console_encoder() {
        let raw = "2026-09-12T09:15:00.000Z\tERROR\tserver/main.go:42\tdatabase timeout\t{\"attempt\": 3}";
        let line = parse_line(raw);
        assert_eq!(line.timestamp, Some(NOON));
        assert_eq!(line.level, Some(Level::Error));
        assert!(line.message.starts_with("server/main.go:42"), "{}", line.message);
    }

    #[test]
    fn go_zap_json_encoder() {
        let raw = r#"{"level":"error","ts":1789204500.123,"caller":"server/main.go:42","msg":"database timeout"}"#;
        let line = parse_line(raw);
        assert_eq!(line.level, Some(Level::Error));
        assert_eq!(line.timestamp, Some(NOON));
        assert_eq!(line.message, "database timeout");
    }

    #[test]
    fn postgres_style_line() {
        let raw = "2026-09-12 09:15:00.123 UTC [4242] LOG:  database system is ready to accept connections";
        let line = parse_line(raw);
        assert_eq!(line.timestamp, Some(NOON));
    }

    #[test]
    fn a_bare_line_keeps_everything() {
        let line = parse_line("just some output");
        assert_eq!(line.timestamp, None);
        assert_eq!(line.level, None);
        assert_eq!(line.message, "just some output");
        assert_eq!(line.raw, "just some output");
    }

    #[test]
    fn line_json_matches_the_documented_shape() {
        let j = parse_line("2026/09/12 09:15:00 [error] boom").to_json();
        assert_eq!(j.get("timestamp").and_then(|v| v.as_i64()), Some(NOON));
        assert_eq!(j.get("level").and_then(|v| v.as_str()), Some("error"));
        assert_eq!(j.get("message").and_then(|v| v.as_str()), Some("boom"));
        assert_eq!(j.get("source").and_then(|v| v.as_str()), Some("file"));
        assert!(j.get("raw").is_some());

        let j = parse_line("nothing special").to_json();
        assert!(j.get("timestamp").unwrap().is_null());
        assert!(j.get("level").unwrap().is_null());
    }

    // ---- tailing ---------------------------------------------------------

    fn write_lines(path: &Path, count: usize) {
        let mut f = File::create(path).unwrap();
        for i in 0..count {
            writeln!(f, "2026/09/12 09:15:00 [info] line {i}").unwrap();
        }
    }

    #[test]
    fn tails_the_last_n_lines() {
        let t = TempDir::new("tail");
        write_lines(&t.path().join("app.log"), 1_000);
        let q = LogQuery { lines: 10, ..Default::default() };
        let batch = tail_file(&policy(&t), &t.s("app.log"), &q).unwrap();
        assert_eq!(batch.lines.len(), 10);
        assert!(batch.lines[0].message.ends_with("line 990"));
        assert!(batch.lines[9].message.ends_with("line 999"));
        assert!(batch.truncated, "there is more file above the window");
    }

    #[test]
    fn tails_a_file_larger_than_the_first_chunk() {
        let t = TempDir::new("tailbig");
        let p = t.path().join("big.log");
        // ~40 bytes a line × 20 000 ≈ 800 KB, far past the 8 KiB first read.
        write_lines(&p, 20_000);
        assert!(fs::metadata(&p).unwrap().len() > (TAIL_CHUNK * 4) as u64);

        let q = LogQuery { lines: 5, ..Default::default() };
        let started = Instant::now();
        let batch = tail_file(&policy(&t), &t.s("big.log"), &q).unwrap();
        assert_eq!(batch.lines.len(), 5);
        assert!(batch.lines[4].message.ends_with("line 19999"));
        assert!(started.elapsed().as_secs() < 5);
    }

    #[test]
    fn asking_for_more_lines_than_exist_returns_them_all() {
        let t = TempDir::new("tailshort");
        write_lines(&t.path().join("small.log"), 7);
        let q = LogQuery { lines: 500, ..Default::default() };
        let batch = tail_file(&policy(&t), &t.s("small.log"), &q).unwrap();
        assert_eq!(batch.lines.len(), 7);
        assert!(!batch.truncated, "the whole file was read");
        assert!(batch.lines[0].message.ends_with("line 0"));
    }

    #[test]
    fn an_empty_log_is_an_empty_batch() {
        let t = TempDir::new("tailempty");
        File::create(t.path().join("empty.log")).unwrap();
        let batch = tail_file(&policy(&t), &t.s("empty.log"), &LogQuery::default()).unwrap();
        assert!(batch.lines.is_empty());
        assert!(!batch.truncated);
    }

    #[test]
    fn a_file_without_a_trailing_newline_still_yields_its_last_line() {
        let t = TempDir::new("tailnonl");
        fs::write(t.path().join("a.log"), b"first\nsecond").unwrap();
        let batch = tail_file(&policy(&t), &t.s("a.log"), &LogQuery::default()).unwrap();
        assert_eq!(batch.lines.len(), 2);
        assert_eq!(batch.lines[1].message, "second");
    }

    #[test]
    fn a_substring_filter_selects_lines() {
        let t = TempDir::new("tailfilter");
        let mut f = File::create(t.path().join("a.log")).unwrap();
        for i in 0..200 {
            let level = if i % 50 == 0 { "error" } else { "info" };
            writeln!(f, "2026/09/12 09:15:00 [{level}] line {i}").unwrap();
        }
        drop(f);
        let q = LogQuery { lines: 10, filter: Some("[error]".into()), ..Default::default() };
        let batch = tail_file(&policy(&t), &t.s("a.log"), &q).unwrap();
        assert_eq!(batch.lines.len(), 4);
        assert!(batch.lines.iter().all(|l| l.level == Some(Level::Error)));
    }

    #[test]
    fn a_regex_filter_selects_lines() {
        let t = TempDir::new("tailregex");
        let mut f = File::create(t.path().join("a.log")).unwrap();
        writeln!(f, r#"10.0.0.1 - - [12/Sep/2026:09:15:00 +0000] "GET /a HTTP/1.1" 200 1"#).unwrap();
        writeln!(f, r#"10.0.0.2 - - [12/Sep/2026:09:15:01 +0000] "GET /b HTTP/1.1" 502 2"#).unwrap();
        writeln!(f, r#"10.0.0.3 - - [12/Sep/2026:09:15:02 +0000] "GET /c HTTP/1.1" 503 3"#).unwrap();
        drop(f);
        let q = LogQuery {
            lines: 10,
            filter: Some(r#"" 5[0-9][0-9] "#.into()),
            regex: true,
            ..Default::default()
        };
        let batch = tail_file(&policy(&t), &t.s("a.log"), &q).unwrap();
        assert_eq!(batch.lines.len(), 2);
    }

    #[test]
    fn a_bad_regex_is_rejected_before_the_file_is_touched() {
        let t = TempDir::new("tailbadregex");
        let q = LogQuery { filter: Some("(oops".into()), regex: true, ..Default::default() };
        let e = tail_file(&policy(&t), &t.s("missing.log"), &q).unwrap_err();
        assert_eq!(e.kind(), "invalid_pattern");
    }

    #[test]
    fn since_drops_older_lines_but_keeps_continuations() {
        let t = TempDir::new("tailsince");
        let mut f = File::create(t.path().join("a.log")).unwrap();
        writeln!(f, "2026-09-12T09:00:00Z old line").unwrap();
        writeln!(f, "    continuation of the old line").unwrap();
        writeln!(f, "2026-09-12T09:15:00Z new line").unwrap();
        writeln!(f, "    continuation of the new line").unwrap();
        drop(f);
        let q = LogQuery { lines: 100, since: Some(NOON - 60), ..Default::default() };
        let batch = tail_file(&policy(&t), &t.s("a.log"), &q).unwrap();
        assert_eq!(batch.lines.len(), 2);
        assert!(batch.lines[0].message.contains("new line"));
        assert!(batch.lines[1].message.contains("continuation of the new"));
    }

    #[test]
    fn tailing_a_directory_is_an_error() {
        let t = TempDir::new("taildir");
        fs::create_dir(t.path().join("d")).unwrap();
        let e = tail_file(&policy(&t), &t.s("d"), &LogQuery::default()).unwrap_err();
        assert_eq!(e.kind(), "is_a_directory");
    }

    #[test]
    fn tailing_respects_the_path_policy() {
        let e = tail_file(&PathPolicy::whole_filesystem(), "/proc/self/status", &LogQuery::default())
            .unwrap_err();
        assert_eq!(e.kind(), "denied");
    }

    #[test]
    fn batch_json_matches_the_documented_shape() {
        let t = TempDir::new("tailjson");
        write_lines(&t.path().join("a.log"), 3);
        let j = tail_file(&policy(&t), &t.s("a.log"), &LogQuery::default()).unwrap().to_json();
        assert_eq!(j.get("source").and_then(|v| v.as_str()), Some("file"));
        assert_eq!(j.get("count").and_then(|v| v.as_u64()), Some(3));
        assert_eq!(j.get("truncated").and_then(|v| v.as_bool()), Some(false));
        assert!(j.get("unit").unwrap().is_null());
        assert_eq!(j.get("lines").and_then(|v| v.as_array()).map(|a| a.len()), Some(3));
    }

    // ---- following -------------------------------------------------------

    #[test]
    fn follow_yields_new_lines_only() {
        let t = TempDir::new("follow");
        let p = t.path().join("app.log");
        fs::write(&p, b"before the follow\n").unwrap();

        let mut follower = follow_file(&policy(&t), &t.s("app.log"), true).unwrap();
        assert!(follower.poll(Duration::from_millis(10)).unwrap().is_empty());

        let mut f = fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "2026/09/12 09:15:00 [warn] disk at 81%").unwrap();
        f.flush().unwrap();

        let lines = follower.poll(Duration::from_secs(2)).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].level, Some(Level::Warn));
        assert!(lines[0].message.contains("disk at 81%"));
    }

    #[test]
    fn follow_from_the_start_replays_the_file() {
        let t = TempDir::new("followstart");
        fs::write(t.path().join("a.log"), b"one\ntwo\n").unwrap();
        let mut follower = follow_file(&policy(&t), &t.s("a.log"), false).unwrap();
        let lines = follower.poll(Duration::from_secs(1)).unwrap();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn follow_holds_a_partial_line_until_it_is_complete() {
        let t = TempDir::new("followpartial");
        let p = t.path().join("a.log");
        File::create(&p).unwrap();
        let mut follower = follow_file(&policy(&t), &t.s("a.log"), true).unwrap();

        let mut f = fs::OpenOptions::new().append(true).open(&p).unwrap();
        write!(f, "half a line").unwrap();
        f.flush().unwrap();
        assert!(follower.poll(Duration::from_millis(100)).unwrap().is_empty());

        writeln!(f, " and the rest").unwrap();
        f.flush().unwrap();
        let lines = follower.poll(Duration::from_secs(2)).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].message, "half a line and the rest");
    }

    #[test]
    fn follow_survives_rotation() {
        let t = TempDir::new("followrotate");
        let p = t.path().join("app.log");
        fs::write(&p, b"first generation\n").unwrap();

        let mut follower = follow_file(&policy(&t), &t.s("app.log"), true).unwrap();

        // Write, then rotate exactly as logrotate does: rename away, recreate.
        {
            let mut f = fs::OpenOptions::new().append(true).open(&p).unwrap();
            writeln!(f, "last line before rotation").unwrap();
        }
        let before = follower.poll(Duration::from_secs(2)).unwrap();
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].message, "last line before rotation");

        fs::rename(&p, t.path().join("app.log.1")).unwrap();
        fs::write(&p, b"first line after rotation\n").unwrap();

        let after = follower.poll(Duration::from_secs(2)).unwrap();
        assert!(after.len() >= 2, "expected a notice plus the new line, got {after:?}");
        assert_eq!(after[0].source, LogSource::Agent);
        assert!(after[0].message.contains("rotated"));
        assert_eq!(after[1].message, "first line after rotation");
    }

    #[test]
    fn follow_notices_a_line_written_to_the_old_file_before_rotation() {
        let t = TempDir::new("followdrain");
        let p = t.path().join("app.log");
        File::create(&p).unwrap();
        let mut follower = follow_file(&policy(&t), &t.s("app.log"), true).unwrap();

        {
            let mut f = fs::OpenOptions::new().append(true).open(&p).unwrap();
            writeln!(f, "written just before the rename").unwrap();
        }
        fs::rename(&p, t.path().join("app.log.1")).unwrap();
        fs::write(&p, b"new file\n").unwrap();

        let lines = follower.poll(Duration::from_secs(2)).unwrap();
        assert_eq!(lines[0].message, "written just before the rename", "nothing may be lost");
        assert!(lines.iter().any(|l| l.source == LogSource::Agent));
        assert!(lines.iter().any(|l| l.message == "new file"));
    }

    #[test]
    fn follow_survives_truncation() {
        let t = TempDir::new("followtruncate");
        let p = t.path().join("app.log");
        fs::write(&p, b"a line that will be truncated away\n").unwrap();
        let mut follower = follow_file(&policy(&t), &t.s("app.log"), true).unwrap();

        // `> app.log` keeps the inode and resets the length.
        let f = fs::OpenOptions::new().write(true).truncate(true).open(&p).unwrap();
        drop(f);
        fs::write(&p, b"fresh start\n").unwrap();

        let lines = follower.poll(Duration::from_secs(2)).unwrap();
        assert!(lines.iter().any(|l| l.message.contains("truncated")));
        assert!(lines.iter().any(|l| l.message == "fresh start"));
    }

    #[test]
    fn follow_applies_a_filter() {
        let t = TempDir::new("followfilter");
        let p = t.path().join("a.log");
        File::create(&p).unwrap();
        let mut follower = follow_file(&policy(&t), &t.s("a.log"), true).unwrap();
        follower
            .set_filter(&LogQuery { filter: Some("error".into()), ..Default::default() })
            .unwrap();

        let mut f = fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(f, "info: all is well").unwrap();
        writeln!(f, "error: it is not").unwrap();
        f.flush().unwrap();

        let lines = follower.poll(Duration::from_secs(2)).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].message, "it is not");
    }

    #[test]
    fn follow_reports_the_path_and_respects_the_policy() {
        let t = TempDir::new("followpath");
        fs::write(t.path().join("a.log"), b"").unwrap();
        let f = follow_file(&policy(&t), &t.s("a.log"), true).unwrap();
        assert_eq!(f.path(), t.path().join("a.log"));

        let e = follow_file(&PathPolicy::whole_filesystem(), "/etc/shadow", true).unwrap_err();
        assert_eq!(e.kind(), "denied");
    }

    #[test]
    fn poll_returns_empty_on_timeout_rather_than_blocking_forever() {
        let t = TempDir::new("followtimeout");
        fs::write(t.path().join("a.log"), b"").unwrap();
        let mut follower = follow_file(&policy(&t), &t.s("a.log"), true).unwrap();
        let started = Instant::now();
        assert!(follower.poll(Duration::from_millis(150)).unwrap().is_empty());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    // ---- the journal -----------------------------------------------------

    #[test]
    fn unit_names_are_validated() {
        for ok in ["nginx.service", "postgresql@16-main.service", "sshd", "system-getty.slice"] {
            assert!(validate_unit(ok).is_ok(), "{ok} should be accepted");
        }
        for bad in ["nginx;rm -rf /", "../etc/passwd", "unit name", "$(whoami)", "a\nb", ""] {
            assert!(validate_unit(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn a_journal_entry_is_parsed() {
        let raw = r#"{"__REALTIME_TIMESTAMP":"1789204500123456","PRIORITY":"3","MESSAGE":"Failed to start nginx.service","_SYSTEMD_UNIT":"nginx.service"}"#;
        let line = parse_journal_entry(raw).unwrap();
        assert_eq!(line.timestamp, Some(NOON));
        assert_eq!(line.level, Some(Level::Error));
        assert_eq!(line.message, "Failed to start nginx.service");
        assert_eq!(line.source, LogSource::Journal);
    }

    #[test]
    fn a_journal_entry_with_a_byte_array_message_is_parsed() {
        let raw = r#"{"__REALTIME_TIMESTAMP":"1789204500000000","PRIORITY":"6","MESSAGE":[104,105]}"#;
        let line = parse_journal_entry(raw).unwrap();
        assert_eq!(line.message, "hi");
        assert_eq!(line.level, Some(Level::Info));
    }

    #[test]
    fn a_journal_entry_without_a_message_is_skipped() {
        assert!(parse_journal_entry(r#"{"PRIORITY":"6"}"#).is_none());
        assert!(parse_journal_entry("not json").is_none());
    }

    #[test]
    fn the_journal_degrades_gracefully_where_it_does_not_exist() {
        if journal_available() {
            // On a systemd host, the read must actually work.
            let batch = journal_tail(None, &LogQuery { lines: 5, ..Default::default() }).unwrap();
            assert_eq!(batch.source, LogSource::Journal);
            return;
        }
        let e = journal_tail(None, &LogQuery::default()).unwrap_err();
        assert_eq!(e.kind(), "unsupported");
        assert!(e.to_string().contains("journal"), "{e}");
    }

    #[test]
    fn a_bad_unit_name_is_refused_whether_or_not_systemd_is_present() {
        let e = journal_tail(Some("nginx; rm -rf /"), &LogQuery::default()).unwrap_err();
        // Either "no journal here" or "that is not a unit name" — never an
        // attempt to run it.
        assert!(matches!(e.kind(), "denied" | "unsupported"), "{e}");
    }
}
