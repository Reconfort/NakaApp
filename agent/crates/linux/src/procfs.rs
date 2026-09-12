//! The low-level reading habits every other module in this crate shares.
//!
//! `/proc` and `/sys` are not ordinary files. They lie about their length
//! (`stat` reports 0), they can vanish between `read_dir` and `open` (a process
//! exits), and they are populated by whichever kernel the customer happens to
//! run — fields appear, disappear and change column count across versions.
//!
//! Three rules come out of that, and they are enforced here rather than
//! repeated in five modules:
//!
//!   1. **Read whole files, never seek.** `read_to_string` on a procfs file is
//!      a single atomic snapshot from the kernel's point of view. Reading in
//!      chunks can interleave with kernel updates and produce a file that never
//!      existed.
//!   2. **Missing is normal, not exceptional.** A container without
//!      `/sys/class/dmi` is healthy. `read_text_opt` exists so callers can say
//!      "absent means unknown" without an error-handling ceremony.
//!   3. **Never index blindly.** Every accessor here returns `Option`, so a
//!      truncated file degrades a single field instead of panicking the agent.

use crate::error::LinuxError;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

/// Read a whole procfs file, attaching the path to any I/O error.
pub fn read_text(path: &str) -> Result<String, LinuxError> {
    fs::read_to_string(path).map_err(|e| LinuxError::io(path, e))
}

/// Read a whole file, treating "missing" and "not permitted" as `None`.
///
/// Used for every source that is genuinely optional on some systems:
/// `/etc/shadow` (needs root), `/sys/class/dmi/*` (absent in containers),
/// `~/.ssh/authorized_keys` (may not exist).
pub fn read_text_opt(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

/// Read a file whose contents are not guaranteed to be UTF-8, replacing any
/// invalid bytes.
///
/// `/proc/<pid>/cmdline` is the motivating case: argv is a byte array, and a
/// process started with a latin-1 filename produces bytes `read_to_string`
/// rejects outright. Losing the whole command line over one mis-encoded byte
/// would make that process look like a kernel thread.
pub fn read_lossy_opt(path: &str) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read a single-line file and trim it, yielding `None` when it is missing or
/// blank. `/proc/sys/kernel/hostname` and `/sys/class/net/*/operstate` are the
/// motivating cases — one value, one trailing newline.
pub fn read_line_opt(path: &str) -> Option<String> {
    let text = read_text_opt(path)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Wall-clock seconds since the Unix epoch.
///
/// Falls back to 0 rather than panicking if the clock is before the epoch,
/// which only happens on a machine whose RTC has not been set — exactly the
/// sort of machine an agent must keep running on.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Find the line `key:` in a `/proc/meminfo`-style file and return its value in
/// **bytes**, converting from the kB the kernel reports.
///
/// Matching is exact on the key, so `MemTotal` never matches `MemTotalHuge`.
/// A value with no unit suffix is taken as bytes (a few `status` fields are
/// plain counts), which is why the unit is inspected rather than assumed.
pub fn kv_bytes(text: &str, key: &str) -> Option<u64> {
    let rest = kv_raw(text, key)?;
    let mut parts = rest.split_whitespace();
    let number: u64 = parts.next()?.parse().ok()?;
    match parts.next() {
        Some(u) if u.eq_ignore_ascii_case("kb") => Some(number.saturating_mul(1024)),
        Some(u) if u.eq_ignore_ascii_case("mb") => Some(number.saturating_mul(1024 * 1024)),
        _ => Some(number),
    }
}

/// The raw text after `key:` in a `Key:\tvalue` file, trimmed.
pub fn kv_raw<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(key) else {
            continue;
        };
        let Some(rest) = rest.strip_prefix(':') else {
            continue; // `MemTotalFoo:` must not match `MemTotal`.
        };
        return Some(rest.trim());
    }
    None
}

/// The value after `key` in a `/proc/cpuinfo`-style file, where the separator
/// is a colon surrounded by arbitrary whitespace and the key itself contains
/// spaces (`model name`, `cpu MHz`).
pub fn colon_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let (lhs, rhs) = line.split_once(':')?;
    if lhs.trim() == key { Some(rhs.trim()) } else { None }
}

/// The `n`-th whitespace-separated field of a line (0-based).
pub fn field(line: &str, n: usize) -> Option<&str> {
    line.split_whitespace().nth(n)
}

/// The first line of `text`, or `""`.
pub fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or("")
}

/// Parse a `u64`, tolerating surrounding whitespace. Returns `None` rather than
/// 0 on garbage so callers can distinguish "absent" from "genuinely zero".
pub fn parse_u64(s: &str) -> Option<u64> {
    s.trim().parse().ok()
}

/// Parse an `f64`, rejecting non-finite results. `/proc` occasionally reports
/// `nan` for a cpu frequency on a suspended core; a NaN that reaches the JSON
/// writer would serialise as `0` and silently lie, so it is filtered here.
pub fn parse_f64(s: &str) -> Option<f64> {
    let v: f64 = s.trim().parse().ok()?;
    if v.is_finite() { Some(v) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEMINFO: &str = "\
MemTotal:        8216192 kB
MemFree:         6474612 kB
MemAvailable:    7527360 kB
Buffers:           66136 kB
HugePages_Total:       0
";

    #[test]
    fn kv_bytes_converts_kb() {
        assert_eq!(kv_bytes(MEMINFO, "MemTotal"), Some(8_216_192 * 1024));
        assert_eq!(kv_bytes(MEMINFO, "Buffers"), Some(66_136 * 1024));
    }

    #[test]
    fn kv_bytes_treats_unitless_as_bytes() {
        assert_eq!(kv_bytes(MEMINFO, "HugePages_Total"), Some(0));
    }

    #[test]
    fn kv_bytes_matches_the_whole_key_only() {
        // `MemTotal` must not be found by looking for `Mem`.
        assert_eq!(kv_bytes(MEMINFO, "Mem"), None);
        assert_eq!(kv_bytes(MEMINFO, "Total"), None);
    }

    #[test]
    fn kv_bytes_on_missing_and_garbage() {
        assert_eq!(kv_bytes(MEMINFO, "SwapTotal"), None);
        assert_eq!(kv_bytes("MemTotal:   not-a-number kB", "MemTotal"), None);
        assert_eq!(kv_bytes("MemTotal:", "MemTotal"), None);
        assert_eq!(kv_bytes("", "MemTotal"), None);
    }

    #[test]
    fn colon_value_handles_tabbed_cpuinfo() {
        assert_eq!(colon_value("model name\t: Intel Xeon", "model name"), Some("Intel Xeon"));
        assert_eq!(colon_value("cpu MHz\t\t: 2799.998", "cpu MHz"), Some("2799.998"));
        assert_eq!(colon_value("model name\t: x", "cpu MHz"), None);
        assert_eq!(colon_value("no colon here", "model name"), None);
    }

    #[test]
    fn field_and_first_line_never_panic() {
        assert_eq!(field("a b  c", 2), Some("c"));
        assert_eq!(field("a b  c", 9), None);
        assert_eq!(field("", 0), None);
        assert_eq!(first_line("one\ntwo"), "one");
        assert_eq!(first_line(""), "");
    }

    #[test]
    fn numeric_parsers_reject_garbage_and_nan() {
        assert_eq!(parse_u64(" 42 "), Some(42));
        assert_eq!(parse_u64("4.2"), None);
        assert_eq!(parse_f64("1.5"), Some(1.5));
        assert_eq!(parse_f64("nan"), None);
        assert_eq!(parse_f64("inf"), None);
    }

    #[test]
    fn missing_files_are_none_not_errors() {
        assert!(read_text_opt("/proc/definitely-not-a-real-file").is_none());
        assert!(read_line_opt("/proc/definitely-not-a-real-file").is_none());
        assert!(read_lossy_opt("/proc/definitely-not-a-real-file").is_none());
        assert!(read_text("/proc/definitely-not-a-real-file").is_err());
    }

    #[test]
    fn lossy_read_accepts_a_file_strict_utf8_would_reject() {
        // `/proc/self/cmdline` of the test harness: NUL-separated and always
        // readable, which is the shape `read_lossy_opt` exists for.
        let raw = read_lossy_opt("/proc/self/cmdline").expect("own cmdline is readable");
        assert!(!raw.is_empty());
    }

    #[test]
    fn read_error_message_contains_path() {
        let err = read_text("/proc/definitely-not-a-real-file").unwrap_err();
        assert!(err.to_string().contains("definitely-not-a-real-file"), "{err}");
    }

    #[test]
    fn now_unix_is_after_2020() {
        assert!(now_unix() > 1_577_836_800);
    }
}
