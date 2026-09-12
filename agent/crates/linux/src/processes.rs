//! The process table, read by walking `/proc/<pid>/`.
//!
//! # Two things that bite everyone who parses `/proc/<pid>/stat`
//!
//! **The second field is not safe to split on.** It is the executable name in
//! parentheses, and the kernel does not escape it — a process named
//! `a (weird) name` produces `1234 (a (weird) name) S 1 ...`. Splitting on
//! whitespace shifts every subsequent field and yields a process whose parent
//! pid is the letter `S`. The only correct parse is to find the **last** `)` in
//! the line and treat everything after it as field 3 onward, which is what
//! [`parse_stat`] does.
//!
//! **Processes disappear while you read them.** Between `read_dir("/proc")` and
//! `open("/proc/1234/stat")` the process can exit, and every read in this
//! module can therefore fail with `ENOENT` on a perfectly healthy system. A
//! vanished pid is silently skipped; it is not an error, it is a process that
//! finished.
//!
//! # CPU percentage
//!
//! `cpu_percent` is lifetime-average CPU — total CPU time divided by wall-clock
//! time since the process started — which is what `ps %cpu` reports. It is
//! deliberately *not* `top`'s instantaneous figure: that needs a second sample
//! of every process, doubling the walk cost of a call whose whole job is to
//! answer "what is eating this box" quickly. A process spinning right now shows
//! up in the system CPU metric and in its own rising average.

use crate::error::LinuxError;
use crate::procfs;
use crate::system::parse_uptime_secs;
use crate::users;
use serveros_json::{Object, Value, round};

/// Kernel clock ticks per second — the unit of `utime`, `stime` and
/// `starttime` in `/proc/<pid>/stat`.
///
/// The portable way to obtain this is `sysconf(_SC_CLK_TCK)`, which is libc and
/// therefore `unsafe`, which this crate forbids. 100 is correct for every
/// target ServerOS supports: `CONFIG_HZ` affects the *timer* frequency, but
/// USER_HZ — the unit procfs reports in — has been fixed at 100 on Linux for
/// every architecture since 2.6, precisely so that userspace could stop asking.
/// Alpha is the historical exception at 1024, and Linux/Alpha has been dead for
/// two decades.
pub const CLOCK_TICKS: u64 = 100;

/// How to order a process listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortKey {
    /// Busiest first — the default, because "what is eating my server" is the
    /// question this screen exists to answer.
    #[default]
    Cpu,
    /// Largest resident set first.
    Memory,
    /// Ascending pid, i.e. roughly oldest first.
    Pid,
    /// Alphabetical by executable name, case-insensitive.
    Name,
}

/// What to list.
#[derive(Debug, Clone)]
pub struct ProcessQuery {
    /// Case-insensitive substring matched against name, command line and user.
    pub search: Option<String>,
    pub sort: SortKey,
    /// Maximum rows to return; `0` means no limit.
    pub limit: usize,
}

impl Default for ProcessQuery {
    fn default() -> Self {
        // 50 rows fills a window without making the agent serialise a thousand
        // objects the user will never scroll to.
        ProcessQuery { search: None, sort: SortKey::Cpu, limit: 50 }
    }
}

/// One running process.
#[derive(Debug, Clone, PartialEq)]
pub struct Process {
    pub pid: u32,
    pub ppid: u32,
    /// `comm` — the executable name, truncated to 15 characters by the kernel.
    pub name: String,
    /// Full command line, or `[name]` for a kernel thread.
    pub command: String,
    /// Owner's name; `None` when the uid is not in `/etc/passwd`.
    pub user: Option<String>,
    pub uid: u32,
    /// Human-readable run state: `running`, `sleeping`, `disk-sleep`,
    /// `stopped`, `zombie`, `idle`, `unknown`.
    pub state: &'static str,
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub memory_percent: f64,
    pub threads: u32,
    /// Unix time the process started.
    pub started_at: u64,
}

impl Process {
    /// Serialise in the exact shape the macOS app decodes.
    pub fn to_json(&self) -> Value {
        Object::new()
            .set("pid", self.pid)
            .set("ppid", self.ppid)
            .set("name", self.name.as_str())
            .set("command", self.command.as_str())
            .set("user", Value::from(self.user.clone()))
            .set("uid", self.uid)
            .set("state", self.state)
            .set("cpu_percent", self.cpu_percent)
            .set("memory_bytes", self.memory_bytes)
            .set("memory_percent", self.memory_percent)
            .set("threads", self.threads)
            .set("started_at", self.started_at)
            .into()
    }
}

/// `[{...}, {...}]` for a list of processes.
pub fn process_json(list: &[Process]) -> Value {
    Value::Array(list.iter().map(Process::to_json).collect())
}

/// The subset of `/proc/<pid>/stat` this crate uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatFields {
    pub pid: u32,
    /// `comm`, without its parentheses.
    pub name: String,
    /// The raw single-letter state code.
    pub state: char,
    pub ppid: u32,
    /// User-mode CPU time in clock ticks.
    pub utime: u64,
    /// Kernel-mode CPU time in clock ticks.
    pub stime: u64,
    pub threads: u32,
    /// Clock ticks between boot and this process starting.
    pub starttime: u64,
}

/// The subset of `/proc/<pid>/status` this crate uses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusFields {
    /// Real uid — the first of the four in the `Uid:` row.
    pub uid: Option<u32>,
    /// Resident set size in bytes, from `VmRSS`.
    ///
    /// Read from `status` rather than from `stat`'s field 24 on purpose: that
    /// field is in *pages*, and converting it needs `sysconf(_SC_PAGESIZE)`,
    /// which is libc. `VmRSS` is already in kB, so no page size is assumed and
    /// the number is right on a 16k-page arm64 host too.
    pub rss_bytes: Option<u64>,
    /// `Name:` — the same value as `comm`, used when `stat` is unreadable.
    pub name: Option<String>,
}

/// List processes matching `q`.
///
/// Fails only if `/proc` cannot be enumerated. Individual processes that vanish
/// or refuse to be read mid-walk are skipped.
pub fn list_processes(q: &ProcessQuery) -> Result<Vec<Process>, LinuxError> {
    // Read the shared context once. Doing any of this per-process would turn a
    // 500-process walk into 2000 extra file reads.
    let uptime = procfs::read_text_opt("/proc/uptime").and_then(|t| parse_uptime_secs(&t));
    let boot_time = procfs::read_text_opt("/proc/stat")
        .and_then(|t| crate::system::parse_btime(&t))
        .unwrap_or(0);
    let mem_total = procfs::read_text_opt("/proc/meminfo")
        .and_then(|t| procfs::kv_bytes(&t, "MemTotal"))
        .unwrap_or(0);
    let uid_names = users::uid_name_map();
    let cpu_ceiling = 100.0
        * std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as f64;

    let dir = std::fs::read_dir("/proc").map_err(|e| LinuxError::io("/proc", e))?;
    let mut out = Vec::new();
    for entry in dir.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue; // `/proc/self`, `/proc/meminfo`, ... are not processes
        };
        if let Some(p) =
            read_process(pid, uptime, boot_time, mem_total, &uid_names, cpu_ceiling)
        {
            out.push(p);
        }
    }

    if let Some(needle) = q.search.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let needle = needle.to_lowercase();
        out.retain(|p| matches_search(p, &needle));
    }
    sort_processes(&mut out, q.sort);
    if q.limit > 0 && out.len() > q.limit {
        out.truncate(q.limit);
    }
    Ok(out)
}

/// Read one process, or `None` if it vanished or is unreadable.
fn read_process(
    pid: u32,
    uptime: Option<f64>,
    boot_time: u64,
    mem_total: u64,
    uid_names: &[(u32, String)],
    cpu_ceiling: f64,
) -> Option<Process> {
    let base = format!("/proc/{pid}");
    // `stat` is mandatory: without it there is no state, parent or CPU time,
    // and a row of zeroes would be worse than an absent row.
    let stat = parse_stat(&procfs::read_text_opt(&format!("{base}/stat"))?)?;
    let status = procfs::read_text_opt(&format!("{base}/status"))
        .map(|t| parse_status(&t))
        .unwrap_or_default();
    let cmdline = procfs::read_lossy_opt(&format!("{base}/cmdline")).unwrap_or_default();

    let memory_bytes = status.rss_bytes.unwrap_or(0);
    let uid = status.uid.unwrap_or(0);

    Some(Process {
        pid: stat.pid,
        ppid: stat.ppid,
        command: parse_cmdline(&cmdline, &stat.name),
        name: stat.name,
        user: uid_names.iter().find(|(u, _)| *u == uid).map(|(_, n)| n.clone()),
        uid,
        state: state_name(stat.state),
        cpu_percent: round(
            cpu_percent(stat.utime, stat.stime, stat.starttime, uptime, cpu_ceiling),
            1,
        ),
        memory_bytes,
        memory_percent: round(memory_percent(memory_bytes, mem_total), 1),
        threads: stat.threads,
        started_at: boot_time.saturating_add(stat.starttime / CLOCK_TICKS),
    })
}

// ---- parsers (pure, so they can be tested against fixtures) ---------------

/// Parse `/proc/<pid>/stat`.
///
/// Fields are numbered as in `proc(5)`, 1-based. Everything after the last `)`
/// starts at field 3, so field N lives at offset `N - 3` in the tail.
pub fn parse_stat(text: &str) -> Option<StatFields> {
    let line = procfs::first_line(text);
    let open = line.find('(')?;
    // LAST `)`, not the first: `comm` may itself contain parentheses.
    let close = line.rfind(')')?;
    if close < open {
        return None;
    }

    let pid = procfs::parse_u64(line[..open].trim())? as u32;
    let name = line[open + 1..close].to_string();

    let tail: Vec<&str> = line[close + 1..].split_whitespace().collect();
    // Offset of field N (1-based, N >= 3) within `tail`.
    let f = |n: usize| tail.get(n - 3).copied();
    // A missing numeric column reads as 0: a truncated `stat` should cost that
    // one number, not the whole process row.
    let num = |n: usize| f(n).and_then(procfs::parse_u64).unwrap_or(0);

    Some(StatFields {
        pid,
        name,
        state: f(3).and_then(|s| s.chars().next()).unwrap_or('?'),
        ppid: num(4) as u32,
        utime: num(14),
        stime: num(15),
        threads: (num(20) as u32).max(1),
        starttime: num(22),
    })
}

/// Parse the handful of `/proc/<pid>/status` rows this crate needs.
pub fn parse_status(text: &str) -> StatusFields {
    StatusFields {
        // `Uid: <real> <effective> <saved> <fs>` — the real uid is the owner.
        uid: procfs::kv_raw(text, "Uid")
            .and_then(|v| procfs::field(v, 0).and_then(procfs::parse_u64))
            .map(|v| v as u32),
        rss_bytes: procfs::kv_bytes(text, "VmRSS"),
        name: procfs::kv_raw(text, "Name").map(str::to_string),
    }
}

/// Turn a NUL-separated `/proc/<pid>/cmdline` into a display string.
///
/// An empty cmdline means a kernel thread (it has no userspace argv), which is
/// why those are shown as `[kworker/0:1]` — the same convention `ps` uses, so
/// the list matches what an administrator expects to see.
pub fn parse_cmdline(raw: &str, name: &str) -> String {
    let joined = raw
        .split('\0')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let joined = joined.trim();
    if joined.is_empty() { format!("[{name}]") } else { joined.to_string() }
}

/// Map the single-letter state code from `stat` to a word the UI can show.
pub fn state_name(code: char) -> &'static str {
    match code {
        'R' => "running",
        'S' => "sleeping",
        // Uninterruptible sleep: almost always blocked on I/O, and the reason a
        // "hung" process cannot be killed. Worth its own label.
        'D' => "disk-sleep",
        'T' => "stopped",
        't' => "tracing-stop",
        'Z' => "zombie",
        // Since 4.2, idle kernel threads report `I` instead of `S` so they stop
        // inflating the load average.
        'I' => "idle",
        'X' | 'x' => "dead",
        'K' => "wakekill",
        'W' => "waking",
        'P' => "parked",
        _ => "unknown",
    }
}

/// Lifetime-average CPU use, as a percentage of one core.
///
/// Returns 0.0 when uptime is unknown or the process claims to have started in
/// the future — both happen transiently on a machine whose clock has just been
/// stepped, and neither is worth failing a listing over. The ceiling is
/// `100 * cores`, because a genuinely multithreaded process legitimately uses
/// more than one core's worth.
pub fn cpu_percent(
    utime: u64,
    stime: u64,
    starttime: u64,
    uptime_secs: Option<f64>,
    ceiling: f64,
) -> f64 {
    let Some(uptime) = uptime_secs else {
        return 0.0;
    };
    let used = utime.saturating_add(stime) as f64 / CLOCK_TICKS as f64;
    let alive = uptime - (starttime as f64 / CLOCK_TICKS as f64);
    if !alive.is_finite() || alive <= 0.0 {
        return 0.0;
    }
    let pct = used / alive * 100.0;
    if pct.is_finite() { pct.clamp(0.0, ceiling.max(100.0)) } else { 0.0 }
}

/// Resident set as a percentage of installed memory.
pub fn memory_percent(rss_bytes: u64, mem_total: u64) -> f64 {
    if mem_total == 0 {
        return 0.0;
    }
    let pct = rss_bytes as f64 / mem_total as f64 * 100.0;
    if pct.is_finite() { pct.clamp(0.0, 100.0) } else { 0.0 }
}

/// Does this process match the (already lowercased) search needle?
fn matches_search(p: &Process, needle: &str) -> bool {
    p.name.to_lowercase().contains(needle)
        || p.command.to_lowercase().contains(needle)
        || p.user.as_deref().is_some_and(|u| u.to_lowercase().contains(needle))
}

/// Order a listing in place.
///
/// Both numeric sorts break ties on pid so that a refresh of an idle machine
/// does not reshuffle rows under the user's cursor.
pub fn sort_processes(list: &mut [Process], key: SortKey) {
    match key {
        SortKey::Cpu => list.sort_by(|a, b| {
            b.cpu_percent
                .partial_cmp(&a.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.pid.cmp(&b.pid))
        }),
        SortKey::Memory => {
            list.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes).then(a.pid.cmp(&b.pid)))
        }
        SortKey::Pid => list.sort_by_key(|p| p.pid),
        SortKey::Name => list.sort_by(|a, b| {
            a.name.to_lowercase().cmp(&b.name.to_lowercase()).then(a.pid.cmp(&b.pid))
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `/proc/1/stat` from a running container.
    const STAT_PID1: &str = "1 (process_api) S 0 0 0 0 -1 4194560 13227 170 0 0 53 280 0 0 20 0 9 0 36 22614016 1367 18446744073709551615 1 1 0 0 0 0 0 4096 1088 0 0 0 17 1 0 0 0 0 0 0 0 0 0 0 0 0 0\n";

    /// Real `/proc/<pid>/status`, abridged to the rows we read plus neighbours
    /// that must not be confused with them.
    const STATUS: &str = "\
Name:\tprocess_api
Umask:\t0022
State:\tS (sleeping)
Tgid:\t1
Pid:\t1
PPid:\t0
TracerPid:\t0
Uid:\t33\t33\t33\t33
Gid:\t33\t33\t33\t33
VmPeak:\t   23548 kB
VmSize:\t   22084 kB
VmHWM:\t   11644 kB
VmRSS:\t    5656 kB
RssAnon:\t    2200 kB
Threads:\t9
";

    // ---- stat ------------------------------------------------------------

    #[test]
    fn stat_parses_a_real_pid_1() {
        let s = parse_stat(STAT_PID1).unwrap();
        assert_eq!(s.pid, 1);
        assert_eq!(s.name, "process_api");
        assert_eq!(s.state, 'S');
        assert_eq!(s.ppid, 0);
        assert_eq!(s.utime, 53);
        assert_eq!(s.stime, 280);
        assert_eq!(s.threads, 9);
        assert_eq!(s.starttime, 36);
    }

    #[test]
    fn stat_handles_a_comm_with_spaces_and_parentheses() {
        // The case that breaks every naive whitespace split.
        let line = "1234 (a (weird) name) S 1 1234 1234 0 -1 4194304 100 0 0 0 11 22 0 0 20 0 4 0 9876 1000 200";
        let s = parse_stat(line).unwrap();
        assert_eq!(s.pid, 1234);
        assert_eq!(s.name, "a (weird) name");
        assert_eq!(s.state, 'S');
        assert_eq!(s.ppid, 1);
        assert_eq!(s.utime, 11);
        assert_eq!(s.stime, 22);
        assert_eq!(s.threads, 4);
        assert_eq!(s.starttime, 9876);
    }

    #[test]
    fn stat_handles_a_comm_that_is_only_parentheses() {
        let s = parse_stat("7 (()) R 1 0 0 0 -1 0 0 0 0 0 1 2 0 0 20 0 1 0 5").unwrap();
        assert_eq!(s.name, "()");
        assert_eq!(s.state, 'R');
        assert_eq!(s.ppid, 1);
    }

    #[test]
    fn stat_handles_a_kernel_thread_name_with_a_slash() {
        let s =
            parse_stat("42 (kworker/0:1-events) I 2 0 0 0 -1 69238880 0 0 0 0 0 5 0 0 20 0 1 0 77")
                .unwrap();
        assert_eq!(s.name, "kworker/0:1-events");
        assert_eq!(state_name(s.state), "idle");
    }

    #[test]
    fn stat_truncated_after_the_comm_yields_zeroes_not_a_panic() {
        let s = parse_stat("99 (short) S").unwrap();
        assert_eq!(s.pid, 99);
        assert_eq!(s.state, 'S');
        assert_eq!(s.ppid, 0);
        assert_eq!(s.utime, 0);
        assert_eq!(s.threads, 1, "thread count is never zero");
    }

    #[test]
    fn stat_rejects_input_it_cannot_trust() {
        assert!(parse_stat("").is_none());
        assert!(parse_stat("no parens here").is_none());
        assert!(parse_stat("notapid (x) S 1").is_none());
        assert!(parse_stat(") backwards ( S 1").is_none());
    }

    #[test]
    fn stat_survives_non_numeric_columns() {
        let s = parse_stat("5 (x) S 1 0 0 0 -1 0 0 0 0 0 BAD 22 0 0 20 0 3 0 40").unwrap();
        assert_eq!(s.utime, 0);
        assert_eq!(s.stime, 22);
        assert_eq!(s.threads, 3);
    }

    // ---- status ----------------------------------------------------------

    #[test]
    fn status_reads_uid_rss_and_name() {
        let s = parse_status(STATUS);
        assert_eq!(s.uid, Some(33), "the real uid, not the effective one");
        assert_eq!(s.rss_bytes, Some(5656 * 1024));
        assert_eq!(s.name.as_deref(), Some("process_api"));
    }

    #[test]
    fn status_does_not_confuse_vmrss_with_vmpeak_or_rssanon() {
        let s = parse_status(STATUS);
        assert_ne!(s.rss_bytes, Some(23548 * 1024));
        assert_ne!(s.rss_bytes, Some(2200 * 1024));
    }

    #[test]
    fn status_of_a_kernel_thread_has_no_rss() {
        let s = parse_status("Name:\tkthreadd\nUid:\t0\t0\t0\t0\n");
        assert_eq!(s.rss_bytes, None);
        assert_eq!(s.uid, Some(0));
    }

    #[test]
    fn status_empty_or_malformed_is_all_none() {
        assert_eq!(parse_status(""), StatusFields::default());
        assert_eq!(parse_status("Uid:\tnope\n").uid, None);
        assert_eq!(parse_status("VmRSS:\t kB\n").rss_bytes, None);
    }

    // ---- cmdline ---------------------------------------------------------

    #[test]
    fn cmdline_joins_nul_separated_arguments() {
        assert_eq!(parse_cmdline("nginx\0-g\0daemon off;\0", "nginx"), "nginx -g daemon off;");
        assert_eq!(parse_cmdline("/usr/bin/env\0", "env"), "/usr/bin/env");
    }

    #[test]
    fn cmdline_empty_means_kernel_thread() {
        assert_eq!(parse_cmdline("", "kworker/0:1"), "[kworker/0:1]");
        assert_eq!(parse_cmdline("\0\0\0", "kthreadd"), "[kthreadd]");
        assert_eq!(parse_cmdline("   ", "ksoftirqd/0"), "[ksoftirqd/0]");
    }

    // ---- state -----------------------------------------------------------

    #[test]
    fn state_codes_map_to_words() {
        assert_eq!(state_name('R'), "running");
        assert_eq!(state_name('S'), "sleeping");
        assert_eq!(state_name('D'), "disk-sleep");
        assert_eq!(state_name('T'), "stopped");
        assert_eq!(state_name('Z'), "zombie");
        assert_eq!(state_name('I'), "idle");
        assert_eq!(state_name('?'), "unknown");
        assert_eq!(state_name('\u{0}'), "unknown");
    }

    // ---- percentages -----------------------------------------------------

    #[test]
    fn cpu_percent_is_cpu_time_over_lifetime() {
        // 500 ticks = 5s of CPU, over 10s alive (uptime 20s, started at tick
        // 1000 = second 10) => 50%.
        assert_eq!(cpu_percent(300, 200, 1000, Some(20.0), 400.0), 50.0);
    }

    #[test]
    fn cpu_percent_allows_a_multithreaded_process_past_100() {
        // 4 cores' worth of CPU time over its lifetime.
        assert_eq!(cpu_percent(4000, 0, 0, Some(10.0), 400.0), 400.0);
        // ...but never past the ceiling.
        assert_eq!(cpu_percent(999_999, 0, 0, Some(1.0), 400.0), 400.0);
    }

    #[test]
    fn cpu_percent_guards_every_degenerate_denominator() {
        assert_eq!(cpu_percent(100, 100, 0, None, 100.0), 0.0);
        // Started "after" the current uptime: clock stepped.
        assert_eq!(cpu_percent(100, 100, 5000, Some(10.0), 100.0), 0.0);
        // Started exactly now.
        assert_eq!(cpu_percent(100, 100, 1000, Some(10.0), 100.0), 0.0);
        assert!(cpu_percent(1, 1, 0, Some(f64::NAN), 100.0).is_finite());
    }

    #[test]
    fn memory_percent_guards_a_zero_total() {
        assert_eq!(memory_percent(1024, 0), 0.0);
        assert_eq!(memory_percent(512, 1024), 50.0);
        assert_eq!(memory_percent(9999, 1024), 100.0, "clamped, never 976%");
    }

    // ---- query -----------------------------------------------------------

    fn proc_row(pid: u32, name: &str, cpu: f64, mem: u64, user: Option<&str>) -> Process {
        Process {
            pid,
            ppid: 1,
            name: name.to_string(),
            command: format!("/usr/bin/{name} --serve"),
            user: user.map(String::from),
            uid: 0,
            state: "sleeping",
            cpu_percent: cpu,
            memory_bytes: mem,
            memory_percent: 0.0,
            threads: 1,
            started_at: 1_757_600_000,
        }
    }

    fn sample_rows() -> Vec<Process> {
        vec![
            proc_row(3, "nginx", 1.2, 40_000_000, Some("www-data")),
            proc_row(1, "systemd", 0.1, 10_000_000, Some("root")),
            proc_row(2, "postgres", 9.5, 900_000_000, Some("postgres")),
            proc_row(4, "Redis", 9.5, 5_000_000, Some("redis")),
        ]
    }

    #[test]
    fn sorting_by_cpu_is_descending_and_stable_on_pid() {
        let mut rows = sample_rows();
        sort_processes(&mut rows, SortKey::Cpu);
        let pids: Vec<u32> = rows.iter().map(|p| p.pid).collect();
        assert_eq!(pids, vec![2, 4, 3, 1], "9.5 ties broken by ascending pid");
    }

    #[test]
    fn sorting_by_memory_pid_and_name() {
        let mut rows = sample_rows();
        sort_processes(&mut rows, SortKey::Memory);
        assert_eq!(rows[0].name, "postgres");

        let mut rows = sample_rows();
        sort_processes(&mut rows, SortKey::Pid);
        assert_eq!(rows.iter().map(|p| p.pid).collect::<Vec<_>>(), vec![1, 2, 3, 4]);

        let mut rows = sample_rows();
        sort_processes(&mut rows, SortKey::Name);
        // Case-insensitive: "Redis" sorts after "postgres", not before "nginx".
        assert_eq!(
            rows.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["nginx", "postgres", "Redis", "systemd"]
        );
    }

    #[test]
    fn search_matches_name_command_and_user_case_insensitively() {
        let rows = sample_rows();
        assert!(matches_search(&rows[0], "NGINX".to_lowercase().as_str()));
        assert!(matches_search(&rows[0], "www-data"));
        assert!(matches_search(&rows[0], "/usr/bin"));
        assert!(!matches_search(&rows[0], "postgres"));
        // A process with no resolved user must not panic the matcher.
        let anon = proc_row(9, "x", 0.0, 0, None);
        assert!(!matches_search(&anon, "root"));
    }

    #[test]
    fn default_query_is_busiest_first_and_bounded() {
        let q = ProcessQuery::default();
        assert_eq!(q.sort, SortKey::Cpu);
        assert!(q.limit > 0);
        assert!(q.search.is_none());
    }

    // ---- JSON ------------------------------------------------------------

    #[test]
    fn process_json_has_the_documented_shape() {
        let p = Process {
            pid: 1234,
            ppid: 1,
            name: "nginx".into(),
            command: "nginx: worker process".into(),
            user: Some("www-data".into()),
            uid: 33,
            state: "sleeping",
            cpu_percent: 1.2,
            memory_bytes: 41_943_040,
            memory_percent: 0.5,
            threads: 4,
            started_at: 1_757_600_000,
        };
        let v = p.to_json();
        assert_eq!(v.get("pid").and_then(|v| v.as_u64()), Some(1234));
        assert_eq!(v.get("name").and_then(|v| v.as_str()), Some("nginx"));
        assert_eq!(v.get("command").and_then(|v| v.as_str()), Some("nginx: worker process"));
        assert_eq!(v.get("user").and_then(|v| v.as_str()), Some("www-data"));
        assert_eq!(v.get("state").and_then(|v| v.as_str()), Some("sleeping"));
        assert_eq!(v.get("cpu_percent").and_then(|v| v.as_f64()), Some(1.2));
        assert_eq!(v.get("memory_bytes").and_then(|v| v.as_u64()), Some(41_943_040));
        assert_eq!(v.get("threads").and_then(|v| v.as_u64()), Some(4));
        assert_eq!(v.get("started_at").and_then(|v| v.as_u64()), Some(1_757_600_000));
    }

    #[test]
    fn process_json_emits_null_for_an_unresolved_user() {
        let mut p = sample_rows().remove(0);
        p.user = None;
        assert!(p.to_json().get("user").unwrap().is_null());
    }

    #[test]
    fn process_json_is_an_array() {
        let v = process_json(&sample_rows());
        assert_eq!(v.as_array().map(|a| a.len()), Some(4));
    }
}
