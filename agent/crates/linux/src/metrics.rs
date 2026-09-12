//! Live metrics: the numbers behind the health card.
//!
//! # Why this is a stateful sampler
//!
//! Two of the four metric families are *rates*, and a rate cannot be read — it
//! has to be differenced. `/proc/stat` reports cumulative jiffies since boot
//! and `/proc/net/dev` reports cumulative octets since the interface came up.
//! A single read of either tells you the machine's lifetime average, which is
//! never what anyone means by "CPU usage". So [`MetricsSampler`] keeps the
//! previous counters and the instant they were taken, and every `sample()`
//! reports the change since the last one. The first call has no baseline and
//! honestly reports 0% rather than inventing a number.
//!
//! The agent's WebSocket stream calls `sample()` on a fixed cadence, so the
//! window is the stream interval and the numbers match what the user sees tick.
//!
//! # The disk-usage limitation — read this before integrating
//!
//! `used_bytes`, `available_bytes`, `usage_percent` and the inode counts are
//! **the output of `statvfs(2)` and of nothing else**. They are not exposed
//! anywhere in `/proc` or `/sys`: procfs gives us the mount *table*, and sysfs
//! gives us the *block device* size, but neither knows how many blocks a
//! filesystem currently has free — only the filesystem driver does, and the
//! only way to ask it is the syscall.
//!
//! This crate is `#![forbid(unsafe_code)]` with zero dependencies, and `std`
//! exposes no `statvfs` binding. The alternatives were all worse:
//!   * shelling out to `df` — banned, and parsing another program's output is
//!     exactly the architecture ServerOS exists to replace;
//!   * walking the tree with `std::fs` to sum file sizes — O(inodes) per
//!     sample, minutes on a real server, and still wrong (sparse files, holes,
//!     unreadable subtrees);
//!   * reporting a plausible number — a monitoring tool that invents capacity
//!     figures is worse than one that admits it does not know.
//!
//! So: [`ProcDiskSource`] reports `total_bytes` where it is derivable from
//! `/sys/block/<disk>/<part>/size`, and reports used/available/inodes as
//! `None`. `None` fields are **omitted** from the JSON (via `set_opt`), so an
//! integrator must treat them as optional and render "—" rather than 0.
//!
// TODO(agent): wire statvfs via a tiny C shim or the `rustix` crate once dependencies are permitted
//!
//! The [`DiskSource`] trait is the seam for that fix: swap in an implementation
//! whose `statfs` actually calls the syscall and every field above populates
//! with no change to the JSON shape or to the app.

use crate::error::LinuxError;
use crate::procfs;
use crate::system::{LoadAverage, parse_loadavg};
use serveros_json::{Object, Value, round};
use std::time::Instant;

/// Sector size assumed by `/sys/block/*/size`. The kernel documents this as
/// fixed at 512 bytes regardless of the device's logical block size, so it is a
/// constant rather than something to read from `queue/logical_block_size`.
const SYSFS_SECTOR_BYTES: u64 = 512;

// =========================================================================
// CPU
// =========================================================================

/// One `cpu*` row of `/proc/stat`, in USER_HZ jiffies since boot.
///
/// `guest` and `guest_nice` are deliberately absent: the kernel already counts
/// them inside `user` and `nice`, so adding them would double-count guest time
/// on a KVM host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTimes {
    /// All accounted jiffies.
    pub fn total(&self) -> u64 {
        self.user
            .saturating_add(self.nice)
            .saturating_add(self.system)
            .saturating_add(self.idle)
            .saturating_add(self.iowait)
            .saturating_add(self.irq)
            .saturating_add(self.softirq)
            .saturating_add(self.steal)
    }

    /// Jiffies in which the CPU had nothing to run. `iowait` counts as idle:
    /// the core really was free, it is the disk that was busy, which is why it
    /// is also reported separately.
    pub fn idle_all(&self) -> u64 {
        self.idle.saturating_add(self.iowait)
    }

    /// `self - earlier`, saturating. A counter that went backwards means the
    /// CPU was hot-unplugged and re-added, or the container was migrated;
    /// saturating to zero yields one flat sample instead of a nonsense spike.
    pub fn since(&self, earlier: &CpuTimes) -> CpuTimes {
        CpuTimes {
            user: self.user.saturating_sub(earlier.user),
            nice: self.nice.saturating_sub(earlier.nice),
            system: self.system.saturating_sub(earlier.system),
            idle: self.idle.saturating_sub(earlier.idle),
            iowait: self.iowait.saturating_sub(earlier.iowait),
            irq: self.irq.saturating_sub(earlier.irq),
            softirq: self.softirq.saturating_sub(earlier.softirq),
            steal: self.steal.saturating_sub(earlier.steal),
        }
    }
}

/// The aggregate row plus every per-core row from one read of `/proc/stat`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpuSnapshot {
    pub total: CpuTimes,
    pub cores: Vec<CpuTimes>,
}

/// Parse the `cpu` and `cpuN` rows of `/proc/stat`.
///
/// Column count varies by kernel age: 2.6.0 had 7, `steal` arrived in 2.6.11,
/// `guest` in 2.6.24, `guest_nice` in 2.6.33, and future kernels may add more.
/// Missing trailing columns read as 0 and unknown extra columns are ignored, so
/// the same code works from RHEL 6 to a 6.x kernel.
pub fn parse_cpu_stat(text: &str) -> Option<CpuSnapshot> {
    let mut total = None;
    let mut cores: Vec<(usize, CpuTimes)> = Vec::new();

    for line in text.lines() {
        let Some(rest) = line.strip_prefix("cpu") else {
            continue;
        };
        let (index, fields) = match rest.split_once(char::is_whitespace) {
            // "cpu  9184 0 ..." — the aggregate row.
            Some(("", fields)) => (None, fields),
            // "cpu0 4678 0 ..." — a per-core row.
            Some((n, fields)) => match n.parse::<usize>() {
                Ok(i) => (Some(i), fields),
                Err(_) => continue, // not a cpu row at all
            },
            None => continue,
        };

        let times = parse_cpu_times(fields);
        match index {
            None => total = Some(times),
            Some(i) => cores.push((i, times)),
        }
    }

    let total = total?;
    // Kernels list cores in order, but nothing promises it; sort so `per_core`
    // indices always mean cpu0, cpu1, ... to the app.
    cores.sort_by_key(|(i, _)| *i);
    Some(CpuSnapshot { total, cores: cores.into_iter().map(|(_, t)| t).collect() })
}

/// Parse the whitespace-separated jiffy columns of one `cpu` row.
fn parse_cpu_times(fields: &str) -> CpuTimes {
    let mut it = fields.split_whitespace();
    // A non-numeric column reads as 0 rather than aborting the row: one bad
    // field should cost one metric, not the whole sample.
    let mut next = || it.next().and_then(procfs::parse_u64).unwrap_or(0);
    CpuTimes {
        user: next(),
        nice: next(),
        system: next(),
        idle: next(),
        iowait: next(),
        irq: next(),
        softirq: next(),
        steal: next(),
    }
}

/// Percentages derived from one interval of CPU time.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CpuMetrics {
    pub usage_percent: f64,
    pub user_percent: f64,
    pub system_percent: f64,
    pub iowait_percent: f64,
    pub per_core: Vec<f64>,
    pub load_average: LoadAverage,
    pub core_count: usize,
}

/// Turn a pair of CPU snapshots into percentages.
///
/// `previous` is `None` on the very first sample, where there is no interval to
/// divide by; every percentage is then 0.0 and the caller is expected to
/// discard or label that first frame.
pub fn cpu_metrics(
    now: &CpuSnapshot,
    previous: Option<&CpuSnapshot>,
    load_average: LoadAverage,
) -> CpuMetrics {
    let core_count = now.cores.len().max(1);
    let Some(prev) = previous else {
        return CpuMetrics {
            per_core: vec![0.0; now.cores.len()],
            load_average,
            core_count,
            ..CpuMetrics::default()
        };
    };

    let d = now.total.since(&prev.total);
    let total = d.total();
    let pct = |part: u64| percent_of(part, total);

    let per_core = now
        .cores
        .iter()
        .enumerate()
        .map(|(i, core)| match prev.cores.get(i) {
            // A core that appeared since the last sample (hotplug) has no
            // baseline of its own; 0.0 for one interval, correct thereafter.
            None => 0.0,
            Some(before) => {
                let cd = core.since(before);
                let ct = cd.total();
                round(percent_of(ct.saturating_sub(cd.idle_all()), ct), 1)
            }
        })
        .collect();

    CpuMetrics {
        usage_percent: round(pct(total.saturating_sub(d.idle_all())), 1),
        // `nice` is user time; separating it would surprise anyone comparing
        // against `top`'s us column on a machine that uses nice levels.
        user_percent: round(pct(d.user.saturating_add(d.nice)), 1),
        // Kernel time only. Hard and soft IRQ time is counted in
        // `usage_percent` but not here, so user+system+iowait can be less than
        // usage on an interrupt-heavy box — that gap is real, not rounding.
        system_percent: round(pct(d.system), 1),
        iowait_percent: round(pct(d.iowait), 1),
        per_core,
        load_average,
        core_count,
    }
}

/// `part / whole * 100`, clamped to a sane percentage. A zero interval (two
/// samples inside the same jiffy) yields 0.0 rather than a division by zero.
fn percent_of(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    clamp_percent(part as f64 / whole as f64 * 100.0)
}

/// Force a percentage into 0..=100 and kill any non-finite value before it can
/// reach the JSON writer.
fn clamp_percent(v: f64) -> f64 {
    if v.is_finite() { v.clamp(0.0, 100.0) } else { 0.0 }
}

impl CpuMetrics {
    fn to_json(&self) -> Value {
        Object::new()
            .set("usage_percent", self.usage_percent)
            .set("user_percent", self.user_percent)
            .set("system_percent", self.system_percent)
            .set("iowait_percent", self.iowait_percent)
            .set("per_core", self.per_core.clone())
            .set("load_average", self.load_average.to_json())
            .set("core_count", self.core_count)
            .into()
    }
}

// =========================================================================
// Memory
// =========================================================================

/// Memory and swap, in bytes plus the two percentages the UI shows.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemoryMetrics {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub cached_bytes: u64,
    pub buffers_bytes: u64,
    pub usage_percent: f64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_usage_percent: f64,
}

/// Parse `/proc/meminfo` into the numbers the health card needs.
///
/// `used = MemTotal - MemAvailable` is the modern, correct definition: page
/// cache and reclaimable slab are *available* to applications, so counting them
/// as used is why "Linux ate my RAM" screenshots exist. `MemAvailable` has been
/// present since kernel 3.14; older kernels fall back to
/// `MemTotal - MemFree - Buffers - Cached`, which is what `free` did before it.
pub fn parse_memory(meminfo: &str) -> MemoryMetrics {
    let get = |key: &str| procfs::kv_bytes(meminfo, key).unwrap_or(0);

    let total = get("MemTotal");
    let free = get("MemFree");
    let buffers = get("Buffers");
    let cached = get("Cached");

    let available = match procfs::kv_bytes(meminfo, "MemAvailable") {
        Some(v) => v,
        None => free.saturating_add(buffers).saturating_add(cached),
    };
    // `available` can exceed `total` on a badly-behaved kernel; saturating
    // keeps `used` at 0 instead of wrapping to 18 exabytes.
    let used = total.saturating_sub(available);

    let swap_total = get("SwapTotal");
    let swap_used = swap_total.saturating_sub(get("SwapFree"));

    MemoryMetrics {
        total_bytes: total,
        used_bytes: used,
        available_bytes: available,
        cached_bytes: cached,
        buffers_bytes: buffers,
        usage_percent: round(percent_of(used, total), 1),
        swap_total_bytes: swap_total,
        swap_used_bytes: swap_used,
        // A machine with swap off is at 0%, not undefined.
        swap_usage_percent: round(percent_of(swap_used, swap_total), 1),
    }
}

impl MemoryMetrics {
    fn to_json(&self) -> Value {
        Object::new()
            .set("total_bytes", self.total_bytes)
            .set("used_bytes", self.used_bytes)
            .set("available_bytes", self.available_bytes)
            .set("cached_bytes", self.cached_bytes)
            .set("buffers_bytes", self.buffers_bytes)
            .set("usage_percent", self.usage_percent)
            .set("swap_total_bytes", self.swap_total_bytes)
            .set("swap_used_bytes", self.swap_used_bytes)
            .set("swap_usage_percent", self.swap_usage_percent)
            .into()
    }
}

// =========================================================================
// Disk
// =========================================================================

/// One row of `/proc/self/mounts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// Source: a block device path, or a pseudo-source like `tmpfs`.
    pub device: String,
    pub mount_point: String,
    pub fstype: String,
    /// Raw comma-separated mount options, kept for `ro` detection upstream.
    pub options: String,
}

/// Capacity figures for one filesystem. Every field is optional because the
/// only source that can answer all of them is `statvfs(2)` — see the module
/// docs for why this crate cannot call it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsUsage {
    pub total_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub inodes_total: Option<u64>,
    pub inodes_used: Option<u64>,
}

/// Where per-filesystem capacity comes from.
///
/// This exists as a trait for exactly one reason: it is the seam at which a
/// real `statvfs` implementation drops in once the no-dependency rule is
/// relaxed, with no change to callers, to the JSON, or to the app.
pub trait DiskSource {
    /// Capacity for the filesystem mounted at `path`.
    fn statfs(&self, path: &str) -> Result<FsUsage, LinuxError>;
}

/// The pure-`std` disk source: mount table from `/proc/self/mounts`, sizes from
/// `/sys/block`. Reports totals where derivable and `None` everywhere else.
#[derive(Debug, Clone, Default)]
pub struct ProcDiskSource {
    mounts: Vec<MountEntry>,
}

impl ProcDiskSource {
    /// Read and filter the live mount table.
    pub fn new() -> Result<Self, LinuxError> {
        let text = procfs::read_text("/proc/self/mounts")?;
        Ok(Self::from_mounts(reportable_mounts(&text)))
    }

    /// Build from an already-filtered mount list (used by tests and by callers
    /// that have a mount table in hand).
    pub fn from_mounts(mounts: Vec<MountEntry>) -> Self {
        ProcDiskSource { mounts }
    }

    /// The filesystems this source will report on.
    pub fn mounts(&self) -> &[MountEntry] {
        &self.mounts
    }
}

impl DiskSource for ProcDiskSource {
    fn statfs(&self, path: &str) -> Result<FsUsage, LinuxError> {
        let Some(entry) = self.mounts.iter().find(|m| m.mount_point == path) else {
            return Err(LinuxError::parse("/proc/self/mounts", format!("{path} is not mounted")));
        };
        Ok(FsUsage {
            total_bytes: block_device_bytes(&entry.device),
            // Deliberately unknowable here. See the module documentation.
            used_bytes: None,
            available_bytes: None,
            inodes_total: None,
            inodes_used: None,
        })
    }
}

/// Read a block device's capacity from sysfs, in bytes.
fn block_device_bytes(device: &str) -> Option<u64> {
    for candidate in sysfs_size_candidates(device) {
        let Some(sectors) = procfs::read_line_opt(&candidate).and_then(|s| procfs::parse_u64(&s))
        else {
            continue;
        };
        // Loop and zram devices with nothing attached report 0; that is "no
        // size", not "an empty disk".
        if sectors > 0 {
            return Some(sectors.saturating_mul(SYSFS_SECTOR_BYTES));
        }
    }
    None
}

/// The sysfs paths that might hold `device`'s size, most likely first.
///
/// A whole disk lives at `/sys/block/vda/size`; a partition lives *under* its
/// disk at `/sys/block/vda/vda1/size`. Both are tried because the device name
/// alone does not reliably say which it is (`nvme0n1` ends in a digit and is a
/// whole disk; `vda1` ends in a digit and is a partition).
pub fn sysfs_size_candidates(device: &str) -> Vec<String> {
    let name = device.strip_prefix("/dev/").unwrap_or(device);
    // `/dev/mapper/vg-root`, `/dev/disk/by-uuid/...` and pseudo-sources like
    // `tmpfs` have no direct sysfs node; resolving the symlink chain is the
    // job of a real statvfs, not of a guess.
    if name.is_empty() || name.contains('/') || name.contains("..") {
        return Vec::new();
    }
    let mut out = vec![format!("/sys/block/{name}/size")];
    if let Some(parent) = parent_disk_name(name) {
        out.push(format!("/sys/block/{parent}/{name}/size"));
    }
    out
}

/// Guess the whole-disk name a partition belongs to: `vda1` -> `vda`,
/// `nvme0n1p3` -> `nvme0n1`, `mmcblk0p2` -> `mmcblk0`.
///
/// The `p` rule exists because NVMe and eMMC names already end in a digit, so
/// they separate the partition number with a literal `p`. A wrong guess is
/// harmless: it produces a sysfs path that does not exist and the caller falls
/// through to the next candidate.
pub fn parent_disk_name(name: &str) -> Option<String> {
    let bytes = name.as_bytes();
    if !bytes.last()?.is_ascii_digit() {
        return None;
    }
    let mut cut = bytes.len();
    while cut > 0 && bytes[cut - 1].is_ascii_digit() {
        cut -= 1;
    }
    if cut >= 2 && bytes[cut - 1] == b'p' && bytes[cut - 2].is_ascii_digit() {
        cut -= 1;
    }
    if cut == 0 { None } else { Some(name[..cut].to_string()) }
}

/// Filesystem types that never represent storage a user manages.
///
/// These are kernel interfaces that happen to be mounted. Showing `sysfs` in a
/// storage list is noise, and every one of them would report an unknown size
/// anyway.
const PSEUDO_FSTYPES: &[&str] = &[
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "mqueue",
    "nsfs",
    "proc",
    "pstore",
    "ramfs",
    "rpc_pipefs",
    "securityfs",
    "selinuxfs",
    "squashfs",
    "sysfs",
    "tracefs",
];

/// Should this mount appear in the storage list?
///
/// Two rules are conditional rather than a flat fstype ban:
///   * **tmpfs** under `/dev` or `/sys` is kernel plumbing (`/dev/shm`, the
///     cgroup root). A tmpfs on `/tmp` or `/run` is real storage that can fill
///     up and take the server down with it, so it stays.
///   * **overlay** at `/` is a container's root filesystem and is exactly what
///     the user means by "disk". Overlay anywhere else is a Docker layer mount
///     on the host, of which there is one per running container.
pub fn is_reportable(m: &MountEntry) -> bool {
    let fstype = m.fstype.as_str();
    if PSEUDO_FSTYPES.contains(&fstype) {
        return false;
    }
    if fstype == "tmpfs" {
        let p = m.mount_point.as_str();
        if p == "/dev" || p.starts_with("/dev/") || p.starts_with("/sys/") || p.starts_with("/proc")
        {
            return false;
        }
    }
    if fstype == "overlay" && m.mount_point != "/" {
        return false;
    }
    true
}

/// Parse `/proc/self/mounts` (or `/etc/mtab`, same format).
///
/// Fields are separated by single spaces and any space, tab, newline or
/// backslash inside a path is octal-escaped — a mount point named
/// `/mnt/my disk` appears as `/mnt/my\040disk`, and passing that straight
/// through would break every path comparison downstream.
pub fn parse_mounts(text: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let (Some(device), Some(mount_point), Some(fstype)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        out.push(MountEntry {
            device: unescape_mount_field(device),
            mount_point: unescape_mount_field(mount_point),
            fstype: fstype.to_string(),
            options: f.next().unwrap_or("").to_string(),
        });
    }
    out
}

/// Parse, filter and de-duplicate the mount table in one step.
///
/// De-duplication keeps the **last** entry for a mount point, because that is
/// the one currently visible: mounting over an existing mount point shadows the
/// earlier mount but leaves both rows in the table.
pub fn reportable_mounts(text: &str) -> Vec<MountEntry> {
    let all = parse_mounts(text);
    let mut out: Vec<MountEntry> = Vec::with_capacity(all.len());
    for m in all.into_iter().filter(is_reportable) {
        match out.iter().position(|e| e.mount_point == m.mount_point) {
            Some(i) => out[i] = m,
            None => out.push(m),
        }
    }
    out
}

/// Resolve the `\0NN` octal escapes the kernel writes into mount fields.
///
/// Works on bytes rather than on `char`s for two reasons: an escape decodes to
/// one byte (not one code point), and a mount point may legitimately contain
/// multi-byte UTF-8 (`/mnt/café`). Slicing such a string by byte offset would
/// panic on a char boundary, and rebuilding it byte-by-byte as `char` would
/// mangle it — so the bytes are collected and converted once at the end.
fn unescape_mount_field(raw: &str) -> String {
    if !raw.contains('\\') {
        return raw.to_string();
    }
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // Needs a backslash plus exactly three octal digits.
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let d = &bytes[i + 1..i + 4];
            if d.iter().all(|b| (b'0'..=b'7').contains(b)) {
                let code = (d[0] - b'0') as u32 * 64 + (d[1] - b'0') as u32 * 8 + (d[2] - b'0') as u32;
                if code <= u8::MAX as u32 {
                    out.push(code as u8);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // A path that is not valid UTF-8 is possible on Linux; replacing the bad
    // bytes keeps it displayable instead of dropping the filesystem entirely.
    String::from_utf8_lossy(&out).into_owned()
}

/// One filesystem as the app renders it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FilesystemUsage {
    pub device: String,
    pub mount_point: String,
    pub fstype: String,
    pub total_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub usage_percent: Option<f64>,
    pub inodes_total: Option<u64>,
    pub inodes_used: Option<u64>,
}

impl FilesystemUsage {
    fn to_json(&self) -> Value {
        Object::new()
            .set("device", self.device.as_str())
            .set("mount_point", self.mount_point.as_str())
            .set("fstype", self.fstype.as_str())
            .set_opt("total_bytes", self.total_bytes)
            .set_opt("used_bytes", self.used_bytes)
            .set_opt("available_bytes", self.available_bytes)
            .set_opt("usage_percent", self.usage_percent)
            .set_opt("inodes_total", self.inodes_total)
            .set_opt("inodes_used", self.inodes_used)
            .into()
    }
}

/// Storage across every reportable filesystem.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiskMetrics {
    pub total_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub usage_percent: Option<f64>,
    pub filesystems: Vec<FilesystemUsage>,
}

impl DiskMetrics {
    fn to_json(&self) -> Value {
        Object::new()
            .set_opt("total_bytes", self.total_bytes)
            .set_opt("used_bytes", self.used_bytes)
            .set_opt("available_bytes", self.available_bytes)
            .set_opt("usage_percent", self.usage_percent)
            .set(
                "filesystems",
                Value::Array(self.filesystems.iter().map(FilesystemUsage::to_json).collect()),
            )
            .into()
    }
}

/// Assemble disk metrics from a mount list and a capacity source.
///
/// The aggregate totals sum over **distinct devices**, not over mounts: a bind
/// mount and a subvolume both appear twice in the mount table and would
/// otherwise double the server's apparent capacity.
pub fn disk_metrics<S: DiskSource + ?Sized>(mounts: &[MountEntry], source: &S) -> DiskMetrics {
    let mut filesystems = Vec::with_capacity(mounts.len());
    let mut counted_devices: Vec<&str> = Vec::new();
    let mut total = 0u64;
    let mut used = 0u64;
    let mut available = 0u64;
    let mut have_total = false;
    let mut have_used = false;
    let mut have_available = false;

    for m in mounts {
        // A filesystem that vanished between reading the table and asking about
        // it is not an error; it is a mount that is no longer there.
        let usage = source.statfs(&m.mount_point).unwrap_or_default();
        let usage_percent = match (usage.used_bytes, usage.total_bytes) {
            (Some(u), Some(t)) if t > 0 => Some(round(percent_of(u, t), 1)),
            _ => None,
        };

        let first_use_of_device = !counted_devices.contains(&m.device.as_str());
        if first_use_of_device {
            counted_devices.push(&m.device);
            if let Some(v) = usage.total_bytes {
                total = total.saturating_add(v);
                have_total = true;
            }
            if let Some(v) = usage.used_bytes {
                used = used.saturating_add(v);
                have_used = true;
            }
            if let Some(v) = usage.available_bytes {
                available = available.saturating_add(v);
                have_available = true;
            }
        }

        filesystems.push(FilesystemUsage {
            device: m.device.clone(),
            mount_point: m.mount_point.clone(),
            fstype: m.fstype.clone(),
            total_bytes: usage.total_bytes,
            used_bytes: usage.used_bytes,
            available_bytes: usage.available_bytes,
            usage_percent,
            inodes_total: usage.inodes_total,
            inodes_used: usage.inodes_used,
        });
    }

    let total_bytes = have_total.then_some(total);
    let used_bytes = have_used.then_some(used);
    DiskMetrics {
        total_bytes,
        used_bytes,
        available_bytes: have_available.then_some(available),
        usage_percent: match (used_bytes, total_bytes) {
            (Some(u), Some(t)) if t > 0 => Some(round(percent_of(u, t), 1)),
            _ => None,
        },
        filesystems,
    }
}

// =========================================================================
// Network
// =========================================================================

/// Cumulative counters for one interface, straight out of `/proc/net/dev`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InterfaceCounters {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

/// One interface as the app renders it: counters plus the rate since the last
/// sample.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InterfaceMetrics {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub up: bool,
}

impl InterfaceMetrics {
    fn to_json(&self) -> Value {
        Object::new()
            .set("name", self.name.as_str())
            .set("rx_bytes", self.rx_bytes)
            .set("tx_bytes", self.tx_bytes)
            .set("rx_bytes_per_sec", self.rx_bytes_per_sec)
            .set("tx_bytes_per_sec", self.tx_bytes_per_sec)
            .set("rx_errors", self.rx_errors)
            .set("tx_errors", self.tx_errors)
            .set("up", self.up)
            .into()
    }
}

/// Aggregate throughput plus the per-interface breakdown.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NetworkMetrics {
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub interfaces: Vec<InterfaceMetrics>,
}

impl NetworkMetrics {
    fn to_json(&self) -> Value {
        Object::new()
            .set("rx_bytes_total", self.rx_bytes_total)
            .set("tx_bytes_total", self.tx_bytes_total)
            .set("rx_bytes_per_sec", self.rx_bytes_per_sec)
            .set("tx_bytes_per_sec", self.tx_bytes_per_sec)
            .set(
                "interfaces",
                Value::Array(self.interfaces.iter().map(InterfaceMetrics::to_json).collect()),
            )
            .into()
    }
}

/// Parse `/proc/net/dev`, skipping the two header rows and the loopback.
///
/// Loopback is excluded because it is not network throughput — it is a process
/// talking to another process on the same box, and including it makes an
/// otherwise-idle server look like it is pushing gigabits.
///
/// The name/colon separator has no guaranteed space around it: a busy interface
/// with a wide byte count renders as `eth0:1234567890`, which is why the split
/// is on `:` rather than on whitespace.
pub fn parse_net_dev(text: &str) -> Vec<InterfaceCounters> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue; // the two header lines have no colon
        };
        let name = name.trim();
        if name.is_empty() || name == "lo" {
            continue;
        }
        let f: Vec<&str> = rest.split_whitespace().collect();
        // Receive: bytes packets errs drop fifo frame compressed multicast
        // Transmit: bytes packets errs drop fifo colls carrier compressed
        let get = |i: usize| f.get(i).and_then(|s| procfs::parse_u64(s)).unwrap_or(0);
        if f.len() < 16 {
            // Truncated row: report the name with zeroed counters rather than
            // dropping an interface the user can see in `ip link`.
            out.push(InterfaceCounters { name: name.to_string(), ..Default::default() });
            continue;
        }
        out.push(InterfaceCounters {
            name: name.to_string(),
            rx_bytes: get(0),
            tx_bytes: get(8),
            rx_errors: get(2),
            tx_errors: get(10),
        });
    }
    out
}

/// `true` when `/sys/class/net/<iface>/operstate` says `up`.
///
/// `unknown` is reported by tunnels and by some virtual NICs that are in fact
/// carrying traffic, but treating `unknown` as up would light up every dormant
/// `ifb`/`veth` in the list. Showing a live tunnel as down is the less
/// misleading of the two errors.
pub fn operstate_is_up(operstate: &str) -> bool {
    operstate.trim().eq_ignore_ascii_case("up")
}

/// Compute rates by differencing two sets of interface counters.
///
/// A counter that went backwards means the interface was recreated (container
/// restart, `ip link del`), so its delta is dropped rather than reported as a
/// huge negative-turned-positive spike.
pub fn network_metrics(
    now: &[InterfaceCounters],
    previous: Option<&[InterfaceCounters]>,
    elapsed_secs: f64,
    is_up: impl Fn(&str) -> bool,
) -> NetworkMetrics {
    // Guard the divisor: two samples in the same instant, or a monotonic clock
    // that did not advance, must not produce infinity.
    let usable_interval = elapsed_secs.is_finite() && elapsed_secs > 0.0;

    let mut interfaces = Vec::with_capacity(now.len());
    let mut rx_total = 0u64;
    let mut tx_total = 0u64;
    let mut rx_rate = 0.0f64;
    let mut tx_rate = 0.0f64;

    for iface in now {
        let before = previous.and_then(|p| p.iter().find(|c| c.name == iface.name));
        let (rx_per_sec, tx_per_sec) = match before {
            Some(b) if usable_interval => (
                rate(iface.rx_bytes.saturating_sub(b.rx_bytes), elapsed_secs),
                rate(iface.tx_bytes.saturating_sub(b.tx_bytes), elapsed_secs),
            ),
            _ => (0.0, 0.0),
        };

        rx_total = rx_total.saturating_add(iface.rx_bytes);
        tx_total = tx_total.saturating_add(iface.tx_bytes);
        rx_rate += rx_per_sec;
        tx_rate += tx_per_sec;

        interfaces.push(InterfaceMetrics {
            name: iface.name.clone(),
            rx_bytes: iface.rx_bytes,
            tx_bytes: iface.tx_bytes,
            rx_bytes_per_sec: round(rx_per_sec, 2),
            tx_bytes_per_sec: round(tx_per_sec, 2),
            rx_errors: iface.rx_errors,
            tx_errors: iface.tx_errors,
            up: is_up(&iface.name),
        });
    }

    NetworkMetrics {
        rx_bytes_total: rx_total,
        tx_bytes_total: tx_total,
        rx_bytes_per_sec: round(rx_rate, 2),
        tx_bytes_per_sec: round(tx_rate, 2),
        interfaces,
    }
}

fn rate(delta: u64, secs: f64) -> f64 {
    let r = delta as f64 / secs;
    if r.is_finite() && r >= 0.0 { r } else { 0.0 }
}

// =========================================================================
// The sample
// =========================================================================

/// One complete metrics frame.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Metrics {
    /// Unix seconds at which this frame was taken.
    pub sampled_at: u64,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub disk: DiskMetrics,
    pub network: NetworkMetrics,
}

impl Metrics {
    /// Serialise in the exact shape the macOS app decodes.
    pub fn to_json(&self) -> Value {
        Object::new()
            .set("sampled_at", self.sampled_at)
            .set("cpu", self.cpu.to_json())
            .set("memory", self.memory.to_json())
            .set("disk", self.disk.to_json())
            .set("network", self.network.to_json())
            .into()
    }
}

/// What the previous `sample()` saw, so the next one can difference against it.
#[derive(Debug, Clone)]
struct Baseline {
    cpu: CpuSnapshot,
    net: Vec<InterfaceCounters>,
    at: Instant,
}

/// Samples live metrics, holding the counters needed to turn them into rates.
///
/// Create one per connected server and call [`sample`](Self::sample) on the
/// stream's cadence. It is deliberately not `Sync`-shared: two callers
/// differencing against each other's baselines would produce intervals that
/// belong to neither.
#[derive(Debug, Default)]
pub struct MetricsSampler {
    previous: Option<Baseline>,
}

impl MetricsSampler {
    /// A sampler with no baseline yet.
    pub fn new() -> Self {
        MetricsSampler { previous: None }
    }

    /// `true` once a baseline exists, i.e. once rates are meaningful.
    pub fn has_baseline(&self) -> bool {
        self.previous.is_some()
    }

    /// Take a sample.
    ///
    /// The first call has nothing to difference against and reports every
    /// percentage and rate as 0.0; absolute values (memory, counters, capacity)
    /// are correct from the first call.
    ///
    /// Fails only when `/proc/stat` cannot be read, which means procfs is gone
    /// and there is nothing to sample. Every other source degrades: a missing
    /// `/proc/net/dev` yields an empty interface list, not an error.
    pub fn sample(&mut self) -> Result<Metrics, LinuxError> {
        let now = Instant::now();

        let stat = procfs::read_text("/proc/stat")?;
        let cpu_now = parse_cpu_stat(&stat)
            .ok_or_else(|| LinuxError::parse("/proc/stat", "no aggregate cpu row"))?;

        let load = procfs::read_text_opt("/proc/loadavg")
            .map(|t| parse_loadavg(&t))
            .unwrap_or_default();
        let cpu = cpu_metrics(&cpu_now, self.previous.as_ref().map(|p| &p.cpu), load);

        let memory = procfs::read_text_opt("/proc/meminfo")
            .map(|t| parse_memory(&t))
            .unwrap_or_default();

        // Re-read the mount table every sample: mounts come and go (a USB disk,
        // a container starting), and a cached table would show storage that is
        // no longer there.
        let disk_source =
            ProcDiskSource::new().unwrap_or_else(|_| ProcDiskSource::from_mounts(Vec::new()));
        let disk = disk_metrics(disk_source.mounts(), &disk_source);

        let net_now = procfs::read_text_opt("/proc/net/dev")
            .map(|t| parse_net_dev(&t))
            .unwrap_or_default();
        let elapsed = self.previous.as_ref().map(|p| now.duration_since(p.at).as_secs_f64());
        let network = network_metrics(
            &net_now,
            self.previous.as_ref().map(|p| p.net.as_slice()),
            elapsed.unwrap_or(0.0),
            |name| {
                procfs::read_line_opt(&format!("/sys/class/net/{name}/operstate"))
                    .map(|s| operstate_is_up(&s))
                    .unwrap_or(false)
            },
        );

        self.previous = Some(Baseline { cpu: cpu_now, net: net_now, at: now });

        Ok(Metrics { sampled_at: procfs::now_unix(), cpu, memory, disk, network })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `/proc/stat` from a 2-vCPU machine, interrupt rows trimmed.
    const STAT: &str = "\
cpu  9184 0 2486 370599 2118 0 322 13 0 0
cpu0 4678 0 1287 184789 1382 0 149 6 0 0
cpu1 4506 0 1198 185809 736 0 172 6 0 0
intr 794196 0 0 0 0 0 0 0
ctxt 949047
btime 1789198631
processes 3550
procs_running 3
procs_blocked 0
softirq 478543 0 74518 51 109952 9964 0 132 266813 260 16853
";

    const MEMINFO: &str = "\
MemTotal:        8216192 kB
MemFree:         6474612 kB
MemAvailable:    7527360 kB
Buffers:           66136 kB
Cached:          1200628 kB
SwapCached:            0 kB
SwapTotal:       2097152 kB
SwapFree:        1048576 kB
";

    /// Real `/proc/net/dev`, including the two header rows and loopback.
    const NET_DEV: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 14041780    3021    0    0    0     0          0         0 14041780    3021    0    0    0     0       0          0
  ifb0:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
  eth0: 34631126   84611    3   20    0     0          0         0 42735941   84390    7    0    0     0       0          0
";

    const MOUNTS: &str = "\
proc /proc proc rw,relatime 0 0
sysfs /sys sysfs rw,relatime 0 0
devtmpfs /dev devtmpfs rw,relatime,size=4098768k 0 0
tmpfs /dev/shm tmpfs rw,relatime,size=8216192k 0 0
devpts /dev/pts devpts rw,relatime,mode=600 0 0
/dev/vda1 / ext4 rw,relatime 0 0
/dev/vdb /opt/rclone squashfs ro,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev,size=1024k 0 0
cgroup2 /sys/fs/cgroup/unified cgroup2 rw,relatime 0 0
overlay /var/lib/docker/overlay2/abc/merged overlay rw,relatime 0 0
/dev/vdc /data ext4 rw,relatime 0 0
";

    // ---- CPU parsing -----------------------------------------------------

    #[test]
    fn cpu_stat_parses_aggregate_and_cores() {
        let s = parse_cpu_stat(STAT).expect("aggregate row");
        assert_eq!(s.cores.len(), 2);
        assert_eq!(s.total.user, 9184);
        assert_eq!(s.total.system, 2486);
        assert_eq!(s.total.idle, 370_599);
        assert_eq!(s.total.iowait, 2118);
        assert_eq!(s.total.steal, 13);
        assert_eq!(s.cores[0].user, 4678);
        assert_eq!(s.cores[1].user, 4506);
    }

    #[test]
    fn cpu_stat_accepts_an_old_kernel_with_fewer_columns() {
        // Pre-2.6.11: no steal, no guest columns at all.
        let s = parse_cpu_stat("cpu  100 10 20 300 5 1 2\ncpu0 100 10 20 300 5 1 2\n").unwrap();
        assert_eq!(s.total.softirq, 2);
        assert_eq!(s.total.steal, 0);
        assert_eq!(s.total.total(), 438);
    }

    #[test]
    fn cpu_stat_ignores_extra_future_columns() {
        let s = parse_cpu_stat("cpu  1 2 3 4 5 6 7 8 9 10 11 12 13\n").unwrap();
        // guest/guest_nice and anything beyond are excluded from the total, so
        // guest time is not double-counted.
        assert_eq!(s.total.total(), 36);
    }

    #[test]
    fn cpu_stat_without_an_aggregate_row_is_none() {
        assert!(parse_cpu_stat("cpu0 1 2 3 4\nbtime 5\n").is_none());
        assert!(parse_cpu_stat("").is_none());
        assert!(parse_cpu_stat("intr 1 2 3\n").is_none());
    }

    #[test]
    fn cpu_stat_survives_non_numeric_columns() {
        let s = parse_cpu_stat("cpu  100 x 20 300\n").unwrap();
        assert_eq!(s.total.nice, 0);
        assert_eq!(s.total.system, 20);
    }

    #[test]
    fn cpu_stat_ignores_rows_that_merely_start_with_cpu() {
        // No such row today, but "cpufreq" would silently become core 0 under
        // a naive `starts_with("cpu")`.
        let s = parse_cpu_stat("cpu  1 2 3 4\ncpufreq 9 9 9\n").unwrap();
        assert!(s.cores.is_empty());
    }

    #[test]
    fn cpu_stat_sorts_cores_by_index() {
        let s = parse_cpu_stat("cpu 1 1 1 1\ncpu2 30 0 0 0\ncpu0 10 0 0 0\ncpu1 20 0 0 0\n")
            .unwrap();
        let users: Vec<u64> = s.cores.iter().map(|c| c.user).collect();
        assert_eq!(users, vec![10, 20, 30]);
    }

    // ---- CPU maths -------------------------------------------------------

    #[test]
    fn first_sample_reports_zero_not_lifetime_average() {
        let now = parse_cpu_stat(STAT).unwrap();
        let m = cpu_metrics(&now, None, LoadAverage::default());
        assert_eq!(m.usage_percent, 0.0);
        assert_eq!(m.per_core, vec![0.0, 0.0]);
        assert_eq!(m.core_count, 2);
    }

    #[test]
    fn cpu_usage_is_busy_over_total() {
        let prev = parse_cpu_stat("cpu  100 0 100 800 0 0 0 0\ncpu0 100 0 100 800 0 0 0 0\n")
            .unwrap();
        // +100 user, +100 system, +800 idle over a 1000-jiffy interval => 20%.
        let now = parse_cpu_stat("cpu  200 0 200 1600 0 0 0 0\ncpu0 200 0 200 1600 0 0 0 0\n")
            .unwrap();
        let m = cpu_metrics(&now, Some(&prev), LoadAverage::default());
        assert_eq!(m.usage_percent, 20.0);
        assert_eq!(m.user_percent, 10.0);
        assert_eq!(m.system_percent, 10.0);
        assert_eq!(m.per_core, vec![20.0]);
    }

    #[test]
    fn cpu_counts_iowait_as_idle_but_reports_it() {
        let prev = parse_cpu_stat("cpu 0 0 0 0 0 0 0 0\n").unwrap();
        let now = parse_cpu_stat("cpu 100 0 0 800 100 0 0 0\n").unwrap();
        let m = cpu_metrics(&now, Some(&prev), LoadAverage::default());
        assert_eq!(m.usage_percent, 10.0); // iowait is not busy
        assert_eq!(m.iowait_percent, 10.0);
    }

    #[test]
    fn identical_samples_are_zero_percent_not_a_division_by_zero() {
        let s = parse_cpu_stat(STAT).unwrap();
        let m = cpu_metrics(&s, Some(&s), LoadAverage::default());
        assert_eq!(m.usage_percent, 0.0);
        assert!(m.usage_percent.is_finite());
    }

    #[test]
    fn counters_going_backwards_do_not_produce_a_spike() {
        // Container migrated; the new host's counters are lower.
        let prev = parse_cpu_stat("cpu 9000 0 9000 9000 0 0 0 0\n").unwrap();
        let now = parse_cpu_stat("cpu 10 0 10 10 0 0 0 0\n").unwrap();
        let m = cpu_metrics(&now, Some(&prev), LoadAverage::default());
        assert_eq!(m.usage_percent, 0.0);
    }

    #[test]
    fn a_hotplugged_core_reports_zero_for_one_interval() {
        let prev = parse_cpu_stat("cpu 100 0 0 100\ncpu0 100 0 0 100\n").unwrap();
        let now = parse_cpu_stat("cpu 300 0 0 100\ncpu0 200 0 0 100\ncpu1 100 0 0 0\n").unwrap();
        let m = cpu_metrics(&now, Some(&prev), LoadAverage::default());
        assert_eq!(m.per_core.len(), 2);
        assert_eq!(m.per_core[1], 0.0);
    }

    #[test]
    fn every_cpu_percentage_stays_in_range() {
        let prev = parse_cpu_stat("cpu 0 0 0 0 0 0 0 0\n").unwrap();
        let now = parse_cpu_stat("cpu 999999 0 0 0 0 0 0 0\n").unwrap();
        let m = cpu_metrics(&now, Some(&prev), LoadAverage::default());
        for v in [m.usage_percent, m.user_percent, m.system_percent, m.iowait_percent] {
            assert!((0.0..=100.0).contains(&v), "{v}");
        }
    }

    // ---- memory ----------------------------------------------------------

    #[test]
    fn memory_uses_memavailable_for_used() {
        let m = parse_memory(MEMINFO);
        assert_eq!(m.total_bytes, 8_216_192 * 1024);
        assert_eq!(m.available_bytes, 7_527_360 * 1024);
        assert_eq!(m.used_bytes, (8_216_192 - 7_527_360) * 1024);
        assert_eq!(m.cached_bytes, 1_200_628 * 1024);
        assert_eq!(m.buffers_bytes, 66_136 * 1024);
        assert_eq!(m.usage_percent, 8.4);
    }

    #[test]
    fn memory_falls_back_when_memavailable_is_absent() {
        // Kernels older than 3.14 have no MemAvailable.
        let old = "MemTotal: 1000 kB\nMemFree: 200 kB\nBuffers: 100 kB\nCached: 300 kB\n";
        let m = parse_memory(old);
        assert_eq!(m.available_bytes, 600 * 1024);
        assert_eq!(m.used_bytes, 400 * 1024);
        assert_eq!(m.usage_percent, 40.0);
    }

    #[test]
    fn memory_swap_off_is_zero_percent_not_nan() {
        let m = parse_memory("MemTotal: 100 kB\nMemAvailable: 50 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n");
        assert_eq!(m.swap_total_bytes, 0);
        assert_eq!(m.swap_usage_percent, 0.0);
        assert!(m.swap_usage_percent.is_finite());
    }

    #[test]
    fn memory_swap_usage_is_total_minus_free() {
        let m = parse_memory(MEMINFO);
        assert_eq!(m.swap_used_bytes, (2_097_152 - 1_048_576) * 1024);
        assert_eq!(m.swap_usage_percent, 50.0);
    }

    #[test]
    fn memory_on_an_empty_file_is_all_zero_and_finite() {
        let m = parse_memory("");
        assert_eq!(m.total_bytes, 0);
        assert_eq!(m.usage_percent, 0.0);
    }

    #[test]
    fn memory_available_larger_than_total_does_not_wrap() {
        let m = parse_memory("MemTotal: 100 kB\nMemAvailable: 900 kB\n");
        assert_eq!(m.used_bytes, 0);
    }

    // ---- mounts ----------------------------------------------------------

    #[test]
    fn mounts_parse_all_four_fields() {
        let m = parse_mounts(MOUNTS);
        let root = m.iter().find(|e| e.mount_point == "/").unwrap();
        assert_eq!(root.device, "/dev/vda1");
        assert_eq!(root.fstype, "ext4");
        assert!(root.options.contains("rw"));
    }

    #[test]
    fn mounts_unescape_octal_paths() {
        let m = parse_mounts("/dev/sdb1 /mnt/my\\040disk ext4 rw 0 0\n");
        assert_eq!(m[0].mount_point, "/mnt/my disk");
        // A backslash that is not a valid escape is passed through untouched.
        let m = parse_mounts("/dev/sdb1 /mnt/back\\slash ext4 rw 0 0\n");
        assert_eq!(m[0].mount_point, "/mnt/back\\slash");
        // A trailing backslash must not read past the end of the field.
        let m = parse_mounts("/dev/sdb1 /mnt/x\\ ext4 rw 0 0\n");
        assert_eq!(m[0].mount_point, "/mnt/x\\");
    }

    #[test]
    fn mounts_with_multibyte_paths_survive_unescaping() {
        // Slicing this by byte offset naively would panic on a char boundary.
        let m = parse_mounts("/dev/sdb1 /mnt/caf\u{e9}\\040dossier ext4 rw 0 0\n");
        assert_eq!(m[0].mount_point, "/mnt/café dossier");
        let m = parse_mounts("/dev/sdb1 /mnt/\u{1f600}\\011tab ext4 rw 0 0\n");
        assert_eq!(m[0].mount_point, "/mnt/\u{1f600}\ttab");
    }

    #[test]
    fn mounts_skip_truncated_lines() {
        assert!(parse_mounts("/dev/sda1 /\n\n  \n").is_empty());
    }

    #[test]
    fn reportable_mounts_drops_kernel_pseudo_filesystems() {
        let kept: Vec<String> =
            reportable_mounts(MOUNTS).iter().map(|m| m.mount_point.clone()).collect();
        let has = |p: &str| kept.iter().any(|m| m == p);
        assert!(has("/"), "{kept:?}");
        assert!(has("/data"), "{kept:?}");
        for dropped in ["/proc", "/sys", "/dev", "/dev/pts", "/sys/fs/cgroup/unified", "/opt/rclone"]
        {
            assert!(!has(dropped), "{dropped} should not be reported: {kept:?}");
        }
    }

    #[test]
    fn tmpfs_is_kept_on_run_but_not_on_dev() {
        let kept: Vec<String> =
            reportable_mounts(MOUNTS).iter().map(|m| m.mount_point.clone()).collect();
        assert!(kept.iter().any(|p| p == "/run"), "{kept:?}");
        assert!(!kept.iter().any(|p| p == "/dev/shm"), "{kept:?}");
    }

    #[test]
    fn overlay_is_kept_at_root_and_dropped_when_nested() {
        let nested = MountEntry {
            device: "overlay".into(),
            mount_point: "/var/lib/docker/overlay2/abc/merged".into(),
            fstype: "overlay".into(),
            options: String::new(),
        };
        let root = MountEntry { mount_point: "/".into(), ..nested.clone() };
        assert!(!is_reportable(&nested));
        assert!(is_reportable(&root));
    }

    #[test]
    fn reportable_mounts_keeps_the_last_entry_for_a_shadowed_mount_point() {
        let text = "/dev/sda1 /data ext4 rw 0 0\n/dev/sdb1 /data xfs rw 0 0\n";
        let m = reportable_mounts(text);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].device, "/dev/sdb1");
    }

    // ---- sysfs size derivation -------------------------------------------

    #[test]
    fn parent_disk_names() {
        assert_eq!(parent_disk_name("vda1").as_deref(), Some("vda"));
        assert_eq!(parent_disk_name("sda12").as_deref(), Some("sda"));
        assert_eq!(parent_disk_name("nvme0n1p3").as_deref(), Some("nvme0n1"));
        assert_eq!(parent_disk_name("mmcblk0p2").as_deref(), Some("mmcblk0"));
        assert_eq!(parent_disk_name("vda"), None); // whole disk, no trailing digit
        assert_eq!(parent_disk_name(""), None);
        assert_eq!(parent_disk_name("123"), None); // nothing left after the digits
    }

    #[test]
    fn sysfs_candidates_try_whole_disk_then_partition() {
        assert_eq!(
            sysfs_size_candidates("/dev/vda1"),
            vec!["/sys/block/vda1/size".to_string(), "/sys/block/vda/vda1/size".to_string()]
        );
        assert_eq!(sysfs_size_candidates("/dev/vda"), vec!["/sys/block/vda/size".to_string()]);
    }

    #[test]
    fn sysfs_candidates_refuse_paths_they_cannot_map() {
        assert!(sysfs_size_candidates("/dev/mapper/vg-root").is_empty());
        assert!(sysfs_size_candidates("/dev/disk/by-uuid/abc").is_empty());
        assert!(sysfs_size_candidates("/dev/").is_empty());
        // No path traversal into sysfs via a hostile mount source.
        assert!(sysfs_size_candidates("..").is_empty());
    }

    #[test]
    fn tmpfs_source_has_no_block_device() {
        assert!(block_device_bytes("tmpfs").is_none());
        assert!(block_device_bytes("overlay").is_none());
    }

    // ---- disk assembly ---------------------------------------------------

    /// A `DiskSource` that knows everything, standing in for the real
    /// `statvfs` this crate cannot call yet.
    struct FakeStatvfs;
    impl DiskSource for FakeStatvfs {
        fn statfs(&self, path: &str) -> Result<FsUsage, LinuxError> {
            match path {
                "/" => Ok(FsUsage {
                    total_bytes: Some(500_000_000_000),
                    used_bytes: Some(240_000_000_000),
                    available_bytes: Some(260_000_000_000),
                    inodes_total: Some(30_000_000),
                    inodes_used: Some(400_000),
                }),
                "/data" => Ok(FsUsage {
                    total_bytes: Some(100),
                    used_bytes: Some(50),
                    available_bytes: Some(50),
                    ..Default::default()
                }),
                _ => Err(LinuxError::NotSupported("unknown mount")),
            }
        }
    }

    fn mount(device: &str, point: &str) -> MountEntry {
        MountEntry {
            device: device.into(),
            mount_point: point.into(),
            fstype: "ext4".into(),
            options: "rw".into(),
        }
    }

    #[test]
    fn disk_metrics_aggregate_and_percentage() {
        let mounts = vec![mount("/dev/vda1", "/"), mount("/dev/vdc", "/data")];
        let d = disk_metrics(&mounts, &FakeStatvfs);
        assert_eq!(d.total_bytes, Some(500_000_000_100));
        assert_eq!(d.used_bytes, Some(240_000_000_050));
        assert_eq!(d.usage_percent, Some(48.0));
        assert_eq!(d.filesystems.len(), 2);
        assert_eq!(d.filesystems[0].usage_percent, Some(48.0));
        assert_eq!(d.filesystems[0].inodes_total, Some(30_000_000));
    }

    #[test]
    fn disk_metrics_do_not_double_count_a_bind_mount() {
        // One device, two mount points: capacity must be counted once.
        let mounts = vec![mount("/dev/vda1", "/"), mount("/dev/vda1", "/data")];
        let d = disk_metrics(&mounts, &FakeStatvfs);
        assert_eq!(d.total_bytes, Some(500_000_000_000));
        assert_eq!(d.filesystems.len(), 2, "both mount points still listed");
    }

    #[test]
    fn disk_metrics_omit_what_they_cannot_know() {
        let mounts = vec![mount("tmpfs", "/run")];
        let d = disk_metrics(&mounts, &ProcDiskSource::from_mounts(mounts.clone()));
        assert_eq!(d.used_bytes, None);
        assert_eq!(d.usage_percent, None);
        let json = d.to_json();
        let fs = &json.get("filesystems").unwrap().as_array().unwrap()[0];
        assert!(fs.get("used_bytes").is_none(), "unknown fields are omitted, never faked");
        assert!(fs.get("usage_percent").is_none());
        assert_eq!(fs.get("mount_point").and_then(|v| v.as_str()), Some("/run"));
    }

    #[test]
    fn disk_metrics_survive_a_mount_that_vanished() {
        let mounts = vec![mount("/dev/vda1", "/"), mount("/dev/vdz", "/gone")];
        let d = disk_metrics(&mounts, &FakeStatvfs);
        assert_eq!(d.filesystems.len(), 2);
        assert_eq!(d.filesystems[1].total_bytes, None);
    }

    #[test]
    fn proc_disk_source_errors_for_an_unknown_mount_point() {
        let s = ProcDiskSource::from_mounts(vec![mount("/dev/vda1", "/")]);
        assert!(s.statfs("/nope").is_err());
        assert!(s.statfs("/").is_ok());
    }

    // ---- network ---------------------------------------------------------

    #[test]
    fn net_dev_parses_counters_and_skips_loopback() {
        let n = parse_net_dev(NET_DEV);
        assert_eq!(n.len(), 2, "lo and both header rows excluded");
        let eth = n.iter().find(|i| i.name == "eth0").unwrap();
        assert_eq!(eth.rx_bytes, 34_631_126);
        assert_eq!(eth.tx_bytes, 42_735_941);
        assert_eq!(eth.rx_errors, 3);
        assert_eq!(eth.tx_errors, 7);
    }

    #[test]
    fn net_dev_handles_a_name_touching_its_colon() {
        // A wide byte count leaves no space after the colon.
        let line = "eth0:34631126 84611 0 0 0 0 0 0 42735941 84390 0 0 0 0 0 0\n";
        let n = parse_net_dev(line);
        assert_eq!(n[0].name, "eth0");
        assert_eq!(n[0].rx_bytes, 34_631_126);
    }

    #[test]
    fn net_dev_keeps_a_truncated_row_with_zero_counters() {
        let n = parse_net_dev("  eth0: 1 2 3\n");
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].rx_bytes, 0);
    }

    #[test]
    fn net_dev_on_empty_input() {
        assert!(parse_net_dev("").is_empty());
        assert!(parse_net_dev("garbage with no colon\n").is_empty());
    }

    fn counters(name: &str, rx: u64, tx: u64) -> InterfaceCounters {
        InterfaceCounters { name: name.into(), rx_bytes: rx, tx_bytes: tx, ..Default::default() }
    }

    #[test]
    fn network_rates_are_delta_over_elapsed() {
        let prev = vec![counters("eth0", 1000, 2000)];
        let now = vec![counters("eth0", 3048, 3024)];
        let m = network_metrics(&now, Some(&prev), 2.0, |_| true);
        assert_eq!(m.interfaces[0].rx_bytes_per_sec, 1024.0);
        assert_eq!(m.interfaces[0].tx_bytes_per_sec, 512.0);
        assert_eq!(m.rx_bytes_per_sec, 1024.0);
        assert_eq!(m.rx_bytes_total, 3048);
    }

    #[test]
    fn network_first_sample_has_no_rate() {
        let m = network_metrics(&[counters("eth0", 10, 20)], None, 0.0, |_| true);
        assert_eq!(m.interfaces[0].rx_bytes_per_sec, 0.0);
        assert_eq!(m.rx_bytes_total, 10);
    }

    #[test]
    fn network_zero_interval_never_divides_by_zero() {
        let prev = vec![counters("eth0", 0, 0)];
        let now = vec![counters("eth0", 1_000_000, 0)];
        let m = network_metrics(&now, Some(&prev), 0.0, |_| true);
        assert_eq!(m.interfaces[0].rx_bytes_per_sec, 0.0);
        assert!(m.rx_bytes_per_sec.is_finite());
    }

    #[test]
    fn network_reset_counters_do_not_spike() {
        let prev = vec![counters("eth0", 9_000_000, 9_000_000)];
        let now = vec![counters("eth0", 10, 10)];
        let m = network_metrics(&now, Some(&prev), 1.0, |_| true);
        assert_eq!(m.interfaces[0].rx_bytes_per_sec, 0.0);
    }

    #[test]
    fn network_a_new_interface_has_no_baseline() {
        let prev = vec![counters("eth0", 0, 0)];
        let now = vec![counters("eth0", 100, 0), counters("veth1", 5000, 0)];
        let m = network_metrics(&now, Some(&prev), 1.0, |n| n == "eth0");
        assert_eq!(m.interfaces[1].rx_bytes_per_sec, 0.0);
        assert!(!m.interfaces[1].up);
        assert!(m.interfaces[0].up);
    }

    #[test]
    fn operstate_only_up_counts_as_up() {
        assert!(operstate_is_up("up\n"));
        assert!(operstate_is_up("UP"));
        assert!(!operstate_is_up("unknown"));
        assert!(!operstate_is_up("down"));
        assert!(!operstate_is_up(""));
    }

    // ---- JSON ------------------------------------------------------------

    #[test]
    fn metrics_json_has_the_documented_shape() {
        let now = parse_cpu_stat(STAT).unwrap();
        let m = Metrics {
            sampled_at: 1_757_635_200,
            cpu: cpu_metrics(&now, None, LoadAverage { one: 0.42, five: 0.51, fifteen: 0.48 }),
            memory: parse_memory(MEMINFO),
            disk: disk_metrics(&[mount("/dev/vda1", "/")], &FakeStatvfs),
            network: network_metrics(&parse_net_dev(NET_DEV), None, 0.0, |_| true),
        };
        let v = m.to_json();
        assert_eq!(v.get("sampled_at").and_then(|v| v.as_u64()), Some(1_757_635_200));
        assert_eq!(v.path("cpu/core_count").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(v.path("cpu/load_average/five").and_then(|v| v.as_f64()), Some(0.51));
        assert_eq!(v.path("cpu/per_core").and_then(|v| v.as_array()).map(|a| a.len()), Some(2));
        assert_eq!(v.path("memory/usage_percent").and_then(|v| v.as_f64()), Some(8.4));
        assert_eq!(v.path("disk/usage_percent").and_then(|v| v.as_f64()), Some(48.0));
        assert_eq!(
            v.path("disk/filesystems").and_then(|v| v.as_array()).map(|a| a.len()),
            Some(1)
        );
        assert_eq!(v.path("network/rx_bytes_total").and_then(|v| v.as_u64()), Some(34_631_126));
        assert_eq!(
            v.path("network/interfaces").and_then(|v| v.as_array()).map(|a| a.len()),
            Some(2)
        );
    }

    #[test]
    fn metrics_json_never_contains_a_nan_or_infinity() {
        // Serialised JSON must be parseable; NaN and Infinity are not JSON.
        let m = Metrics::default();
        let s = m.to_json().to_string();
        assert!(!s.contains("NaN"), "{s}");
        assert!(!s.contains("inf"), "{s}");
        assert!(serveros_json::from_str(&s).is_ok());
    }
}
