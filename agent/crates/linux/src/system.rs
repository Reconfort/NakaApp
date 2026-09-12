//! Static system identity: "what machine is this?"
//!
//! Everything here changes rarely (hostname, distribution, kernel, CPU model,
//! installed RAM) or monotonically (uptime), which is why it is separated from
//! [`crate::metrics`]. The app fetches this once when a server connects and
//! caches it; the live numbers arrive over the metrics stream instead.
//!
//! The governing constraint is that **every field must degrade**. This runs in
//! LXC containers with no `/sys/class/dmi`, on ARM boards whose `/proc/cpuinfo`
//! has no `model name`, and on minimal images with no `/etc/os-release`. A
//! server that reports "Linux / unknown CPU" is far better than a server that
//! fails to connect, so the only hard error is "`/proc` is not mounted at all",
//! which genuinely means we cannot manage this host.

use crate::error::LinuxError;
use crate::procfs;
use serveros_json::{Object, Value, round};

/// Distribution identity, as read from `os-release(5)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsInfo {
    /// `NAME` — "Ubuntu", "Debian GNU/Linux".
    pub name: String,
    /// `VERSION` with the trailing codename stripped — "24.04.1 LTS".
    pub version: String,
    /// `ID` — the lowercase machine-readable id, "ubuntu".
    pub id: String,
    /// `PRETTY_NAME` — the one-line string a human recognises.
    pub pretty: String,
}

impl Default for OsInfo {
    fn default() -> Self {
        OsInfo {
            name: "Linux".to_string(),
            version: String::new(),
            id: "linux".to_string(),
            pretty: "Linux".to_string(),
        }
    }
}

/// Processor identity. Frequency is the nominal figure from `/proc/cpuinfo`,
/// not a live measurement — the live one lives in the metrics stream.
#[derive(Debug, Clone, PartialEq)]
pub struct CpuInfo {
    /// `model name`, e.g. "Intel(R) Xeon(R) Processor @ 2.80GHz".
    pub model: String,
    /// Physical cores, derived from distinct (`physical id`, `core id`) pairs.
    pub cores: u32,
    /// Logical processors — what the scheduler sees.
    pub threads: u32,
    /// Nominal clock in MHz.
    pub mhz: f64,
}

impl Default for CpuInfo {
    fn default() -> Self {
        CpuInfo { model: "Unknown".to_string(), cores: 1, threads: 1, mhz: 0.0 }
    }
}

/// The kernel's 1/5/15-minute run-queue averages.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct LoadAverage {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
}

impl LoadAverage {
    /// `{"one":0.42,"five":0.51,"fifteen":0.48}`
    pub fn to_json(&self) -> Value {
        Object::new()
            .set("one", round(self.one, 2))
            .set("five", round(self.five, 2))
            .set("fifteen", round(self.fifteen, 2))
            .into()
    }
}

/// Everything the app needs to render a server's header and hardware summary.
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub hostname: String,
    pub os: OsInfo,
    /// `uname -r` equivalent, from `/proc/sys/kernel/osrelease`.
    pub kernel: String,
    /// The architecture this agent binary was built for.
    pub architecture: String,
    pub cpu: CpuInfo,
    pub memory_total_bytes: u64,
    pub swap_total_bytes: u64,
    /// Unix time the kernel started.
    pub boot_time: u64,
    pub uptime_seconds: u64,
    /// Best-effort hypervisor identity; `None` on bare metal or when unknown.
    pub virtualization: Option<String>,
    pub load_average: LoadAverage,
}

impl SystemInfo {
    /// Serialise in the exact shape the macOS app decodes.
    pub fn to_json(&self) -> Value {
        let os = Object::new()
            .set("name", self.os.name.as_str())
            .set("version", self.os.version.as_str())
            .set("id", self.os.id.as_str())
            .set("pretty", self.os.pretty.as_str());

        let cpu = Object::new()
            .set("model", self.cpu.model.as_str())
            .set("cores", self.cpu.cores)
            .set("threads", self.cpu.threads)
            .set("mhz", round(self.cpu.mhz, 2));

        Object::new()
            .set("hostname", self.hostname.as_str())
            .set("os", os)
            .set("kernel", self.kernel.as_str())
            .set("architecture", self.architecture.as_str())
            .set("cpu", cpu)
            .set("memory_total_bytes", self.memory_total_bytes)
            .set("swap_total_bytes", self.swap_total_bytes)
            .set("boot_time", self.boot_time)
            .set("uptime_seconds", self.uptime_seconds)
            // Explicitly null, not omitted: "we looked and it is bare metal" is
            // information, and the app renders it as "Physical".
            .set("virtualization", Value::from(self.virtualization.clone()))
            .set("load_average", self.load_average.to_json())
            .into()
    }
}

/// Read the machine's static identity.
///
/// Fails only when `/proc/meminfo` is absent, which means procfs is not mounted
/// and nothing else in this crate can work either. Every other source degrades
/// to a documented default.
pub fn read_system_info() -> Result<SystemInfo, LinuxError> {
    let meminfo = procfs::read_text_opt("/proc/meminfo")
        .ok_or(LinuxError::NotSupported("/proc (procfs is not mounted)"))?;

    let hostname =
        procfs::read_line_opt("/proc/sys/kernel/hostname").unwrap_or_else(|| "localhost".into());
    let kernel = procfs::read_line_opt("/proc/sys/kernel/osrelease").unwrap_or_default();

    // `/usr/lib/os-release` is the fallback mandated by the spec for systems
    // with a read-only or absent `/etc`.
    let os = procfs::read_text_opt("/etc/os-release")
        .or_else(|| procfs::read_text_opt("/usr/lib/os-release"))
        .map(|t| parse_os_release(&t))
        .unwrap_or_default();

    let cpuinfo = procfs::read_text_opt("/proc/cpuinfo").unwrap_or_default();
    let cpu = parse_cpuinfo(&cpuinfo);

    let (memory_total_bytes, swap_total_bytes) = parse_memory_totals(&meminfo);

    let uptime_seconds = procfs::read_text_opt("/proc/uptime")
        .and_then(|t| parse_uptime(&t))
        .unwrap_or(0);

    // `btime` is authoritative. Deriving boot time from `now - uptime` is the
    // fallback, and it drifts by however much the clock has been stepped since
    // boot — acceptable for a "booted 3 days ago" label, not for correlation.
    let boot_time = procfs::read_text_opt("/proc/stat")
        .and_then(|t| parse_btime(&t))
        .unwrap_or_else(|| procfs::now_unix().saturating_sub(uptime_seconds));

    let load_average = procfs::read_text_opt("/proc/loadavg")
        .map(|t| parse_loadavg(&t))
        .unwrap_or_default();

    let virtualization = detect_virtualization(
        procfs::read_line_opt("/sys/class/dmi/id/product_name").as_deref(),
        procfs::read_line_opt("/sys/hypervisor/type").as_deref(),
        cpuinfo_has_hypervisor_flag(&cpuinfo),
    );

    Ok(SystemInfo {
        hostname,
        os,
        kernel,
        // There is no portable runtime source for this without libc's `uname`,
        // and it cannot differ from the binary we are executing anyway: the
        // agent is compiled per-architecture.
        architecture: std::env::consts::ARCH.to_string(),
        cpu,
        memory_total_bytes,
        swap_total_bytes,
        boot_time,
        uptime_seconds,
        virtualization,
        load_average,
    })
}

// ---- parsers (pure, so they can be tested against fixtures) ---------------

/// Parse `os-release(5)`: `KEY=VALUE`, optionally quoted, `#` comments.
///
/// The format is "a subset of shell", so a value may contain `=`, and a
/// double-quoted value may contain backslash escapes. Both are handled; nothing
/// else of shell is (no `$VAR`, no line continuation) because no distribution
/// emits them and guessing wrong is worse than passing the text through.
pub fn parse_os_release(text: &str) -> OsInfo {
    let mut name = None;
    let mut version = None;
    let mut version_id = None;
    let mut id = None;
    let mut pretty = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // `splitn(2)` — a value is allowed to contain `=`.
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let value = unquote_shell(raw.trim());
        if value.is_empty() {
            continue;
        }
        match key.trim() {
            "NAME" => name = Some(value),
            "VERSION" => version = Some(value),
            "VERSION_ID" => version_id = Some(value),
            "ID" => id = Some(value),
            "PRETTY_NAME" => pretty = Some(value),
            _ => {}
        }
    }

    let default = OsInfo::default();
    let name = name.unwrap_or(default.name);
    // `VERSION` carries the codename in parentheses ("24.04.1 LTS (Noble
    // Numbat)"). The codename belongs in neither a header nor a version
    // comparison, and `PRETTY_NAME` already contains it for anyone who wants
    // it, so it is stripped here.
    let version = version
        .map(|v| strip_codename(&v))
        .or(version_id)
        .unwrap_or(default.version);
    let id = id.unwrap_or_else(|| {
        // No `ID`: synthesise one from `NAME` the way the spec suggests.
        name.to_ascii_lowercase().split_whitespace().next().unwrap_or("linux").to_string()
    });
    let pretty = pretty.unwrap_or_else(|| format!("{name} {version}").trim().to_string());

    OsInfo { name, version, id, pretty }
}

/// Strip surrounding quotes and resolve the backslash escapes os-release allows
/// inside double quotes.
fn unquote_shell(raw: &str) -> String {
    let bytes = raw.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' || first == b'\'') && first == last {
            let inner = &raw[1..raw.len() - 1];
            if first == b'\'' {
                // Single quotes are literal in shell; nothing to unescape.
                return inner.to_string();
            }
            let mut out = String::with_capacity(inner.len());
            let mut chars = inner.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    match chars.next() {
                        Some(n @ ('"' | '\\' | '$' | '`')) => out.push(n),
                        Some(other) => {
                            out.push('\\');
                            out.push(other);
                        }
                        None => out.push('\\'),
                    }
                } else {
                    out.push(c);
                }
            }
            return out;
        }
    }
    raw.to_string()
}

/// "24.04.1 LTS (Noble Numbat)" -> "24.04.1 LTS".
fn strip_codename(version: &str) -> String {
    match version.rfind('(') {
        Some(i) if version.trim_end().ends_with(')') => version[..i].trim_end().to_string(),
        _ => version.trim().to_string(),
    }
}

/// Parse `/proc/cpuinfo` into model, core and thread counts, and frequency.
///
/// Thread count is the number of `processor:` blocks. Physical core count is
/// the number of distinct (`physical id`, `core id`) pairs — the only correct
/// way to do it, since `cpu cores` is per-socket and multiplying it by socket
/// count breaks on asymmetric machines. Kernels that omit those fields (most
/// ARM, many VMs) fall back to the thread count, which is what the hardware
/// actually presents there.
pub fn parse_cpuinfo(text: &str) -> CpuInfo {
    let default = CpuInfo::default();
    let mut model: Option<String> = None;
    let mut fallback_model: Option<String> = None;
    let mut mhz: Option<f64> = None;
    let mut threads: u32 = 0;
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut physical_id: Option<String> = None;
    let mut core_id: Option<String> = None;

    /// Commit the (physical id, core id) pair of the block that just ended.
    /// A pair is only meaningful when both halves were present.
    fn flush(
        physical_id: &mut Option<String>,
        core_id: &mut Option<String>,
        pairs: &mut Vec<(String, String)>,
    ) {
        if let (Some(p), Some(c)) = (physical_id.take(), core_id.take()) {
            let pair = (p, c);
            if !pairs.contains(&pair) {
                pairs.push(pair);
            }
        }
    }

    for line in text.lines() {
        if procfs::colon_value(line, "processor").is_some() {
            // A new block begins; commit the previous one's topology.
            flush(&mut physical_id, &mut core_id, &mut pairs);
            threads += 1;
        } else if let Some(v) = procfs::colon_value(line, "model name") {
            model.get_or_insert_with(|| v.to_string());
        } else if let Some(v) = procfs::colon_value(line, "cpu MHz") {
            if mhz.is_none() {
                mhz = procfs::parse_f64(v);
            }
        } else if let Some(v) = procfs::colon_value(line, "physical id") {
            physical_id = Some(v.to_string());
        } else if let Some(v) = procfs::colon_value(line, "core id") {
            core_id = Some(v.to_string());
        } else {
            // ARM and s390 name the CPU differently; take whichever shows up.
            for key in ["Model", "Hardware", "machine", "cpu"] {
                if let Some(v) = procfs::colon_value(line, key) {
                    fallback_model.get_or_insert_with(|| v.to_string());
                }
            }
        }
    }
    flush(&mut physical_id, &mut core_id, &mut pairs);

    let threads = threads.max(1);
    let cores = if pairs.is_empty() { threads } else { pairs.len() as u32 };

    CpuInfo {
        model: model.or(fallback_model).unwrap_or(default.model),
        // A machine cannot have more physical cores than logical processors;
        // if a malformed file says otherwise, trust the processor count.
        cores: cores.clamp(1, threads),
        threads,
        mhz: mhz.unwrap_or(default.mhz),
    }
}

/// `true` when the CPU advertises the `hypervisor` feature bit, which the
/// kernel sets whenever it is running under one.
pub fn cpuinfo_has_hypervisor_flag(text: &str) -> bool {
    for line in text.lines() {
        for key in ["flags", "Features"] {
            if let Some(v) = procfs::colon_value(line, key) {
                if v.split_whitespace().any(|f| f == "hypervisor") {
                    return true;
                }
            }
        }
    }
    false
}

/// `(MemTotal, SwapTotal)` in bytes; missing fields read as 0.
pub fn parse_memory_totals(meminfo: &str) -> (u64, u64) {
    (
        procfs::kv_bytes(meminfo, "MemTotal").unwrap_or(0),
        procfs::kv_bytes(meminfo, "SwapTotal").unwrap_or(0),
    )
}

/// Kernel boot time (Unix seconds) from the `btime` line of `/proc/stat`.
pub fn parse_btime(stat: &str) -> Option<u64> {
    let line = stat.lines().find(|l| l.starts_with("btime "))?;
    procfs::parse_u64(procfs::field(line, 1)?)
}

/// Whole seconds of uptime from `/proc/uptime` (first of two floats).
pub fn parse_uptime(uptime: &str) -> Option<u64> {
    let secs = procfs::parse_f64(procfs::field(procfs::first_line(uptime), 0)?)?;
    if secs < 0.0 { None } else { Some(secs as u64) }
}

/// Uptime as a float, which the process CPU-percentage maths needs.
pub fn parse_uptime_secs(uptime: &str) -> Option<f64> {
    let secs = procfs::parse_f64(procfs::field(procfs::first_line(uptime), 0)?)?;
    if secs < 0.0 { None } else { Some(secs) }
}

/// Parse `/proc/loadavg`. Missing or unparsable columns read as 0.0 rather than
/// failing the whole sample — a load average is a nice-to-have, not a reason to
/// report the server as unreachable.
pub fn parse_loadavg(text: &str) -> LoadAverage {
    let line = procfs::first_line(text);
    let get = |n: usize| procfs::field(line, n).and_then(procfs::parse_f64).unwrap_or(0.0);
    LoadAverage { one: get(0), five: get(1), fifteen: get(2) }
}

/// Best-effort hypervisor identification.
///
/// Kept pure (the three inputs are read by the caller) precisely so the mapping
/// table below can be tested without a DMI table. Order matters:
/// `/sys/hypervisor/type` is the kernel telling us directly and wins; the DMI
/// product name is a vendor string and needs a lookup table; the CPU feature
/// bit only proves that we are virtualised, not by what.
pub fn detect_virtualization(
    product_name: Option<&str>,
    hypervisor_type: Option<&str>,
    hypervisor_cpu_flag: bool,
) -> Option<String> {
    if let Some(t) = hypervisor_type {
        let t = t.trim();
        if !t.is_empty() {
            return Some(t.to_ascii_lowercase());
        }
    }

    if let Some(product) = product_name {
        let p = product.to_ascii_lowercase();
        // Ordered most-specific first: "Virtual Machine" is Hyper-V's generic
        // product name, so it must be tested after anything more precise.
        const TABLE: &[(&str, &str)] = &[
            ("kvm", "kvm"),
            ("vmware", "vmware"),
            ("virtualbox", "virtualbox"),
            ("parallels", "parallels"),
            ("bhyve", "bhyve"),
            ("qemu", "qemu"),
            ("bochs", "kvm"), // QEMU without the KVM product string.
            ("openstack", "kvm"),
            ("droplet", "kvm"), // DigitalOcean.
            ("amazon ec2", "amazon"),
            ("hvm domu", "xen"),
            ("google compute engine", "gce"),
            ("alibaba cloud", "kvm"),
            ("standard pc", "kvm"), // QEMU's i440FX/Q35 machine types.
            ("hyper-v", "hyperv"),
            ("virtual machine", "hyperv"),
        ];
        for (needle, name) in TABLE {
            if p.contains(needle) {
                return Some((*name).to_string());
            }
        }
        if !p.is_empty() && hypervisor_cpu_flag {
            return Some("virtualized".to_string());
        }
    }

    // We know we are in a VM but not which; say so rather than claiming metal.
    if hypervisor_cpu_flag { Some("virtualized".to_string()) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `/etc/os-release` from Ubuntu 24.04.
    const UBUNTU_OS_RELEASE: &str = r#"PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo
"#;

    /// Real `/proc/cpuinfo` from a 2-vCPU KVM guest, flags abridged but with
    /// `hypervisor` retained because that is the bit we look for.
    const CPUINFO: &str = "\
processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 85
model name\t: Intel(R) Xeon(R) Processor @ 2.80GHz
stepping\t: 7
cpu MHz\t\t: 2799.998
cache size\t: 33792 KB
physical id\t: 0
siblings\t: 2
core id\t\t: 0
cpu cores\t: 2
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic hypervisor lahf_lm abm
bogomips\t: 5599.99

processor\t: 1
vendor_id\t: GenuineIntel
cpu family\t: 6
model name\t: Intel(R) Xeon(R) Processor @ 2.80GHz
cpu MHz\t\t: 2799.998
physical id\t: 0
siblings\t: 2
core id\t\t: 1
cpu cores\t: 2
flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic hypervisor lahf_lm abm
";

    const MEMINFO: &str = "\
MemTotal:        8216192 kB
MemFree:         6474612 kB
MemAvailable:    7527360 kB
Buffers:           66136 kB
Cached:          1200628 kB
SwapTotal:       2097152 kB
SwapFree:        2097152 kB
";

    // ---- os-release ------------------------------------------------------

    #[test]
    fn os_release_real_ubuntu() {
        let os = parse_os_release(UBUNTU_OS_RELEASE);
        assert_eq!(os.name, "Ubuntu");
        assert_eq!(os.id, "ubuntu");
        assert_eq!(os.pretty, "Ubuntu 24.04.4 LTS");
        // Codename stripped from VERSION.
        assert_eq!(os.version, "24.04.4 LTS");
    }

    #[test]
    fn os_release_accepts_unquoted_and_single_quoted_values() {
        let os = parse_os_release("NAME=Alpine Linux\nID='alpine'\nVERSION_ID=3.20.0\n");
        assert_eq!(os.name, "Alpine Linux");
        assert_eq!(os.id, "alpine");
        // No VERSION, so VERSION_ID is used.
        assert_eq!(os.version, "3.20.0");
        assert_eq!(os.pretty, "Alpine Linux 3.20.0");
    }

    #[test]
    fn os_release_keeps_equals_signs_inside_values() {
        let os = parse_os_release("NAME=\"Weird=Distro\"\nHOME_URL=\"https://x/?a=b&c=d\"\n");
        assert_eq!(os.name, "Weird=Distro");
    }

    #[test]
    fn os_release_unescapes_double_quoted_values() {
        let os = parse_os_release("NAME=\"He said \\\"hi\\\"\"\n");
        assert_eq!(os.name, "He said \"hi\"");
    }

    #[test]
    fn os_release_skips_comments_blanks_and_junk() {
        let os = parse_os_release("# a comment\n\n   \nnot-a-kv-line\nID=debian\n");
        assert_eq!(os.id, "debian");
        assert_eq!(os.name, "Linux"); // default
    }

    #[test]
    fn os_release_empty_file_yields_defaults() {
        let os = parse_os_release("");
        assert_eq!(os, OsInfo::default());
        assert_eq!(os.pretty, "Linux");
    }

    #[test]
    fn os_release_synthesises_id_from_name() {
        let os = parse_os_release("NAME=\"Rocky Linux\"\nVERSION=\"9.4 (Blue Onyx)\"\n");
        assert_eq!(os.id, "rocky");
        assert_eq!(os.version, "9.4");
        assert_eq!(os.pretty, "Rocky Linux 9.4");
    }

    // ---- cpuinfo ---------------------------------------------------------

    #[test]
    fn cpuinfo_counts_threads_and_physical_cores() {
        let cpu = parse_cpuinfo(CPUINFO);
        assert_eq!(cpu.model, "Intel(R) Xeon(R) Processor @ 2.80GHz");
        assert_eq!(cpu.threads, 2);
        assert_eq!(cpu.cores, 2); // (0,0) and (0,1) are distinct cores
        assert!((cpu.mhz - 2799.998).abs() < 0.001);
    }

    #[test]
    fn cpuinfo_detects_hyperthread_siblings_as_one_core() {
        // Two logical processors sharing (physical id 0, core id 0).
        let text = "\
processor\t: 0
physical id\t: 0
core id\t\t: 0

processor\t: 1
physical id\t: 0
core id\t\t: 0
";
        let cpu = parse_cpuinfo(text);
        assert_eq!(cpu.threads, 2);
        assert_eq!(cpu.cores, 1);
    }

    #[test]
    fn cpuinfo_without_topology_falls_back_to_thread_count() {
        // Typical of ARM and of some hypervisors.
        let text = "processor\t: 0\nprocessor\t: 1\nprocessor\t: 2\nprocessor\t: 3\n";
        let cpu = parse_cpuinfo(text);
        assert_eq!(cpu.threads, 4);
        assert_eq!(cpu.cores, 4);
        assert_eq!(cpu.model, "Unknown");
    }

    #[test]
    fn cpuinfo_uses_arm_style_model_fields() {
        let text = "processor\t: 0\nHardware\t: BCM2835\nModel\t\t: Raspberry Pi 4\n";
        let cpu = parse_cpuinfo(text);
        // Either ARM key is acceptable; the point is that it is not "Unknown".
        assert_ne!(cpu.model, "Unknown");
        assert_eq!(cpu.threads, 1);
    }

    #[test]
    fn cpuinfo_empty_file_never_reports_zero_cores() {
        let cpu = parse_cpuinfo("");
        assert_eq!(cpu.threads, 1);
        assert_eq!(cpu.cores, 1);
        assert_eq!(cpu.mhz, 0.0);
    }

    #[test]
    fn cpuinfo_ignores_non_numeric_mhz() {
        let text = "processor\t: 0\ncpu MHz\t\t: unknown\n";
        assert_eq!(parse_cpuinfo(text).mhz, 0.0);
    }

    #[test]
    fn cpuinfo_never_reports_more_cores_than_threads() {
        // Malformed: one processor block claiming four distinct cores.
        let text = "processor\t: 0\nphysical id\t: 0\ncore id\t\t: 0\ncore id\t\t: 1\n";
        let cpu = parse_cpuinfo(text);
        assert!(cpu.cores <= cpu.threads);
    }

    #[test]
    fn hypervisor_flag_detection() {
        assert!(cpuinfo_has_hypervisor_flag(CPUINFO));
        assert!(!cpuinfo_has_hypervisor_flag("flags\t: fpu vme de pse tsc\n"));
        // Must not match a substring of another flag.
        assert!(!cpuinfo_has_hypervisor_flag("flags\t: hypervisorish\n"));
        assert!(!cpuinfo_has_hypervisor_flag(""));
    }

    // ---- meminfo / stat / uptime / loadavg -------------------------------

    #[test]
    fn memory_totals_convert_kb_to_bytes() {
        let (mem, swap) = parse_memory_totals(MEMINFO);
        assert_eq!(mem, 8_216_192 * 1024);
        assert_eq!(swap, 2_097_152 * 1024);
    }

    #[test]
    fn memory_totals_default_to_zero_when_absent() {
        assert_eq!(parse_memory_totals("MemFree: 10 kB\n"), (0, 0));
        assert_eq!(parse_memory_totals(""), (0, 0));
    }

    #[test]
    fn btime_is_found_among_other_stat_lines() {
        let stat = "cpu  1 2 3\nctxt 949047\nbtime 1789198631\nprocesses 3550\n";
        assert_eq!(parse_btime(stat), Some(1_789_198_631));
    }

    #[test]
    fn btime_missing_or_malformed_is_none() {
        assert_eq!(parse_btime("cpu 1 2 3\n"), None);
        assert_eq!(parse_btime("btime\n"), None);
        assert_eq!(parse_btime("btime not-a-number\n"), None);
        assert_eq!(parse_btime(""), None);
    }

    #[test]
    fn uptime_takes_the_first_column() {
        assert_eq!(parse_uptime("1931.93 3705.99\n"), Some(1931));
        assert_eq!(parse_uptime_secs("1931.93 3705.99\n").map(|v| v as u64), Some(1931));
    }

    #[test]
    fn uptime_rejects_garbage_and_negatives() {
        assert_eq!(parse_uptime(""), None);
        assert_eq!(parse_uptime("hello world\n"), None);
        assert_eq!(parse_uptime("-5.0 1.0\n"), None);
    }

    #[test]
    fn loadavg_parses_the_three_columns() {
        let la = parse_loadavg("0.05 0.03 0.02 4/113 3649\n");
        assert_eq!(la.one, 0.05);
        assert_eq!(la.five, 0.03);
        assert_eq!(la.fifteen, 0.02);
    }

    #[test]
    fn loadavg_degrades_on_truncated_or_junk_input() {
        assert_eq!(parse_loadavg("0.05\n").five, 0.0);
        assert_eq!(parse_loadavg("x y z\n"), LoadAverage::default());
        assert_eq!(parse_loadavg(""), LoadAverage::default());
    }

    // ---- virtualization --------------------------------------------------

    #[test]
    fn virtualization_prefers_the_kernel_hypervisor_node() {
        assert_eq!(detect_virtualization(Some("VMware7,1"), Some("xen"), true).as_deref(), Some("xen"));
    }

    #[test]
    fn virtualization_maps_known_dmi_product_names() {
        let cases = [
            ("KVM", "kvm"),
            ("VMware Virtual Platform", "vmware"),
            ("VirtualBox", "virtualbox"),
            ("Standard PC (i440FX + PIIX, 1996)", "kvm"),
            ("HVM domU", "xen"),
            ("Google Compute Engine", "gce"),
            ("Virtual Machine", "hyperv"),
            ("Droplet", "kvm"),
        ];
        for (product, expected) in cases {
            assert_eq!(
                detect_virtualization(Some(product), None, true).as_deref(),
                Some(expected),
                "product {product}"
            );
        }
    }

    #[test]
    fn virtualization_is_none_on_bare_metal() {
        assert_eq!(detect_virtualization(Some("PowerEdge R640"), None, false), None);
        assert_eq!(detect_virtualization(None, None, false), None);
    }

    #[test]
    fn virtualization_falls_back_to_the_cpu_flag() {
        // Containers have no DMI at all but do inherit the host's CPU flags.
        assert_eq!(detect_virtualization(None, None, true).as_deref(), Some("virtualized"));
        assert_eq!(
            detect_virtualization(Some("Unbranded Board"), None, true).as_deref(),
            Some("virtualized")
        );
    }

    // ---- JSON ------------------------------------------------------------

    fn sample_info() -> SystemInfo {
        SystemInfo {
            hostname: "web-1".into(),
            os: parse_os_release(UBUNTU_OS_RELEASE),
            kernel: "6.8.0-45-generic".into(),
            architecture: "x86_64".into(),
            cpu: parse_cpuinfo(CPUINFO),
            memory_total_bytes: 8_323_072_000,
            swap_total_bytes: 2_147_483_648,
            boot_time: 1_757_600_000,
            uptime_seconds: 128_400,
            virtualization: Some("kvm".into()),
            load_average: LoadAverage { one: 0.42, five: 0.51, fifteen: 0.48 },
        }
    }

    #[test]
    fn system_json_has_the_documented_shape() {
        let v = sample_info().to_json();
        assert_eq!(v.get("hostname").and_then(|v| v.as_str()), Some("web-1"));
        assert_eq!(v.path("os/id").and_then(|v| v.as_str()), Some("ubuntu"));
        assert_eq!(v.path("cpu/cores").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(v.path("cpu/threads").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(v.get("memory_total_bytes").and_then(|v| v.as_u64()), Some(8_323_072_000));
        assert_eq!(v.get("uptime_seconds").and_then(|v| v.as_u64()), Some(128_400));
        assert_eq!(v.get("virtualization").and_then(|v| v.as_str()), Some("kvm"));
        assert_eq!(v.path("load_average/one").and_then(|v| v.as_f64()), Some(0.42));
        // Frequency is rounded, never 2799.9980000000001.
        assert_eq!(v.path("cpu/mhz").and_then(|v| v.as_f64()), Some(2800.0));
    }

    #[test]
    fn system_json_emits_null_virtualization_rather_than_omitting_it() {
        let mut info = sample_info();
        info.virtualization = None;
        let v = info.to_json();
        assert!(v.get("virtualization").is_some(), "key must be present");
        assert!(v.get("virtualization").unwrap().is_null());
    }

    #[test]
    fn system_json_key_order_is_stable() {
        let s = sample_info().to_json().to_string();
        let hostname = s.find("\"hostname\"").unwrap();
        let os = s.find("\"os\"").unwrap();
        let load = s.find("\"load_average\"").unwrap();
        assert!(hostname < os && os < load, "{s}");
    }
}
