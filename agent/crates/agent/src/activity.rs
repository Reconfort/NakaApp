//! The agent's local activity and audit record.
//!
//! Every state-changing operation appends one line here before its response is
//! written. The control plane keeps the authoritative, tamper-evident history,
//! but the agent's own copy matters for two reasons: it survives the control
//! plane being unreachable, and it is what an operator reads when they are
//! already SSH'd into the box asking "what touched this server?".
//!
//! Format is JSON Lines — appendable, greppable, and readable with `tail -f`
//! without any ServerOS tooling.

use crate::logging;
use serveros_json::{Object, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Rotate once the file passes this size, keeping one previous generation.
pub const MAX_LOG_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Succeeded,
    Failed,
}

impl Outcome {
    fn as_str(&self) -> &'static str {
        match self {
            Outcome::Succeeded => "succeeded",
            Outcome::Failed => "failed",
        }
    }
}

/// One recorded action.
#[derive(Debug, Clone)]
pub struct Event {
    /// Dotted action name, e.g. `docker.container.restart`.
    pub action: String,
    /// What kind of thing was acted on: `container`, `service`, `user`, `file`.
    pub resource_type: String,
    /// Its identifier — a container name, a unit name, a path.
    pub resource_id: String,
    /// Token subject: which enrolled client did this.
    pub actor: String,
    pub peer: String,
    pub outcome: Outcome,
    /// One sentence, already written for a human to read in the UI feed.
    pub summary: String,
    /// Extra structured context. Redacted before it is written.
    pub metadata: Option<Object>,
}

impl Event {
    pub fn new(
        action: impl Into<String>,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Event {
        Event {
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            actor: "unknown".into(),
            peer: String::new(),
            outcome: Outcome::Succeeded,
            summary: String::new(),
            metadata: None,
        }
    }

    pub fn actor(mut self, actor: impl Into<String>) -> Event {
        self.actor = actor.into();
        self
    }

    pub fn peer(mut self, peer: impl Into<String>) -> Event {
        self.peer = peer.into();
        self
    }

    pub fn summary(mut self, summary: impl Into<String>) -> Event {
        self.summary = summary.into();
        self
    }

    pub fn failed(mut self) -> Event {
        self.outcome = Outcome::Failed;
        self
    }

    pub fn outcome(mut self, ok: bool) -> Event {
        self.outcome = if ok { Outcome::Succeeded } else { Outcome::Failed };
        self
    }

    pub fn meta(mut self, key: &str, value: impl Into<Value>) -> Event {
        let obj = self.metadata.take().unwrap_or_default();
        self.metadata = Some(obj.set(key, value));
        self
    }

    fn to_json(&self, id: u64, at: i64) -> Value {
        Object::new()
            .set("id", id)
            .set("at", at)
            .set("action", self.action.as_str())
            .set("resource_type", self.resource_type.as_str())
            .set("resource_id", self.resource_id.as_str())
            .set("actor", self.actor.as_str())
            .set_opt("peer", (!self.peer.is_empty()).then(|| self.peer.as_str()))
            .set("outcome", self.outcome.as_str())
            .set("summary", self.summary.as_str())
            .set_opt(
                "metadata",
                self.metadata
                    .as_ref()
                    .map(|m| logging::redact_value(&Value::Object(m.clone()))),
            )
            .into()
    }
}

pub struct ActivityLog {
    path: PathBuf,
    inner: Mutex<LogState>,
}

struct LogState {
    next_id: u64,
    /// Most recent events, so the common "show me the last 50" read does not
    /// touch the disk at all.
    recent: std::collections::VecDeque<Value>,
}

const RECENT_CAPACITY: usize = 200;

impl ActivityLog {
    /// Open (creating if needed). Failing to open is logged, not fatal: losing
    /// the activity feed must never stop the agent from managing the server.
    pub fn open(path: impl Into<PathBuf>) -> ActivityLog {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                logging::warn(&format!("cannot create activity log directory: {e}"));
            }
        }
        let (next_id, recent) = Self::load_tail(&path, RECENT_CAPACITY);
        ActivityLog { path, inner: Mutex::new(LogState { next_id, recent }) }
    }

    fn load_tail(path: &Path, limit: usize) -> (u64, std::collections::VecDeque<Value>) {
        let mut recent = std::collections::VecDeque::with_capacity(limit);
        let mut max_id = 0u64;

        if let Ok(file) = std::fs::File::open(path) {
            for line in BufReader::new(file).lines().map_while(Result::ok) {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(v) = serveros_json::from_str(&line) {
                    max_id = max_id.max(v.get("id").and_then(|i| i.as_u64()).unwrap_or(0));
                    if recent.len() == limit {
                        recent.pop_front();
                    }
                    recent.push_back(v);
                }
                // A corrupt line (partial write from a power loss) is skipped
                // rather than failing the whole read.
            }
        }
        (max_id + 1, recent)
    }

    /// Append an event. Never panics and never propagates an error — an audit
    /// write failing must not turn a successful restart into a 500.
    pub fn record(&self, event: Event) {
        let at = crate::auth::now_unix();
        let Ok(mut state) = self.inner.lock() else {
            logging::error("activity log mutex poisoned; event not recorded");
            return;
        };
        let id = state.next_id;
        state.next_id += 1;

        let record = event.to_json(id, at);
        if state.recent.len() == RECENT_CAPACITY {
            state.recent.pop_front();
        }
        state.recent.push_back(record.clone());
        drop(state);

        self.rotate_if_needed();

        let line = record.to_string();
        match std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{line}") {
                    logging::warn(&format!("cannot append to activity log: {e}"));
                }
            }
            Err(e) => logging::warn(&format!("cannot open activity log: {e}")),
        }

        // Mirror to the process log so `journalctl -u serveros-agent` tells the
        // same story as the app's activity feed.
        logging::info_with(
            &format!("{} {}", event.action, event.resource_id),
            Object::new().set("outcome", event.outcome.as_str()).set("actor", event.actor.as_str()),
        );
    }

    /// Most recent events, newest first.
    pub fn recent(&self, limit: usize, since_id: Option<u64>) -> Vec<Value> {
        let Ok(state) = self.inner.lock() else { return Vec::new() };
        state
            .recent
            .iter()
            .rev()
            .filter(|v| match since_id {
                Some(since) => v.get("id").and_then(|i| i.as_u64()).unwrap_or(0) > since,
                None => true,
            })
            .take(limit.clamp(1, RECENT_CAPACITY))
            .cloned()
            .collect()
    }

    fn rotate_if_needed(&self) {
        let Ok(meta) = std::fs::metadata(&self.path) else { return };
        if meta.len() < MAX_LOG_BYTES {
            return;
        }
        let previous = self.path.with_extension("jsonl.1");
        if let Err(e) = std::fs::rename(&self.path, &previous) {
            logging::warn(&format!("cannot rotate activity log: {e}"));
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let p = std::env::temp_dir()
                .join(format!("serveros-activity-{}-{}-{tag}", std::process::id(), crate::auth::now_unix()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        fn file(&self) -> PathBuf {
            self.0.join("activity.jsonl")
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn records_and_reads_back_events() {
        let dir = TempDir::new("basic");
        let log = ActivityLog::open(dir.file());
        log.record(
            Event::new("docker.container.restart", "container", "estatify-api")
                .actor("mac-of-abebe")
                .summary("Restarted Estatify API"),
        );
        log.record(Event::new("service.restart", "service", "nginx.service").summary("Restarted Nginx"));

        let recent = log.recent(10, None);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].get("resource_id").unwrap().as_str(), Some("nginx.service"));
        assert_eq!(recent[1].get("actor").unwrap().as_str(), Some("mac-of-abebe"));
        assert_eq!(recent[0].get("outcome").unwrap().as_str(), Some("succeeded"));
    }

    #[test]
    fn ids_increase_and_survive_a_restart() {
        let dir = TempDir::new("ids");
        {
            let log = ActivityLog::open(dir.file());
            log.record(Event::new("a", "t", "1"));
            log.record(Event::new("b", "t", "2"));
        }
        // Reopening must not reuse ids — the app pages by id.
        let log = ActivityLog::open(dir.file());
        log.record(Event::new("c", "t", "3"));
        let recent = log.recent(10, None);
        let ids: Vec<u64> = recent.iter().map(|v| v.get("id").unwrap().as_u64().unwrap()).collect();
        assert_eq!(ids, vec![3, 2, 1], "newest first, ids continue across restarts");
    }

    #[test]
    fn since_id_filters_for_incremental_polling() {
        let dir = TempDir::new("since");
        let log = ActivityLog::open(dir.file());
        for i in 0..5 {
            log.record(Event::new("a", "t", i.to_string()));
        }
        let after_two = log.recent(10, Some(2));
        assert_eq!(after_two.len(), 3);
        assert!(after_two.iter().all(|v| v.get("id").unwrap().as_u64().unwrap() > 2));
    }

    #[test]
    fn metadata_is_redacted_before_it_is_written() {
        // The single most important property of this module.
        let dir = TempDir::new("redact");
        let log = ActivityLog::open(dir.file());
        log.record(
            Event::new("user.create", "user", "deploy")
                .summary("Created user deploy")
                .meta("password", "hunter2")
                .meta("shell", "/bin/bash"),
        );

        let on_disk = std::fs::read_to_string(dir.file()).unwrap();
        assert!(!on_disk.contains("hunter2"), "password reached the audit log: {on_disk}");
        assert!(on_disk.contains("[redacted]"));
        assert!(on_disk.contains("/bin/bash"), "non-secret metadata must survive");
    }

    #[test]
    fn a_corrupt_line_does_not_break_the_reader() {
        let dir = TempDir::new("corrupt");
        let path = dir.file();
        std::fs::write(
            &path,
            "{\"id\":1,\"action\":\"a\"}\n{truncated write from a power los\n{\"id\":2,\"action\":\"b\"}\n",
        )
        .unwrap();
        let log = ActivityLog::open(&path);
        let recent = log.recent(10, None);
        assert_eq!(recent.len(), 2, "valid lines either side of the corrupt one should load");
        log.record(Event::new("c", "t", "3"));
        assert_eq!(log.recent(1, None)[0].get("id").unwrap().as_u64(), Some(3));
    }

    #[test]
    fn failed_outcomes_are_recorded_as_such() {
        let dir = TempDir::new("failed");
        let log = ActivityLog::open(dir.file());
        log.record(Event::new("service.restart", "service", "nginx").failed().summary("Failed"));
        assert_eq!(log.recent(1, None)[0].get("outcome").unwrap().as_str(), Some("failed"));
        assert_eq!(Event::new("a", "b", "c").outcome(false).outcome, Outcome::Failed);
    }

    #[test]
    fn an_unwritable_path_does_not_panic() {
        // Disk full or a read-only filesystem must degrade, not crash.
        let log = ActivityLog::open("/proc/definitely-not-writable/activity.jsonl");
        log.record(Event::new("a", "t", "1"));
        // In-memory recents still work even though the write failed.
        assert_eq!(log.recent(10, None).len(), 1);
    }

    #[test]
    fn recent_is_bounded() {
        let dir = TempDir::new("bounded");
        let log = ActivityLog::open(dir.file());
        for i in 0..(RECENT_CAPACITY + 50) {
            log.record(Event::new("a", "t", i.to_string()));
        }
        assert_eq!(log.recent(10_000, None).len(), RECENT_CAPACITY);
    }
}
