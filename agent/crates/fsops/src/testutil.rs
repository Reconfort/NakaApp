//! A temporary directory that cleans up after itself.
//!
//! This crate cannot take a dependency on `tempfile`, and it must not leave
//! droppings in `/tmp` on a developer's machine or in CI. Twenty lines buys
//! both, plus a guarantee the real crate wants anyway: each directory name is
//! unique across threads *and* processes, so no two tests can collide even
//! when `cargo test` runs them in parallel in a shared `TMPDIR`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique temporary directory, removed when the guard is dropped.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create `<temp_dir>/serveros-fsops-<tag>-<pid>-<nanos>-<n>`.
    pub fn new(tag: &str) -> TempDir {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 + d.as_secs())
            .unwrap_or(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let path = std::env::temp_dir().join(format!("serveros-fsops-{tag}-{pid}-{nanos}-{n}"));
        std::fs::create_dir_all(&path).expect("temp dir must be creatable");
        // Canonicalise: on some systems TMPDIR itself is a symlink, and every
        // assertion in this crate compares against canonical paths.
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        TempDir { path }
    }

    /// The directory itself.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `self.path().join(name).to_str().unwrap().to_owned()`, which every test
    /// would otherwise write out longhand.
    pub fn s(&self, name: &str) -> String {
        self.path.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best effort: a test that leaves a read-only directory behind should
        // fail on its own assertion, not on a panic in Drop during unwinding.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
