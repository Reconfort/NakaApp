//! Enrollment: giving one desktop app the ability to manage this server.
//!
//! # The flow
//!
//! ```text
//!   macOS app ──ssh──▶ install script ──▶ serveros-agent enroll --print
//!                                             │
//!                            writes /etc/serveros/agent.key   (0600, root)
//!                            writes /etc/serveros/agent.json
//!                                             │
//!                            prints ONE line on stdout ◀── captured by the app
//!                                                          and put in the Keychain
//! ```
//!
//! The secret crosses the wire exactly once, inside an already-authenticated,
//! already-encrypted SSH session, and is never transmitted again — subsequent
//! requests carry a signature over it, not the secret itself.
//!
//! # Why print rather than accept
//!
//! The alternative is for the app to generate the secret and push it to the
//! server. Generating it on the server is better: the value never exists on the
//! desktop before it exists on the host it protects, there is no window where a
//! half-configured agent holds a key the app thinks is live, and re-running
//! enrollment is the natural way to rotate.

use crate::config::Config;
use serveros_crypto::{b64url_encode, random_bytes};
use std::io::Write;
use std::path::Path;

/// The single line printed on stdout at the end of enrollment.
pub const BUNDLE_PREFIX: &str = "SERVEROS-ENROLLMENT-V1";

#[derive(Debug)]
pub enum EnrollError {
    Io(std::io::Error),
    AlreadyEnrolled(String),
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollError::Io(e) => write!(f, "{e}"),
            EnrollError::AlreadyEnrolled(p) => write!(
                f,
                "this server is already enrolled ({p} exists). Re-run with --force to replace the \
                 key, which will disconnect any Mac currently using it"
            ),
        }
    }
}

impl std::error::Error for EnrollError {}

impl From<std::io::Error> for EnrollError {
    fn from(e: std::io::Error) -> Self {
        EnrollError::Io(e)
    }
}

pub struct Enrollment {
    pub server_id: String,
    pub secret_b64: String,
    pub port: u16,
}

/// Hand-written so the secret cannot reach a log line, a panic message or a
/// test failure. `#[derive(Debug)]` here would print the one value in this
/// whole program that must never be printed twice.
impl std::fmt::Debug for Enrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Enrollment")
            .field("server_id", &self.server_id)
            .field("secret_b64", &"[redacted]")
            .field("port", &self.port)
            .finish()
    }
}

impl Enrollment {
    /// The line the desktop app parses.
    ///
    /// Space-separated and prefixed so the app can find it in a noisy SSH
    /// session where the shell profile has printed a banner, a MOTD and an
    /// "unattended-upgrades" notice before our output.
    pub fn bundle_line(&self) -> String {
        format!(
            "{BUNDLE_PREFIX} {} {} {} {}",
            self.server_id,
            self.secret_b64,
            self.port,
            crate::VERSION
        )
    }

    /// Parse a bundle line. Also used by the desktop app's tests via the
    /// documented format; kept here so both sides share one definition.
    pub fn parse_bundle(line: &str) -> Option<Enrollment> {
        let mut parts = line.split_whitespace();
        if parts.next()? != BUNDLE_PREFIX {
            return None;
        }
        let server_id = parts.next()?.to_string();
        let secret_b64 = parts.next()?.to_string();
        let port: u16 = parts.next()?.parse().ok()?;
        // The version field is optional so an older agent's line still parses.
        if server_id.is_empty() || secret_b64.len() < 43 {
            return None;
        }
        Some(Enrollment { server_id, secret_b64, port })
    }
}

/// Generate a server identity and secret, write them, and return the bundle.
pub fn enroll(config_path: &Path, force: bool) -> Result<Enrollment, EnrollError> {
    let mut config = Config::load(config_path).unwrap_or_default();

    if config.key_path.exists() && !force {
        return Err(EnrollError::AlreadyEnrolled(config.key_path.display().to_string()));
    }

    let secret = random_bytes(32)?;
    let secret_b64 = b64url_encode(&secret);

    let server_id = if config.server_id.is_empty() || force {
        let suffix = random_bytes(8).map(|b| serveros_crypto::hex_encode(&b))?;
        format!("srv_{suffix}")
    } else {
        config.server_id.clone()
    };
    config.server_id = server_id.clone();

    if let Some(parent) = config.key_path.parent() {
        std::fs::create_dir_all(parent)?;
        restrict_dir(parent)?;
    }

    write_private(&config.key_path, secret_b64.as_bytes())?;

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let config_text = config.to_json().to_string_pretty();
    std::fs::write(config_path, config_text)?;

    std::fs::create_dir_all(&config.data_dir)?;
    restrict_dir(&config.data_dir)?;

    Ok(Enrollment { server_id, secret_b64, port: config.port.unwrap_or(crate::config::DEFAULT_PORT) })
}

/// Write a file that only its owner can read, without ever letting it exist
/// with looser permissions.
///
/// `File::create` then `set_permissions` leaves a window — however brief — in
/// which the key is world-readable. Creating with the mode up front closes it.
fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    // Remove first: opening an existing file with `.mode()` does not change the
    // mode of a file that is already there.
    let _ = std::fs::remove_file(path);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn restrict_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> TempDir {
            let p = std::env::temp_dir().join(format!(
                "serveros-enroll-{}-{}-{tag}",
                std::process::id(),
                crate::auth::now_unix()
            ));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn enroll_in(dir: &TempDir, force: bool) -> Result<Enrollment, EnrollError> {
        let config_path = dir.0.join("agent.json");
        // Point the key and data dir inside the temp dir before enrolling.
        let seed = Config {
            key_path: dir.0.join("agent.key"),
            data_dir: dir.0.join("data"),
            ..Config::default()
        };
        std::fs::write(&config_path, seed.to_json().to_string()).unwrap();
        enroll(&config_path, force)
    }

    #[test]
    fn enrollment_writes_a_key_only_root_can_read() {
        let dir = TempDir::new("perms");
        let e = enroll_in(&dir, false).unwrap();
        let key_path = dir.0.join("agent.key");

        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file mode was {mode:o}");
        assert!(!e.secret_b64.is_empty());

        // And the loader accepts it, which is the real end-to-end check.
        let loaded = crate::auth::load_secret(&key_path).unwrap();
        assert_eq!(loaded.len(), 32);
    }

    #[test]
    fn enrollment_is_idempotent_unless_forced() {
        let dir = TempDir::new("idem");
        enroll_in(&dir, false).unwrap();
        let err = enroll(&dir.0.join("agent.json"), false).unwrap_err();
        assert!(matches!(err, EnrollError::AlreadyEnrolled(_)));
        assert!(err.to_string().contains("--force"), "error should say how to proceed");
    }

    #[test]
    fn forcing_replaces_the_key_and_the_identity() {
        let dir = TempDir::new("force");
        let first = enroll_in(&dir, false).unwrap();
        let second = enroll(&dir.0.join("agent.json"), true).unwrap();
        assert_ne!(first.secret_b64, second.secret_b64);
        assert_ne!(first.server_id, second.server_id);

        // The old secret must no longer verify anything signed for the new one.
        let old = serveros_crypto::b64url_decode(&first.secret_b64).unwrap();
        let new = serveros_crypto::b64url_decode(&second.secret_b64).unwrap();
        let token = crate::auth::mint_token(&new, "mac", &[crate::auth::Scope::Read], 60, crate::auth::now_unix());
        assert!(crate::auth::Authenticator::new(old).verify(&token).is_err());
        assert!(crate::auth::Authenticator::new(new).verify(&token).is_ok());
    }

    #[test]
    fn secrets_from_two_enrollments_are_different() {
        let a = TempDir::new("rand-a");
        let b = TempDir::new("rand-b");
        assert_ne!(enroll_in(&a, false).unwrap().secret_b64, enroll_in(&b, false).unwrap().secret_b64);
    }

    #[test]
    fn bundle_round_trips() {
        let e = Enrollment {
            server_id: "srv_abc123".into(),
            secret_b64: b64url_encode(&[9u8; 32]),
            port: 8723,
        };
        let line = e.bundle_line();
        assert!(line.starts_with(BUNDLE_PREFIX));

        let parsed = Enrollment::parse_bundle(&line).expect("should parse");
        assert_eq!(parsed.server_id, e.server_id);
        assert_eq!(parsed.secret_b64, e.secret_b64);
        assert_eq!(parsed.port, 8723);
    }

    #[test]
    fn bundle_is_found_among_ssh_session_noise() {
        // Real servers print a MOTD, update notices and sudo banners. The app
        // scans the session output for our line; it must be unambiguous.
        let e = Enrollment {
            server_id: "srv_x".into(),
            secret_b64: b64url_encode(&[1u8; 32]),
            port: 8723,
        };
        let session = format!(
            "Welcome to Ubuntu 24.04.1 LTS\n\n 12 updates can be applied immediately.\n\
             [sudo] password for deploy:\n{}\nLast login: Fri Sep 12\n",
            e.bundle_line()
        );
        let found = session
            .lines()
            .find_map(Enrollment::parse_bundle)
            .expect("bundle should be findable in noisy output");
        assert_eq!(found.server_id, "srv_x");
    }

    #[test]
    fn rejects_malformed_bundles() {
        for bad in [
            "",
            "SERVEROS-ENROLLMENT-V1",
            "SERVEROS-ENROLLMENT-V1 srv_x",
            "SERVEROS-ENROLLMENT-V1 srv_x shortsecret 8723",
            "SERVEROS-ENROLLMENT-V2 srv_x aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 8723",
            "Welcome to Ubuntu",
        ] {
            assert!(Enrollment::parse_bundle(bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn enrollment_creates_a_private_data_directory() {
        let dir = TempDir::new("datadir");
        enroll_in(&dir, false).unwrap();
        let mode = std::fs::metadata(dir.0.join("data")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "data dir mode was {mode:o}");
    }

    #[test]
    fn the_written_config_contains_no_secret() {
        let dir = TempDir::new("cfg");
        let e = enroll_in(&dir, false).unwrap();
        let written = std::fs::read_to_string(dir.0.join("agent.json")).unwrap();
        assert!(written.contains(&e.server_id));
        assert!(!written.contains(&e.secret_b64), "secret leaked into the config file");
    }
}
