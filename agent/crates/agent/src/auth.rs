//! Request authorisation.
//!
//! # The shape of a token
//!
//! ```text
//! serveros.<base64url(payload)>.<base64url(HMAC-SHA256(secret, "serveros.<payload>"))>
//! ```
//!
//! The payload is compact JSON:
//!
//! ```json
//! {"sub":"mac-of-abebe","iat":1757635200,"exp":1757635380,"jti":"3Qk...","scp":"read write"}
//! ```
//!
//! # Why this rather than a static bearer token
//!
//! A static token is transmitted on every request, so anything that can see one
//! request can impersonate the client forever. Here the shared secret never
//! leaves the client after enrollment; what crosses the wire is a signature over
//! a payload that expires in minutes and carries a unique `jti` the agent
//! refuses to accept twice. Capturing a request buys an attacker nothing.
//!
//! # Why not JWT
//!
//! A JWT header invites algorithm negotiation, and algorithm negotiation invites
//! `alg: none` and RS256/HS256 confusion. There is exactly one algorithm here
//! and it is not expressed in the token, so it cannot be argued with.

use serveros_crypto::{b64url_decode, b64url_encode, constant_time_eq, hmac_sha256, random_bytes};
use serveros_json::Object;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const TOKEN_PREFIX: &str = "serveros";
/// Tokens older than this are refused regardless of their `exp`, so a client
/// cannot mint a year-long credential for itself.
pub const MAX_TOKEN_LIFETIME_SECS: i64 = 300;
/// Tolerance for client/server clock drift.
pub const CLOCK_SKEW_SECS: i64 = 60;
/// How many recently-seen `jti` values to remember. At one request per second
/// with a 5-minute lifetime, 4096 is ~13x the working set.
pub const REPLAY_CACHE_CAPACITY: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Read state: metrics, listings, logs, file contents.
    Read,
    /// Change state: restart a container, write a file, create a user.
    Write,
    /// Irreversible or security-sensitive: delete a user, reveal masked
    /// environment variables, rotate the agent key.
    Admin,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Write => "write",
            Scope::Admin => "admin",
        }
    }

    fn parse(s: &str) -> Option<Scope> {
        Some(match s {
            "read" => Scope::Read,
            "write" => Scope::Write,
            "admin" => Scope::Admin,
            _ => return None,
        })
    }
}

/// A verified caller.
///
/// `PartialEq` is here for the tests, which assert on whole
/// `Result<Principal, AuthError>` values; comparing two principals in
/// production code would be a mistake, since a principal is identified by its
/// subject rather than by the token it happened to arrive on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Which enrolled client this is — typically a device name. Goes into the
    /// audit record so "who restarted production" has an answer.
    pub subject: String,
    pub scopes: Vec<Scope>,
    pub expires_at: i64,
}

impl Principal {
    pub fn has(&self, scope: Scope) -> bool {
        // Admin implies write implies read: a caller trusted to delete a user is
        // trusted to list them.
        self.scopes.iter().any(|s| *s >= scope)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    /// No credential at all.
    Missing,
    /// Structurally wrong: bad prefix, wrong part count, bad base64.
    Malformed(&'static str),
    /// The MAC did not verify. Deliberately indistinguishable, to the client,
    /// from a token signed with the wrong key.
    BadSignature,
    Expired,
    /// `iat` is in the future beyond the skew allowance.
    NotYetValid,
    /// The token asks for a longer life than the agent permits.
    LifetimeTooLong,
    /// This `jti` has already been used.
    Replayed,
    /// Verified, but lacking the scope this route needs.
    InsufficientScope { required: Scope },
    /// Too many failures from this peer.
    RateLimited { retry_after_secs: u64 },
    /// The agent has no key — it was never enrolled.
    NotEnrolled,
}

impl AuthError {
    /// HTTP status for this failure.
    pub fn status(&self) -> u16 {
        match self {
            AuthError::InsufficientScope { .. } => 403,
            AuthError::RateLimited { .. } => 429,
            AuthError::NotEnrolled => 503,
            _ => 401,
        }
    }

    /// Stable machine code for the desktop app.
    pub fn code(&self) -> &'static str {
        match self {
            AuthError::Missing => "auth_missing",
            AuthError::Malformed(_) => "auth_malformed",
            AuthError::BadSignature => "auth_invalid",
            AuthError::Expired => "auth_expired",
            AuthError::NotYetValid => "auth_not_yet_valid",
            AuthError::LifetimeTooLong => "auth_lifetime_too_long",
            AuthError::Replayed => "auth_replayed",
            AuthError::InsufficientScope { .. } => "auth_insufficient_scope",
            AuthError::RateLimited { .. } => "auth_rate_limited",
            AuthError::NotEnrolled => "agent_not_enrolled",
        }
    }

    /// A sentence safe to show a person.
    ///
    /// These stay vague about *why* a token failed. Telling an attacker the
    /// difference between "wrong signature" and "expired" hands them a probe.
    /// The exception is `Expired`, where being specific lets the app silently
    /// re-mint instead of showing the user an error at all.
    pub fn message(&self) -> String {
        match self {
            AuthError::Missing => "This request was not authenticated.".into(),
            AuthError::Expired => "The credential has expired.".into(),
            AuthError::InsufficientScope { required } => format!(
                "This action needs {} access, which this connection does not have.",
                required.as_str()
            ),
            AuthError::RateLimited { retry_after_secs } => format!(
                "Too many failed attempts. Try again in {retry_after_secs} seconds."
            ),
            AuthError::NotEnrolled => {
                "This agent has not been enrolled yet. Re-run the ServerOS installer.".into()
            }
            _ => "The credential was not accepted.".into(),
        }
    }
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Verifies request tokens against the enrollment secret.
pub struct Authenticator {
    secret: Vec<u8>,
    seen: Mutex<ReplayCache>,
    failures: Mutex<FailureTracker>,
}

impl Authenticator {
    pub fn new(secret: Vec<u8>) -> Authenticator {
        Authenticator {
            secret,
            seen: Mutex::new(ReplayCache::new(REPLAY_CACHE_CAPACITY)),
            failures: Mutex::new(FailureTracker::default()),
        }
    }

    /// Verify a token string, at a caller-supplied clock (tests pin it).
    pub fn verify_at(&self, token: &str, now: i64) -> Result<Principal, AuthError> {
        let mut parts = token.split('.');
        let prefix = parts.next().ok_or(AuthError::Malformed("empty token"))?;
        if prefix != TOKEN_PREFIX {
            return Err(AuthError::Malformed("unrecognised token prefix"));
        }
        let payload_b64 = parts.next().ok_or(AuthError::Malformed("missing payload"))?;
        let mac_b64 = parts.next().ok_or(AuthError::Malformed("missing signature"))?;
        if parts.next().is_some() {
            return Err(AuthError::Malformed("too many token segments"));
        }

        let provided_mac = b64url_decode(mac_b64).ok_or(AuthError::Malformed("signature is not base64url"))?;
        if provided_mac.len() != 32 {
            return Err(AuthError::Malformed("signature is the wrong length"));
        }

        // Verify the MAC before parsing the payload. Parsing attacker-controlled
        // JSON that has not been authenticated is how parsers become exploits.
        let signing_input = format!("{TOKEN_PREFIX}.{payload_b64}");
        let expected = hmac_sha256(&self.secret, signing_input.as_bytes());
        if !constant_time_eq(&expected, &provided_mac) {
            return Err(AuthError::BadSignature);
        }

        let payload_bytes =
            b64url_decode(payload_b64).ok_or(AuthError::Malformed("payload is not base64url"))?;
        let payload = serveros_json::from_slice(&payload_bytes)
            .map_err(|_| AuthError::Malformed("payload is not JSON"))?;

        let exp = payload.get("exp").and_then(|v| v.as_i64()).ok_or(AuthError::Malformed("missing exp"))?;
        let iat = payload.get("iat").and_then(|v| v.as_i64()).ok_or(AuthError::Malformed("missing iat"))?;
        let jti = payload
            .get("jti")
            .and_then(|v| v.as_str())
            .ok_or(AuthError::Malformed("missing jti"))?
            .to_string();
        let subject = payload
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        if exp <= now - CLOCK_SKEW_SECS {
            return Err(AuthError::Expired);
        }
        if iat > now + CLOCK_SKEW_SECS {
            return Err(AuthError::NotYetValid);
        }
        if exp - iat > MAX_TOKEN_LIFETIME_SECS {
            return Err(AuthError::LifetimeTooLong);
        }

        let scopes: Vec<Scope> = payload
            .get("scp")
            .and_then(|v| v.as_str())
            .unwrap_or("read")
            .split_whitespace()
            .filter_map(Scope::parse)
            .collect();
        if scopes.is_empty() {
            return Err(AuthError::Malformed("no recognised scopes"));
        }

        // Replay check goes last so a token that would be rejected anyway does
        // not consume a cache slot — otherwise an attacker could evict real
        // entries by flooding expired tokens.
        {
            let mut cache = self.seen.lock().map_err(|_| AuthError::BadSignature)?;
            cache.expire(now);
            if !cache.insert(jti, exp) {
                return Err(AuthError::Replayed);
            }
        }

        Ok(Principal { subject, scopes, expires_at: exp })
    }

    pub fn verify(&self, token: &str) -> Result<Principal, AuthError> {
        self.verify_at(token, now_unix())
    }

    /// Full check for one request: rate limit, verify, then scope.
    pub fn authorise(
        &self,
        token: Option<&str>,
        peer: &str,
        required: Scope,
    ) -> Result<Principal, AuthError> {
        self.authorise_at(token, peer, required, now_unix())
    }

    /// [`authorise`](Self::authorise) at a caller-supplied clock.
    ///
    /// Exists for the same reason [`verify_at`](Self::verify_at) does: expiry,
    /// skew and lockout are all time-dependent, and a test that cannot pin the
    /// clock can only assert on them by sleeping.
    pub fn authorise_at(
        &self,
        token: Option<&str>,
        peer: &str,
        required: Scope,
        now: i64,
    ) -> Result<Principal, AuthError> {
        if let Some(retry) = self.rate_limited(peer, now) {
            return Err(AuthError::RateLimited { retry_after_secs: retry });
        }

        let Some(token) = token else {
            self.record_failure(peer, now);
            return Err(AuthError::Missing);
        };

        match self.verify_at(token, now) {
            Ok(principal) => {
                if !principal.has(required) {
                    // A scope failure is an authorisation problem, not a
                    // credential-guessing one, so it does not count toward the
                    // rate limit.
                    return Err(AuthError::InsufficientScope { required });
                }
                self.clear_failures(peer);
                Ok(principal)
            }
            Err(e) => {
                self.record_failure(peer, now);
                Err(e)
            }
        }
    }

    fn rate_limited(&self, peer: &str, now: i64) -> Option<u64> {
        let mut f = self.failures.lock().ok()?;
        f.check(peer, now)
    }

    fn record_failure(&self, peer: &str, now: i64) {
        if let Ok(mut f) = self.failures.lock() {
            f.record(peer, now);
        }
    }

    fn clear_failures(&self, peer: &str) {
        if let Ok(mut f) = self.failures.lock() {
            f.clear(peer);
        }
    }

    /// Mint a token. Used by the agent's own CLI (`serveros-agent status`) and
    /// by tests; the desktop app mints its own in Swift.
    pub fn mint(&self, subject: &str, scopes: &[Scope], lifetime_secs: i64) -> String {
        mint_token(&self.secret, subject, scopes, lifetime_secs, now_unix())
    }
}

/// Build a token. Free function so tests can sign with a known key and clock.
pub fn mint_token(
    secret: &[u8],
    subject: &str,
    scopes: &[Scope],
    lifetime_secs: i64,
    now: i64,
) -> String {
    let jti = random_bytes(16).map(|b| b64url_encode(&b)).unwrap_or_else(|_| now.to_string());
    let scope_str = scopes.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ");
    let payload = Object::new()
        .set("sub", subject)
        .set("iat", now)
        .set("exp", now + lifetime_secs)
        .set("jti", jti)
        .set("scp", scope_str);

    let payload_b64 = b64url_encode(serveros_json::Value::Object(payload).to_string().as_bytes());
    let signing_input = format!("{TOKEN_PREFIX}.{payload_b64}");
    let mac = hmac_sha256(secret, signing_input.as_bytes());
    format!("{signing_input}.{}", b64url_encode(&mac))
}

/// Bounded set of recently-seen token ids.
struct ReplayCache {
    capacity: usize,
    order: VecDeque<(String, i64)>,
}

impl ReplayCache {
    fn new(capacity: usize) -> ReplayCache {
        ReplayCache { capacity, order: VecDeque::with_capacity(capacity.min(256)) }
    }

    /// Returns false if this id was already present.
    fn insert(&mut self, jti: String, exp: i64) -> bool {
        if self.order.iter().any(|(k, _)| *k == jti) {
            return false;
        }
        if self.order.len() >= self.capacity {
            self.order.pop_front();
        }
        self.order.push_back((jti, exp));
        true
    }

    fn expire(&mut self, now: i64) {
        // Entries past their expiry can never be replayed successfully anyway —
        // the `exp` check rejects them first — so dropping them is free.
        self.order.retain(|(_, exp)| *exp > now - CLOCK_SKEW_SECS);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.order.len()
    }
}

/// Per-peer failure counter with a backoff window.
#[derive(Default)]
struct FailureTracker {
    entries: Vec<(String, Vec<i64>)>,
}

const FAILURE_THRESHOLD: usize = 10;
const FAILURE_WINDOW_SECS: i64 = 60;
const LOCKOUT_SECS: i64 = 60;

impl FailureTracker {
    fn record(&mut self, peer: &str, now: i64) {
        if let Some(slot) = self.entries.iter_mut().find(|(p, _)| p == peer) {
            slot.1.retain(|t| now - t < FAILURE_WINDOW_SECS);
            slot.1.push(now);
            return;
        }
        if self.entries.len() > 256 {
            // Bound the tracker itself; otherwise it is the memory leak.
            self.entries.remove(0);
        }
        self.entries.push((peer.to_string(), vec![now]));
    }

    fn check(&mut self, peer: &str, now: i64) -> Option<u64> {
        let slot = self.entries.iter_mut().find(|(p, _)| p == peer)?;
        slot.1.retain(|t| now - t < FAILURE_WINDOW_SECS);
        if slot.1.len() >= FAILURE_THRESHOLD {
            let newest = *slot.1.last()?;
            let remaining = LOCKOUT_SECS - (now - newest);
            if remaining > 0 {
                return Some(remaining as u64);
            }
        }
        None
    }

    fn clear(&mut self, peer: &str) {
        self.entries.retain(|(p, _)| p != peer);
    }
}

/// Read the enrollment secret from disk, checking its permissions.
pub fn load_secret(path: &std::path::Path) -> Result<Vec<u8>, std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(path)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        // A key readable by any local user is not a key. Refuse rather than
        // silently operating with a credential the whole box can read.
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} has mode {:o}; it must not be readable by group or others. \
                 Run: chmod 600 {}",
                path.display(),
                mode,
                path.display()
            ),
        ));
    }

    let text = std::fs::read_to_string(path)?;
    let trimmed = text.trim();
    let secret = b64url_decode(trimmed).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "key file is not valid base64url")
    })?;
    if secret.len() < 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "key is shorter than 32 bytes",
        ));
    }
    Ok(secret)
}

#[cfg(test)]
mod tests;
