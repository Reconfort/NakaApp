//! Structured logging with mandatory redaction.
//!
//! The agent handles passwords for new Linux users, database credentials and
//! container environment variables. A log line is the easiest place for one of
//! those to escape — logs get tailed in support calls, shipped to aggregators,
//! and pasted into issues. So redaction is not a helper that callers may use;
//! it is applied to every message on the way out.
//!
//! Output goes to stderr as one JSON object per line, which journald captures
//! as-is and which `jq` can filter.

use crate::config::LogLevel;
use serveros_json::{Object, Value};
use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};

static LEVEL: AtomicU8 = AtomicU8::new(2); // info

pub fn set_level(level: LogLevel) {
    LEVEL.store(
        match level {
            LogLevel::Error => 0,
            LogLevel::Warn => 1,
            LogLevel::Info => 2,
            LogLevel::Debug => 3,
        },
        Ordering::Relaxed,
    );
}

fn enabled(level: u8) -> bool {
    level <= LEVEL.load(Ordering::Relaxed)
}

/// Substrings that mark a value as secret when they appear in a KEY.
///
/// Over-matching is the safe direction: a redacted `MONKEY_COUNT` is a cosmetic
/// annoyance, a leaked `API_KEY` is an incident.
const SECRET_KEY_MARKERS: &[&str] = &[
    "pass", "secret", "token", "key", "credential", "auth", "private", "signature", "cookie",
    "session", "dsn", "connection_string", "salt", "cert",
];

/// True if a field with this name should have its value hidden.
pub fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEY_MARKERS.iter().any(|m| lower.contains(m))
}

/// Replace anything that looks like a credential inside free text.
///
/// This catches the case the key-based check cannot: a secret pasted into a
/// message, or embedded in a URL or a command line.
pub fn redact_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    // Set when the previous token was a bare `password:` or `api_key=`, i.e.
    // the secret is the *next* token. Without this, the single most common
    // shape a credential appears in — `api_key: abc123`, with a space — sails
    // straight through, because neither token contains both halves.
    let mut value_is_next = false;

    for token in text.split_inclusive(char::is_whitespace) {
        if value_is_next {
            let trimmed = token.trim_end();
            if trimmed.is_empty() {
                // Run of whitespace between the key and its value; keep looking.
                out.push_str(token);
                continue;
            }
            value_is_next = false;
            out.push_str("[redacted]");
            out.push_str(&token[trimmed.len()..]);
            continue;
        }

        let trimmed = token.trim_end();
        if let Some(key) = trimmed.strip_suffix(':').or_else(|| trimmed.strip_suffix('=')) {
            if !key.is_empty() && is_secret_key(key) {
                value_is_next = true;
                // Emit the key without its trailing whitespace, so the redacted
                // form reads `api_key:[redacted]` however it was spaced.
                out.push_str(trimmed);
                continue;
            }
        }

        out.push_str(&redact_token(token));
    }
    out
}

fn redact_token(token: &str) -> String {
    let trimmed = token.trim_end();
    let trailing = &token[trimmed.len()..];

    // user:password@host — the classic leak.
    if let Some(scheme_end) = trimmed.find("://") {
        let rest = &trimmed[scheme_end + 3..];
        if let Some(at) = rest.find('@') {
            let creds = &rest[..at];
            if creds.contains(':') {
                let user = creds.split(':').next().unwrap_or("");
                return format!(
                    "{}://{}:[redacted]@{}{}",
                    &trimmed[..scheme_end],
                    user,
                    &rest[at + 1..],
                    trailing
                );
            }
        }
    }

    // key=value and key: value forms.
    for sep in ['=', ':'] {
        if let Some(i) = trimmed.find(sep) {
            let (k, v) = trimmed.split_at(i);
            let v = &v[1..];
            if !v.is_empty() && is_secret_key(k) {
                return format!("{k}{sep}[redacted]{trailing}");
            }
        }
    }

    // A bare ServerOS token, wherever it appears.
    if trimmed.starts_with("serveros.") && trimmed.matches('.').count() >= 2 {
        return format!("serveros.[redacted]{trailing}");
    }

    token.to_string()
}

/// Recursively redact a JSON value by key name.
pub fn redact_value(value: &Value) -> Value {
    match value {
        Value::Object(obj) => {
            let mut out = Object::with_capacity(obj.len());
            for (k, v) in obj.iter() {
                if is_secret_key(k) {
                    out.insert(k, "[redacted]");
                } else {
                    out.insert(k, redact_value(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_value).collect()),
        Value::String(s) => Value::String(redact_text(s)),
        other => other.clone(),
    }
}

fn emit(level: &str, level_num: u8, message: &str, fields: Option<Object>) {
    if !enabled(level_num) {
        return;
    }
    let mut record = Object::new()
        .set("ts", crate::auth::now_unix())
        .set("level", level)
        .set("msg", redact_text(message));

    if let Some(fields) = fields {
        for (k, v) in fields.iter() {
            let safe = if is_secret_key(k) { Value::from("[redacted]") } else { redact_value(v) };
            record.insert(k, safe);
        }
    }

    let line = Value::Object(record).to_string();
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{line}");
}

pub fn error(message: &str) {
    emit("error", 0, message, None);
}
pub fn warn(message: &str) {
    emit("warn", 1, message, None);
}
pub fn info(message: &str) {
    emit("info", 2, message, None);
}
pub fn debug(message: &str) {
    emit("debug", 3, message, None);
}

pub fn error_with(message: &str, fields: Object) {
    emit("error", 0, message, Some(fields));
}
pub fn warn_with(message: &str, fields: Object) {
    emit("warn", 1, message, Some(fields));
}
pub fn info_with(message: &str, fields: Object) {
    emit("info", 2, message, Some(fields));
}
pub fn debug_with(message: &str, fields: Object) {
    emit("debug", 3, message, Some(fields));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_secret_key_names() {
        for key in [
            "password", "PASSWORD", "db_pass", "API_KEY", "apiKey", "SECRET_KEY_BASE",
            "access_token", "AWS_CREDENTIALS", "Authorization", "private_key", "DATABASE_DSN",
            "session_id", "Cookie", "TLS_CERT",
        ] {
            assert!(is_secret_key(key), "{key} should be treated as secret");
        }
    }

    #[test]
    fn leaves_ordinary_key_names_alone() {
        for key in ["name", "hostname", "count", "cpu_percent", "path", "container_id", "state"] {
            assert!(!is_secret_key(key), "{key} should not be redacted");
        }
    }

    #[test]
    fn redacts_credentials_inside_urls() {
        assert_eq!(
            redact_text("connecting to postgres://admin:hunter2@db.internal/app"),
            "connecting to postgres://admin:[redacted]@db.internal/app"
        );
        // No credentials, no change.
        assert_eq!(redact_text("fetching https://example.com/x"), "fetching https://example.com/x");
    }

    #[test]
    fn redacts_key_value_pairs_in_free_text() {
        assert_eq!(redact_text("PGPASSWORD=hunter2"), "PGPASSWORD=[redacted]");
        assert_eq!(redact_text("api_key: abc123"), "api_key:[redacted]");
        assert_eq!(redact_text("count=42"), "count=42");
    }

    #[test]
    fn redacts_a_bare_agent_token() {
        let line = redact_text("rejected serveros.eyJzdWIiOiJ4In0.c2lnbmF0dXJl from peer");
        assert!(line.contains("serveros.[redacted]"), "{line}");
        assert!(!line.contains("c2lnbmF0dXJl"), "{line}");
    }

    #[test]
    fn redacts_nested_json_by_key() {
        let v = serveros_json::from_str(
            r#"{"user":"deploy","password":"hunter2","nested":{"API_TOKEN":"abc","port":5432},
                "list":[{"secret":"s"},{"ok":1}]}"#,
        )
        .unwrap();
        let text = redact_value(&v).to_string();
        assert!(!text.contains("hunter2"));
        assert!(!text.contains("abc"));
        assert!(text.contains("deploy"), "non-secret fields must survive");
        assert!(text.contains("5432"));
        assert!(!text.contains(r#""secret":"s""#));
    }

    #[test]
    fn redaction_preserves_structure() {
        let v = serveros_json::from_str(r#"{"a":{"b":[1,2,{"token":"x"}]}}"#).unwrap();
        let redacted = redact_value(&v);
        assert_eq!(redacted.path("a/b").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(
            redacted.path("a/b").unwrap().as_array().unwrap()[2].get("token").unwrap().as_str(),
            Some("[redacted]")
        );
    }

    #[test]
    fn redaction_keeps_whitespace_intact() {
        // A mangled message is a message nobody reads.
        let input = "starting   agent\tversion=1";
        assert_eq!(redact_text(input), input);
    }

    #[test]
    fn level_filtering_works() {
        set_level(LogLevel::Error);
        assert!(enabled(0));
        assert!(!enabled(2));
        set_level(LogLevel::Debug);
        assert!(enabled(3));
        set_level(LogLevel::Info);
        assert!(enabled(2));
        assert!(!enabled(3));
    }
}
