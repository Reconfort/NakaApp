//! Reading what this server has been saying.
//!
//! Two sources, one shape: a log file anywhere the path policy allows, and the
//! systemd journal. Both return the same `LogLine` objects — timestamp, level,
//! message, raw text — so the app has one log view rather than two.
//!
//! # Why following is a chunked NDJSON stream
//!
//! A tail that only arrives when it is complete is not a tail. `?follow=true`
//! answers with `Transfer-Encoding: chunked` and writes **one JSON object per
//! line, flushed immediately**, so the app renders each line as it happens. A
//! JSON array could not do this: it would have to be closed, and a follow has
//! no end.
//!
//! A quiet log emits a `{"type":"heartbeat"}` line every
//! [`HEARTBEAT_SECS`] seconds. That is not decoration — without a periodic
//! write, a follower on a silent file has no way to notice that the client hung
//! up, and the connection (and its thread) would stay alive indefinitely. The
//! heartbeat turns a dead peer into a write error, which ends the stream.

use crate::api::{bad_request, unavailable};
use crate::auth::Principal;
use crate::state::AgentState;
use serveros_fsops::LogQuery;
use serveros_http::{Request, Response};
use serveros_json::{Object, Value};
use std::time::Duration;

/// Lines returned when `?lines` is absent.
const DEFAULT_LINES: usize = 200;
/// Ceiling on `?lines`. The fsops tailer caps at 10 000 anyway; this keeps the
/// response a size an app can render.
const MAX_LINES: usize = 5_000;

/// How often a silent follow writes, so a vanished client is noticed.
const HEARTBEAT_SECS: u64 = 15;

/// How long each follow poll blocks before looping.
const POLL: Duration = Duration::from_secs(1);

/// How often a journal follow re-runs `journalctl`.
///
/// Longer than the file poll on purpose: each pass spawns a process, so a
/// one-second cadence would mean 60 forks a minute for a log nobody is reading
/// closely.
const JOURNAL_POLL_SECS: u64 = 3;

/// Content type for a followed log stream.
const NDJSON: &str = "application/x-ndjson";

/// `GET /v1/logs/file` — the tail of a log file.
///
/// `?path=` (required), `?lines=` (default 200, capped at 5000), `?since=`,
/// `?filter=`, `?regex=true`, `?follow=true`.
///
/// The path goes through `state.path_policy` inside `serveros-fsops`; there is
/// no branch here that reads a file directly.
pub fn file(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let Some(path) = req.query_str("path").filter(|p| !p.trim().is_empty()) else {
        return bad_request("\"path\" is required — which log file should ServerOS read?");
    };
    let query = log_query(req);

    if !req.query_flag("follow") {
        return match serveros_fsops::tail_file(&state.path_policy, &path, &query) {
            Ok(batch) => Response::json(batch.to_json()),
            Err(e) => super::files::fs_response(e),
        };
    }

    // Open the follower *before* reading the tail. The two operations cannot be
    // atomic, and this ordering means a line written in between is delivered
    // twice rather than not at all — a duplicate is a cosmetic annoyance, a
    // dropped line during an incident is not.
    let mut follower = match serveros_fsops::follow_file(&state.path_policy, &path, true) {
        Ok(follower) => follower,
        Err(e) => return super::files::fs_response(e),
    };
    if let Err(e) = follower.set_filter(&query) {
        return super::files::fs_response(e);
    }

    let backlog = match serveros_fsops::tail_file(&state.path_policy, &path, &query) {
        Ok(batch) => batch,
        Err(e) => return super::files::fs_response(e),
    };

    Response::stream(NDJSON, move |out| {
        for line in &backlog.lines {
            writeln!(out, "{}", line.to_json())?;
        }
        out.flush()?;

        let mut quiet = 0u64;
        loop {
            match follower.poll(POLL) {
                Ok(lines) if lines.is_empty() => {
                    quiet += POLL.as_secs();
                    if quiet >= HEARTBEAT_SECS {
                        quiet = 0;
                        writeln!(out, "{}", heartbeat())?;
                        out.flush()?;
                    }
                }
                Ok(lines) => {
                    quiet = 0;
                    for line in lines {
                        writeln!(out, "{}", line.to_json())?;
                    }
                    out.flush()?;
                }
                // The file became unreadable — deleted and not recreated,
                // permissions changed. Say so in the stream and end cleanly
                // rather than dropping the connection with no explanation.
                Err(e) => {
                    writeln!(out, "{}", stream_error(&e.to_string()))?;
                    out.flush()?;
                    return Ok(());
                }
            }
        }
    })
}

/// `GET /v1/logs/journal` — the systemd journal, optionally for one unit.
///
/// `?unit=` narrows to a unit; the other parameters match [`file`].
///
/// `journalctl --output=json` is the documented machine-readable interface and
/// is the one place `serveros-fsops` invokes a program — with an argv and a
/// validated unit name, never a shell.
pub fn journal(_state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    if !serveros_fsops::journal_available() {
        return unavailable(
            "The system journal",
            "journalctl is not installed, or systemd-journald is not running on this host",
        );
    }

    let unit = req.query_str("unit").filter(|u| !u.trim().is_empty());
    let query = log_query(req);

    if !req.query_flag("follow") {
        return match serveros_fsops::journal_tail(unit.as_deref(), &query) {
            Ok(batch) => Response::json(batch.to_json()),
            Err(e) => super::files::fs_response(e),
        };
    }

    // Prime the stream with a backlog, then poll forward from its newest entry.
    let backlog = match serveros_fsops::journal_tail(unit.as_deref(), &query) {
        Ok(batch) => batch,
        Err(e) => return super::files::fs_response(e),
    };

    Response::stream(NDJSON, move |out| {
        let mut cursor = JournalCursor::default();
        for line in &backlog.lines {
            cursor.remember(line);
            writeln!(out, "{}", line.to_json())?;
        }
        out.flush()?;

        let mut quiet = 0u64;
        loop {
            std::thread::sleep(Duration::from_secs(JOURNAL_POLL_SECS));

            // `journalctl` has no cursor we can resume from through this
            // interface, so each pass asks for everything at or after the
            // newest timestamp already delivered and the cursor discards what
            // it has already seen at that exact second.
            let mut next = LogQuery {
                lines: query.lines,
                since: cursor.since.or(query.since),
                filter: query.filter.clone(),
                regex: query.regex,
            };
            if next.lines == 0 {
                next.lines = DEFAULT_LINES;
            }

            match serveros_fsops::journal_tail(unit.as_deref(), &next) {
                Ok(batch) => {
                    let mut wrote = false;
                    for line in &batch.lines {
                        if cursor.is_new(line) {
                            cursor.remember(line);
                            writeln!(out, "{}", line.to_json())?;
                            wrote = true;
                        }
                    }
                    if wrote {
                        quiet = 0;
                        out.flush()?;
                    } else {
                        quiet += JOURNAL_POLL_SECS;
                        if quiet >= HEARTBEAT_SECS {
                            quiet = 0;
                            writeln!(out, "{}", heartbeat())?;
                            out.flush()?;
                        }
                    }
                }
                Err(e) => {
                    writeln!(out, "{}", stream_error(&e.to_string()))?;
                    out.flush()?;
                    return Ok(());
                }
            }
        }
    })
}

/// Remembers how far a journal follow has read.
///
/// The journal's only resumption key available through `journalctl --since` is
/// a timestamp, and a busy second holds many entries — so the raw text of every
/// line already delivered *at the newest second* is kept, and only that second.
/// The set is bounded by how much one second of logging can hold, which is the
/// smallest window that makes duplicates impossible.
#[derive(Default)]
struct JournalCursor {
    since: Option<i64>,
    seen_at_since: Vec<String>,
}

impl JournalCursor {
    fn is_new(&self, line: &serveros_fsops::LogLine) -> bool {
        match (line.timestamp, self.since) {
            (Some(ts), Some(since)) if ts > since => true,
            (Some(ts), Some(since)) if ts == since => !self.seen_at_since.contains(&line.raw),
            (Some(_), Some(_)) => false,
            // An entry with no timestamp cannot be positioned, so it is always
            // treated as new. journalctl's JSON always carries one, so this is
            // the degenerate case rather than the common one.
            _ => true,
        }
    }

    fn remember(&mut self, line: &serveros_fsops::LogLine) {
        let Some(ts) = line.timestamp else { return };
        match self.since {
            Some(since) if ts == since => self.seen_at_since.push(line.raw.clone()),
            Some(since) if ts < since => {}
            _ => {
                self.since = Some(ts);
                self.seen_at_since.clear();
                self.seen_at_since.push(line.raw.clone());
            }
        }
    }
}

/// Build the query shared by both sources, clamping everything a caller sends.
fn log_query(req: &Request) -> LogQuery {
    LogQuery {
        lines: req.query_num::<usize>("lines").unwrap_or(DEFAULT_LINES).clamp(1, MAX_LINES),
        since: req.query_num::<i64>("since"),
        filter: req.query_str("filter").filter(|f| !f.is_empty()),
        regex: req.query_flag("regex"),
    }
}

/// A keep-alive line. Carries `type` so a client can skip it without having to
/// distinguish it from a log line by absence.
fn heartbeat() -> Value {
    Object::new().set("type", "heartbeat").set("at", crate::auth::now_unix()).into()
}

/// An in-stream failure. The response status was already sent, so this is the
/// only way left to say what went wrong.
fn stream_error(detail: &str) -> Value {
    Object::new()
        .set("type", "error")
        .set("message", "ServerOS stopped following this log.")
        .set("detail", detail)
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serveros_fsops::{LogLine, LogSource};

    fn line(ts: i64, text: &str) -> LogLine {
        LogLine {
            timestamp: Some(ts),
            level: None,
            message: text.to_string(),
            raw: text.to_string(),
            source: LogSource::Journal,
        }
    }

    #[test]
    fn a_journal_cursor_never_repeats_a_line() {
        let mut cursor = JournalCursor::default();
        let first = line(100, "started");
        assert!(cursor.is_new(&first));
        cursor.remember(&first);
        assert!(!cursor.is_new(&first), "the same line must not be delivered twice");
    }

    #[test]
    fn two_lines_in_the_same_second_are_both_delivered() {
        // The case a naive `since > last` filter gets wrong.
        let mut cursor = JournalCursor::default();
        let a = line(100, "connected");
        let b = line(100, "ready");
        cursor.remember(&a);
        assert!(cursor.is_new(&b));
        cursor.remember(&b);
        assert!(!cursor.is_new(&b));
        assert!(cursor.is_new(&line(101, "next second")));
    }

    #[test]
    fn the_seen_set_is_cleared_when_the_second_advances() {
        let mut cursor = JournalCursor::default();
        cursor.remember(&line(100, "a"));
        cursor.remember(&line(100, "b"));
        assert_eq!(cursor.seen_at_since.len(), 2);
        cursor.remember(&line(101, "c"));
        assert_eq!(cursor.seen_at_since.len(), 1, "only the newest second is retained");
        assert_eq!(cursor.since, Some(101));
    }

    #[test]
    fn older_lines_are_dropped_rather_than_rewound_to() {
        let mut cursor = JournalCursor::default();
        cursor.remember(&line(200, "new"));
        assert!(!cursor.is_new(&line(100, "old")));
    }

    #[test]
    fn heartbeats_and_errors_are_one_json_object_each() {
        for value in [heartbeat(), stream_error("broken pipe")] {
            let text = value.to_string();
            assert!(!text.contains('\n'), "NDJSON lines cannot contain newlines: {text}");
            let parsed = serveros_json::from_str(&text).unwrap();
            assert!(parsed.get("type").is_some());
        }
        assert_eq!(heartbeat().get("type").and_then(Value::as_str), Some("heartbeat"));
    }

    #[test]
    fn an_in_stream_error_keeps_the_technical_text_out_of_the_message() {
        let value = stream_error("Permission denied (os error 13)");
        assert_eq!(
            value.get("message").and_then(Value::as_str),
            Some("ServerOS stopped following this log.")
        );
        assert!(value.get("detail").and_then(Value::as_str).unwrap().contains("os error 13"));
    }
}
