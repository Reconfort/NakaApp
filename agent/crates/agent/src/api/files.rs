//! The file browser.
//!
//! # The one rule
//!
//! **No function in this module touches `std::fs` with a caller-supplied
//! path.** Every path arrives as a `&str` from a query parameter or a JSON
//! body, and goes into `serveros-fsops`, which resolves it through
//! `state.path_policy` exactly once and hands a canonical `PathBuf` to the
//! syscall. That is what makes `?path=/tmp/../etc/shadow` and a symlink
//! pointing out of a configured root both answer 403 instead of returning a
//! file. Reaching for `std::fs::read` here — even "just to check whether it
//! exists" — reintroduces the hole the policy exists to close, which is why
//! this module has no `use std::fs` at all.
//!
//! # Other decisions worth stating
//!
//!   * **Downloads stream.** A 4 GB backup is served from an open `File`
//!     through a chunked response; nothing here allocates a body.
//!   * **`Content-Disposition` is built from a sanitised filename.** A file
//!     called `report".pdf` or one containing a newline would otherwise let a
//!     filename inject a header. See [`sanitise_filename`].
//!   * **Deleting can be undoable.** With `trash_deletes` on, a delete is a
//!     move into a trash directory, and the response says which happened, so
//!     the app can say "moved to trash" rather than implying it is gone.
//!   * **Every mutation is audited with its target in the sentence.** For
//!     `delete` and `chmod` the path *is* the consequence; an activity feed
//!     saying "Deleted a file" would be useless during an incident.

use crate::activity::Event;
use crate::api::{bad_request, internal, json_body, record, required_str};
use crate::auth::Principal;
use crate::state::AgentState;
use serveros_fsops::{FsError, ListOptions, SortBy};
use serveros_http::{Request, Response, Status};
use serveros_json::{Object, Value};
use std::io::Read;

/// Streaming copy buffer for downloads. Matches the fsops copy buffer.
const DOWNLOAD_BUFFER: usize = 64 * 1024;

/// Ceiling on `?limit` for a directory listing. The fsops lister clamps to
/// 10 000 as well; clamping here means an absurd value never even allocates.
const MAX_LIST_LIMIT: usize = 10_000;

/// `GET /v1/files` — list a directory.
///
/// `?path=` (default `/`), `?show_hidden=`, `?sort=name|size|modified|kind`,
/// `?limit=`, `?offset=`.
pub fn list(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let path = req.query_str("path").unwrap_or_else(|| "/".to_string());
    let options = ListOptions {
        show_hidden: req.query_flag("show_hidden"),
        sort: req.query_str("sort").map(|s| SortBy::parse(&s)).unwrap_or_default(),
        // `0` means "the crate's default"; anything absurd is clamped rather
        // than honoured, so `?limit=99999999` cannot make the agent allocate.
        limit: req.query_num::<usize>("limit").unwrap_or(0).min(MAX_LIST_LIMIT),
        offset: req.query_num::<usize>("offset").unwrap_or(0),
    };

    match serveros_fsops::list_directory(&state.path_policy, &path, &options) {
        Ok(listing) => Response::json(listing.to_json()),
        Err(e) => fs_response(e),
    }
}

/// `GET /v1/files/stat` — one entry's metadata, without reading it.
pub fn stat(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let path = match required_path(req) {
        Ok(path) => path,
        Err(response) => return response,
    };
    match serveros_fsops::stat_entry(&state.path_policy, &path) {
        Ok(entry) => Response::json(entry.to_json()),
        Err(e) => fs_response(e),
    }
}

/// `GET /v1/files/read` — a text file's contents, for the editor.
///
/// A binary file is refused rather than returned as mojibake: `FsError::NotText`
/// carries a sentence saying so, and the app offers a download instead.
pub fn read(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let path = match required_path(req) {
        Ok(path) => path,
        Err(response) => return response,
    };
    match serveros_fsops::read_text(&state.path_policy, &path) {
        Ok(file) => Response::json(file.to_json()),
        Err(e) => fs_response(e),
    }
}

/// `GET /v1/files/download` — stream a file's bytes.
///
/// The only operation with no size limit, so it must never hold the file in
/// memory: the response is chunked and copied through a fixed buffer.
pub fn download(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let path = match required_path(req) {
        Ok(path) => path,
        Err(response) => return response,
    };

    let (mut file, entry) = match serveros_fsops::open_download(&state.path_policy, &path) {
        Ok(pair) => pair,
        Err(e) => return fs_response(e),
    };

    let filename = sanitise_filename(&entry.name);
    let size = entry.size_bytes;

    Response::stream("application/octet-stream", move |out| {
        let mut buffer = vec![0u8; DOWNLOAD_BUFFER];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                return out.flush();
            }
            out.write_all(&buffer[..read])?;
        }
    })
    .header("Content-Disposition", format!("attachment; filename=\"{filename}\""))
    // Advisory only — the body is chunked, so this is a progress hint rather
    // than a framing header.
    .header("X-File-Size", size.to_string())
}

/// `PUT /v1/files/write` — replace a file's contents with the request body.
///
/// The body is the new content, verbatim: no JSON wrapper, no base64. That
/// keeps a 3 MB config file a 3 MB request instead of a 4 MB one, and means
/// `curl --data-binary @file` works.
pub fn write(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let path = match required_path(req) {
        Ok(path) => path,
        Err(response) => return response,
    };

    let contents = req.body.as_bytes();
    let bytes = contents.len();
    let (response, ok) = match serveros_fsops::write_file(&state.path_policy, &path, contents) {
        Ok(entry) => (Response::json(entry.to_json()), true),
        Err(e) => (fs_response(e), false),
    };

    record(
        state,
        req,
        principal,
        Event::new("file.write", "file", &path)
            .summary(if ok {
                format!("Wrote {bytes} bytes to {path}")
            } else {
                format!("Could not write to {path}")
            })
            .meta("bytes", bytes)
            .outcome(ok),
    );
    response
}

/// `POST /v1/files/directory` — create a directory.
///
/// Body: `{"path": "/srv/app/releases"}`.
pub fn create_directory(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let body = match json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let path = match required_str(&body, "path") {
        Ok(path) => path,
        Err(response) => return response,
    };

    let (response, ok) = match serveros_fsops::create_directory(&state.path_policy, &path) {
        Ok(entry) => (Response::json_status(Status::CREATED, entry.to_json()), true),
        Err(e) => (fs_response(e), false),
    };

    record(
        state,
        req,
        principal,
        Event::new("file.mkdir", "directory", &path)
            .summary(if ok {
                format!("Created the folder {path}")
            } else {
                format!("Could not create the folder {path}")
            })
            .outcome(ok),
    );
    response
}

/// `POST /v1/files/rename` — rename or move.
///
/// Body: `{"from": "...", "to": "..."}`. Both ends go through the policy, so a
/// move cannot be used to walk a file out of an allowed root.
pub fn rename(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let body = match json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let from = match required_str(&body, "from") {
        Ok(from) => from,
        Err(response) => return response,
    };
    let to = match required_str(&body, "to") {
        Ok(to) => to,
        Err(response) => return response,
    };

    let (response, ok) = match serveros_fsops::rename(&state.path_policy, &from, &to) {
        Ok(entry) => (Response::json(entry.to_json()), true),
        Err(e) => (fs_response(e), false),
    };

    record(
        state,
        req,
        principal,
        Event::new("file.rename", "file", &from)
            .summary(if ok {
                format!("Renamed {from} to {to}")
            } else {
                format!("Could not rename {from} to {to}")
            })
            .meta("to", to.as_str())
            .outcome(ok),
    );
    response
}

/// `POST /v1/files/chmod` — change permissions.
///
/// Body: `{"path": "...", "mode": "0640"}`. The mode may be an octal string or
/// a number; a string is preferred because `0640` in JSON is a syntax error and
/// `640` decimal is not what anyone means.
///
/// Admin scope. Permissions are the mechanism every other permission rests on,
/// and `chmod 777` on the wrong directory is not something `write` should buy.
pub fn chmod(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let body = match json_body(req) {
        Ok(body) => body,
        Err(response) => return response,
    };
    let path = match required_str(&body, "path") {
        Ok(path) => path,
        Err(response) => return response,
    };
    let mode = match parse_mode(body.get("mode")) {
        Ok(mode) => mode,
        Err(response) => return response,
    };

    let (response, ok) = match serveros_fsops::set_mode(&state.path_policy, &path, mode) {
        Ok(entry) => (Response::json(entry.to_json()), true),
        Err(e) => (fs_response(e), false),
    };

    record(
        state,
        req,
        principal,
        Event::new("file.chmod", "file", &path)
            .summary(if ok {
                format!("Changed the permissions of {path} to {mode:04o}")
            } else {
                format!("Could not change the permissions of {path}")
            })
            .meta("mode", format!("{mode:04o}"))
            .outcome(ok),
    );
    response
}

/// `DELETE /v1/files` — delete a file or directory.
///
/// `?path=` (required), `?recursive=true` for a non-empty directory.
///
/// When `trash_deletes` is on — the default — this *moves* the target to a
/// trash directory instead of unlinking it, and the response says which
/// happened via `"trashed"` and `"restore_path"`. That is what lets the app say
/// "Moved to trash · Undo" honestly, and what makes a mis-click recoverable on
/// a server with no Finder to drag things out of.
pub fn delete(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let path = match required_path(req) {
        Ok(path) => path,
        Err(response) => return response,
    };
    let recursive = req.query_flag("recursive");
    let trash = state.config.trash_deletes;

    let (response, ok, summary) = if trash {
        match serveros_fsops::move_to_trash(&state.path_policy, &path) {
            Ok(destination) => (
                Response::json(
                    Object::new()
                        .set("path", path.as_str())
                        .set("trashed", true)
                        .set("restore_path", destination.display().to_string()),
                ),
                true,
                format!("Moved {path} to the trash"),
            ),
            Err(e) => (fs_response(e), false, format!("Could not delete {path}")),
        }
    } else {
        match serveros_fsops::delete(&state.path_policy, &path, recursive) {
            Ok(report) => {
                let Value::Object(body) = report.to_json() else {
                    return internal(
                        format!("ServerOS couldn't report what it deleted at {path}."),
                        "delete report did not serialise as an object",
                    );
                };
                (
                    Response::json(
                        body.set("path", path.as_str()).set("trashed", false),
                    ),
                    true,
                    format!("Deleted {path}"),
                )
            }
            Err(e) => (fs_response(e), false, format!("Could not delete {path}")),
        }
    };

    record(
        state,
        req,
        principal,
        Event::new("file.delete", "file", &path)
            .summary(summary)
            .meta("recursive", recursive)
            .meta("trashed", trash)
            .outcome(ok),
    );
    response
}

/// `POST /v1/files/upload` — write an uploaded body to a path.
///
/// Registered as a streaming-body route, so the server has already spooled the
/// request to a temporary file with mode 0600 and put its path in the
/// `__body_file` parameter. A 2 GB upload therefore costs 64 KiB of agent
/// memory rather than 2 GB, and this handler only ever copies between two
/// files.
///
/// `?path=` is the destination and `?overwrite=true` permits replacing. The
/// spool path is the agent's own and is *not* policy-checked — it is not
/// caller-supplied — while the destination goes through the policy like
/// everything else.
pub fn upload(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let destination = match required_path(req) {
        Ok(path) => path,
        Err(response) => return response,
    };

    let Some(spooled) = req.params.get("__body_file") else {
        return bad_request(
            "That upload had no content. Send the file as the request body.",
        );
    };
    let overwrite = req.query_flag("overwrite");

    let (response, ok) = match serveros_fsops::copy_from(
        &state.path_policy,
        std::path::Path::new(spooled),
        &destination,
        overwrite,
    ) {
        Ok(entry) => (Response::json_status(Status::CREATED, entry.to_json()), true),
        Err(e) => (fs_response(e), false),
    };

    record(
        state,
        req,
        principal,
        Event::new("file.upload", "file", &destination)
            .summary(if ok {
                format!("Uploaded {destination}")
            } else {
                format!("Could not upload {destination}")
            })
            .meta("overwrite", overwrite)
            .outcome(ok),
    );
    response
}

// ---------------------------------------------------------------- plumbing ---

/// `?path=`, which every file route needs and none may default.
fn required_path(req: &Request) -> Result<String, Response> {
    req.query_str("path")
        .filter(|p| !p.trim().is_empty())
        .ok_or_else(|| bad_request("\"path\" is required — which file did you mean?"))
}

/// Accept `"0640"`, `"640"` or `416` and land on the same mode.
fn parse_mode(value: Option<&Value>) -> Result<u32, Response> {
    let invalid = || {
        bad_request(
            "\"mode\" has to be an octal permission string such as \"0644\" or \"0750\".",
        )
    };
    match value {
        Some(Value::String(text)) => {
            let text = text.trim().trim_start_matches("0o");
            u32::from_str_radix(text, 8).ok().filter(|m| *m <= 0o7777).ok_or_else(invalid)
        }
        // A JSON number cannot carry a leading zero, so a numeric mode is read
        // as octal digits too: `644` means `0o644`, which is what was meant.
        Some(Value::Int(_)) | Some(Value::UInt(_)) => {
            let n = value.and_then(Value::as_u64).ok_or_else(invalid)?;
            u32::from_str_radix(&n.to_string(), 8).ok().filter(|m| *m <= 0o7777).ok_or_else(invalid)
        }
        _ => Err(invalid()),
    }
}

/// Make a filename safe to place inside a quoted header value.
///
/// A `Content-Disposition` is built by concatenation, so a filename is
/// attacker-controlled text landing in a header. Three characters matter:
///
///   * `"` would close the quoted string early and let the rest become
///     parameters;
///   * CR and LF would end the header line entirely and let the rest become a
///     *new header* — response splitting;
///   * `\` would escape whatever follows it inside the quoted string.
///
/// They are replaced rather than rejected: a user whose file is genuinely
/// called `re"port.txt` should still be able to download it. Path separators go
/// too, so the suggested name can never be a path. The response writer refuses
/// CR/LF in any header value as a second line of defence, but a handler that
/// relies on that is a handler that will be copied somewhere without it.
pub fn sanitise_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter_map(|c| match c {
            // Structural characters become an underscore, so the name stays
            // recognisable and the same length.
            '"' | '\\' | '/' => Some('_'),
            // Control characters are dropped rather than substituted: a name
            // that is *only* control characters must end up empty, and so fall
            // through to the "download" default, rather than becoming a row of
            // underscores.
            c if c.is_control() => None,
            c => Some(c),
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() { "download".to_string() } else { trimmed.to_string() }
}

/// Map an `FsError` onto the agent's error envelope.
///
/// Shared with [`super::logs`], which reads through the same crate. Status and
/// machine code come from the crate; `Display` is already a complete,
/// user-safe sentence (it is written for this purpose and never quotes file
/// contents), and `detail` carries the underlying `io::Error` when there is
/// one.
pub(crate) fn fs_response(e: FsError) -> Response {
    let status = Status(e.http_status());
    match e.detail() {
        Some(detail) => Response::error_detail(status, e.kind(), e.to_string(), detail),
        None => Response::error(status, e.kind(), e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_filename_cannot_inject_a_header() {
        // The bug this function exists to prevent: CRLF ends the header and
        // everything after it becomes headers of our response.
        let hostile = "report\r\nX-Injected: yes\r\n\r\n<html>";
        let safe = sanitise_filename(hostile);
        assert!(!safe.contains('\r'), "{safe}");
        assert!(!safe.contains('\n'), "{safe}");
        assert!(!safe.contains('"'));

        let header = format!("attachment; filename=\"{safe}\"");
        assert_eq!(header.lines().count(), 1, "{header}");
    }

    #[test]
    fn quotes_and_backslashes_cannot_escape_the_quoted_string() {
        assert_eq!(sanitise_filename("re\"port.txt"), "re_port.txt");
        assert_eq!(sanitise_filename("re\\port.txt"), "re_port.txt");
        assert_eq!(sanitise_filename("a\"; filename=\"b"), "a_; filename=_b");
    }

    #[test]
    fn a_filename_can_never_become_a_path() {
        assert_eq!(sanitise_filename("../../etc/passwd"), ".._.._etc_passwd");
    }

    #[test]
    fn ordinary_names_survive_untouched() {
        assert_eq!(sanitise_filename("backup-2026-09-12.tar.gz"), "backup-2026-09-12.tar.gz");
        assert_eq!(sanitise_filename("rapport financier.pdf"), "rapport financier.pdf");
        assert_eq!(sanitise_filename("日報.txt"), "日報.txt");
    }

    #[test]
    fn an_empty_name_still_yields_a_usable_header() {
        assert_eq!(sanitise_filename(""), "download");
        assert_eq!(sanitise_filename("   "), "download");
        assert_eq!(sanitise_filename("\r\n"), "download");
    }

    #[test]
    fn modes_parse_as_octal_from_either_json_type() {
        let octal = |text: &str| parse_mode(Some(&Value::from(text))).unwrap();
        assert_eq!(octal("0644"), 0o644);
        assert_eq!(octal("644"), 0o644);
        assert_eq!(octal("0o750"), 0o750);
        assert_eq!(parse_mode(Some(&Value::from(644u32))).unwrap(), 0o644);
    }

    #[test]
    fn nonsense_modes_are_refused() {
        for bad in ["", "rwxr-xr-x", "0999", "-1", "77777"] {
            assert!(parse_mode(Some(&Value::from(bad))).is_err(), "{bad} should be refused");
        }
        assert!(parse_mode(None).is_err());
        assert!(parse_mode(Some(&Value::Null)).is_err());
    }

    #[test]
    fn fs_errors_keep_the_technical_text_out_of_the_message() {
        let denied = FsError::denied("ServerOS will not read /etc/shadow on this server.");
        let response = fs_response(denied);
        assert_eq!(response.status, Status::FORBIDDEN);

        let missing = FsError::NotFound { path: "/srv/nope".into() };
        assert_eq!(fs_response(missing).status, Status::NOT_FOUND);

        let too_big = FsError::TooLarge {
            path: "/var/log/huge".into(),
            size: 900_000_000,
            limit: 2_097_152,
        };
        assert_eq!(fs_response(too_big).status, Status::PAYLOAD_TOO_LARGE);
    }
}
