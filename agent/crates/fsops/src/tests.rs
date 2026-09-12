//! Cross-module tests: the journeys the app actually performs, and the hostile
//! paths pushed through *every* entry point rather than just through
//! [`crate::path`].
//!
//! The per-module tests pin each function's behaviour. These exist to catch the
//! integration mistake that unit tests cannot: an entry point that forgets to
//! call the policy, or a flow that leaves the disk in a state the next step
//! cannot handle.

use crate::listing::{ListOptions, list_directory, stat_entry};
use crate::logs::{LogQuery, tail_file};
use crate::ops::{
    TRASH_DIR_NAME, copy_from, create_directory, create_file, delete, move_to_trash, rename,
    set_mode, write_file,
};
use crate::path::PathPolicy;
use crate::read::{open_download, read_text};
use crate::testutil::TempDir;
use std::fs;
use std::os::unix::fs::symlink;

fn policy(t: &TempDir) -> PathPolicy {
    PathPolicy::rooted_at(vec![t.path().to_path_buf()])
}

#[test]
fn the_edit_a_config_file_journey() {
    let t = TempDir::new("journey-edit");
    let p = policy(&t);

    create_directory(&p, &t.s("nginx")).unwrap();
    let created = create_file(
        &p,
        &t.s("nginx/nginx.conf"),
        b"worker_processes 1;\nevents {\n  worker_connections 512;\n}\n",
    )
    .unwrap();
    assert_eq!(created.kind.as_str(), "file");

    let listing = list_directory(&p, &t.s("nginx"), &ListOptions::default()).unwrap();
    assert_eq!(listing.total, 1);
    assert!(listing.entries[0].is_text);

    let opened = read_text(&p, &t.s("nginx/nginx.conf")).unwrap();
    assert_eq!(opened.line_count, 4);

    let edited = opened.content.replace("worker_processes 1;", "worker_processes auto;");
    let saved = write_file(&p, &t.s("nginx/nginx.conf"), edited.as_bytes()).unwrap();
    assert_eq!(saved.size_bytes, edited.len() as u64);

    let reopened = read_text(&p, &t.s("nginx/nginx.conf")).unwrap();
    assert!(reopened.content.contains("worker_processes auto;"));
    assert!(!reopened.content.contains("worker_processes 1;"));
}

#[test]
fn the_upload_then_tidy_up_journey() {
    let t = TempDir::new("journey-upload");
    let spool = TempDir::new("journey-spool");
    let p = policy(&t);

    let body = spool.path().join("upload-body");
    fs::write(&body, vec![b'k'; 300_000]).unwrap();

    create_directory(&p, &t.s("releases")).unwrap();
    let landed = copy_from(&p, &body, &t.s("releases/build.tar"), false).unwrap();
    assert_eq!(landed.size_bytes, 300_000);

    let (mut file, entry) = open_download(&p, &t.s("releases/build.tar")).unwrap();
    assert_eq!(entry.size_bytes, 300_000);
    let mut sink = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut sink).unwrap();
    assert_eq!(sink.len(), 300_000);

    rename(&p, &t.s("releases/build.tar"), &t.s("releases/build-42.tar")).unwrap();
    set_mode(&p, &t.s("releases/build-42.tar"), 0o640).unwrap();
    assert_eq!(stat_entry(&p, &t.s("releases/build-42.tar")).unwrap().mode, "0640");

    let trashed = move_to_trash(&p, &t.s("releases/build-42.tar")).unwrap();
    assert!(trashed.exists());
    assert!(!t.path().join("releases/build-42.tar").exists());

    // Emptying the trash is an ordinary recursive delete of a nested path.
    let report = delete(&p, t.path().join(TRASH_DIR_NAME).to_str().unwrap(), true).unwrap();
    assert_eq!(report.files_deleted, 1);
    assert_eq!(report.bytes_freed, 300_000);
}

#[test]
fn every_entry_point_refuses_a_symlink_out_of_the_root() {
    let t = TempDir::new("journey-escape");
    let inside = t.path().join("inside");
    let outside = t.path().join("outside");
    fs::create_dir_all(&inside).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"not yours\n").unwrap();
    symlink(outside.join("secret.txt"), inside.join("bait.txt")).unwrap();
    symlink(&outside, inside.join("bait-dir")).unwrap();

    let p = PathPolicy::rooted_at(vec![inside.clone()]);
    let file_bait = inside.join("bait.txt").to_string_lossy().into_owned();
    let dir_bait = inside.join("bait-dir").to_string_lossy().into_owned();

    assert_eq!(read_text(&p, &file_bait).unwrap_err().kind(), "denied");
    assert_eq!(stat_entry(&p, &file_bait).unwrap_err().kind(), "denied");
    assert_eq!(open_download(&p, &file_bait).unwrap_err().kind(), "denied");
    assert_eq!(write_file(&p, &file_bait, b"pwned").unwrap_err().kind(), "denied");
    assert_eq!(set_mode(&p, &file_bait, 0o777).unwrap_err().kind(), "denied");
    assert_eq!(
        tail_file(&p, &file_bait, &LogQuery::default()).unwrap_err().kind(),
        "denied"
    );
    assert_eq!(list_directory(&p, &dir_bait, &ListOptions::default()).unwrap_err().kind(), "denied");
    assert_eq!(
        create_file(&p, &format!("{dir_bait}/new.txt"), b"x").unwrap_err().kind(),
        "denied"
    );
    assert_eq!(create_directory(&p, &format!("{dir_bait}/new")).unwrap_err().kind(), "denied");

    assert_eq!(fs::read(outside.join("secret.txt")).unwrap(), b"not yours\n");
    assert!(!outside.join("new.txt").exists());
    assert!(!outside.join("new").exists());
}

#[test]
fn deleting_a_symlink_out_of_the_root_removes_only_the_link() {
    // Delete is the exception: the *link* is inside the root, so removing it is
    // legitimate. What must not happen is following it.
    let t = TempDir::new("journey-unlink");
    let inside = t.path().join("inside");
    let outside = t.path().join("outside");
    fs::create_dir_all(&inside).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"not yours\n").unwrap();
    symlink(outside.join("secret.txt"), inside.join("bait.txt")).unwrap();

    let p = PathPolicy::rooted_at(vec![inside.clone()]);
    delete(&p, inside.join("bait.txt").to_str().unwrap(), true).unwrap();
    assert!(!inside.join("bait.txt").exists());
    assert_eq!(fs::read(outside.join("secret.txt")).unwrap(), b"not yours\n");
}

#[test]
fn every_entry_point_refuses_traversal_out_of_the_root() {
    let t = TempDir::new("journey-traversal");
    let inside = t.path().join("inside");
    fs::create_dir_all(&inside).unwrap();
    fs::write(t.path().join("outer.txt"), b"outer\n").unwrap();

    let p = PathPolicy::rooted_at(vec![inside.clone()]);
    let escape = format!("{}/../outer.txt", inside.display());

    assert_eq!(read_text(&p, &escape).unwrap_err().kind(), "denied");
    assert_eq!(write_file(&p, &escape, b"x").unwrap_err().kind(), "denied");
    assert_eq!(delete(&p, &escape, false).unwrap_err().kind(), "denied");
    assert_eq!(move_to_trash(&p, &escape).unwrap_err().kind(), "denied");
    assert_eq!(stat_entry(&p, &escape).unwrap_err().kind(), "denied");
    assert_eq!(fs::read(t.path().join("outer.txt")).unwrap(), b"outer\n");
}

#[test]
fn every_entry_point_refuses_the_agents_own_secrets() {
    let p = PathPolicy::whole_filesystem();
    for path in ["/etc/serveros/agent.key", "/etc/shadow", "/root/.ssh/id_ed25519", "/proc/1/environ"]
    {
        assert_eq!(read_text(&p, path).unwrap_err().kind(), "denied", "{path}");
        assert_eq!(stat_entry(&p, path).unwrap_err().kind(), "denied", "{path}");
        assert_eq!(write_file(&p, path, b"x").unwrap_err().kind(), "denied", "{path}");
        assert_eq!(delete(&p, path, false).unwrap_err().kind(), "denied", "{path}");
        assert_eq!(
            tail_file(&p, path, &LogQuery::default()).unwrap_err().kind(),
            "denied",
            "{path}"
        );
    }
}

#[test]
fn an_ordinary_system_file_is_still_readable() {
    // The counter-example to the test above: locking everything down is easy
    // and useless. `/etc/passwd` is exactly the kind of file the product exists
    // to let people look at.
    let p = PathPolicy::whole_filesystem();
    let entry = stat_entry(&p, "/etc/passwd").unwrap();
    assert_eq!(entry.owner, "root");
    assert!(entry.is_text);
    let text = read_text(&p, "/etc/passwd").unwrap();
    assert!(text.content.contains("root:"));
}

#[test]
fn writing_a_log_then_tailing_it_round_trips() {
    let t = TempDir::new("journey-logs");
    let p = policy(&t);
    let mut body = String::new();
    for i in 0..500 {
        body.push_str(&format!("2026/09/12 09:15:00 [info] request {i}\n"));
    }
    body.push_str("2026/09/12 09:15:01 [error] upstream timed out\n");
    create_file(&p, &t.s("app.log"), body.as_bytes()).unwrap();

    let batch = tail_file(&p, &t.s("app.log"), &LogQuery { lines: 3, ..Default::default() }).unwrap();
    assert_eq!(batch.lines.len(), 3);
    assert_eq!(batch.lines[2].level.map(|l| l.as_str()), Some("error"));

    let errors = tail_file(
        &p,
        &t.s("app.log"),
        &LogQuery { lines: 50, filter: Some("error".into()), ..Default::default() },
    )
    .unwrap();
    assert_eq!(errors.lines.len(), 1);
}

#[test]
fn a_deep_tree_can_be_created_listed_and_removed() {
    let t = TempDir::new("journey-deep");
    let p = policy(&t);
    let mut path = t.path().to_path_buf();
    for level in 0..40 {
        path = path.join(format!("level-{level}"));
        create_directory(&p, path.to_str().unwrap()).unwrap();
        create_file(&p, path.join("marker.txt").to_str().unwrap(), b"x").unwrap();
    }

    let listing = list_directory(&p, t.path().join("level-0").to_str().unwrap(), &ListOptions::default())
        .unwrap();
    assert_eq!(listing.total, 2, "one directory and one file");
    assert_eq!(listing.entries[0].kind.as_str(), "directory");

    let report = delete(&p, t.path().join("level-0").to_str().unwrap(), true).unwrap();
    assert_eq!(report.files_deleted, 40);
    assert_eq!(report.directories_deleted, 40);
    assert!(!t.path().join("level-0").exists());
}

#[test]
fn concurrent_writes_to_the_same_file_never_corrupt_it() {
    // Two threads saving the same config: one must win cleanly. The file must
    // never contain a mixture, because the write is a rename.
    let t = TempDir::new("journey-race");
    let p = std::sync::Arc::new(policy(&t));
    let path = std::sync::Arc::new(t.s("config.conf"));
    fs::write(t.path().join("config.conf"), b"original\n").unwrap();

    let a = {
        let (p, path) = (p.clone(), path.clone());
        std::thread::spawn(move || write_file(&p, &path, &vec![b'a'; 50_000]).is_ok())
    };
    let b = {
        let (p, path) = (p.clone(), path.clone());
        std::thread::spawn(move || write_file(&p, &path, &vec![b'b'; 50_000]).is_ok())
    };
    let (a, b) = (a.join().unwrap(), b.join().unwrap());
    assert!(a || b, "at least one writer must succeed");

    let content = fs::read(t.path().join("config.conf")).unwrap();
    let all_a = content.iter().all(|c| *c == b'a');
    let all_b = content.iter().all(|c| *c == b'b');
    assert!(all_a || all_b, "the file must be one version or the other, never a mixture");
    assert_eq!(content.len(), 50_000);
}
