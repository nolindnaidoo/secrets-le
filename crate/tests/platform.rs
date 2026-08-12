//! Behaviour that differs by operating system, asserted rather than
//! hoped.
//!
//! Three platforms run this file. Everything in it is a place where one
//! of them answers differently from the others unless the code says
//! otherwise: the path separator, the environment, case folding,
//! reserved names, and a pipe whose far end has already gone.
//!
//! Where a platform cannot express a case, the skip is printed by name.
//! A case that quietly did not run is a case that is not covered.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_secrets-le");
static COUNTER: AtomicUsize = AtomicUsize::new(0);

const LINE: &str = "DATABASE_PASSWORD=hunter2hunter2";

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "secrets-le-platform-{name}-{}-{unique}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("a temporary directory");
        Self {
            root: std::fs::canonicalize(&root).expect("a canonical directory"),
        }
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let target = self.root.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("a parent directory");
        }
        std::fs::write(&target, contents).expect("a file");
        target
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run_with(args: &[&str], timezone: Option<&str>) -> Run {
    let mut command = Command::new(BINARY);
    command.args(args);
    match timezone {
        Some(zone) => command.env("TZ", zone),
        None => command.env_remove("TZ"),
    };
    let output = command.output().expect("the binary runs");
    Run {
        code: output.status.code().expect("an exit code, not a signal"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn run(args: &[&str]) -> Run {
    run_with(args, Some("UTC"))
}

fn reports(run: &Run) -> Vec<serde_json::Value> {
    run.stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("stdout carries only JSON"))
        .collect()
}

fn files(reports: &[serde_json::Value]) -> Vec<String> {
    reports
        .iter()
        .map(|report| report["file"].as_str().expect("a file").to_string())
        .collect()
}

/// **stdout is protocol**, and a protocol that spells a path two ways is
/// two protocols. envsync-le shipped `\` on Windows for a release.
#[test]
fn every_path_in_the_report_uses_forward_slashes() {
    let tree = Tree::new("separators");
    tree.write("config/nested/deeper/app.env", &format!("{LINE}\n"));
    tree.write("top.env", &format!("{LINE}\n"));

    // The guard against a vacuous assertion: the path handed to the
    // binary is spelled with **this platform's** separator, so on Windows
    // the input really does contain the backslashes the output must not.
    // Without this the test would pass on a platform where there was
    // never anything to convert.
    let argument = tree.path().to_string_lossy().into_owned();
    assert!(
        argument.contains(std::path::MAIN_SEPARATOR),
        "the input path has no separator at all, so this proves nothing: {argument}"
    );

    let run = run(&[&argument]);
    assert_eq!(run.code, 1, "{}", run.stderr);
    let reported = files(&reports(&run));
    assert!(!reported.is_empty(), "nothing was reported");
    for file in &reported {
        assert!(
            !file.contains('\\'),
            "a report path used a backslash: {file}\n\
             stdout is protocol and must read the same on every platform"
        );
        assert!(
            file.contains('/'),
            "a report path has no separator at all, so nothing was converted: {file}"
        );
    }
    assert!(
        reported
            .iter()
            .any(|file| file.ends_with("config/nested/deeper/app.env")),
        "the nested path was not reported with forward slashes: {reported:?}"
    );

    // The human half restates the JSON; it must not spell paths a second
    // way.
    assert!(
        !run.stderr.contains(".env\\") && !run.stderr.contains("config\\"),
        "{}",
        run.stderr
    );
}

/// The guard on the rule above: a backslash is an ordinary character in
/// a Unix filename. Rewriting one there would name a file that does not
/// exist. Unix-only because Windows cannot create the file at all.
#[cfg(unix)]
#[test]
fn a_backslash_inside_a_unix_filename_is_not_a_separator() {
    let tree = Tree::new("backslash");
    tree.write("od\\d.env", &format!("{LINE}\n"));
    let run = run(&[&tree.path().to_string_lossy()]);
    assert_eq!(run.code, 1, "{}", run.stderr);
    assert!(
        files(&reports(&run))
            .iter()
            .any(|file| file.ends_with("od\\d.env")),
        "the backslash in the name was rewritten as a separator"
    );
}

#[cfg(not(unix))]
#[test]
fn a_backslash_inside_a_unix_filename_is_not_a_separator() {
    eprintln!("SKIPPED a backslash in a filename: Windows reserves it as the separator");
}

/// The suite must not depend on `TZ`, because Windows ignores it. This
/// tool reads no clock at all, and this is what keeps that true: a date
/// or a timestamp arriving in the output would show up here as two
/// different answers to one question.
#[test]
fn the_answer_does_not_depend_on_the_timezone() {
    let tree = Tree::new("timezone");
    tree.write("app.env", &format!("{LINE}\n"));
    tree.write("clean.js", "const total = 1 + 2;\n");
    let arguments = [tree.path().to_string_lossy().to_string()];
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();

    let utc = run_with(&borrowed, Some("UTC"));
    let unset = run_with(&borrowed, None);
    let elsewhere = run_with(&borrowed, Some("Pacific/Kiritimati"));

    assert_eq!(utc.stdout, unset.stdout, "TZ=UTC and no TZ disagree");
    assert_eq!(
        utc.stdout, elsewhere.stdout,
        "the timezone changed a report"
    );
    assert_eq!(utc.stderr, unset.stderr);
    assert_eq!(utc.code, unset.code);
}

/// `README.md` and `readme.md` are one file on macOS and Windows and two
/// on Linux. Either way the walk reports each file it found exactly
/// once: a duplicated line is a duplicated finding, and a scanner that
/// double-counts is one people stop believing.
#[test]
fn a_case_insensitive_filesystem_does_not_report_one_file_twice() {
    let tree = Tree::new("case-folding");
    tree.write("README.md", &format!("{LINE}\n"));
    tree.write("readme.md", &format!("{LINE}\n"));

    let on_disk = std::fs::read_dir(tree.path())
        .expect("the tree is readable")
        .filter_map(Result::ok)
        .count();
    let insensitive = on_disk == 1;
    eprintln!(
        "case folding: this filesystem holds {on_disk} file(s) for README.md and readme.md \
         ({})",
        if insensitive {
            "case-insensitive"
        } else {
            "case-sensitive"
        }
    );

    let run = run(&[&tree.path().to_string_lossy()]);
    assert_eq!(run.code, 1, "{}", run.stderr);
    let mut reported = files(&reports(&run));
    assert_eq!(
        reported.len(),
        on_disk,
        "the walk reported {} file(s) for {on_disk} on disk: {reported:?}",
        reported.len()
    );
    let before = reported.len();
    reported.sort();
    reported.dedup();
    assert_eq!(reported.len(), before, "a file was reported twice");
}

/// `CON`, `PRN`, `AUX`, `NUL` and `COM1` are device names on Windows and
/// ordinary files everywhere else. The point is not that they exist —
/// on Windows they cannot — but that the walk survives whatever the
/// filesystem did with them, and still finds everything beside them.
#[test]
fn a_reserved_windows_filename_does_not_stop_the_walk() {
    let tree = Tree::new("reserved");
    tree.write("ordinary.env", &format!("{LINE}\n"));

    let mut created = Vec::new();
    for name in ["CON", "PRN", "AUX", "NUL", "COM1"] {
        match std::fs::write(tree.path().join(name), format!("{LINE}\n")) {
            Ok(()) => created.push(name),
            Err(error) => eprintln!("SKIPPED reserved name {name}: {error}"),
        }
    }

    let run = run(&[&tree.path().to_string_lossy()]);
    assert_eq!(
        run.code, 1,
        "the walk did not survive the reserved names\n{}",
        run.stderr
    );
    let reported = files(&reports(&run));
    assert!(
        reported.iter().any(|file| file.ends_with("ordinary.env")),
        "the file beside them was lost: {reported:?}"
    );
    for name in created {
        assert!(
            reported.iter().any(|file| file.ends_with(name)),
            "{name} was created but never reported: {reported:?}"
        );
    }
}

/// A child that refuses before reading closes the pipe under the write.
/// **The exit code is what is asserted, never the write** — the write
/// races the refusal, and asserting on it cost this family a red CI once
/// for a reason that had nothing to do with the tool.
#[test]
fn a_child_that_refuses_stdin_still_answers_with_its_exit_code() {
    let tree = Tree::new("stdin-race");
    let file = tree.write("app.env", &format!("{LINE}\n"));

    // `--stdin` with a file argument is refused during parsing, before
    // anything is read.
    let mut child = Command::new(BINARY)
        .args(["--stdin", &file.to_string_lossy()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");

    let mut pipe = child.stdin.take().expect("stdin");
    // A megabyte, so the write is guaranteed to outlive the refusal on
    // every platform. Its result is deliberately dropped.
    let _ = pipe.write_all(&vec![b'x'; 1_000_000]);
    let _ = pipe.flush();
    drop(pipe);

    let output = child.wait_with_output().expect("finishes");
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "a refusal writes no report: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
