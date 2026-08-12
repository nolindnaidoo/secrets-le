//! Inputs that break scanners, run against the built binary.
//!
//! Every case here is a shape that has emptied a report, moved a column
//! or ended a run at 2 in this family of tools. The tree is **built at
//! runtime**, not checked in: Windows cannot hold a FIFO, a permission
//! -denied file or a symlink loop in git, so each of those is created
//! where the platform can express it and skipped by name where it
//! cannot. A skip prints what it skipped; it never passes silently.
//!
//! The floor under every case: **the process does not panic, does not
//! hang, and exits 0, 1 or 2 — never on a signal.** A secret scanner
//! that dies part way through a tree has reported a clean repository it
//! never finished reading.
//!
//! Every credential below is invented for this file. Nothing here is a
//! real key, and nothing here is read from the machine running it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::Duration;

const BINARY: &str = env!("CARGO_BIN_EXE_secrets-le");
static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Every hazard file carries this, so "was it read at all" and "did the
/// hazard change the answer" are the same question.
const SECRET: &str = "hunter2hunter2";
const LINE: &str = "DATABASE_PASSWORD=hunter2hunter2";

/// Generous enough for a 100k-line file on a shared runner, short enough
/// that a genuine hang fails the job rather than timing it out.
const PATIENCE: Duration = Duration::from_secs(60);

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "secrets-le-hazard-{name}-{}-{unique}",
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

    fn bytes(&self, relative: &str, contents: &[u8]) -> PathBuf {
        let target = self.root.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("a parent directory");
        }
        std::fs::write(&target, contents).expect("a file");
        target
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        self.bytes(relative, contents.as_bytes())
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        // A file with no read permission also has no permission to be
        // removed from a directory this process created; restore it
        // before the tree goes, or the next run inherits it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(entries) = std::fs::read_dir(&self.root) {
                for entry in entries.flatten() {
                    let _ = std::fs::set_permissions(
                        entry.path(),
                        std::fs::Permissions::from_mode(0o755),
                    );
                }
            }
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Run {
    /// `None` when the process died on a signal — the outcome this file
    /// exists to rule out.
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run the binary and refuse to wait forever.
///
/// The child is drained on another thread rather than polled, because a
/// report over a few hundred files is larger than a pipe buffer and a
/// polling loop would deadlock against the child's own write.
fn run(label: &str, args: &[&str]) -> Run {
    let child = Command::new(BINARY)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    let pid = child.id();

    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });

    match receiver.recv_timeout(PATIENCE) {
        Ok(Ok(output)) => Run {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Ok(Err(error)) => panic!("{label}: the binary could not be run: {error}"),
        Err(_) => {
            terminate(pid);
            panic!("{label}: still running after {PATIENCE:?} — treat this as a hang");
        }
    }
}

/// The same, with a document piped in rather than named.
fn run_stdin(label: &str, document: &[u8]) -> Run {
    let mut child = Command::new(BINARY)
        .arg("--stdin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    let pid = child.id();
    // The write is never asserted on: a child that refuses before
    // reading closes the pipe, and the error that produces belongs to
    // this process rather than to the answer under test.
    let _ = std::io::Write::write_all(child.stdin.as_mut().expect("stdin"), document);
    drop(child.stdin.take());

    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    match receiver.recv_timeout(PATIENCE) {
        Ok(Ok(output)) => Run {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Ok(Err(error)) => panic!("{label}: the binary could not be run: {error}"),
        Err(_) => {
            terminate(pid);
            panic!("{label}: still running after {PATIENCE:?} — treat this as a hang");
        }
    }
}

/// Kill a child that outlived its patience, so a hung scan cannot outlive
/// the job that found it.
fn terminate(pid: u32) {
    #[cfg(unix)]
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    #[cfg(windows)]
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status();
}

/// The floor: no signal, and one of the three documented exit codes.
fn survived(label: &str, run: &Run) -> i32 {
    let Some(code) = run.code else {
        panic!(
            "{label}: the process died on a signal rather than answering\n{}",
            run.stderr
        );
    };
    assert!(
        (0..=2).contains(&code),
        "{label}: exit {code} is not one of 0 (clean), 1 (findings), 2 (malformed question)\n{}",
        run.stderr
    );
    code
}

fn reports(label: &str, run: &Run) -> Vec<serde_json::Value> {
    run.stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("{label}: stdout is not JSON Lines: {error}\n{line}")
            })
        })
        .collect()
}

fn report_for<'a>(reports: &'a [serde_json::Value], name: &str) -> Option<&'a serde_json::Value> {
    reports.iter().find(|report| {
        report["file"]
            .as_str()
            .is_some_and(|file| file.ends_with(name))
    })
}

fn scan_one(label: &str, file: &Path) -> (i32, serde_json::Value) {
    let run = run(label, &[&file.to_string_lossy()]);
    let code = survived(label, &run);
    let parsed = reports(label, &run);
    assert_eq!(parsed.len(), 1, "{label}: expected exactly one report line");
    (code, parsed[0].clone())
}

fn findings(report: &serde_json::Value) -> &Vec<serde_json::Value> {
    report["findings"].as_array().expect("a findings array")
}

// ---------------------------------------------------------------- content

/// Every content hazard, each holding the same credential, each scanned
/// on its own so one file's refusal cannot mask another's answer.
#[test]
fn a_content_hazard_never_costs_the_finding_in_it() {
    let tree = Tree::new("content");
    let utf16: Vec<u8> = [0xff, 0xfe]
        .into_iter()
        .chain(
            format!("{LINE}\n")
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        )
        .collect();

    // name, bytes, whether the credential must still be found
    let cases: Vec<(&str, Vec<u8>, bool)> = vec![
        ("bom.env", format!("\u{feff}{LINE}\n").into_bytes(), true),
        ("crlf.env", format!("{LINE}\r\n").into_bytes(), true),
        ("lone-cr.env", format!("x=1\r{LINE}\r").into_bytes(), true),
        ("no-trailing-newline.env", LINE.as_bytes().to_vec(), true),
        ("empty.env", Vec::new(), false),
        ("whitespace.env", b"   \t\n \n".to_vec(), false),
        ("nul.env", format!("a\0b\n{LINE}\n").into_bytes(), true),
        // Invalid UTF-8: a lone continuation byte. Not text, so not
        // scanned — but named, never dropped.
        ("invalid-utf8.env", b"\x80\x80bad\n".to_vec(), false),
        ("utf16le.env", utf16, false),
        // A four-byte emoji ahead of the value on the same line.
        (
            "emoji.env",
            format!("# \u{1f3af} {LINE}\n").into_bytes(),
            true,
        ),
        ("long-line.js", long_line(), true),
        ("many-lines.env", many_lines(), true),
    ];

    for (name, contents, expect_finding) in &cases {
        let file = tree.bytes(name, contents);
        let (code, report) = scan_one(name, &file);
        assert!(
            report["file"].as_str().is_some(),
            "{name}: the file vanished from the report"
        );
        if *expect_finding {
            assert_eq!(
                findings(&report).len(),
                1,
                "{name}: the credential in it was not found — {report}"
            );
            assert_eq!(code, 1, "{name}");
        } else {
            assert!(findings(&report).is_empty(), "{name}: {report}");
        }
        assert!(
            !run_output_holds_the_secret(&report.to_string()),
            "{name}: the report carries the value it found"
        );
    }
}

fn run_output_holds_the_secret(text: &str) -> bool {
    text.contains(SECRET)
}

/// One megabyte on a single line, punctuated the way a bundler emits it.
/// This is the ordinary case: a minified file is a normal thing to find
/// in a tree and must not cost the scan.
fn long_line() -> Vec<u8> {
    let mut line = String::with_capacity(1_100_000);
    let mut counter: u32 = 0;
    while line.len() < 1_000_000 {
        counter = counter.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let word = (counter % 11) as usize + 1;
        for index in 0..word {
            line.push(char::from(b'a' + ((counter as usize + index) % 26) as u8));
        }
        line.push(['(', ')', ';', ',', '.', '=', '+', '!'][(counter % 8) as usize]);
    }
    format!("{line}\nconst DATABASE_PASSWORD = 'hunter2hunter2';\n").into_bytes()
}

fn many_lines() -> Vec<u8> {
    let mut content = String::with_capacity(1_200_000);
    for _ in 0..100_000 {
        content.push_str("// a line that holds nothing\n");
    }
    content.push_str(LINE);
    content.push('\n');
    content.into_bytes()
}

/// Three invisible bytes that Notepad, Excel and a PowerShell redirect
/// all add. They must not move the column, or every position this tool
/// reports for a Windows-written file is off by one.
#[test]
fn a_byte_order_mark_does_not_move_the_reported_column() {
    let tree = Tree::new("bom-column");
    let with = tree.write("with.env", &format!("\u{feff}{LINE}\n"));
    let without = tree.write("without.env", &format!("{LINE}\n"));

    let (_, marked) = scan_one("with a mark", &with);
    let (_, plain) = scan_one("without a mark", &without);
    assert_eq!(
        findings(&marked)[0]["column"],
        findings(&plain)[0]["column"],
        "the mark moved the column"
    );
    assert_eq!(
        findings(&marked)[0]["context"],
        findings(&plain)[0]["context"]
    );

    // The regression: the same document arriving through a pipe is the
    // same document. `secrets-le config.env` and
    // `secrets-le --stdin < config.env` were answering with different
    // columns, because only the path route dropped the mark.
    let piped = run_stdin(
        "the same document piped in",
        format!("\u{feff}{LINE}\n").as_bytes(),
    );
    survived("the same document piped in", &piped);
    let from_pipe = reports("the same document piped in", &piped);
    assert_eq!(
        findings(&from_pipe[0])[0],
        findings(&marked)[0],
        "a document read from a path and the same document piped in disagree"
    );
}

/// stdin is a byte stream, and a byte stream is not always text. The
/// refusal must be a refusal, not a crash.
#[test]
fn a_document_piped_in_that_is_not_text_is_refused_rather_than_crashing() {
    let run = run_stdin(
        "invalid UTF-8 on stdin",
        &[0x80, 0x80, b'b', b'a', b'd', b'\n'],
    );
    assert_eq!(survived("invalid UTF-8 on stdin", &run), 2);
    assert!(run.stdout.is_empty(), "a refusal writes no report");
    assert!(!run.stderr.is_empty(), "a refusal says what it refused");
}

/// An astral character is two UTF-16 code units, which is what an editor
/// counts and therefore what a person comparing this output against the
/// file in front of them counts.
#[test]
fn an_emoji_before_a_value_counts_as_two_columns() {
    let tree = Tree::new("emoji-column");
    let emoji = tree.write("emoji.env", &format!("# \u{1f3af} {LINE}\n"));
    // "xx" occupies the same two code units the emoji does.
    let ascii = tree.write("ascii.env", &format!("# xx {LINE}\n"));
    let (_, from_emoji) = scan_one("emoji", &emoji);
    let (_, from_ascii) = scan_one("ascii", &ascii);
    assert_eq!(
        findings(&from_emoji)[0]["column"],
        findings(&from_ascii)[0]["column"]
    );
}

/// SPEC.md, "Files that cannot be read": named on stderr, carried in the
/// report with a `skipped` diagnostic, left out of the exit code — and
/// turned back into a failure by `--strict`.
///
/// This crate deliberately does **not** drop a binary file from the
/// report. A file that vanishes reads to whoever ran the scan as a file
/// that was clean, which in a secret scanner is the dangerous direction
/// for an ambiguity to run in.
#[test]
fn a_file_that_is_not_text_is_named_and_only_strict_fails_on_it() {
    let tree = Tree::new("binary");
    let file = tree.bytes(
        "logo.png",
        &[0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe, 0x00, 0x01],
    );

    let (code, report) = scan_one("a PNG", &file);
    assert_eq!(code, 0, "a PNG is not a malformed question");
    assert!(findings(&report).is_empty());
    assert_eq!(report["diagnostics"][0]["code"], "skipped", "{report}");
    assert_eq!(report["diagnostics"][0]["severity"], "warning", "{report}");

    let strict = run(
        "a PNG under --strict",
        &["--strict", &file.to_string_lossy()],
    );
    assert_eq!(survived("a PNG under --strict", &strict), 2);
}

/// Exit 2 is for a malformed question. An unreadable file is not one.
#[test]
fn exit_two_is_for_a_malformed_question_not_an_unreadable_file() {
    let tree = Tree::new("exit-two");
    tree.write("app.env", &format!("{LINE}\n"));

    let unknown = run(
        "an unknown flag",
        &["--stict", &tree.path().to_string_lossy()],
    );
    assert_eq!(survived("an unknown flag", &unknown), 2);
    assert!(unknown.stdout.is_empty(), "a refusal writes no report");

    let missing = run("a path that is not there", &["no-such-file-xyz.env"]);
    assert_eq!(survived("a path that is not there", &missing), 2);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let denied = tree.write("denied.env", &format!("{LINE}\n"));
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000))
            .expect("permissions");
        if std::fs::read(&denied).is_ok() {
            // Running as root: the case cannot be expressed. Said out
            // loud rather than passed quietly.
            eprintln!("SKIPPED permission-denied: this process can read a 0o000 file (root?)");
        } else {
            let (code, report) = scan_one("a file this process may not read", &denied);
            assert_eq!(code, 0, "an unreadable file is not a malformed question");
            assert_eq!(report["diagnostics"][0]["code"], "skipped", "{report}");
        }
        let _ = std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o644));
    }
    #[cfg(not(unix))]
    eprintln!("SKIPPED permission-denied: Windows has no 0o000");
}

/// The documented limit, pinned so it cannot drift into a silent one.
///
/// A million unbroken word characters is what the raised backtracking
/// budget in `detect/patterns.rs` cannot cover: thirteen patterns begin
/// with `[A-Za-z0-9_-]*`, and the engine saves a backtrack frame per
/// character of the run. Measured, not guessed — 800k answers, a million
/// refuses. The refusal is the honest outcome and the reason the budget
/// is raised rather than removed: the report says the file was not fully
/// scanned and the run exits 2, instead of reporting a clean file the
/// scanner never finished.
#[test]
fn a_crafted_word_run_refuses_out_loud_rather_than_reporting_clean() {
    let tree = Tree::new("wordrun");
    let mut content = "x".repeat(1_000_000);
    content.push('\n');
    content.push_str(LINE);
    content.push('\n');
    let file = tree.write("crafted.txt", &content);

    let (code, report) = scan_one("a million-character word run", &file);
    assert_eq!(code, 2, "a scan that stopped early must not answer 0 or 1");
    assert_eq!(report["diagnostics"][0]["code"], "incomplete", "{report}");
    assert_eq!(report["diagnostics"][0]["severity"], "error", "{report}");
    assert!(
        report["file"]
            .as_str()
            .is_some_and(|file| file.ends_with("crafted.txt")),
        "the refusal must name the file it could not finish: {report}"
    );
}

// ------------------------------------------------------------- filesystem

/// Links, pipes, permissions and awkward names, all in one tree. The
/// walk must come out the other side with an answer.
#[test]
fn a_filesystem_hazard_never_ends_the_walk() {
    let tree = Tree::new("filesystem");
    tree.write("plain.env", &format!("{LINE}\n"));
    tree.write("x.json/inside.env", &format!("{LINE}\n"));
    tree.write("with space.env", &format!("{LINE}\n"));
    tree.write("\u{fc}n\u{ef}cod\u{e9}.env", &format!("{LINE}\n"));
    tree.write("\u{1f3af}.env", &format!("{LINE}\n"));

    let mut expected = vec![
        "plain.env",
        "inside.env",
        "with space.env",
        "\u{fc}n\u{ef}cod\u{e9}.env",
        "\u{1f3af}.env",
    ];

    #[cfg(unix)]
    {
        use std::os::unix::fs;
        // A link to a file, a link to nothing, and a pair that point at
        // each other. The walker never follows a link — a link out of
        // the tree would have this reading files the caller did not
        // point it at — so none of these is scanned; what matters is
        // that none of them ends the walk either.
        fs::symlink("plain.env", tree.path().join("link.env")).expect("a symlink");
        fs::symlink("nowhere.env", tree.path().join("broken.env")).expect("a symlink");
        fs::symlink("loop-b", tree.path().join("loop-a")).expect("a symlink");
        fs::symlink("loop-a", tree.path().join("loop-b")).expect("a symlink");
        make_fifo(tree.path().join("pipe.env").as_path());
    }
    #[cfg(not(unix))]
    eprintln!("SKIPPED symlinks and FIFO: creating either needs privileges Windows CI lacks");

    // Windows refuses a path over 260 characters unless long paths are
    // enabled, so the case is attempted and named rather than asserted.
    let deep: PathBuf = tree.path().join("d".repeat(120)).join("e".repeat(120));
    match std::fs::create_dir_all(&deep) {
        Ok(()) => {
            std::fs::write(deep.join("deep.env"), format!("{LINE}\n")).expect("a deep file");
            expected.push("deep.env");
        }
        Err(error) => eprintln!("SKIPPED a path over 260 characters: {error}"),
    }

    let run = run(
        "a hazardous tree",
        &["--hidden", "--no-ignore", &tree.path().to_string_lossy()],
    );
    let code = survived("a hazardous tree", &run);
    assert_eq!(
        code, 1,
        "the credentials in it are still findings\n{}",
        run.stderr
    );

    let parsed = reports("a hazardous tree", &run);
    for name in expected {
        let report = report_for(&parsed, name)
            .unwrap_or_else(|| panic!("{name} is missing from the report entirely"));
        assert_eq!(findings(report).len(), 1, "{name}: {report}");
    }
    assert!(!run.stdout.contains(SECRET), "a value reached stdout");
    assert!(!run.stderr.contains(SECRET), "a value reached stderr");
}

#[cfg(unix)]
fn make_fifo(path: &Path) {
    // `mkfifo` rather than libc: `unsafe` is forbidden crate-wide, and a
    // test is not the place to make the first exception.
    let made = Command::new("mkfifo")
        .arg(path)
        .status()
        .is_ok_and(|status| status.success());
    if !made {
        eprintln!("SKIPPED a FIFO: mkfifo is not available here");
    }
}

/// A directory whose name looks like a file must not be opened as one.
#[test]
fn a_directory_named_like_a_file_is_walked_not_read() {
    let tree = Tree::new("dir-named-file");
    tree.write("config.json/real.env", &format!("{LINE}\n"));
    let run = run(
        "a directory named config.json",
        &[&tree.path().to_string_lossy()],
    );
    assert_eq!(survived("a directory named config.json", &run), 1);
    let parsed = reports("a directory named config.json", &run);
    assert!(report_for(&parsed, "real.env").is_some(), "{}", run.stdout);
    assert!(
        parsed.iter().all(|report| report["file"]
            .as_str()
            .is_some_and(|file| file.ends_with("real.env"))),
        "the directory itself was read as a document: {}",
        run.stdout
    );
}
