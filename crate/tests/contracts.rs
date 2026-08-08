//! The exit codes, the stdout contract, and the property the tool
//! rests on — driven against the built binary.
//!
//! The exit codes are the API: a CI step branches on them, so they are
//! pinned here rather than inferred from unit tests of the functions
//! behind them. Nothing here needs a network or a privileged filesystem
//! operation, so it runs everywhere on every push.
//!
//! The last test is the one that matters most: it plants credentials
//! whose values it knows, runs the real binary, and asserts that not one
//! of them appears anywhere in stdout or stderr. Every other check in
//! this crate reasons about masking; this one looks at what a CI log
//! would actually have captured.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_secrets-le");
static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "secrets-le-contract-{name}-{}-{unique}",
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

fn run(args: &[&str]) -> Run {
    let output = Command::new(BINARY)
        .args(args)
        .output()
        .expect("the binary runs");
    Run {
        code: output.status.code().expect("an exit code"),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Every line of stdout, parsed. Doubles as the assertion that stdout
/// is JSON Lines and nothing else — a stray human message there would
/// fail to parse.
fn reports(run: &Run) -> Vec<serde_json::Value> {
    run.stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("stdout carries only JSON"))
        .collect()
}

/// The values planted by `dirty_tree`. Held here so the leak test can
/// assert on the exact strings a real run would have had in hand.
const PLANTED: [&str; 5] = [
    "hunter2hunter2hunter2",
    "AKIAIOSFODNN7EXAMPLE",
    "sk_live_abcdefghijklmnop1234",
    "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
];

fn dirty_tree(name: &str) -> Tree {
    let tree = Tree::new(name);
    tree.write(
        "config/app.env",
        &format!(
            "DATABASE_PASSWORD={}\nAWS_ACCESS_KEY_ID={}\n",
            PLANTED[0], PLANTED[1]
        ),
    );
    tree.write(
        "src/client.js",
        &format!(
            "const stripe = '{}';\nconst gh = '{}';\nconst jwt = '{}';\n",
            PLANTED[2], PLANTED[3], PLANTED[4]
        ),
    );
    tree
}

#[test]
fn a_clean_tree_exits_clear() {
    let tree = Tree::new("clean");
    tree.write("src/app.js", "const total = 1 + 2;\n");
    tree.write("README.md", "# nothing to see\n");
    let run = run(&[&tree.path().to_string_lossy()]);
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert!(reports(&run).iter().all(|r| r["summary"]["findings"] == 0));
}

#[test]
fn a_credential_exits_one() {
    let tree = dirty_tree("finding");
    let run = run(&[&tree.path().to_string_lossy()]);
    assert_eq!(run.code, 1);
    let total: u64 = reports(&run)
        .iter()
        .filter_map(|r| r["summary"]["findings"].as_u64())
        .sum();
    assert!(total >= 5, "expected every planted credential, got {total}");
}

/// **The test this crate exists for.** A real run over real files, with
/// the planted values checked against everything the process wrote.
#[test]
fn no_planted_value_reaches_stdout_or_stderr() {
    let tree = dirty_tree("noleak");
    for args in [
        vec![tree.path().to_string_lossy().to_string()],
        vec![
            "--sensitivity".to_string(),
            "low".to_string(),
            tree.path().to_string_lossy().to_string(),
        ],
    ] {
        let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
        let run = run(&borrowed);
        for value in PLANTED {
            assert!(
                !run.stdout.contains(value),
                "a planted value reached stdout: {value}"
            );
            assert!(
                !run.stderr.contains(value),
                "a planted value reached stderr: {value}"
            );
        }
        // The findings must actually have happened, or the assertion
        // above proves nothing.
        assert_eq!(run.code, 1, "{}", run.stderr);
    }
}

#[test]
fn sensitivity_narrows_what_is_reported() {
    let tree = Tree::new("sensitivity");
    tree.write("app.env", "cookie=abcdefghijklmnopqrstuvwxyz\n");
    assert_eq!(
        run(&["--sensitivity", "high", &tree.path().to_string_lossy()]).code,
        0
    );
    assert_eq!(
        run(&["--sensitivity", "low", &tree.path().to_string_lossy()]).code,
        1
    );
}

#[test]
fn a_detector_family_can_be_switched_off() {
    let tree = Tree::new("family");
    tree.write("app.env", "DATABASE_PASSWORD=hunter2hunter2\n");
    assert_eq!(run(&[&tree.path().to_string_lossy()]).code, 1);
    assert_eq!(
        run(&["--no-passwords", &tree.path().to_string_lossy()]).code,
        0
    );
}

/// A clean answer that skipped the `.env` is a dangerous answer.
#[test]
fn files_held_back_by_gitignore_are_counted_in_the_summary() {
    let tree = Tree::new("skipped");
    std::fs::create_dir_all(tree.path().join(".git")).expect("a git dir");
    tree.write(".gitignore", ".env\n");
    tree.write(".env", "DATABASE_PASSWORD=hunter2hunter2\n");

    let default = run(&[&tree.path().to_string_lossy()]);
    assert_eq!(
        default.code, 0,
        "the ignored file is not scanned by default"
    );
    assert!(
        default.stderr.contains("skipped"),
        "the miss must be stated: {}",
        default.stderr
    );

    let everything = run(&["--hidden", "--no-ignore", &tree.path().to_string_lossy()]);
    assert_eq!(everything.code, 1, "{}", everything.stderr);
}

#[test]
fn an_unknown_flag_exits_two_and_names_itself() {
    let tree = Tree::new("badflag");
    let run = run(&["--no-passwrods", &tree.path().to_string_lossy()]);
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("--no-passwrods"), "{}", run.stderr);
    assert!(run.stdout.is_empty(), "a refusal writes no report");
}

/// There must be no way to ask the binary for the values.
#[test]
fn no_flag_reveals_a_value() {
    let tree = dirty_tree("novalues");
    for attempt in ["--show-values", "--unsafe", "--raw", "--no-mask"] {
        let run = run(&[attempt, &tree.path().to_string_lossy()]);
        assert_eq!(run.code, 2, "{attempt} was accepted");
    }
    let help = run(&["--help"]);
    for value in PLANTED {
        assert!(!help.stdout.contains(value));
    }
}

#[test]
fn a_path_that_does_not_exist_exits_two() {
    assert_eq!(run(&["/no/such/place-xyz"]).code, 2);
}

#[test]
fn naming_nothing_exits_two() {
    assert_eq!(run(&[]).code, 2);
}

#[test]
fn version_and_help_exit_clear() {
    let version = run(&["--version"]);
    assert_eq!(version.code, 0);
    assert!(version.stdout.contains("secrets-le"));
    let help = run(&["--help"]);
    assert_eq!(help.code, 0);
    assert!(help.stdout.contains("usage: secrets-le"));
}

#[test]
fn stdout_carries_only_reports_and_stderr_only_the_summary() {
    let tree = dirty_tree("streams");
    let run = run(&[&tree.path().to_string_lossy()]);
    assert!(!reports(&run).is_empty());
    assert!(!run.stderr.contains('{'), "{}", run.stderr);
    assert!(run.stderr.contains("findings in"), "{}", run.stderr);
}

#[test]
fn a_document_on_stdin_is_scanned() {
    let mut child = Command::new(BINARY)
        .args(["--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"DATABASE_PASSWORD=hunter2hunter2\n")
        .expect("written");
    let output = child.wait_with_output().expect("finishes");
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout carries JSON");
    assert_eq!(report["file"], "<stdin>");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("hunter2hunter2"));
}

/// **The cross-surface contract.** Both surfaces call one entry point,
/// so they must answer identically for the same tree.
#[test]
fn the_cli_and_the_mcp_server_report_the_same_thing() {
    let tree = dirty_tree("agreement");
    let cli = run(&[&tree.path().to_string_lossy()]);
    let from_cli = reports(&cli);

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "secrets_le_scan",
            "arguments": { "path": tree.path().to_string_lossy() },
        },
    });
    let mut child = Command::new(BINARY)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the server starts");
    writeln!(child.stdin.as_mut().expect("stdin"), "{request}").expect("written");
    let output = child.wait_with_output().expect("finishes");
    let response: serde_json::Value = serde_json::from_slice(
        output
            .stdout
            .split(|byte| *byte == b'\n')
            .next()
            .expect("a line"),
    )
    .expect("the reply is JSON");

    let from_mcp = response["result"]["structuredContent"]["data"]["reports"]
        .as_array()
        .expect("reports")
        .clone();
    assert_eq!(from_mcp, from_cli, "the two surfaces disagree");
}
