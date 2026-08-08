//! The tier that needs the real world: a directory this process cannot
//! enter, and a file big enough to exhaust a regex engine.
//!
//! Gated behind `SECRETS_LE_SCENARIOS` and run by CI on macOS, Windows
//! and Linux. Nothing here substitutes for `contracts.rs`, which runs
//! everywhere on every push.
//!
//! **A skipped scenario is never reported as a pass.** Each test says
//! plainly that it did not run.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_secrets-le");
static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn enabled(name: &str) -> bool {
    if std::env::var_os("SECRETS_LE_SCENARIOS").is_some() {
        return true;
    }
    eprintln!("SKIPPED {name}: set SECRETS_LE_SCENARIOS to run it");
    false
}

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "secrets-le-scenario-{name}-{}-{unique}",
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

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(BINARY)
        .args(args)
        .output()
        .expect("the binary runs");
    (
        output.status.code().expect("an exit code"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// **The regression that made the tool unusable.** A lockfile is ~150 KB
/// of base64-ish tokens, and the `aws-secret` pattern exhausted the
/// default backtracking budget on one — so the scan refused, and every
/// repository with a lockfile exited 2. Found by running the binary over
/// seven real repositories; no test had a file large enough to reach it.
#[test]
fn a_large_lockfile_does_not_exhaust_the_regex_engine() {
    if !enabled("a_large_lockfile_does_not_exhaust_the_regex_engine") {
        return;
    }
    let tree = Tree::new("lockfile");
    let mut lockfile = String::with_capacity(300_000);
    for index in 0..4_000 {
        use std::fmt::Write as _;
        let _ = writeln!(
            lockfile,
            "  \"pkg-{index}\": [\"pkg-{index}@1.0.{index}\", \"\", {{}}, \
             \"sha512-aB3xY7zQ9mK2pL5vN8wR4tS6aB3xY7zQ9mK2pL5vN8wR4tS6==\"],"
        );
    }
    tree.write("bun.lock", &lockfile);

    let (code, stdout, stderr) = run(&[&tree.path().to_string_lossy()]);
    assert_ne!(
        code, 2,
        "the scan refused on an ordinary lockfile: {stderr}"
    );
    assert!(
        !stdout.contains("incomplete"),
        "a pattern gave up: {stdout}"
    );
}

/// A directory the process cannot enter must end the run at 2. A scan
/// that silently skipped it would report a clean repository it never
/// finished looking at.
#[cfg(unix)]
#[test]
fn an_unreadable_directory_ends_the_run_at_two() {
    use std::os::unix::fs::PermissionsExt;

    if !enabled("an_unreadable_directory_ends_the_run_at_two") {
        return;
    }
    let tree = Tree::new("locked");
    tree.write("open/a.env", "x=1\n");
    let locked = tree.path().join("locked");
    std::fs::create_dir_all(&locked).expect("a directory");
    std::fs::write(locked.join("b.env"), "PASSWORD=hunter2hunter2\n").expect("a file");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).expect("perms");

    let (code, _, stderr) = run(&[&tree.path().to_string_lossy()]);
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).expect("perms");

    assert_eq!(code, 2, "an unwalkable directory means it could not answer");
    assert!(
        stderr.contains("locked") || stderr.contains("ermission"),
        "the refusal must name what it could not read: {stderr}"
    );
}

/// The property, over a tree big enough that a buffering mistake would
/// show: no planted value anywhere in the output.
#[test]
fn no_value_leaks_from_a_large_scan() {
    if !enabled("no_value_leaks_from_a_large_scan") {
        return;
    }
    let tree = Tree::new("bulk");
    let value = "hunter2hunter2hunter2hunter2";
    for index in 0..500 {
        tree.write(
            &format!("src/mod{index}/config.env"),
            &format!("DATABASE_PASSWORD={value}\n"),
        );
    }
    let (code, stdout, stderr) = run(&["--sensitivity", "low", &tree.path().to_string_lossy()]);
    assert_eq!(code, 1, "{stderr}");
    assert!(!stdout.contains(value), "a value reached stdout");
    assert!(!stderr.contains(value), "a value reached stderr");
}
