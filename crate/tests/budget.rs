//! A wall-clock ceiling, and the shape of the curve underneath it.
//!
//! This crate was **fifty times slower than every sibling for a whole
//! release** — 8.55s over a tree the others crossed in 0.06s — because
//! thirteen of its nineteen patterns begin with `[A-Za-z0-9_-]*` and a
//! backtracking engine had nothing to anchor on. Nobody noticed, because
//! nothing measured it. The DFA prefilter in `detect/patterns.rs` fixed
//! it; this file is what stops it coming back.
//!
//! Two assertions, and the second matters more:
//!
//! - **A ceiling**, at ten times the local measurement recorded below.
//!   Loose enough not to flake on a shared runner, tight enough to catch
//!   an order of magnitude — which is the size the regression was.
//! - **Linearity.** The same tree four times over must not cost more
//!   than six times as long. A ceiling catches a scan that got slower; a
//!   ratio catches a scan whose cost stopped being proportional to its
//!   input, which is the class of bug that only shows on a tree bigger
//!   than the one anybody tested on.
//!
//! The tree is generated from a fixed seed rather than checked in: 500
//! files of plausible source is a megabyte of fixtures nobody would ever
//! read, and a seed is reproducible in one line. The seed is printed on
//! failure.
//!
//! **Run in release, and only when asked.** A debug binary measures the
//! profile rather than the program, and `cargo test` builds debug — so
//! this file is gated behind `SECRETS_LE_BUDGET`, the same way
//! `scenarios.rs` is gated, and CI runs
//! `SECRETS_LE_BUDGET=1 cargo test --release --test budget`. A skipped
//! measurement says so out loud; it is never reported as a pass.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_secrets-le");
static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// The tree, and the seed that produces it.
const FILES: usize = 500;
const SEED: u64 = 0x5EC2_E751_1E20_2607;

/// **Local measurement**, taken on an Apple M-series laptop (macOS 15,
/// release profile, warm page cache), best of three:
///
/// - 500 files, ~1.2 MB of text: **0.047s**
/// - the same tree four times over, 2000 files: **0.162s** (3.46x)
///
/// The ceiling is ten times the first, rounded up. A GitHub-hosted
/// ubuntu runner is slower than this machine, but not by an order of
/// magnitude — and an order of magnitude is exactly what this is here to
/// catch, because the regression it exists for was fifty times.
const CEILING: Duration = Duration::from_millis(500);

/// Four times the tree, at most six times the time. The slack is for
/// process start and the walk's own sort, both of which are paid once.
const LINEARITY: u32 = 6;

/// Whether to measure at all. A timing taken from a debug build is a
/// number about the profile, not about the program.
fn enabled(name: &str) -> bool {
    if std::env::var_os("SECRETS_LE_BUDGET").is_some() {
        return true;
    }
    eprintln!("SKIPPED {name}: set SECRETS_LE_BUDGET and build --release to measure it");
    false
}

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "secrets-le-budget-{name}-{}-{unique}",
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

    fn write(&self, relative: &str, contents: &str) {
        let target = self.root.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).expect("a parent directory");
        }
        std::fs::write(&target, contents).expect("a file");
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A named, seeded, entirely ordinary pseudo-random source. Not for
/// cryptography and not pretending to be: it exists so a 500-file tree
/// is one number rather than a megabyte of fixtures.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        // xorshift64*, three lines, no dependency.
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }
}

const EXTENSIONS: [&str; 8] = ["ts", "js", "py", "go", "rs", "json", "yaml", "env"];

/// Lines that look like the inside of a repository: imports, comments,
/// configuration, and — every so often — a credential, so the scan has
/// something to find and the finding path is measured too.
const ORDINARY: [&str; 12] = [
    "import { readFileSync } from 'node:fs';",
    "const total = items.reduce((sum, item) => sum + item.count, 0);",
    "// The walk is deliberately shallow here; see the note above.",
    "export const DEFAULT_TIMEOUT_MS = 30_000;",
    "def resolve(path: str) -> str:\n    return os.path.abspath(path)",
    "func handler(w http.ResponseWriter, r *http.Request) {",
    "pub(crate) fn describe(report: &Report) -> String {",
    "  \"name\": \"a-package-nobody-published\",",
    "database:\n  host: localhost\n  port: 5432",
    "LOG_LEVEL=debug",
    "let cached = registry.get(&key).cloned().unwrap_or_default();",
    "<!-- nothing to see in this line at all -->",
];

/// Every credential below is invented for this file.
const PLANTED: [&str; 4] = [
    "DATABASE_PASSWORD=hunter2hunter2",
    "api_key = 'abcdefghijklmnopqrstuvwx'",
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    "session_id: aB3xY7zQ9mK2pL5vN8wR4tS6",
];

fn build(tree: &Tree, prefix: &str, files: usize, seed: u64) {
    let mut random = Seeded(seed);
    for index in 0..files {
        let extension = EXTENSIONS[random.below(EXTENSIONS.len())];
        let depth = random.below(4);
        let mut path = String::from(prefix);
        for level in 0..depth {
            let _ = write!(path, "dir{level}/");
        }
        let _ = write!(path, "file{index}.{extension}");

        let mut content = String::with_capacity(2_500);
        let lines = 20 + random.below(60);
        for _ in 0..lines {
            content.push_str(ORDINARY[random.below(ORDINARY.len())]);
            content.push('\n');
        }
        // One file in ten holds something.
        if random.below(10) == 0 {
            content.push_str(PLANTED[random.below(PLANTED.len())]);
            content.push('\n');
        }
        tree.write(&path, &content);
    }
}

/// The fastest of three runs, and how many findings it produced. The
/// fastest is the honest one: a slower run measured the runner's other
/// tenants, not this program. The count comes back so a timing can never
/// pass because the scan quietly found nothing to do.
fn fastest(root: &Path) -> (Duration, usize) {
    let mut best = Duration::MAX;
    let mut findings = 0;
    for _ in 0..3 {
        let started = Instant::now();
        let output = Command::new(BINARY)
            .args(["--hidden", "--no-ignore", &root.to_string_lossy()])
            .output()
            .expect("the binary runs");
        let elapsed = started.elapsed();
        let code = output.status.code().expect("an exit code, not a signal");
        assert!(
            code == 0 || code == 1,
            "the scan did not complete (exit {code}): {}",
            String::from_utf8_lossy(&output.stderr)
        );
        findings = String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let report: serde_json::Value =
                    serde_json::from_str(line).expect("stdout carries only JSON");
                report["summary"]["findings"].as_u64().unwrap_or(0) as usize
            })
            .sum();
        best = best.min(elapsed);
    }
    (best, findings)
}

#[test]
fn a_five_hundred_file_tree_stays_inside_its_budget() {
    if !enabled("a_five_hundred_file_tree_stays_inside_its_budget") {
        return;
    }
    let tree = Tree::new("ceiling");
    build(&tree, "", FILES, SEED);
    let (taken, findings) = fastest(tree.path());
    eprintln!(
        "budget: {FILES} files, {findings} findings, in {taken:?} \
         (ceiling {CEILING:?}, seed {SEED:#x})"
    );
    assert!(
        findings > 0,
        "the generated tree holds no credentials, so this measured the walk and nothing else"
    );
    assert!(
        taken <= CEILING,
        "scanning {FILES} files took {taken:?}, over the {CEILING:?} ceiling.\n\
         Reproduce with seed {SEED:#x}. This crate was fifty times slower than its siblings \
         for a release because nothing measured it; if the new cost is deliberate, move the \
         ceiling in the same commit as the change that earned it."
    );
}

/// The direct test for the quadratic class: four times the input, at
/// most six times the time.
#[test]
fn four_times_the_tree_is_not_more_than_six_times_the_time() {
    if !enabled("four_times_the_tree_is_not_more_than_six_times_the_time") {
        return;
    }
    let one = Tree::new("linear-1");
    build(&one, "", FILES, SEED);
    let four = Tree::new("linear-4");
    for copy in 0..4 {
        build(&four, &format!("copy{copy}/"), FILES, SEED);
    }

    let (base, found) = fastest(one.path());
    let (bigger, found_bigger) = fastest(four.path());
    eprintln!(
        "linearity: {FILES} files in {base:?}, {} files in {bigger:?} ({:.2}x)",
        FILES * 4,
        bigger.as_secs_f64() / base.as_secs_f64().max(f64::EPSILON)
    );
    assert_eq!(
        found_bigger,
        found * 4,
        "four copies of the tree did not produce four times the findings"
    );
    assert!(
        bigger <= base * LINEARITY,
        "four times the tree took {bigger:?} against {base:?} for one — more than {LINEARITY}x.\n\
         Cost that stops being proportional to the input is the class of bug that only shows on \
         a tree bigger than the one anyone tested on. Seed {SEED:#x}."
    );
}

/// The other half of the quadratic class, and the one a tree cannot
/// reach: **many findings on a single very long line.**
///
/// A column is counted in UTF-16 code units. On an all-ASCII document a
/// byte offset *is* that count and the lookup is arithmetic; on anything
/// else it is a scan from the start of the line. One non-ASCII character
/// is enough to take that path for the whole document — so a minified
/// file with a copyright sign in it, and a hundred findings on its one
/// line, is where an O(line x findings) lookup shows up.
#[test]
fn many_findings_on_one_long_line_do_not_cost_quadratic_time() {
    if !enabled("many_findings_on_one_long_line_do_not_cost_quadratic_time") {
        return;
    }
    let measure = |pairs: usize| -> (Duration, usize) {
        let tree = Tree::new("one-line");
        // The non-ASCII character is what forces the counted path.
        let mut line = String::from("// \u{a9} generated, do not edit; ");
        for index in 0..pairs {
            // The key has to *end* in the detector's name, so the index
            // goes in front of it. Every value is different, which is the
            // worst case for masking a context line: each one has to be
            // redacted out of every window it appears in.
            let _ = write!(line, "db{index}_password=hunter2hunter2hunt{index:04} ");
        }
        line.push('\n');
        tree.write("bundle.min.js", &line);
        fastest(tree.path())
    };

    let (small, small_found) = measure(400);
    let (large, large_found) = measure(1_600);
    eprintln!(
        "one long line: {small_found} findings in {small:?}, {large_found} in {large:?} ({:.2}x)",
        large.as_secs_f64() / small.as_secs_f64().max(f64::EPSILON)
    );
    assert_eq!(
        (small_found, large_found),
        (400, 1_600),
        "the line under test produced the wrong number of findings, so the timing means nothing"
    );
    assert!(
        large <= small * LINEARITY,
        "four times the findings on one line took {large:?} against {small:?} — more than \
         {LINEARITY}x. A position lookup that rescans the line for every finding is quadratic \
         in exactly this shape."
    );
}
