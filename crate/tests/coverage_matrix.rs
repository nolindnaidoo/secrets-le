//! Does this crate open what it claims to open?
//!
//! Most of the family answers that against an alias table: a format is
//! listed, so a document in it must be read. **This crate has no such
//! table, and that is the claim** — AGENTS.md: *every file is scanned,
//! whatever its extension*, because a scanner that only looked at the
//! extensions it recognised would report a clean tree while sitting next
//! to a `.bak` full of passwords.
//!
//! So the matrix here is the inverse of the family's: one file per
//! extension across a broad sample, **plus a dozen extensions nothing
//! knows**, plus names with no extension at all — and every one of them
//! must come back with a report line and the credential in it. A file
//! that produced no line would read to whoever ran the scan as a file
//! that was clean.
//!
//! The sample is checked in rather than derived, because there is no
//! table to derive it from. Its floor is pinned to the shared corpus: an
//! extension the corpus uses and this list does not is a failure.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_secrets-le");
const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/documents");
static COUNTER: AtomicUsize = AtomicUsize::new(0);

const LINE: &str = "DATABASE_PASSWORD=hunter2hunter2";

/// Extensions a credential plausibly hides in — configuration, source,
/// data, documentation, build and shell. Nothing here is special-cased
/// by the code; the list exists so the *absence* of special-casing is
/// measured rather than assumed.
const KNOWN: [&str; 58] = [
    "env",
    "ini",
    "cfg",
    "conf",
    "properties",
    "toml",
    "yaml",
    "yml",
    "json",
    "json5",
    "jsonc",
    "xml",
    "plist",
    "csv",
    "tsv",
    "md",
    "mdx",
    "txt",
    "rst",
    "js",
    "mjs",
    "cjs",
    "jsx",
    "ts",
    "tsx",
    "py",
    "rb",
    "go",
    "rs",
    "java",
    "kt",
    "swift",
    "c",
    "h",
    "cpp",
    "cs",
    "php",
    "pl",
    "lua",
    "r",
    "scala",
    "sh",
    "bash",
    "zsh",
    "fish",
    "ps1",
    "bat",
    "sql",
    "graphql",
    "proto",
    "tf",
    "tfvars",
    "gradle",
    "dockerfile",
    "makefile",
    "pem",
    "key",
    "log",
];

/// Extensions nothing in this family has heard of. They must be read
/// exactly like the ones above — that is the whole point.
const UNKNOWN: [&str; 12] = [
    "bak", "orig", "swp", "tmp", "old", "save", "dist", "sample", "example", "local", "wat", "qqq",
];

/// Files with no extension, an uppercase one, two extensions, and a
/// dotfile. Each has broken an extension-driven walker somewhere.
const AWKWARD: [&str; 8] = [
    "Makefile",
    "Dockerfile",
    "Procfile",
    "CREDENTIALS",
    "config.ENV",
    "settings.Yaml",
    "app.env.backup",
    "notes",
];

struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "secrets-le-matrix-{name}-{}-{unique}",
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

/// Every file this crate is asked to look at, and the one credential
/// each of them holds.
fn matrix() -> Vec<String> {
    let mut names: Vec<String> = KNOWN
        .iter()
        .chain(UNKNOWN.iter())
        .map(|extension| format!("file.{extension}"))
        .collect();
    names.extend(AWKWARD.iter().map(ToString::to_string));
    names
}

#[test]
fn every_file_in_the_matrix_comes_back_with_its_finding() {
    let tree = Tree::new("all");
    let names = matrix();
    for name in &names {
        tree.write(name, &format!("{LINE}\n"));
    }

    let output = Command::new(BINARY)
        .args(["--hidden", "--no-ignore", &tree.path().to_string_lossy()])
        .output()
        .expect("the binary runs");
    let code = output.status.code().expect("an exit code, not a signal");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(code, 1, "{stderr}");

    let reports: Vec<serde_json::Value> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("stdout carries only JSON"))
        .collect();

    let mut missing = Vec::new();
    let mut empty = Vec::new();
    for name in &names {
        let Some(report) = reports.iter().find(|report| {
            report["file"]
                .as_str()
                .is_some_and(|file| file.ends_with(&format!("/{name}")))
        }) else {
            missing.push(name.clone());
            continue;
        };
        let findings = report["findings"].as_array().expect("findings");
        if findings.len() != 1 {
            empty.push(format!("{name} ({} findings)", findings.len()));
        }
    }

    assert!(
        missing.is_empty(),
        "the walk skipped {} file(s) entirely, which reads as \"they were clean\": {missing:?}",
        missing.len()
    );
    assert!(
        empty.is_empty(),
        "{} file(s) were opened but the credential in them was not reported: {empty:?}",
        empty.len()
    );
    assert_eq!(
        reports.len(),
        names.len(),
        "the report has {} lines for {} files",
        reports.len(),
        names.len()
    );
}

/// The floor under the checked-in list: every extension the shared
/// corpus uses must be in it. The corpus is what both frontends
/// reproduce, so a document type it covers and this matrix does not is a
/// gap nobody would see.
#[test]
fn the_matrix_covers_every_extension_the_corpus_uses() {
    let documents = std::fs::read_dir(CORPUS).expect("the corpus is readable");
    let mut absent = Vec::new();
    for entry in documents.filter_map(Result::ok) {
        let path = entry.path();
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if !KNOWN.contains(&extension) && !UNKNOWN.contains(&extension) {
            absent.push(extension.to_string());
        }
    }
    assert!(
        absent.is_empty(),
        "the corpus carries document types this matrix never checks: {absent:?}"
    );
}

/// A dotfile is where a credential most often is, and the default walk
/// deliberately does not reach it. Both halves are asserted, because
/// "nothing found" and "nothing found in what I was allowed to look at"
/// are different claims.
#[test]
fn a_hidden_file_is_reached_only_when_asked_for_and_the_miss_is_stated() {
    let tree = Tree::new("hidden");
    tree.write(".env", &format!("{LINE}\n"));
    tree.write(
        ".npmrc",
        "//registry.example.invalid/:_authToken=abcdefghijklmnopqrstuvwx\n",
    );
    let root = tree.path().to_string_lossy().into_owned();

    let default = Command::new(BINARY).arg(&root).output().expect("runs");
    assert_eq!(default.status.code(), Some(0));
    let said = String::from_utf8_lossy(&default.stderr).into_owned();
    assert!(
        said.contains("excluded") || said.contains("not scanned"),
        "the default walk missed both files without saying so: {said}"
    );

    let asked = Command::new(BINARY)
        .args(["--hidden", "--no-ignore", &root])
        .output()
        .expect("runs");
    assert_eq!(asked.status.code(), Some(1));
    let reports = String::from_utf8_lossy(&asked.stdout).into_owned();
    assert!(reports.contains(".env"), "{reports}");
    assert!(reports.contains(".npmrc"), "{reports}");
}
