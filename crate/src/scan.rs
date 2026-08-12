//! One file end to end — the only path either surface calls.
//!
//! `cli.rs` and `mcp/` both come through here, so a rule can only be
//! written once. A surface that grows its own copy of one is a bug, and
//! `tests/contracts.rs` asserts the two agree on the same tree.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::detect::{self, Confidence, Finding, Options};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Diagnostic {
    pub(crate) severity: String,
    pub(crate) code: String,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) struct Summary {
    pub(crate) findings: usize,
    pub(crate) high: usize,
    pub(crate) medium: usize,
    pub(crate) low: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct FileReport {
    pub(crate) file: String,
    pub(crate) findings: Vec<Finding>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) summary: Summary,
}

impl FileReport {
    /// Whether this file could not be scanned at all.
    /// Whether this file was not read at all — not text, or not
    /// openable.
    ///
    /// Reported rather than swallowed, because a report that quietly
    /// skipped a file would be claiming coverage it does not have. It
    /// does **not** fail the run on its own: every repository has a PNG
    /// and a zip in it, and exiting 2 on those makes a secret scanner
    /// unusable in CI, which is the one place it is most worth running.
    pub(crate) fn was_skipped(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "skipped")
    }

    /// Whether a detector gave up part way through this file.
    ///
    /// This **does** fail the run, and must: reporting no findings for
    /// a file the scanner did not finish reading is the exact failure
    /// mode a secret scanner cannot have. It is a different thing from
    /// a PNG, and the two are no longer conflated.
    pub(crate) fn is_incomplete(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == "error")
    }
}

fn summarise(findings: &[Finding]) -> Summary {
    let count = |level: Confidence| findings.iter().filter(|f| f.confidence == level).count();
    Summary {
        findings: findings.len(),
        high: count(Confidence::High),
        medium: count(Confidence::Medium),
        low: count(Confidence::Low),
    }
}

fn report(file: String, findings: Vec<Finding>, diagnostics: Vec<Diagnostic>) -> FileReport {
    FileReport {
        file,
        summary: summarise(&findings),
        findings,
        diagnostics,
    }
}

/// Scan one file.
///
/// A file that is not UTF-8 is **not** an error: a repository is full of
/// images and archives, and a scanner that failed on each would be
/// unusable. It is not text, so there is no hardcoded credential in it
/// to find. The walker's skip count is what keeps that visible.
pub(crate) fn scan_file(path: &PathBuf, options: Options) -> FileReport {
    let file = reported_path(path);
    let skipped = |file: String, reason: &str| {
        report(
            file,
            Vec::new(),
            vec![Diagnostic {
                severity: "warning".to_string(),
                code: "skipped".to_string(),
                message: reason.to_string(),
            }],
        )
    };
    match std::fs::read(path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(content) => scan_content(&content, file, options),
            // Named rather than dropped. A file that vanishes from a
            // secret scanner's report is a file the reader believes was
            // clean.
            Err(_) => skipped(file, "not UTF-8 text"),
        },
        Err(error) => skipped(file, &error.to_string()),
    }
}

/// The same scan over content already in hand, so the whole path below
/// the file read is testable without one.
///
/// The byte-order mark is dropped **here** rather than in `scan_file`,
/// because `--stdin` is the same document arriving by a different route:
/// `secrets-le config.env` and `secrets-le --stdin < config.env` were
/// answering with different columns for the same file, which makes the
/// exit code trustworthy and the position not.
pub(crate) fn scan_content(content: &str, file: String, options: Options) -> FileReport {
    let content = without_bom(content);
    match detect::detect(content, options) {
        Ok(findings) => report(file, findings, Vec::new()),
        // A refusal, not a clean result: reporting no findings when a
        // pattern gave up would be the tool lying about coverage, which
        // in a secret scanner is the whole failure mode.
        Err(message) => report(
            file,
            Vec::new(),
            vec![Diagnostic {
                severity: "error".to_string(),
                code: "incomplete".to_string(),
                message,
            }],
        ),
    }
}

/// The exit code for a whole run: 0 clean, 1 findings, 2 could not
/// answer. A run over many files reports the worst outcome in it.
pub(crate) fn exit_code(reports: &[FileReport], strict: bool) -> u8 {
    // A detector that gave up always fails: reporting "no secrets" for
    // a file it never finished is the one thing this must never do.
    if reports.iter().any(FileReport::is_incomplete) {
        return 2;
    }
    if strict && reports.iter().any(FileReport::was_skipped) {
        return 2;
    }
    u8::from(reports.iter().any(|report| report.summary.findings > 0))
}

/// The one-line human projection of a finding. It says exactly what the
/// JSON says — and like the JSON, it carries no value.
pub(crate) fn describe(report: &FileReport, finding: &Finding) -> String {
    let key = finding
        .key
        .as_deref()
        .map(|key| format!(" {key}"))
        .unwrap_or_default();
    format!(
        "{}:{}:{}  {}{key}  {}  [{}]",
        report.file,
        finding.position.line,
        finding.position.column,
        finding.kind,
        finding.preview,
        confidence_name(finding.confidence)
    )
}

pub(crate) fn confidence_name(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "low",
        Confidence::Medium => "medium",
        Confidence::High => "high",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TempTree;

    #[test]
    fn a_clean_file_reports_nothing_and_exits_clear() {
        let tree = TempTree::new("scan-clean");
        let file = tree.write("app.js", "const total = 1 + 2;\n");
        let report = scan_file(&file, Options::default());
        assert_eq!(report.summary.findings, 0);
        assert_eq!(exit_code(&[report], false), 0);
    }

    #[test]
    fn a_credential_is_a_finding_and_exits_one() {
        let tree = TempTree::new("scan-finding");
        let file = tree.write("app.env", "DATABASE_PASSWORD=hunter2hunter2\n");
        let report = scan_file(&file, Options::default());
        assert_eq!(report.summary.findings, 1);
        assert_eq!(report.summary.high, 1);
        assert_eq!(exit_code(&[report], false), 1);
    }

    /// The property, at the layer a surface actually calls.
    #[test]
    fn a_report_never_carries_a_value() {
        let tree = TempTree::new("scan-noleak");
        let value = "hunter2hunter2hunter2";
        let file = tree.write("app.env", &format!("PASSWORD={value}\n"));
        let report = scan_file(&file, Options::default());
        let rendered = serde_json::to_string(&report).expect("serializes");
        assert!(!rendered.contains(value), "{rendered}");
        assert!(
            !describe(&report, &report.findings[0]).contains(value),
            "the human line leaked it"
        );
    }

    /// A repository is full of binaries. Failing on each would make the
    /// tool unusable, and there is no hardcoded credential in a PNG.
    #[test]
    fn a_binary_file_is_named_rather_than_dropped() {
        let tree = TempTree::new("scan-binary");
        let file = tree.path().join("logo.png");
        std::fs::write(&file, [0x89, 0x50, 0x4e, 0xff, 0xfe, 0x00]).expect("a file");
        // It used to vanish from the report entirely, which in a secret
        // scanner reads to whoever runs it as "that file was clean".
        let report = scan_file(&file, Options::default());
        assert!(report.was_skipped());
        assert_eq!(report.diagnostics[0].message, "not UTF-8 text");
        assert_eq!(exit_code(std::slice::from_ref(&report), false), 0);
        assert_eq!(exit_code(&[report], true), 2);
    }

    /// Changed deliberately: a file that could not be opened is
    /// reported and does not fail the run on its own. A detector that
    /// gives up part way still does — see the test below.
    #[test]
    fn an_unreadable_file_is_reported_and_does_not_end_the_run() {
        let tree = TempTree::new("scan-unreadable");
        let missing = tree.path().join("gone.env");
        let report = scan_file(&missing, Options::default());
        assert!(report.was_skipped());
        assert_eq!(report.diagnostics[0].code, "skipped");
        assert_eq!(exit_code(std::slice::from_ref(&report), false), 0);
        assert_eq!(exit_code(&[report], true), 2, "--strict is opt-in");
    }

    /// The distinction that matters most here: a scan that stopped
    /// early is not the same as a file that was never text, and it
    /// still fails without asking.
    #[test]
    fn a_detector_that_gave_up_still_ends_the_run_at_two() {
        let incomplete = report(
            "big.env".to_string(),
            Vec::new(),
            vec![Diagnostic {
                severity: "error".to_string(),
                code: "incomplete".to_string(),
                message: "a detector stopped early".to_string(),
            }],
        );
        assert!(!incomplete.was_skipped());
        assert!(incomplete.is_incomplete());
        assert_eq!(exit_code(&[incomplete], false), 2);
    }

    #[test]
    fn the_summary_counts_by_confidence() {
        let content = "PASSWORD=hunter2hunter2\ncookie=abcdefghijklmnopqrstuvwxyz\n";
        let report = scan_content(
            content,
            "x".to_string(),
            Options {
                sensitivity: Confidence::Low,
                ..Options::default()
            },
        );
        assert_eq!(
            report.summary.findings,
            report.summary.high + report.summary.medium + report.summary.low
        );
        assert!(report.summary.low >= 1, "{:?}", report.summary);
    }

    #[test]
    fn the_worst_outcome_in_a_run_is_the_one_reported() {
        let clean = scan_content("x = 1\n", "clean".to_string(), Options::default());
        let dirty = scan_content(
            "PASSWORD=hunter2hunter2\n",
            "dirty".to_string(),
            Options::default(),
        );
        assert_eq!(exit_code(&[clean, dirty], false), 1);
    }

    #[test]
    fn nothing_to_scan_exits_clean() {
        assert_eq!(exit_code(&[], false), 0);
    }

    #[test]
    fn the_human_line_names_the_finding_without_its_value() {
        let report = scan_content(
            "DATABASE_PASSWORD=hunter2hunter2\n",
            "app.env".to_string(),
            Options::default(),
        );
        let line = describe(&report, &report.findings[0]);
        assert!(line.contains("app.env:1:"), "{line}");
        assert!(line.contains("password"), "{line}");
        assert!(line.contains("[high]"), "{line}");
        assert!(!line.contains("hunter2hunter2"), "{line}");
    }
}

/// A path as every surface spells it: `/` on every platform.
///
/// stdout is protocol, and a secret scanner's output is the thing a
/// reviewer files, diffs and baselines. `config\app.env` on Windows and
/// `config/app.env` everywhere else are two answers to one question, and
/// a baseline taken on one platform is useless on the other. A sibling
/// in this family shipped `\` for a whole release before anyone noticed.
///
/// Rewritten **only where `\` is the separator**. On Unix a backslash is
/// an ordinary character in a filename, and rewriting it there would
/// name a file that was never scanned.
pub(crate) fn reported_path(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    if cfg!(windows) {
        return forward_slashes(&rendered);
    }
    rendered.into_owned()
}

/// The Windows half of `reported_path`, written as a pure string
/// function so that **every** platform compiles and tests it. A branch
/// only Windows can execute is a branch only Windows CI can catch, and
/// this one was wrong in six crates at once.
fn forward_slashes(rendered: &str) -> String {
    // `canonicalize` hands back an extended-length path, so the reports
    // for a scan of an absolute path would otherwise all begin `//?/`.
    // `\\?\UNC\server\share` is `\\server\share` written the long way,
    // so dropping the whole prefix there would lose the host.
    let bare = match rendered.strip_prefix(r"\\?\UNC\") {
        Some(tail) => format!(r"\\{tail}"),
        None => rendered
            .strip_prefix(r"\\?\")
            .unwrap_or(rendered)
            .to_string(),
    };
    bare.replace('\\', "/")
}

/// Drop a leading byte-order mark.
///
/// No editor shows it and VS Code strips it before the extension ever
/// sees a document, so without this the two frontends read the same file
/// differently the moment anything on Windows saves it — Notepad, Excel,
/// a PowerShell redirect. Three invisible bytes shift every column on
/// the first line, and a detector anchored to the start of a value can
/// miss it entirely.
pub(crate) fn without_bom(content: &str) -> &str {
    content.strip_prefix('\u{feff}').unwrap_or(content)
}

#[cfg(test)]
mod hazards {
    use super::*;
    use crate::testing::TempTree;

    #[test]
    fn a_byte_order_mark_is_not_part_of_the_document() {
        assert_eq!(without_bom("\u{feff}abc"), "abc");
        assert_eq!(without_bom("abc"), "abc");
        assert_eq!(without_bom("a\u{feff}b"), "a\u{feff}b");
    }

    /// The regression: the mark was dropped when the document arrived as
    /// a path and kept when the same document arrived as text, so
    /// `secrets-le config.env` and `secrets-le --stdin < config.env`
    /// answered with different columns and different context lines.
    #[test]
    fn a_document_reads_the_same_by_path_and_by_text() {
        let tree = TempTree::new("scan-bom-routes");
        let line = "DATABASE_PASSWORD=hunter2hunter2\n";
        let file = tree.write("app.env", &format!("\u{feff}{line}"));

        let by_path = scan_file(&file, Options::default());
        let by_text = scan_content(
            &format!("\u{feff}{line}"),
            "app.env".to_string(),
            Options::default(),
        );
        assert_eq!(by_path.findings, by_text.findings);

        let without = scan_content(line, "app.env".to_string(), Options::default());
        assert_eq!(
            by_text.findings[0].position, without.findings[0].position,
            "three invisible bytes moved the column"
        );
        assert_eq!(by_text.findings[0].context, without.findings[0].context);
    }

    /// A report is protocol, and a pipeline written against one platform
    /// has to read the report from another.
    #[test]
    fn a_report_path_uses_forward_slashes() {
        let tree = TempTree::new("scan-sep");
        let file = tree.write("config/nested/app.env", "x=1\n");
        let report = scan_file(&file, Options::default());
        assert!(!report.file.contains('\\'), "{}", report.file);
        assert!(
            report.file.ends_with("config/nested/app.env"),
            "{}",
            report.file
        );
    }

    /// The Windows branch, exercised on every platform. Without this the
    /// only machine that ever runs these lines is the one nobody
    /// develops on.
    #[test]
    fn the_windows_spelling_becomes_the_reported_one() {
        assert_eq!(
            forward_slashes(r"config\nested\app.env"),
            "config/nested/app.env"
        );
        assert_eq!(forward_slashes(r"\\?\C:\src\app.env"), "C:/src/app.env");
        assert_eq!(
            forward_slashes(r"\\?\UNC\server\share\app.env"),
            "//server/share/app.env"
        );
        assert_eq!(
            forward_slashes("already/forward.env"),
            "already/forward.env"
        );
    }

    /// The guard on the fix: a backslash is a legal character in a Unix
    /// filename, so rewriting one there would name a file that was never
    /// scanned. Unix-only because Windows cannot create the file.
    #[cfg(unix)]
    #[test]
    fn a_backslash_in_a_unix_filename_survives_the_report() {
        let tree = TempTree::new("scan-backslash");
        let file = tree.write("od\\d.env", "x=1\n");
        assert!(
            scan_file(&file, Options::default())
                .file
                .contains("od\\d.env")
        );
    }
}
