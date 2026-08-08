//! One file end to end — the only path either surface calls.
//!
//! `cli.rs` and `mcp/` both come through here, so a rule can only be
//! written once. A surface that grows its own copy of one is a bug, and
//! `tests/contracts.rs` asserts the two agree on the same tree.

use std::path::PathBuf;

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
    pub(crate) fn is_unscanned(&self) -> bool {
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
pub(crate) fn scan_file(path: &PathBuf, options: Options) -> Option<FileReport> {
    let file = path.to_string_lossy().into_owned();
    match std::fs::read(path) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(content) => Some(scan_content(&content, file, options)),
            Err(_) => None,
        },
        Err(error) => Some(report(
            file,
            Vec::new(),
            vec![Diagnostic {
                severity: "error".to_string(),
                code: "unreadable".to_string(),
                message: format!("could not be read: {error}"),
            }],
        )),
    }
}

/// The same scan over content already in hand, so the whole path below
/// the file read is testable without one.
pub(crate) fn scan_content(content: &str, file: String, options: Options) -> FileReport {
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
pub(crate) fn exit_code(reports: &[FileReport]) -> u8 {
    if reports.iter().any(FileReport::is_unscanned) {
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
        let report = scan_file(&file, Options::default()).expect("a text file");
        assert_eq!(report.summary.findings, 0);
        assert_eq!(exit_code(&[report]), 0);
    }

    #[test]
    fn a_credential_is_a_finding_and_exits_one() {
        let tree = TempTree::new("scan-finding");
        let file = tree.write("app.env", "DATABASE_PASSWORD=hunter2hunter2\n");
        let report = scan_file(&file, Options::default()).expect("a text file");
        assert_eq!(report.summary.findings, 1);
        assert_eq!(report.summary.high, 1);
        assert_eq!(exit_code(&[report]), 1);
    }

    /// The property, at the layer a surface actually calls.
    #[test]
    fn a_report_never_carries_a_value() {
        let tree = TempTree::new("scan-noleak");
        let value = "hunter2hunter2hunter2";
        let file = tree.write("app.env", &format!("PASSWORD={value}\n"));
        let report = scan_file(&file, Options::default()).expect("a text file");
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
    fn a_binary_file_is_skipped_rather_than_failed() {
        let tree = TempTree::new("scan-binary");
        let file = tree.path().join("logo.png");
        std::fs::write(&file, [0x89, 0x50, 0x4e, 0xff, 0xfe, 0x00]).expect("a file");
        assert!(scan_file(&file, Options::default()).is_none());
    }

    #[test]
    fn an_unreadable_file_is_reported_and_ends_the_run_at_two() {
        let tree = TempTree::new("scan-unreadable");
        let missing = tree.path().join("gone.env");
        let report = scan_file(&missing, Options::default()).expect("a report");
        assert!(report.is_unscanned());
        assert_eq!(report.diagnostics[0].code, "unreadable");
        assert_eq!(exit_code(&[report]), 2);
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
        assert_eq!(exit_code(&[clean, dirty]), 1);
    }

    #[test]
    fn nothing_to_scan_exits_clean() {
        assert_eq!(exit_code(&[]), 0);
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
