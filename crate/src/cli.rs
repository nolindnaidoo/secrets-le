//! The terminal surface.
//!
//! stdout is always protocol — one JSON report per line, one line per
//! file. stderr is always for the human. **Neither ever carries a
//! value**, because both end up in a CI log.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use crate::detect::{Confidence, Options};
use crate::scan::{self, FileReport};
use crate::walk::{self, WalkOptions};

const USAGE: &str = "usage: secrets-le [options] <file|dir>...
       secrets-le [options] --stdin
       secrets-le mcp
       secrets-le --version | --help

Finds hardcoded credentials and reports where they are — never what they
are. One JSON report per line on stdout, human summary on stderr.

Options:
  --sensitivity <level>   low, medium (default) or high. Higher reports
                          fewer, more certain findings.
  --no-api-keys           skip the API-key detectors
  --no-passwords          skip the password detectors
  --no-tokens             skip the token detectors
  --no-private-keys       skip the private-key detectors
  --strict             exit 2 if any file could not be read, rather than
                       reporting it and carrying on
  --stdin                 read one document from stdin
  --hidden                scan hidden files and directories too
  --no-ignore             scan files that .gitignore excludes

No preview is ever the whole value, and there is no flag that changes
that: a flag which turned it off would end up in someone's CI config.

Files that are not text, or that cannot be opened, are named on stderr
and carried in the report, and do not by themselves fail the run — every
repository has a PNG in it. --strict turns them back into a failure, and
a detector that gives up part way always does.

Exit codes: 0 nothing found · 1 findings · 2 malformed question.
For a run over many files, the exit code is the worst outcome in it.";

/// Every flag the parser accepts. Held equal to the flags named in USAGE
/// by a test, and consulted at runtime so the list is what the parser
/// actually honours.
const FLAGS: [&str; 9] = [
    "--strict",
    "--sensitivity",
    "--no-api-keys",
    "--no-passwords",
    "--no-tokens",
    "--no-private-keys",
    "--stdin",
    "--hidden",
    "--no-ignore",
];

#[derive(Debug)]
struct Parsed {
    /// Fail the run if any file could not be read.
    strict: bool,
    inputs: Vec<PathBuf>,
    stdin: bool,
    options: Options,
    walk: WalkOptions,
}

pub(crate) fn run() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if let Some(first) = args.first() {
        match first.as_str() {
            "mcp" => return crate::mcp::serve(),
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--version" | "-V" => {
                println!("secrets-le {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            _ => {}
        }
    }

    match execute(&args) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("secrets-le: {message}");
            ExitCode::from(2)
        }
    }
}

fn execute(args: &[String]) -> Result<u8, String> {
    let parsed = parse(args)?;

    let (reports, walked, scanned) = if parsed.stdin {
        let mut content = String::new();
        std::io::stdin()
            .read_to_string(&mut content)
            .map_err(|error| format!("could not read stdin: {error}"))?;
        (
            vec![scan::scan_content(
                &content,
                "<stdin>".to_string(),
                parsed.options,
            )],
            walk::Walked::default(),
            1,
        )
    } else {
        let walked = walk::collect(&parsed.inputs, &parsed.walk)?;
        let total = walked.files.len();
        let reports: Vec<FileReport> = walked
            .files
            .iter()
            .map(|file| scan::scan_file(file, parsed.options))
            .collect();
        (reports, walked, total)
    };

    let mut stdout = std::io::stdout().lock();
    for report in &reports {
        let line = serde_json::to_string(report).expect("a report serializes");
        writeln!(stdout, "{line}")
            .map_err(|error| format!("could not write the report: {error}"))?;
    }
    drop(stdout);

    summarise(&reports, &walked, scanned);
    Ok(scan::exit_code(&reports, parsed.strict))
}

fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut parsed = Parsed {
        inputs: Vec::new(),
        stdin: false,
        strict: false,
        options: Options::default(),
        walk: WalkOptions::default(),
    };

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        // Strict parsing, never a silent default. A typo'd
        // `--no-passwrods` that quietly did nothing would report a clean
        // scan that never ran the detector it was asked to skip — or,
        // worse, one it was asked to keep.
        if arg.starts_with('-') && !FLAGS.contains(&arg.as_str()) {
            return Err(format!("{arg} is not an option. Try --help."));
        }

        match arg.as_str() {
            "--stdin" => parsed.stdin = true,
            "--strict" => parsed.strict = true,
            "--hidden" => parsed.walk.hidden = true,
            "--no-ignore" => parsed.walk.respect_ignore = false,
            "--no-api-keys" => parsed.options.api_keys = false,
            "--no-passwords" => parsed.options.passwords = false,
            "--no-tokens" => parsed.options.tokens = false,
            "--no-private-keys" => parsed.options.private_keys = false,
            "--sensitivity" => {
                let value = rest
                    .next()
                    .ok_or_else(|| "--sensitivity needs a level".to_string())?;
                parsed.options.sensitivity = match value.as_str() {
                    "low" => Confidence::Low,
                    "medium" => Confidence::Medium,
                    "high" => Confidence::High,
                    other => {
                        return Err(format!(
                            "{other} is not a sensitivity; one of: low, medium, high"
                        ));
                    }
                };
            }
            path => parsed.inputs.push(PathBuf::from(path)),
        }
    }

    if parsed.stdin && !parsed.inputs.is_empty() {
        return Err("reading from stdin takes no file arguments".to_string());
    }
    if !parsed.stdin && parsed.inputs.is_empty() {
        return Err("name a file or a directory to scan. Try --help.".to_string());
    }
    Ok(parsed)
}

/// The human half. Every line restates something already in the JSON.
fn summarise(reports: &[FileReport], walked: &walk::Walked, scanned: usize) {
    let mut stderr = std::io::stderr().lock();
    let mut findings = 0;

    for report in reports {
        for diagnostic in &report.diagnostics {
            let _ = writeln!(stderr, "{}: {}", report.file, diagnostic.message);
        }
        for finding in &report.findings {
            findings += 1;
            let _ = writeln!(stderr, "{}", scan::describe(report, finding));
        }
    }

    // Named before the tally, because it is the line that changes what
    // someone does next. The bare count sits at the end, where a number
    // in the tens of thousands cannot be mistaken for a list of
    // problems.
    for path in &walked.skipped_of_note {
        let _ = writeln!(
            stderr,
            "not scanned: {} — excluded by .gitignore or the hidden rule, and its name says it \
             holds credentials. --no-ignore --hidden reaches it.",
            path.display()
        );
    }

    let _ = writeln!(
        stderr,
        "{} in {}{}",
        plural(findings, "finding", "findings"),
        plural(scanned, "file", "files"),
        // "Nothing found" and "nothing found in what I was allowed to
        // look at" are different claims, and only the second one is
        // true by default.
        if walked.skipped == 0 {
            String::new()
        } else {
            format!(
                " — {} others excluded by .gitignore or the hidden rule, mostly dependencies",
                walked.skipped - walked.skipped_of_note.len()
            )
        }
    );
}

fn plural(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_documented_flag_is_parsed_and_the_reverse() {
        let mut documented: Vec<&str> = USAGE
            .split_whitespace()
            .filter(|word| word.starts_with("--"))
            .map(|word| word.trim_end_matches([',', '.', ':', ';']))
            .filter(|word| !matches!(*word, "--version" | "--help"))
            .collect();
        documented.sort_unstable();
        documented.dedup();

        let mut implemented = FLAGS.to_vec();
        implemented.sort_unstable();
        assert_eq!(documented, implemented);
    }

    #[test]
    fn the_parser_accepts_every_flag_it_lists() {
        for flag in FLAGS {
            let args: Vec<String> = match flag {
                "--sensitivity" => {
                    vec![flag.to_string(), "high".to_string(), "x".to_string()]
                }
                "--stdin" => vec![flag.to_string()],
                _ => vec![flag.to_string(), "x".to_string()],
            };
            assert!(parse(&args).is_ok(), "{flag}");
        }
    }

    #[test]
    fn an_unknown_flag_is_refused_rather_than_ignored() {
        let error = parse(&["--no-passwrods".to_string(), "x".to_string()]).expect_err("a refusal");
        assert!(error.contains("--no-passwrods"), "{error}");
    }

    /// There must be no way to ask for the values. If this test ever
    /// needs changing, something has gone badly wrong.
    #[test]
    fn no_flag_reveals_a_value() {
        for attempt in [
            "--show-values",
            "--unsafe",
            "--raw",
            "--no-mask",
            "--values",
        ] {
            assert!(
                parse(&[attempt.to_string(), "x".to_string()]).is_err(),
                "{attempt} was accepted"
            );
        }
        assert!(!USAGE.contains("show"), "the usage text offers one");
    }

    #[test]
    fn an_unknown_sensitivity_is_refused_by_name() {
        let error = parse(&[
            "--sensitivity".to_string(),
            "paranoid".to_string(),
            "x".to_string(),
        ])
        .expect_err("a refusal");
        assert!(error.contains("paranoid"), "{error}");
    }

    #[test]
    fn sensitivity_defaults_to_medium() {
        let parsed = parse(&["x".to_string()]).expect("parses");
        assert_eq!(parsed.options.sensitivity, Confidence::Medium);
    }

    #[test]
    fn each_detector_family_can_be_switched_off() {
        let parsed = parse(&[
            "--no-api-keys".to_string(),
            "--no-passwords".to_string(),
            "--no-tokens".to_string(),
            "--no-private-keys".to_string(),
            "x".to_string(),
        ])
        .expect("parses");
        assert!(!parsed.options.api_keys);
        assert!(!parsed.options.passwords);
        assert!(!parsed.options.tokens);
        assert!(!parsed.options.private_keys);
    }

    #[test]
    fn naming_nothing_is_refused() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn stdin_and_file_arguments_together_are_refused() {
        assert!(parse(&["--stdin".to_string(), "x".to_string()]).is_err());
    }

    #[test]
    fn the_usage_text_names_the_exit_codes_it_returns() {
        for code in ["0", "1", "2"] {
            assert!(USAGE.contains(code), "exit code {code} is undocumented");
        }
    }
}
