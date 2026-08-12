//! A standing net over the detector table.
//!
//! Nineteen patterns from `signatures/patterns.toml`, compiled by
//! `fancy-regex` with a raised backtracking budget, run over documents
//! nobody wrote. The corpus pins the cases somebody thought of; this
//! looks for the one nobody did.
//!
//! Documents go in through `--stdin`, which is the shortest path to the
//! pure layer: no walk, no filesystem, one document straight into
//! `detect`. Every input is valid UTF-8 by construction — a few
//! deliberately are not, and those must be *refused*, not survived by
//! accident.
//!
//! What counts as a failure:
//!
//! - **A panic or a signal.** A SIGABRT slicing a multi-byte character
//!   is how this class of bug shows up in this family.
//! - **A hang.** Enforced, not hoped for.
//! - **Any exit code other than 0, 1 or 2.**
//! - **`incomplete`.** The backtracking budget is meant to survive
//!   anything under 64 KB, which is all this generates. A refusal here
//!   is a document shape the budget does not cover, and the report names
//!   it. (The crafted million-character word run that legitimately
//!   exhausts it lives in `hazards.rs`, where the refusal is the
//!   assertion.)
//! - **A value the run *detected*, appearing anywhere in the output.**
//!   This is the one that matters. A secret scanner that prints what it
//!   found has leaked it to a CI log, which is archived, often
//!   world-readable, and outlives the credential — and a fuzzer is
//!   exactly what finds the one document shape that slips past the
//!   masking. A finding is recognised here by its preview, which is a
//!   deterministic function of the value.
//!
//!   Text the run did **not** detect is a different thing, and the line
//!   between them is drawn in SPEC.md under "What a context line can
//!   still contain": a context is a bounded excerpt of the source line,
//!   every detected value is masked out of it, and this tool cannot mask
//!   what it never recognised. So the size of that excerpt is pinned
//!   here too — it is the whole exposure surface.
//!
//! Not run to convergence: 60 seconds in CI, a fixed handful of
//! iterations locally so `cargo test` stays quick. The point is a net,
//! not a proof.
//!
//! Every credential below is invented for this file.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const BINARY: &str = env!("CARGO_BIN_EXE_secrets-le");
const CORPUS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/documents");

/// Locally: enough to be worth running on every `cargo test`, quick
/// enough that nobody stops running it. CI raises it with
/// `SECRETS_LE_FUZZ_SECONDS`.
const DEFAULT_ITERATIONS: usize = 50;

const PATIENCE: Duration = Duration::from_secs(30);

/// The exposure surface, bounded.
///
/// `detect/mask.rs` keeps 60 code units of source either side of the
/// value and puts the value's preview between them, so a context is two
/// margins, one preview and at most two ellipses.
///
/// Masking **grows** a margin rather than shrinking it: the shortest
/// value any pattern in the table will report is eight characters (the
/// password detector's floor) and its preview is fifteen, so 60 units of
/// source can become at most 120. Two of those, plus a preview of at
/// most 26 for a value of any length this can generate, plus the two
/// ellipses, is 266. Rounded up, with the arithmetic written down so
/// the next person can check it rather than trust it.
///
/// The number is not the point — the bound is. Before the window
/// existed, a context was the *whole* source line, which on a minified
/// file is the whole file.
const MAX_CONTEXT_UNITS: usize = 300;

/// `mask_secret_value`, as a caller outside the crate can compute it: at
/// most eight characters, at most half the value, and the length. Used
/// to recognise that a run reported a particular value without ever
/// being handed the value back.
fn preview_of(value: &str) -> String {
    let length = value.encode_utf16().count();
    if length < 3 {
        return format!("({length} chars)");
    }
    let shown = 8.min(length / 2);
    format!("{}… ({length} chars)", &value[..shown])
}

/// Long enough that no eight-character preview can contain one, so
/// "this value appears in the output" means a leak and never a preview.
const PLANTED: [&str; 6] = [
    "hunter2hunter2hunter2",
    "aB3xY7zQ9mK2pL5vN8wR4tS6",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
    "postgres://user:pass@db.example.invalid:5432/app",
];

const KEYS: [&str; 12] = [
    "password",
    "DATABASE_PASSWORD",
    "pwd",
    "api_key",
    "aws_secret_access_key",
    "access_token",
    "refresh_token",
    "jwt",
    "token",
    "session_id",
    "cookie",
    "connection_string",
];

/// Characters that have broken a scanner somewhere: quotes, separators,
/// a byte-order mark, an astral character, a lone carriage return.
const AWKWARD: [&str; 14] = [
    "'",
    "\"",
    "=",
    ":",
    " ",
    "\t",
    "\r",
    "\n",
    "\u{feff}",
    "\u{1f3af}",
    "\u{e9}",
    ";",
    "-",
    "_",
];

/// Mulberry32 — deterministic, seeded, three lines, no dependency.
struct Seeded(u32);

impl Seeded {
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_add(0x6d2b_79f5);
        let mut t = self.0;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 0x3d));
        t ^ (t >> 14)
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() as usize) % limit.max(1)
    }

    fn pick<'a, T>(&mut self, from: &'a [T]) -> &'a T {
        &from[self.below(from.len())]
    }
}

fn seeds() -> Vec<String> {
    let mut documents: Vec<String> = std::fs::read_dir(CORPUS)
        .expect("the corpus is readable")
        .filter_map(Result::ok)
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .collect();
    assert!(!documents.is_empty(), "the corpus seeded nothing");
    // Shapes the corpus does not carry, so the first mutations have
    // something hostile to work from.
    documents.push(String::new());
    documents.push("\u{feff}".to_string());
    documents.push("password=".to_string());
    documents.push("-----BEGIN RSA PRIVATE KEY-----".to_string());
    documents.push("\u{1f3af}".repeat(64));
    documents.push("a".repeat(4_096));
    documents
}

/// One generated document, and the planted values it actually contains.
struct Case {
    content: String,
    present: Vec<&'static str>,
}

/// Mutate a seed into something the corpus does not contain, keeping the
/// result valid UTF-8 — the invalid-input path is asserted separately,
/// because it must be a refusal rather than a survival.
fn mutate(random: &mut Seeded, seeds: &[String]) -> Case {
    let mut content: Vec<char> = random.pick(seeds).chars().collect();

    for _ in 0..=random.below(6) {
        match random.below(8) {
            // Splice in a key/value pair the table should claim.
            0 => {
                let key = *random.pick(&KEYS);
                let value = *random.pick(&PLANTED);
                let at = random.below(content.len() + 1);
                let insert: Vec<char> = format!("{key}={value}").chars().collect();
                content.splice(at..at, insert);
            }
            // Splice in a bare value with no key at all.
            1 => {
                let value = *random.pick(&PLANTED);
                let at = random.below(content.len() + 1);
                content.splice(at..at, value.chars().collect::<Vec<_>>());
            }
            // A character that has broken a scanner somewhere.
            2 => {
                let at = random.below(content.len() + 1);
                let insert: Vec<char> = random.pick(&AWKWARD).chars().collect();
                content.splice(at..at, insert);
            }
            // A run of word characters, which is what the thirteen
            // `[A-Za-z0-9_-]*` patterns backtrack over.
            3 => {
                let run = 1 + random.below(2_000);
                let at = random.below(content.len() + 1);
                let insert: Vec<char> = std::iter::repeat_n('x', run).collect();
                content.splice(at..at, insert);
            }
            // Cut a piece out, which is how a value ends up truncated
            // mid-character.
            4 if !content.is_empty() => {
                let at = random.below(content.len());
                let to = (at + 1 + random.below(64)).min(content.len());
                content.drain(at..to);
            }
            // Duplicate what is there.
            5 if content.len() < 16_000 => {
                let copy = content.clone();
                content.extend(copy);
            }
            // Strip the newlines, turning the document into one long line.
            6 => content.retain(|character| *character != '\n'),
            // Two credentials on one line — the shape that carried a
            // real leak through a context line.
            _ => {
                let one = *random.pick(&PLANTED);
                let two = *random.pick(&PLANTED);
                let at = random.below(content.len() + 1);
                let insert: Vec<char> = format!("password={one} api_key={two}\n").chars().collect();
                content.splice(at..at, insert);
            }
        }
    }

    // Bounded on purpose: the budget is meant to cover anything this
    // size, so a refusal within it is a bug rather than a crafted file.
    content.truncate(64_000);
    let content: String = content.into_iter().collect();
    let present = PLANTED
        .iter()
        .copied()
        .filter(|value| content.contains(value))
        .collect();
    Case { content, present }
}

struct Answer {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn ask(document: &[u8]) -> Answer {
    let mut child = Command::new(BINARY)
        .args(["--stdin", "--sensitivity", "low"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the binary runs");
    let pid = child.id();
    // Never asserted on: a child that refuses before reading closes the
    // pipe under the write, and that race is this process's problem
    // rather than part of the answer.
    let _ = child.stdin.as_mut().expect("stdin").write_all(document);
    drop(child.stdin.take());

    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    match receiver.recv_timeout(PATIENCE) {
        Ok(Ok(output)) => Answer {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Ok(Err(error)) => panic!("the binary could not be run: {error}"),
        Err(_) => {
            terminate(pid);
            panic!("a document took longer than {PATIENCE:?} — treat this as a hang");
        }
    }
}

fn terminate(pid: u32) {
    #[cfg(unix)]
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    #[cfg(windows)]
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status();
}

/// Enough of the document to act on, written to a file when it is too
/// long to read in a log. A failing fuzz case nobody can reproduce is a
/// failing build somebody reruns instead of reading.
fn preserve(seed: u32, iteration: usize, content: &str) -> String {
    let path: PathBuf =
        std::env::temp_dir().join(format!("secrets-le-fuzz-{seed}-{iteration}.txt"));
    let written = std::fs::write(&path, content).is_ok();
    let head: String = content.chars().take(300).collect();
    format!(
        "seed {seed}, iteration {iteration}\n  reproduce: SECRETS_LE_FUZZ_SEED={seed}\n  \
         document ({} chars, first 300 shown): {head:?}\n  full document: {}",
        content.chars().count(),
        if written {
            path.display().to_string()
        } else {
            "could not be written".to_string()
        }
    )
}

/// The head of a preview — everything before the ellipsis — is a verbatim
/// slice of the value, so it must equal the document text at the line and
/// column the same finding reports.
fn assert_preview_sits_where_it_says(
    document: &str,
    finding: &serde_json::Value,
    where_from: &dyn Fn() -> String,
) {
    let preview = finding["preview"].as_str().expect("a preview");
    let Some(head) = preview.split('…').next().filter(|head| !head.is_empty()) else {
        return; // a value too short to preview shows only its length
    };
    let line_number = finding["line"].as_u64().expect("a line") as usize;
    let column = finding["column"].as_u64().expect("a column") as usize;

    // The scan drops a leading byte-order mark before it counts, so the
    // check has to read the same document the scan did.
    let scanned = document.strip_prefix('\u{feff}').unwrap_or(document);
    let Some(line) = scanned.split('\n').nth(line_number - 1) else {
        panic!(
            "the finding names line {line_number}, which is past the end\n{}",
            where_from()
        );
    };
    let units: Vec<u16> = line.encode_utf16().collect();
    let at = column - 1;
    let expected: Vec<u16> = head.encode_utf16().collect();
    assert!(
        at + expected.len() <= units.len(),
        "the preview runs past the end of line {line_number}\n{}",
        where_from()
    );
    assert_eq!(
        &units[at..at + expected.len()],
        expected.as_slice(),
        "the preview does not match the document at {line_number}:{column} — the span the \
         finding reports and the span the preview was cut from are not the same span\n{}",
        where_from()
    );
}

#[test]
fn no_generated_document_crashes_hangs_or_leaks() {
    let seed: u32 = std::env::var("SECRETS_LE_FUZZ_SEED")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0x5EC2_E751);
    let budget: Option<Duration> = std::env::var("SECRETS_LE_FUZZ_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .map(Duration::from_secs);

    let corpus = seeds();
    let mut random = Seeded(seed);
    let started = Instant::now();
    let mut iteration = 0;

    loop {
        match budget {
            Some(limit) if started.elapsed() >= limit => break,
            None if iteration >= DEFAULT_ITERATIONS => break,
            _ => {}
        }

        let case = mutate(&mut random, &corpus);
        let answer = ask(case.content.as_bytes());
        let where_from = || preserve(seed, iteration, &case.content);

        let Some(code) = answer.code else {
            panic!(
                "the process died on a signal rather than answering\n{}\n{}",
                where_from(),
                answer.stderr
            );
        };
        assert!(
            (0..=2).contains(&code),
            "exit {code} is not one of 0, 1, 2\n{}\n{}",
            where_from(),
            answer.stderr
        );

        for line in answer.stdout.lines().filter(|line| !line.trim().is_empty()) {
            let report: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|error| {
                panic!("stdout is not JSON Lines: {error}\n{}", where_from())
            });
            assert!(
                !report["diagnostics"]
                    .as_array()
                    .is_some_and(|list| list.iter().any(|d| d["code"] == "incomplete")),
                "a detector gave up on a document under 64 KB, so this run reported no findings \
                 for a file it never finished reading\n{}\n{line}",
                where_from()
            );
            // The exposure surface, pinned. A context is a bounded
            // excerpt of the source line; it used to be the whole line,
            // which on a minified file is the whole file.
            for finding in report["findings"].as_array().into_iter().flatten() {
                let Some(context) = finding["context"].as_str() else {
                    continue;
                };
                let units = context.encode_utf16().count();
                assert!(
                    units <= MAX_CONTEXT_UNITS,
                    "a context line ran to {units} code units, past the {MAX_CONTEXT_UNITS} the \
                     window allows — every character past the window is source nobody asked to \
                     have printed\n{}",
                    where_from()
                );
            }
        }

        // **The preview is cut from the offsets the finding reports.**
        // A sibling aborted its process because a span was taken from a
        // `to_lowercase()` copy and used against the original — lowercasing
        // is not length-preserving, so every span after one slid. Here a
        // slid span would not crash, it would cut the preview from the
        // wrong place, and a preview cut from the wrong place can show
        // bytes the mask was meant to cover. So the two are checked
        // against each other: the visible head of every preview must be
        // exactly what stands at the line and column the finding reports.
        for line in answer.stdout.lines().filter(|line| !line.trim().is_empty()) {
            let report: serde_json::Value =
                serde_json::from_str(line).expect("stdout carries only JSON");
            for finding in report["findings"].as_array().into_iter().flatten() {
                assert_preview_sits_where_it_says(&case.content, finding, &where_from);
            }
        }

        // **The property.** Not "the finding's own value" — every value
        // this run reported, checked against everything it wrote. A
        // finding on one line whose context carries the credential from
        // the finding beside it is the shape that slipped through for a
        // release.
        for value in &case.present {
            if !answer.stdout.contains(&preview_of(value)) {
                // Never reported, so there is nothing the masking was
                // asked to cover. See the module note.
                continue;
            }
            assert!(
                !answer.stdout.contains(value),
                "a reported value reached stdout: {value}\n{}",
                where_from()
            );
            assert!(
                !answer.stderr.contains(value),
                "a reported value reached stderr: {value}\n{}",
                where_from()
            );
        }

        iteration += 1;
    }

    assert!(iteration > 0, "the fuzzer ran no iterations at all");
    eprintln!(
        "fuzz: {iteration} documents, seed {seed}, {:?}",
        started.elapsed()
    );
}

/// stdin is a byte stream and a byte stream is not always text. Every
/// one of these must be refused by name, never survived by accident and
/// never crashed on.
#[test]
fn invalid_input_is_refused_rather_than_survived() {
    for (name, bytes) in [
        ("a lone continuation byte", vec![0x80]),
        ("a truncated three-byte sequence", vec![0xe2, 0x82]),
        ("a truncated four-byte sequence", vec![0xf0, 0x9f, 0x8e]),
        ("an overlong encoding", vec![0xc0, 0xaf]),
        ("a surrogate half", vec![0xed, 0xa0, 0x80]),
        (
            "invalid bytes after a credential",
            [
                b"DATABASE_PASSWORD=hunter2hunter2\n".as_slice(),
                &[0xff, 0xfe],
            ]
            .concat(),
        ),
    ] {
        let answer = ask(&bytes);
        assert_eq!(
            answer.code,
            Some(2),
            "{name}: a document that is not text is a malformed question\n{}",
            answer.stderr
        );
        assert!(
            answer.stdout.is_empty(),
            "{name}: a refusal writes no report"
        );
        assert!(
            !answer.stderr.contains("hunter2hunter2"),
            "{name}: the refusal quoted the document back"
        );
    }
}
