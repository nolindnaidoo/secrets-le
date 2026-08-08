//! The shared corpus, run against this implementation.
//!
//! `../scripts/check-detection-parity.ts` runs the extension over these
//! same files; this module runs the crate over them. Neither side may be
//! the sole author of a case.
//!
//! Embedded rather than read from disk so the tests pass from a packaged
//! crate, where the working directory is not this repository — which is
//! what lets someone who installed the crate verify the never-leak
//! property themselves.

use serde::Deserialize;

use super::{Confidence, Options, detect, mask};

const DETECTION: &str = include_str!("../../fixtures/detection.json");
const MASK: &str = include_str!("../../fixtures/mask.json");

const DOCUMENTS: [(&str, &str); 8] = [
    (
        "secrets.env",
        include_str!("../../fixtures/documents/secrets.env"),
    ),
    (
        "secrets.ini",
        include_str!("../../fixtures/documents/secrets.ini"),
    ),
    (
        "secrets.js",
        include_str!("../../fixtures/documents/secrets.js"),
    ),
    (
        "secrets.json",
        include_str!("../../fixtures/documents/secrets.json"),
    ),
    (
        "secrets.py",
        include_str!("../../fixtures/documents/secrets.py"),
    ),
    (
        "secrets.yaml",
        include_str!("../../fixtures/documents/secrets.yaml"),
    ),
    (
        "multiline-key.pem",
        include_str!("../../fixtures/documents/multiline-key.pem"),
    ),
    (
        "jwt-lookalikes.txt",
        include_str!("../../fixtures/documents/jwt-lookalikes.txt"),
    ),
];

pub(crate) fn document(name: &str) -> &'static str {
    DOCUMENTS
        .iter()
        .find(|(file, _)| *file == name)
        .map_or_else(
            || panic!("the corpus refers to {name}, which is not embedded"),
            |(_, content)| *content,
        )
}

#[derive(Debug, Deserialize)]
struct DetectionCorpus {
    documents: Vec<DocumentCase>,
    toggles: Vec<ToggleCase>,
}

#[derive(Debug, Deserialize)]
struct DocumentCase {
    name: String,
    file: String,
    sensitivity: Confidence,
    expected: Vec<Expected>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Expected {
    #[serde(rename = "type")]
    kind: String,
    confidence: Confidence,
    key: Option<String>,
    preview: String,
    context: Option<String>,
    line: Option<usize>,
    column: Option<usize>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ToggleCase {
    name: String,
    file: String,
    options: ToggleOptions,
    expected: Vec<ToggleExpected>,
}

#[derive(Debug, Deserialize, Default)]
struct ToggleOptions {
    #[serde(rename = "includeApiKeys")]
    api_keys: Option<bool>,
    #[serde(rename = "includePasswords")]
    passwords: Option<bool>,
    #[serde(rename = "includeTokens")]
    tokens: Option<bool>,
    #[serde(rename = "includePrivateKeys")]
    private_keys: Option<bool>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct ToggleExpected {
    #[serde(rename = "type")]
    kind: String,
    confidence: Confidence,
    line: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct MaskCorpus {
    #[serde(rename = "maskSecretValue")]
    mask_secret_value: Vec<MaskValueCase>,
    #[serde(rename = "maskWithin")]
    mask_within: Vec<MaskWithinCase>,
}

#[derive(Debug, Deserialize)]
struct MaskValueCase {
    input: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct MaskWithinCase {
    context: String,
    value: String,
    expected: String,
}

#[test]
fn every_document_case_reproduces() {
    let corpus: DetectionCorpus =
        serde_json::from_str(DETECTION).expect("the corpus is valid JSON");
    assert!(!corpus.documents.is_empty(), "the corpus is empty");

    for case in corpus.documents {
        let findings = detect(
            document(&case.file),
            Options {
                sensitivity: case.sensitivity,
                ..Options::default()
            },
        )
        .expect("the patterns hold");
        let actual: Vec<Expected> = findings
            .iter()
            .map(|finding| Expected {
                kind: finding.kind.clone(),
                confidence: finding.confidence,
                key: finding.key.clone(),
                preview: finding.preview.clone(),
                context: finding.context.clone(),
                line: Some(finding.position.line),
                column: Some(finding.position.column),
                description: Some(finding.description.clone()),
            })
            .collect();
        assert_eq!(actual, case.expected, "{}", case.name);
    }
}

#[test]
fn every_toggle_case_reproduces() {
    let corpus: DetectionCorpus =
        serde_json::from_str(DETECTION).expect("the corpus is valid JSON");

    for case in corpus.toggles {
        let defaults = Options::default();
        let options = Options {
            api_keys: case.options.api_keys.unwrap_or(defaults.api_keys),
            passwords: case.options.passwords.unwrap_or(defaults.passwords),
            tokens: case.options.tokens.unwrap_or(defaults.tokens),
            private_keys: case.options.private_keys.unwrap_or(defaults.private_keys),
            sensitivity: defaults.sensitivity,
        };
        let actual: Vec<ToggleExpected> = detect(document(&case.file), options)
            .expect("the patterns hold")
            .iter()
            .map(|finding| ToggleExpected {
                kind: finding.kind.clone(),
                confidence: finding.confidence,
                line: Some(finding.position.line),
            })
            .collect();
        assert_eq!(actual, case.expected, "{}", case.name);
    }
}

#[test]
fn every_mask_case_reproduces() {
    let corpus: MaskCorpus = serde_json::from_str(MASK).expect("the corpus is valid JSON");

    for case in corpus.mask_secret_value {
        assert_eq!(
            mask::mask_secret_value(&case.input),
            case.expected,
            "maskSecretValue {:?}",
            case.input
        );
    }
    for case in corpus.mask_within {
        assert_eq!(
            mask::mask_within(&case.context, &case.value),
            case.expected,
            "maskWithin {:?}",
            case.context
        );
    }
}

/// Every embedded document must be used by a case, and every case must
/// name an embedded document.
#[test]
fn the_corpus_and_the_embedded_documents_match() {
    let corpus: DetectionCorpus =
        serde_json::from_str(DETECTION).expect("the corpus is valid JSON");
    for (name, _) in DOCUMENTS {
        assert!(
            corpus.documents.iter().any(|case| case.file == name),
            "{name} is embedded but no case uses it"
        );
    }
    for case in &corpus.documents {
        assert!(
            DOCUMENTS.iter().any(|(name, _)| *name == case.file),
            "{} names {}, which is not embedded",
            case.name,
            case.file
        );
    }
}

/// **The property the whole tool rests on**, checked against the real
/// corpus rather than against synthetic values: scan every document at
/// the most permissive setting and assert that no value the detector
/// actually matched survives into anything the crate emits.
///
/// It asserts over the *detected values*, not over every long token in
/// the file. Key names are tokens too, and they are reported on purpose
/// — `connection_string` in the output is the finding being
/// identifiable, not a credential escaping.
///
/// Because it re-derives the values from the documents, it fails when a
/// *new* document introduces one the masking does not fully cover, not
/// only when an expectation changes.
#[test]
fn no_document_leaks_a_detected_value() {
    let permissive = Options {
        sensitivity: Confidence::Low,
        ..Options::default()
    };

    let mut checked = 0;
    for (name, content) in DOCUMENTS {
        let findings = detect(content, permissive).expect("the patterns hold");
        let rendered = serde_json::to_string(&findings).expect("findings serialize");

        for value in super::detect_values(content, permissive).expect("the patterns hold") {
            assert!(
                !rendered.contains(&value),
                "{name}: a detected value survived into the output"
            );
            checked += 1;
        }
    }
    assert!(
        checked > 0,
        "the property proved nothing — no values were detected to check"
    );
}
