//! The pure detection layer: text in, masked findings out.
//!
//! **Nothing in here touches the filesystem**, which is what makes the
//! whole decision layer — including the masking the tool's safety rests
//! on — testable from a fixture file with no disk and no flake. A
//! `std::fs` call below this line is a bug, and CI greps for one.
//!
//! A `Finding` carries no secret. The raw value exists only inside
//! `detect`, long enough to be measured and masked, and is never a field
//! on anything this module returns. That is deliberate: a surface
//! cannot leak what it was never handed.

pub(crate) mod mask;
pub(crate) mod patterns;

mod heuristics;
mod position;

#[cfg(test)]
pub(crate) mod corpus;

pub(crate) use patterns::Confidence;
pub(crate) use position::Position;

use serde::Serialize;

use position::PositionIndex;

/// What the caller wants looked for. Mirrors the extension's options.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Options {
    pub(crate) api_keys: bool,
    pub(crate) passwords: bool,
    pub(crate) tokens: bool,
    pub(crate) private_keys: bool,
    pub(crate) sensitivity: Confidence,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            api_keys: true,
            passwords: true,
            tokens: true,
            private_keys: true,
            // The extension's default. `medium` drops low-confidence
            // findings; `low` keeps everything; `high` keeps only high.
            sensitivity: Confidence::Medium,
        }
    }
}

/// One finding, already masked.
///
/// There is no `value` field, and adding one would be the single change
/// that could turn this tool into a disclosure. The type, confidence,
/// key name and position are enough to locate the credential in a file
/// the caller already has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Finding {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) confidence: Confidence,
    pub(crate) key: Option<String>,
    /// A bounded preview — never the whole value. See `mask`.
    pub(crate) preview: String,
    /// The source line, with every occurrence of the value masked out.
    pub(crate) context: Option<String>,
    #[serde(flatten)]
    pub(crate) position: Position,
    pub(crate) description: String,
}

/// Which `--no-…` switch each type answers to.
///
/// Every type the table can produce must be in exactly one of these
/// four: `included` returns true for anything it does not recognise, so
/// a type left out is one no switch can turn off — a `--no-api-keys`
/// run that still reports API keys. A test below walks the table and
/// asserts the coverage rather than trusting this list.
/// A connection string and a database URL are reported *because* they
/// carry a credential in the URI, so `--no-passwords` is the switch a
/// user reaches for when they do not want them. Both answered to none
/// of the four before, which meant no flag could turn them off — and
/// `cookie` and `session-id` were in the same position, now under
/// tokens, since a session credential is a bearer credential.
const PASSWORD_TYPES: [&str; 3] = ["password", "connection-string", "database-url"];

const API_KEY_TYPES: [&str; 11] = [
    "api-key",
    "aws-key",
    "aws-secret",
    "gcp-key",
    "azure-key",
    "azure-sas",
    "anthropic-key",
    "mailgun-key",
    "openai-key",
    "sendgrid-key",
    "supabase-key",
];
const TOKEN_TYPES: [&str; 17] = [
    "token",
    "jwt",
    "oauth-token",
    "bearer-token",
    "access-token",
    "refresh-token",
    "docker-token",
    "gitlab-token",
    "npm-token",
    "pypi-token",
    "sentry-token",
    "shopify-token",
    "square-token",
    "terraform-token",
    "vault-token",
    "cookie",
    "session-id",
];
const PRIVATE_KEY_TYPES: [&str; 3] = ["private-key", "ssh-key", "pgp-key"];

/// PEM blocks carry their kind in the header; refine the reported type.
fn classify_pem_block(block: &str) -> &'static str {
    if block.contains("OPENSSH") {
        return "ssh-key";
    }
    if block.contains("PGP") {
        return "pgp-key";
    }
    "private-key"
}

fn included(kind: &str, options: Options) -> bool {
    if API_KEY_TYPES.contains(&kind) {
        return options.api_keys;
    }
    if PASSWORD_TYPES.contains(&kind) {
        return options.passwords;
    }
    if TOKEN_TYPES.contains(&kind) {
        return options.tokens;
    }
    if PRIVATE_KEY_TYPES.contains(&kind) {
        return options.private_keys;
    }
    true
}

fn meets_sensitivity(confidence: Confidence, sensitivity: Confidence) -> bool {
    match sensitivity {
        Confidence::High => confidence == Confidence::High,
        Confidence::Medium => confidence != Confidence::Low,
        Confidence::Low => true,
    }
}

/// Scan content for credentials.
///
/// `Err` is a refusal, not a finding: a pattern that exhausted its
/// backtracking budget on a pathological document. Reporting a clean
/// result in that case would be the tool lying about coverage.
pub(crate) fn detect(content: &str, options: Options) -> Result<Vec<Finding>, String> {
    Ok(detect_with_values(content, options)?
        .into_iter()
        .map(|(finding, _)| finding)
        .collect())
}

/// The same scan, paired with the raw values, for the one caller that
/// legitimately needs them: the test asserting that **none** of them
/// reaches the output.
///
/// The property cannot be checked from outside this module, because the
/// public result deliberately has nowhere to put a value — so the check
/// gets a door that `#[cfg(test)]` closes in every shipped build.
#[cfg(test)]
pub(crate) fn detect_values(content: &str, options: Options) -> Result<Vec<String>, String> {
    Ok(detect_with_values(content, options)?
        .into_iter()
        .map(|(_, value)| value)
        .collect())
}

fn detect_with_values(content: &str, options: Options) -> Result<Vec<(Finding, String)>, String> {
    let index = PositionIndex::new(content);
    let mut findings: Vec<(usize, Finding, String)> = Vec::new();
    let mut seen: Vec<(usize, String)> = Vec::new();

    for pattern in patterns::PATTERNS.iter() {
        // A private-key pattern is classified per match from its PEM
        // header, so the family filter runs after the match rather than
        // before it.
        let fixed_kind = (pattern.value_group != 0 || pattern.kind != "private-key")
            .then(|| pattern.kind.clone());
        if let Some(kind) = &fixed_kind
            && !included(kind, options)
        {
            continue;
        }

        // Ask the cheap question first. This never changes an answer —
        // the relaxed pattern matches a superset — it only avoids
        // running a backtracking scan over a file that cannot contain
        // what it is looking for, which is nearly every file.
        if let Some(prefilter) = &pattern.prefilter
            && !prefilter.is_match(content)
        {
            continue;
        }

        for captures in pattern.regex.captures_iter(content) {
            let captures = captures
                .map_err(|error| format!("the {} pattern gave up: {error}", pattern.kind))?;
            let Some(matched) = captures.get(pattern.value_group) else {
                continue;
            };
            let value = matched.as_str();
            if value.is_empty() || heuristics::looks_like_placeholder(value) {
                continue;
            }

            let kind = match &fixed_kind {
                Some(kind) => kind.clone(),
                None => classify_pem_block(value).to_string(),
            };
            if fixed_kind.is_none() && !included(&kind, options) {
                continue;
            }

            let confidence = pattern.confidence(value);
            if !meets_sensitivity(confidence, options.sensitivity) {
                continue;
            }

            let start = matched.start();
            let dedupe_key = (start, value.to_string());
            if seen.contains(&dedupe_key) {
                continue;
            }
            seen.push(dedupe_key);

            // Kept verbatim for now: the key is a slice of the document
            // and can carry a credential of its own, so it is masked in
            // the same pass as the context, once every value is known.
            let key = pattern
                .key_group
                .and_then(|group| captures.get(group))
                .map(|found| found.as_str().to_string());

            findings.push((
                start,
                Finding {
                    kind,
                    confidence,
                    key,
                    preview: mask::mask_secret_value(value),
                    // Filled in below, once every value in the document
                    // is known: a context line holds whatever else sits
                    // beside the finding, and masking only this
                    // finding's own value left those in the clear.
                    context: None,
                    position: index.at(start),
                    description: pattern.description.clone(),
                },
                value.to_string(),
            ));
        }
    }

    // Report in document order regardless of which pattern found what.
    // `sort_by_key` is stable, as JavaScript's sort has been since
    // ES2019, so two findings at one offset keep table order.
    findings.sort_by_key(|(start, _, _)| *start);

    let order = mask::masking_order(
        &findings
            .iter()
            .map(|(_, _, value)| value.clone())
            .collect::<Vec<_>>(),
    );
    for (start, finding, value) in &mut findings {
        let (line, offset) = position::line_and_offset(content, *start);
        finding.context = Some(mask::mask_context(line, offset, value.len(), value, &order));
        // Masked before it is lowercased: the key is source text, so an
        // embedded value appears in it with the case it was written in.
        finding.key = finding
            .key
            .as_ref()
            .map(|key| mask::mask_all(key, &order).to_lowercase());
    }

    Ok(findings
        .into_iter()
        .map(|(_, finding, value)| (finding, value))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_ok(content: &str) -> Vec<Finding> {
        detect(content, Options::default()).expect("the patterns hold")
    }

    #[test]
    fn a_clean_document_yields_nothing() {
        assert!(detect_ok("const total = 1 + 2;\n").is_empty());
        assert!(detect_ok("").is_empty());
    }

    #[test]
    fn a_password_assignment_is_found_with_its_key() {
        let findings = detect_ok("DATABASE_PASSWORD=hunter2hunter2\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "password");
        assert_eq!(findings[0].key.as_deref(), Some("database_password"));
        assert_eq!(findings[0].position.line, 1);
    }

    /// The whole point of the crate, asserted at the layer that builds
    /// the finding rather than only at the masking helpers.
    #[test]
    fn no_finding_carries_its_value() {
        let value = "hunter2hunter2hunter2";
        let findings = detect_ok(&format!("PASSWORD={value}\n"));
        let rendered = serde_json::to_string(&findings).expect("serializes");
        assert!(!rendered.contains(value), "{rendered}");
    }

    #[test]
    fn placeholders_are_not_reported() {
        assert!(detect_ok("PASSWORD=${DB_PASSWORD}\n").is_empty());
        assert!(detect_ok("api_key = xxxxxxxxxxxxxxxxxxxxxxxx\n").is_empty());
    }

    /// The trailing lookahead on `aws-secret` used to exclude a quote,
    /// so the pattern allowed an opening `"` and then refused the
    /// closing one — a quoted 40-character key, which is how it is
    /// written in code, could never match. Only the unquoted form was in
    /// the corpus, which is why it went unnoticed.
    #[test]
    fn a_quoted_aws_secret_is_found_the_same_as_an_unquoted_one() {
        const VALUE: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        for line in [
            format!("aws_secret_access_key = {VALUE}"),
            format!("aws_secret_access_key = \"{VALUE}\""),
            format!("aws_secret_access_key = '{VALUE}'"),
            format!("\"aws_secret_access_key\": \"{VALUE}\","),
        ] {
            let found = detect_ok(&line);
            assert_eq!(
                found.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>(),
                ["aws-secret"],
                "{line}"
            );
        }
    }

    /// The lookahead still has a job: 40 characters must be the whole
    /// value, not the first 40 of a longer one.
    #[test]
    fn a_longer_value_is_not_truncated_to_forty_characters() {
        let long = "a".repeat(45);
        assert!(detect_ok(&format!("aws_secret_access_key = \"{long}\"")).is_empty());
    }

    #[test]
    fn sensitivity_filters_on_confidence() {
        // A cookie is a low-confidence detector.
        let content = "cookie=abcdefghijklmnopqrstuvwxyz\n";
        let strict = detect(
            content,
            Options {
                sensitivity: Confidence::High,
                ..Options::default()
            },
        )
        .expect("holds");
        let loose = detect(
            content,
            Options {
                sensitivity: Confidence::Low,
                ..Options::default()
            },
        )
        .expect("holds");
        assert!(strict.is_empty());
        assert!(!loose.is_empty());
    }

    /// Every type the table can produce must answer to exactly one
    /// switch.
    ///
    /// `included` returns true for a kind it does not recognise, so a
    /// type missing from the three family lists is a type no `--no-…`
    /// flag can turn off — a `--no-api-keys` run that still reports API
    /// keys, silently. This walks the *table* rather than the lists, so
    /// it fails for the next pattern somebody adds without classifying
    /// it, which is the only version of this check worth having.
    #[test]
    fn every_type_the_table_can_produce_answers_to_exactly_one_switch() {
        let mut kinds: Vec<String> = patterns::PATTERNS
            .iter()
            .map(|pattern| pattern.kind.clone())
            .collect();
        // Named by no pattern: classified from the PEM header instead.
        kinds.push("ssh-key".to_string());
        kinds.push("pgp-key".to_string());
        kinds.sort();
        kinds.dedup();

        for kind in kinds {
            let switches = [
                Options {
                    api_keys: false,
                    ..Options::default()
                },
                Options {
                    passwords: false,
                    ..Options::default()
                },
                Options {
                    tokens: false,
                    ..Options::default()
                },
                Options {
                    private_keys: false,
                    ..Options::default()
                },
            ];
            let excluded = switches
                .into_iter()
                .filter(|options| !included(&kind, *options))
                .count();
            assert_eq!(
                excluded, 1,
                "{kind} is excluded by {excluded} of the four switches, not one"
            );
        }
    }

    /// An issuer-prefixed value and the key name beside it claim the
    /// same span, and the first pattern in the table wins the dedupe.
    /// The issuer is the more specific answer, so it is the one reported.
    #[test]
    fn an_issuer_prefixed_value_is_reported_by_its_issuer_not_by_its_key_name() {
        for (line, expected) in [
            (
                "NPM_TOKEN=npm_EXAMPLEnotarealnpmtoken00000000000000000\n",
                "npm-token",
            ),
            (
                "ANTHROPIC_API_KEY=sk-ant-api03-EXAMPLEnotarealanthropickey00000\n",
                "anthropic-key",
            ),
            (
                "\"gitlab_token\": \"glpat-EXAMPLEnotarealgitlab00\",\n",
                "gitlab-token",
            ),
        ] {
            let findings = detect_ok(line);
            assert_eq!(
                findings.iter().map(|f| f.kind.as_str()).collect::<Vec<_>>(),
                [expected],
                "{line}"
            );
        }
    }

    /// Why the order is what it is, stated as a test rather than as a
    /// comment.
    ///
    /// This value is 31 characters, one short of the generic api-key
    /// rule's `high` threshold. Graded by that rule it is `medium`, and
    /// `--sensitivity high` — the setting a pipeline picks when it wants
    /// only the certain findings — drops it. Graded by its own shape it
    /// is high, and survives. Behind the key patterns instead of in
    /// front of them, this is a live `OpenAI` key going unreported.
    #[test]
    fn a_short_issuer_prefixed_value_survives_a_high_sensitivity_run() {
        const VALUE: &str = "sk-proj-EXAMPLEnotarealopenai00";
        assert_eq!(VALUE.len(), 31, "the point of the case is its length");

        let findings = detect(
            &format!("api_key={VALUE}\n"),
            Options {
                sensitivity: Confidence::High,
                ..Options::default()
            },
        )
        .expect("the patterns hold");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].kind, "openai-key");
        assert_eq!(findings[0].confidence, Confidence::High);
    }

    #[test]
    fn each_family_can_be_switched_off() {
        let content = "PASSWORD=hunter2hunter2\napi_key=abcdefghijklmnopqrstuvwx\n";
        let without_passwords = detect(
            content,
            Options {
                passwords: false,
                ..Options::default()
            },
        )
        .expect("holds");
        assert!(without_passwords.iter().all(|f| f.kind != "password"));
        assert!(without_passwords.iter().any(|f| f.kind == "api-key"));
    }

    #[test]
    fn a_pem_block_is_classified_from_its_header() {
        assert_eq!(
            classify_pem_block("-----BEGIN OPENSSH PRIVATE KEY-----"),
            "ssh-key"
        );
        assert_eq!(
            classify_pem_block("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
            "pgp-key"
        );
        assert_eq!(
            classify_pem_block("-----BEGIN RSA PRIVATE KEY-----"),
            "private-key"
        );
    }

    #[test]
    fn findings_come_back_in_document_order() {
        let content = "line one\napi_key=abcdefghijklmnopqrstuvwx\nPASSWORD=hunter2hunter2\n";
        let findings = detect_ok(content);
        assert!(
            findings
                .windows(2)
                .all(|w| w[0].position.line <= w[1].position.line)
        );
    }

    #[test]
    fn the_context_line_is_masked_not_raw() {
        let findings = detect_ok("DATABASE_PASSWORD=hunter2hunter2\n");
        let context = findings[0].context.as_deref().expect("a context line");
        assert!(context.starts_with("DATABASE_PASSWORD="), "{context}");
        assert!(!context.contains("hunter2hunter2"), "{context}");
    }
}
