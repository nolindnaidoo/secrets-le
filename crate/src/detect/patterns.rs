//! The detection table, loaded from the corpus it shares with the
//! extension.
//!
//! `signatures/patterns.toml` is embedded at build time and is the same
//! file `../scripts/check-detection-parity.ts` holds the extension's
//! `SECRET_PATTERNS` against. Neither side may edit it alone.
//!
//! **Order is load-bearing.** Specific key patterns run before the
//! generic token pattern, and the first pattern to claim a span wins
//! the dedupe. The table is a sequence, not a set.

use std::sync::LazyLock;

use fancy_regex::Regex;
use serde::Deserialize;

use super::heuristics;

const TABLE: &str = include_str!("../../signatures/patterns.toml");

#[derive(Debug, Deserialize)]
struct Table {
    pattern: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    #[serde(rename = "type")]
    kind: String,
    description: String,
    regex: String,
    flags: String,
    key_group: Option<usize>,
    value_group: usize,
    confidence: Rule,
}

/// A confidence *rule*, because the extension holds a lambda and a
/// function cannot be mirrored into data. The parity script evaluates
/// both over probe values and fails when they disagree.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Rule {
    Fixed {
        level: Confidence,
    },
    Length {
        high: usize,
        medium: usize,
    },
    /// A JWT's header is base64 JSON and always begins `eyJ`; anything
    /// else scores lower.
    Jwt {
        matched: Confidence,
        unmatched: Confidence,
    },
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Confidence {
    Low,
    Medium,
    High,
}

pub(crate) struct Pattern {
    pub(crate) kind: String,
    pub(crate) description: String,
    pub(crate) regex: Regex,
    /// A cheap test for "this pattern definitely cannot match here".
    ///
    /// Thirteen of these patterns begin with `[A-Za-z0-9_-]*` before
    /// their keyword, which leaves the backtracking engine nothing to
    /// anchor on: it tries a variable-length run at every offset in the
    /// file. Scanning a repository took fifty times as long as any
    /// sibling tool for that reason alone.
    ///
    /// This is the same pattern with every lookaround removed, compiled
    /// by the DFA engine. Removing a lookaround can only *relax* a
    /// pattern — a positive one drops a requirement, a negative one
    /// drops a prohibition — so whatever the real pattern matches, this
    /// matches too. If this finds nothing, the real one cannot, and it
    /// is skipped. It never changes an answer; it only avoids asking.
    ///
    /// `None` where the relaxed form would not compile, in which case
    /// the real pattern simply runs.
    pub(crate) prefilter: Option<regex::Regex>,
    pub(crate) key_group: Option<usize>,
    pub(crate) value_group: usize,
    rule: Rule,
}

impl Pattern {
    pub(crate) fn confidence(&self, value: &str) -> Confidence {
        match self.rule {
            Rule::Fixed { level } => level,
            Rule::Length { high, medium } => heuristics::confidence_by_length(value, high, medium),
            Rule::Jwt { matched, unmatched } => {
                if heuristics::is_jwt_shaped(value) {
                    matched
                } else {
                    unmatched
                }
            }
        }
    }
}

/// How much backtracking a single match may spend before the engine
/// gives up.
///
/// The default (1,000,000) is exhausted by the `aws-secret` pattern on
/// an ordinary `bun.lock` — 158 KB of base64-ish tokens, which is a file
/// in nearly every repository this will be pointed at. Refusing there
/// meant exiting 2 on seven of seven real repositories, so the tool was
/// unusable rather than cautious. Measured, not guessed: found by
/// running the binary over the fleet.
///
/// The limit is raised rather than removed. A budget that cannot be
/// exhausted is a scanner that can be made to hang by a crafted file,
/// and the refusal it produces is honest — the report says the file was
/// not fully scanned and the run exits 2.
const BACKTRACK_LIMIT: usize = 100_000_000;

pub(crate) static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    let table: Table = toml::from_str(TABLE).expect("the embedded pattern table parses");
    table
        .pattern
        .into_iter()
        .map(|entry| {
            let translated = to_rust_syntax(&entry.regex, &entry.flags);
            Pattern {
                prefilter: relaxed(&translated),
                regex: fancy_regex::RegexBuilder::new(&translated)
                    .backtrack_limit(BACKTRACK_LIMIT)
                    .build()
                    .expect("a pattern from the shared table compiles"),
                kind: entry.kind,
                description: entry.description,
                key_group: entry.key_group,
                value_group: entry.value_group,
                rule: entry.confidence,
            }
        })
        .collect()
});

/// The same pattern with every lookaround group removed.
///
/// Sound as a prefilter because dropping a lookaround only ever widens
/// what a pattern accepts: a positive one is a requirement removed, a
/// negative one a prohibition removed. The result therefore matches a
/// superset, so "the relaxed one found nothing" proves the real one
/// would find nothing too.
fn relaxed(source: &str) -> Option<regex::Regex> {
    let bytes: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut index = 0;

    while index < bytes.len() {
        // An escape carries its next character through untouched, so a
        // literal `\(` is never mistaken for a group.
        if bytes[index] == '\\' && index + 1 < bytes.len() {
            out.push(bytes[index]);
            out.push(bytes[index + 1]);
            index += 2;
            continue;
        }
        if bytes[index] == '(' && is_lookaround(&bytes, index) {
            index = closing_paren(&bytes, index)? + 1;
            continue;
        }
        out.push(bytes[index]);
        index += 1;
    }

    regex::RegexBuilder::new(&out)
        .size_limit(1 << 22)
        .build()
        .ok()
}

fn is_lookaround(chars: &[char], open: usize) -> bool {
    let rest: String = chars[open..].iter().take(4).collect();
    rest.starts_with("(?=")
        || rest.starts_with("(?!")
        || rest.starts_with("(?<=")
        || rest.starts_with("(?<!")
}

/// The index of the `)` closing the group that opens at `open`, tracking
/// nesting, escapes and character classes — inside a class a paren is a
/// literal.
fn closing_paren(chars: &[char], open: usize) -> Option<usize> {
    let mut depth = 0;
    let mut in_class = false;
    let mut index = open;
    while index < chars.len() {
        match chars[index] {
            '\\' => index += 1,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// JavaScript's `\b`: a boundary between an ASCII word character
/// (`[A-Za-z0-9_]`) and anything else, including the ends of the input.
const ASCII_BOUNDARY: &str =
    r"(?:(?<![A-Za-z0-9_])(?=[A-Za-z0-9_])|(?<=[A-Za-z0-9_])(?![A-Za-z0-9_]))";

/// Translate a JavaScript pattern into one this engine reads the same
/// way.
///
/// The corpus holds the extension's source verbatim — that is what
/// makes the both-ways parity check possible — so the differences
/// between the two engines are resolved here instead, and each is a
/// behaviour difference rather than a spelling one:
///
/// - **`\s`** is Unicode `White_Space` in Rust and a different set in
///   JavaScript: it excludes U+FEFF, which JavaScript counts, and
///   includes U+0085, which it does not. A config file beginning with a
///   byte-order mark is ordinary.
/// - **`\b`** is Unicode-aware in Rust and ASCII in JavaScript, so
///   `passwordé=…` has a word boundary for JavaScript and none for
///   Rust. Left alone, this engine would silently *miss* a credential
///   the extension reports — the worst direction for the difference to
///   run in.
/// - **`i`** is a flag in JavaScript and an inline group here.
fn to_rust_syntax(source: &str, flags: &str) -> String {
    let space = format!("[{}]", heuristics::JS_SPACE_CLASS);
    let non_space = format!("[^{}]", heuristics::JS_SPACE_CLASS);

    let mut out = String::with_capacity(source.len() + 32);
    if flags.contains('i') {
        out.push_str("(?i)");
    }

    let mut chars = source.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        match chars.next() {
            Some('s') => out.push_str(&space),
            Some('S') => out.push_str(&non_space),
            // An ASCII word boundary, matching JavaScript's, spelled out
            // with lookarounds. `(?-u:\b)` would say the same thing far
            // more briefly and this engine rejects it —
            // `ChangingUnicodeModeUnsupported` — so the boundary is
            // written as what it means: a transition into or out of an
            // ASCII word character.
            Some('b') => out.push_str(ASCII_BOUNDARY),
            Some(escaped) => {
                out.push('\\');
                out.push(escaped);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod prefilter_soundness {
    use super::*;

    /// The property the prefilter rests on: it matches a superset.
    ///
    /// If this ever fails, the prefilter is suppressing a real finding
    /// — which in a secret scanner is the worst defect available, and
    /// silent. Checked against the corpus rather than argued from the
    /// code.
    #[test]
    fn the_relaxed_pattern_matches_whenever_the_real_one_does() {
        let corpus: Vec<(&str, &str)> = crate::detect::corpus::documents().collect();
        for pattern in PATTERNS.iter() {
            let Some(prefilter) = &pattern.prefilter else {
                continue;
            };
            for (name, content) in &corpus {
                let real = pattern.regex.find(content).ok().flatten().is_some();
                if real {
                    assert!(
                        prefilter.is_match(content),
                        "the {} prefilter would have suppressed a real match in {name}",
                        pattern.kind
                    );
                }
            }
        }
    }

    /// The same property over text built to trip it: a value that only
    /// the strict pattern rejects must still reach the strict pattern.
    #[test]
    fn a_lookaround_only_rejection_still_reaches_the_real_pattern() {
        for text in [
            "aws_secret_access_key = \"AKIAIOSFODNN7EXAMPLEAKIAIOSFODNN7EXAMPLE\"",
            "password: \"hunter2hunter2\"",
            "api_key='abcdefghijklmnopqrstuvwxyz'",
            "Authorization: bearer abcdefghijklmnopqrstuvwxyz",
            "eyJhbGciOi.eyJzdWIiOi.SflKxwRJSM",
            "postgres://user:pass@host/db",
            "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
            "square-cli --access-token sq0atp-EXAMPLEnotarealsquare00",
            "https://x.blob.core.windows.invalid/c/b?sv=2024-11-04&sp=r&sig=EXAMPLEnotarealazuresas0000",
        ] {
            for pattern in PATTERNS.iter() {
                let Some(prefilter) = &pattern.prefilter else {
                    continue;
                };
                if pattern.regex.find(text).ok().flatten().is_some() {
                    assert!(
                        prefilter.is_match(text),
                        "the {} prefilter would have suppressed {text:?}",
                        pattern.kind
                    );
                }
            }
        }
    }

    /// The same property over **generated** documents rather than the
    /// ones somebody thought of.
    ///
    /// The corpus proves the prefilter is sound for the cases it holds.
    /// This builds tens of thousands more by crossing every key name the
    /// table looks for with every way a value gets written — quoted,
    /// spaced, commented, in an attribute, mid-line — and asserts the
    /// same thing over all of them.
    ///
    /// **This is a correctness claim, not a performance one.** If the
    /// relaxed pattern ever fails to match where the real one would, the
    /// real one is never asked, and a credential goes unreported on both
    /// surfaces with the scan still exiting clean. That is the worst
    /// defect this codebase can have, and it is silent.
    ///
    /// The cross-product is deterministic and fully enumerated — no
    /// clock, no randomness, reproducible by construction — which is what
    /// `AGENTS.md` requires of anything under `detect/`.
    #[test]
    fn no_generated_document_is_suppressed_by_its_prefilter() {
        const KEYS: [&str; 18] = [
            "password",
            "DATABASE_PASSWORD",
            "passwd",
            "pwd",
            "api_key",
            "apiKey",
            "aws_secret_access_key",
            "secretkey",
            "access_token",
            "refresh_token",
            "oauth2_token",
            "jwt",
            "json_web_token",
            "token",
            "session_id",
            "cookie",
            "connection_string",
            "accountkey",
        ];
        // Every issuer-prefixed shape is here as well as the generic
        // ones. The prefilter is the reason a pattern runs at all, so a
        // new pattern whose relaxed form does not match is a detector
        // that never fires — and it would fire in no test that did not
        // cross it with the ways a value gets written.
        const VALUES: [&str; 21] = [
            "hunter2hunter2",
            "aB3xY7zQ9mK2pL5vN8wR4tS6",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
            "postgres://user:pass@db.example.invalid/app",
            "Server=prod;Database=app;Uid=admin;Pwd=secret123;",
            "sk-ant-api03-EXAMPLEnotarealanthropickey00000",
            "sk-proj-EXAMPLEnotarealopenaikey000000000000",
            "glpat-EXAMPLEnotarealgitlab00",
            "SG.EXAMPLEnotarealsendgridselector1234.EXAMPLEnotarealsendgridsecret00000",
            "key-deadbeefdeadbeefdeadbeefdeadbeefface",
            "sntrys_EXAMPLEnotarealsentryorgauthtoken00000000",
            "npm_EXAMPLEnotarealnpmtoken00000000000000000",
            "pypi-AgENOTAREALpypitokenEXAMPLE0000000000000000000000000000",
            "dckr_pat_EXAMPLEnotarealdockertoken00000000",
            "hvs.EXAMPLEnotarealvaulttoken00",
            "EXAMPLEnotar.atlasv1.EXAMPLEnotarealterraformcloudtoken000000000000",
            "sbp_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefface",
            // Joined at compile time rather than written out: a
            // complete Shopify-shaped token in a checked-in file trips
            // other scanners, including GitHub's push protection.
            concat!("shpat_", "deadbeef", "deadbeef", "deadbeef", "deadbeef"),
        ];
        // `{key}` and `{value}` stand in for the pair.
        const WRAPPERS: [&str; 12] = [
            "{key}={value}",
            "{key} = {value}",
            "{key} = \"{value}\"",
            "{key} = '{value}'",
            "  \"{key}\": \"{value}\",",
            "{key}: {value}",
            "// {key}={value}",
            "# {key}={value}",
            "<config {key}=\"{value}\" />",
            "const c = {{ {key}: '{value}' }};",
            "Authorization: Bearer {value} # {key}",
            "\u{fc}nicode \u{1f3af} {key}={value}\u{feff}",
        ];

        let mut checked = 0_usize;
        for key in KEYS {
            for value in VALUES {
                for wrapper in WRAPPERS {
                    let document = wrapper
                        .replace("{key}", key)
                        .replace("{value}", value)
                        .replace("{{", "{")
                        .replace("}}", "}");
                    for pattern in PATTERNS.iter() {
                        let Some(prefilter) = &pattern.prefilter else {
                            continue;
                        };
                        checked += 1;
                        if pattern.regex.find(&document).ok().flatten().is_none() {
                            continue;
                        }
                        assert!(
                            prefilter.is_match(&document),
                            "the {} prefilter would have suppressed a real match, so this \
                             credential would go unreported and the scan would still exit \
                             clean:\n  {document:?}",
                            pattern.kind
                        );
                    }
                }
            }
        }
        assert!(
            checked > 20_000,
            "only {checked} pattern/document pairs ran"
        );
    }

    /// Every pattern with a lookaround in it should have produced a
    /// prefilter. If one silently did not, the speedup quietly is not
    /// there and nobody would notice.
    #[test]
    fn every_pattern_has_a_prefilter() {
        let without: Vec<&str> = PATTERNS
            .iter()
            .filter(|pattern| pattern.prefilter.is_none())
            .map(|pattern| pattern.kind.as_str())
            .collect();
        assert!(without.is_empty(), "no prefilter for: {without:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_table_loads_and_compiles() {
        assert!(!PATTERNS.is_empty());
        assert_eq!(PATTERNS.len(), 34, "the corpus carries 34 patterns");
    }

    /// The issuer-prefixed patterns lead the table, and the list of
    /// which they are is written out rather than derived, so adding one
    /// in the wrong place fails here instead of quietly changing what a
    /// scan reports.
    ///
    /// They and the key-name patterns match the same span — `NPM_TOKEN=
    /// npm_…` is both — and the first to claim it wins the dedupe.
    #[test]
    fn the_issuer_prefixed_patterns_lead_the_table() {
        const ISSUERS: [&str; 15] = [
            "anthropic-key",
            "openai-key",
            "gitlab-token",
            "sendgrid-key",
            "mailgun-key",
            "sentry-token",
            "npm-token",
            "pypi-token",
            "docker-token",
            "vault-token",
            "terraform-token",
            "supabase-key",
            "shopify-token",
            "square-token",
            "azure-sas",
        ];
        let leading: Vec<&str> = PATTERNS
            .iter()
            .take_while(|pattern| pattern.key_group.is_none())
            .map(|pattern| pattern.kind.as_str())
            .collect();
        assert_eq!(leading, ISSUERS);
    }

    /// Order is what makes the dedupe deterministic: the specific key
    /// patterns must run before the generic token pattern, or a
    /// `refresh_token` is reported as a plain token.
    #[test]
    fn the_specific_key_patterns_run_before_the_generic_one() {
        let position = |kind: &str| {
            PATTERNS
                .iter()
                .position(|pattern| pattern.kind == kind)
                .unwrap_or_else(|| panic!("{kind} is missing from the table"))
        };
        for specific in ["access-token", "refresh-token", "oauth-token", "jwt"] {
            assert!(
                position(specific) < position("token"),
                "{specific} must precede the generic token pattern"
            );
        }
    }

    #[test]
    fn every_pattern_names_a_group_that_could_exist() {
        for pattern in PATTERNS.iter() {
            let groups = pattern.regex.captures_len();
            assert!(
                pattern.value_group < groups,
                "{}: value group {} but only {groups} groups",
                pattern.kind,
                pattern.value_group
            );
            if let Some(key_group) = pattern.key_group {
                assert!(
                    key_group < groups,
                    "{}: key group out of range",
                    pattern.kind
                );
            }
        }
    }

    #[test]
    fn a_case_insensitive_flag_becomes_an_inline_group() {
        assert!(to_rust_syntax("abc", "dgi").starts_with("(?i)"));
        assert!(!to_rust_syntax("abc", "dg").starts_with("(?i)"));
    }

    #[test]
    fn word_boundaries_become_ascii_like_javascripts() {
        assert_eq!(to_rust_syntax(r"\bx", "dg"), format!("{ASCII_BOUNDARY}x"));
    }

    /// The translated boundary must actually behave the way JavaScript's
    /// does, or the reason for translating it is unproven.
    #[test]
    fn an_ascii_boundary_matches_before_a_non_ascii_letter() {
        let translated = Regex::new(&to_rust_syntax(r"\bpassword\b", "dg")).expect("compiles");
        assert!(
            translated
                .is_match("passwordé")
                .expect("no backtrack limit"),
            "JavaScript sees a boundary here, so this must too"
        );
        let unicode = Regex::new(r"\bpassword\b").expect("compiles");
        assert!(
            !unicode.is_match("passwordé").expect("no backtrack limit"),
            "the untranslated form is what would have missed it"
        );
    }

    #[test]
    fn whitespace_classes_use_javascripts_set() {
        let translated = Regex::new(&to_rust_syntax(r"a\sb", "dg")).expect("compiles");
        assert!(translated.is_match("a\u{feff}b").expect("no limit"));
        let unicode = Regex::new(r"a\sb").expect("compiles");
        assert!(!unicode.is_match("a\u{feff}b").expect("no limit"));
    }

    #[test]
    fn other_escapes_are_left_alone() {
        assert_eq!(to_rust_syntax(r"a\.b\+c", "dg"), r"a\.b\+c");
    }

    #[test]
    fn confidence_rules_answer_for_every_pattern() {
        for pattern in PATTERNS.iter() {
            let level = pattern.confidence("aB3xY7zQ9mK2pL5vN8wR4tS6");
            assert!(matches!(
                level,
                Confidence::Low | Confidence::Medium | Confidence::High
            ));
        }
    }
}
