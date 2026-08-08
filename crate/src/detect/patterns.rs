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

pub(crate) static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    let table: Table = toml::from_str(TABLE).expect("the embedded pattern table parses");
    table
        .pattern
        .into_iter()
        .map(|entry| Pattern {
            regex: Regex::new(&to_rust_syntax(&entry.regex, &entry.flags))
                .expect("a pattern from the shared table compiles"),
            kind: entry.kind,
            description: entry.description,
            key_group: entry.key_group,
            value_group: entry.value_group,
            rule: entry.confidence,
        })
        .collect()
});

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
mod tests {
    use super::*;

    #[test]
    fn the_embedded_table_loads_and_compiles() {
        assert!(!PATTERNS.is_empty());
        assert_eq!(PATTERNS.len(), 19, "the corpus carries 19 patterns");
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
