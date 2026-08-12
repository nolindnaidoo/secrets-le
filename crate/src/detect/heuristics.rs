//! The value heuristics every pattern shares.
//!
//! Intentional rejections, ported from the extension and documented
//! there as decisions rather than bugs:
//!
//! - **Template placeholders are never secrets**: `${VAR}`, `{{var}}`,
//!   `<your-key>`, and any run of a single repeated character.
//! - **A bare `x.y.z` dotted triple is not a JWT.** A JWT header is
//!   base64 JSON and always begins `eyJ`; anything else is a version
//!   number, a hostname or a module path. JWTs with non-JSON headers are
//!   missed, and that trade kills the dominant false positive.

use std::sync::LazyLock;

use regex::Regex;

use super::patterns::Confidence;

/// JavaScript's `\s`, spelled out — see `to_rust_syntax` for why the
/// two engines disagree and why it matters here.
pub(crate) const JS_SPACE_CLASS: &str =
    r"\t\n\x0B\f\r \u{a0}\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}\u{feff}";

/// True for exactly the characters JavaScript's `\s` matches.
///
/// Rust's `char::is_whitespace` is not that set twice over: it **excludes**
/// U+FEFF, which JavaScript counts, and **includes** U+0085, which
/// JavaScript does not.
pub(crate) fn is_js_space(character: char) -> bool {
    if matches!(character, '\u{2000}'..='\u{200a}') {
        return true;
    }
    matches!(
        character,
        '\t' | '\n'
            | '\u{b}'
            | '\u{c}'
            | '\r'
            | ' '
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// `String.prototype.trim`, one end at a time — and it is not
/// `str::trim`.
///
/// The difference is one character and it is the one that matters here: a
/// byte-order mark. JavaScript trims it, Rust does not — so a document
/// beginning with one produced a context line with three invisible bytes
/// on one frontend and without them on the other. Both servers offer the
/// *same* `detect_secrets` tool, so a caller must not be able to tell
/// which one it reached.
pub(crate) fn js_trim_start(text: &str) -> &str {
    text.trim_start_matches(is_js_space)
}

pub(crate) fn js_trim_end(text: &str) -> &str {
    text.trim_end_matches(is_js_space)
}

/// `^(.)\1+$` — a single repeated character. The backreference is the
/// whole point, so this one pattern is matched by hand rather than by
/// an engine that would need backtracking for it.
fn is_single_repeated_character(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    characters.all(|character| character == first) && value.chars().count() >= 2
}

/// True when a candidate is a template placeholder rather than a secret.
pub(crate) fn looks_like_placeholder(value: &str) -> bool {
    if value.contains("${") || value.contains("{{") {
        return true;
    }
    if value.starts_with('<') && value.ends_with('>') {
        return true;
    }
    // The extension's guard is `length >= 4` on UTF-16 code units.
    value.encode_utf16().count() >= 4 && is_single_repeated_character(value)
}

/// Length-tiered confidence, shared by the key/value patterns.
pub(crate) fn confidence_by_length(value: &str, high_at: usize, medium_at: usize) -> Confidence {
    let length = value.encode_utf16().count();
    if length >= high_at {
        return Confidence::High;
    }
    if length >= medium_at {
        return Confidence::Medium;
    }
    Confidence::Low
}

static JWT_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
        .expect("a constant pattern compiles")
});

/// True when the value is shaped like a JWT: three base64url segments
/// with the `eyJ` header prefix.
pub(crate) fn is_jwt_shaped(value: &str) -> bool {
    JWT_SHAPE.is_match(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolations_and_angle_brackets_are_placeholders() {
        assert!(looks_like_placeholder("${DATABASE_PASSWORD}"));
        assert!(looks_like_placeholder("{{secret}}"));
        assert!(looks_like_placeholder("<your-key-here>"));
    }

    #[test]
    fn a_run_of_one_character_is_a_placeholder() {
        assert!(looks_like_placeholder("xxxxxxxx"));
        assert!(looks_like_placeholder("********"));
        assert!(looks_like_placeholder("...."));
    }

    /// The guard is four characters, so a shorter run is not a
    /// placeholder — pinned because the boundary is arbitrary and
    /// someone will otherwise "tidy" it.
    #[test]
    fn a_short_run_is_not_a_placeholder() {
        assert!(!looks_like_placeholder("xxx"));
        assert!(!looks_like_placeholder("xx"));
    }

    #[test]
    fn a_real_value_is_not_a_placeholder() {
        assert!(!looks_like_placeholder("hunter2hunter2"));
        assert!(!looks_like_placeholder("AKIAIOSFODNN7EXAMPLE"));
        assert!(!looks_like_placeholder(""));
    }

    #[test]
    fn confidence_tiers_on_length() {
        assert_eq!(
            confidence_by_length("a".repeat(32).as_str(), 32, 20),
            Confidence::High
        );
        assert_eq!(
            confidence_by_length("a".repeat(20).as_str(), 32, 20),
            Confidence::Medium
        );
        assert_eq!(
            confidence_by_length("a".repeat(19).as_str(), 32, 20),
            Confidence::Low
        );
    }

    /// The drift guard: `is_js_space` is written out by hand and
    /// `JS_SPACE_CLASS` is handed to the regex engine. They are the same
    /// claim in two spellings, so they are checked against each other
    /// rather than kept in step by hope.
    #[test]
    fn the_spelled_out_space_set_matches_the_class_the_engine_gets() {
        let class = Regex::new(&format!("^[{JS_SPACE_CLASS}]$")).expect("compiles");
        for code in 0..=0x3100_u32 {
            let Some(character) = char::from_u32(code) else {
                continue;
            };
            assert_eq!(
                is_js_space(character),
                class.is_match(&character.to_string()),
                "U+{code:04X} is in one spelling of JavaScript's \\s and not the other"
            );
        }
    }

    /// The two characters Rust and JavaScript disagree about, pinned.
    #[test]
    fn a_byte_order_mark_is_space_to_javascript_and_a_next_line_is_not() {
        assert_eq!(js_trim_end(js_trim_start("\u{feff}abc\u{feff}")), "abc");
        assert!(!"\u{feff}".trim().is_empty(), "Rust's own trim keeps it");
        assert_eq!(js_trim_start("\u{85}abc"), "\u{85}abc");
        assert!("\u{85}".trim().is_empty(), "Rust's own trim drops it");
        assert_eq!(js_trim_end(js_trim_start("  abc\t\n")), "abc");
    }

    #[test]
    fn only_a_base64_json_header_counts_as_a_jwt() {
        assert!(is_jwt_shaped("eyJhbGciOi.eyJzdWIi.dozjgNryP4"));
        // The dominant false positive this rejects.
        assert!(!is_jwt_shaped("1.2.3"));
        assert!(!is_jwt_shaped("my.host.name"));
        assert!(!is_jwt_shaped("src.utils.helper"));
        assert!(!is_jwt_shaped("abc.def.ghi"));
    }
}
