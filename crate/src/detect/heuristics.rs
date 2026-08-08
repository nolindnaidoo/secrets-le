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
