//! Bounded previews of detected values.
//!
//! **This module is why the tool is safe to run in CI.** Everything else
//! finds credentials; this is what stops the finding from becoming a
//! second disclosure — one to a log that is archived, often
//! world-readable, and outlives the credential.
//!
//! The rule, from SPEC.md: a preview is capped at eight characters
//! **and** at half the value's length, and always carries the length.
//! Half-length is what makes the cap hold for short values — an
//! eight-character cap on an eight-character password is the password,
//! and the password detector matches from eight characters up.
//!
//! There is no option, flag or code path that turns this off.

const MAX_PREVIEW: usize = 8;

/// A preview that can never be the whole value.
///
/// The length is included because it is what lets a reader tell two
/// similar findings apart without revealing more of either.
pub(crate) fn mask_secret_value(value: &str) -> String {
    if value.is_empty() {
        return "(empty)".to_string();
    }

    // Lengths are counted in UTF-16 code units, matching the extension's
    // `String.length`, so a value containing an emoji is described the
    // same way by both frontends.
    let length = value.encode_utf16().count();

    // Below three characters any preview at all is the whole value, so
    // give the length only. Real findings are far longer than this, but
    // the property has to hold unconditionally or it is not a property.
    if length < 3 {
        return format!("({length} chars)");
    }

    let shown = MAX_PREVIEW.min(length / 2);
    format!("{}… ({length} chars)", take_utf16(value, shown))
}

/// Redact every occurrence of `value` from a line of source.
///
/// The context line is taken verbatim from the file, so it contains the
/// secret it is providing context for.
pub(crate) fn mask_within(context: &str, value: &str) -> String {
    if value.is_empty() {
        return context.to_string();
    }
    context.replace(value, &mask_secret_value(value))
}

/// The first `units` UTF-16 code units of `value`, never splitting a
/// character. `String.prototype.slice` counts code units, and a preview
/// that differed between the two frontends would be a parity break in
/// the one place it matters most.
fn take_utf16(value: &str, units: usize) -> &str {
    let mut seen = 0;
    for (offset, character) in value.char_indices() {
        if seen >= units {
            return &value[..offset];
        }
        seen += character.len_utf16();
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_value_is_named_rather_than_previewed() {
        assert_eq!(mask_secret_value(""), "(empty)");
    }

    #[test]
    fn a_value_too_short_to_preview_gives_only_its_length() {
        assert_eq!(mask_secret_value("a"), "(1 chars)");
        assert_eq!(mask_secret_value("ab"), "(2 chars)");
    }

    #[test]
    fn the_preview_is_capped_at_half_the_length() {
        // Four characters would allow two, not four.
        assert_eq!(mask_secret_value("abcd"), "ab… (4 chars)");
        assert_eq!(mask_secret_value("abcdef"), "abc… (6 chars)");
    }

    #[test]
    fn the_preview_is_capped_at_eight_characters() {
        let value = "a".repeat(200);
        assert_eq!(mask_secret_value(&value), "aaaaaaaa… (200 chars)");
    }

    #[test]
    fn every_occurrence_in_a_context_line_is_masked() {
        let masked = mask_within("a=secret and again secret", "secret");
        assert!(!masked.contains("secret and"), "{masked}");
        assert_eq!(masked.matches("sec…").count(), 2, "{masked}");
    }

    #[test]
    fn a_context_without_the_value_is_unchanged() {
        assert_eq!(mask_within("nothing here", "absent"), "nothing here");
        assert_eq!(mask_within("empty value", ""), "empty value");
    }

    /// A one- or two-character value is described **only** by its
    /// length: the output contains no part of it at all, which is the
    /// strongest form the property can take.
    ///
    /// Checked by construction rather than by substring, because at that
    /// size a substring test is meaningless — the literal word "chars"
    /// contains an `a`, so any single-letter value "appears" in it.
    #[test]
    fn a_value_too_short_to_preview_discloses_nothing_but_its_length() {
        for value in ["a", "x", "1", "ab", "xy", "()"] {
            let length = value.encode_utf16().count();
            assert_eq!(mask_secret_value(value), format!("({length} chars)"));
        }
    }

    /// **The property the whole tool rests on.** Exhaustive over lengths
    /// rather than a handful of examples, because a cap that holds for
    /// the cases someone thought of is not a guarantee.
    #[test]
    fn no_preview_ever_contains_its_whole_value() {
        for length in 3..=300 {
            let value: String = std::iter::repeat_n('x', length).collect();
            let preview = mask_secret_value(&value);
            assert!(
                !preview.contains(&value),
                "a {length}-character value leaked through its preview: {preview}"
            );
            let context = format!("KEY={value}");
            let masked = mask_within(&context, &value);
            assert!(
                !masked.contains(&value),
                "a {length}-character value leaked through its context line: {masked}"
            );
        }
    }

    /// The same property over values that are not a single repeated
    /// character — a repeated run is the easiest case for a substring
    /// check to pass by accident.
    #[test]
    fn no_preview_leaks_a_varied_value() {
        let alphabet: Vec<char> = "aB3xY7zQ9mK2pL5vN8wR4tS6/+=-_.".chars().collect();
        for length in 3..=300 {
            let value: String = (0..length).map(|i| alphabet[i % alphabet.len()]).collect();
            assert!(!mask_secret_value(&value).contains(&value), "{length}");
            let context = format!("KEY={value} trailing");
            assert!(!mask_within(&context, &value).contains(&value), "{length}");
        }
    }

    /// A preview must not split a character in half, and its length must
    /// be counted the way the extension counts it. Fifteen characters
    /// allow seven — half, rounded down — not the eight-character cap.
    #[test]
    fn multibyte_values_are_previewed_by_code_unit() {
        let value = "ééééééééééééééé";
        let preview = mask_secret_value(value);
        assert_eq!(preview, "ééééééé… (15 chars)");
        assert!(!preview.contains(value));
    }

    #[test]
    fn an_astral_value_counts_in_utf16_units_like_the_extension() {
        // Four emoji are eight UTF-16 code units, so the preview shows
        // four of them — half of eight — not four of a count of four.
        let value = "🎯🎯🎯🎯";
        let preview = mask_secret_value(value);
        assert!(preview.contains("(8 chars)"), "{preview}");
        assert!(!preview.contains(value), "{preview}");
    }
}
