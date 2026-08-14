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

use super::heuristics::{js_trim_end, js_trim_start};

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

/// How much of the source line either side of the value the context
/// keeps, counted in UTF-16 code units so both frontends cut in the same
/// place.
///
/// A context line used to be the *whole* source line. On an ordinary
/// file that is a sentence; on a minified one it is the entire file, and
/// a file with a thousand findings on its single line produced a
/// hundred megabytes of report — the same line, a thousand times. The
/// cost of a scan stopped being proportional to what was in it.
const CONTEXT_MARGIN: usize = 60;

/// `line[from..to]`, with any part of it that overlaps a finding's span
/// replaced by a marker rather than shown.
///
/// Spans are byte offsets into the same line. Overlap is what matters,
/// not containment: a window edge can cut through a finding, and the
/// half that lands inside the window is still credential text.
fn redact_spans(line: &str, from: usize, to: usize, spans: &[(usize, usize)]) -> String {
    let mut out = String::new();
    let mut cursor = from;
    for (start, end) in spans.iter().copied() {
        let start = start.max(from);
        let end = end.min(to);
        if start >= end || end <= cursor {
            continue;
        }
        if start > cursor {
            out.push_str(&line[cursor..start]);
        }
        out.push('\u{2026}');
        cursor = end;
    }
    if cursor < to {
        out.push_str(&line[cursor..to]);
    }
    out
}

/// The context line for one finding: a bounded window of its source
/// line, with **every** detected value in it masked.
///
/// The second half is the part that matters. Masking only the finding's
/// own value left every *other* credential on that line in the clear:
///
/// ```text
/// DB_PASSWORD=hunter2… (14 chars) API_KEY=abcdefghijklmnopqrstuvwx
/// ```
///
/// which is a complete API key, printed by a tool whose one promise is
/// that it never prints one — into a CI log, which is archived and
/// outlives the credential. A line holding two credentials is not
/// exotic: it is what a compact JSON config looks like.
///
/// `values` is every distinct value the document yielded. Longest first,
/// so a value containing a shorter one is replaced whole rather than
/// broken into pieces by its own substring.
pub(crate) fn mask_context(
    line: &str,
    value_start: usize,
    value_length: usize,
    value: &str,
    values: &[String],
    spans: &[(usize, usize)],
) -> String {
    // Assembled from three parts rather than cut out and searched.
    //
    // Searching only works when the value is present in the window whole.
    // A PEM block is not: it runs past the end of its own line, so the
    // line holds a *prefix* of it, which no replacement matches — and the
    // context came out carrying seventeen hundred characters of key
    // material in the clear. Building the middle from the preview means
    // the value's own text has nowhere to appear from.
    let value_end = value_start.saturating_add(value_length).min(line.len());
    let before_start = back_from(line, value_start, CONTEXT_MARGIN);
    let after_end = forward_from(line, value_end, CONTEXT_MARGIN);

    // Masked by **span** and not only by text. A value is replaced by
    // searching for it, which needs it to be present whole — and a
    // credential can be reported only as part of a longer run, so the
    // window shows a *prefix* of a reported value that no replacement
    // matches. The fuzzer found a planted connection string surviving
    // inside a 1,595-character database URL that way. Blanking the span
    // first means the window cannot show source that overlaps any
    // finding, whatever the text happens to be; the text pass after it
    // still covers a value repeated somewhere the spans do not reach.
    let mut before_raw = redact_spans(line, before_start, value_start, spans);
    let mut after_raw = redact_spans(line, value_end, after_end, spans);
    // Only where the margin actually cut. A window that reaches the start
    // or the end of the line is showing whole tokens already.
    if before_start > 0 {
        before_raw = drop_leading_partial(&before_raw).to_string();
    }
    if after_end < line.len() {
        after_raw = drop_trailing_partial(&after_raw).to_string();
    }
    // Collapsed after masking, never before: a value the detector *did*
    // claim earns its `prefix… (n chars)` preview, and collapsing first
    // would flatten every finding's neighbour into a bare length.
    let before = collapse_unclaimed_runs(&mask_all(js_trim_start(&before_raw), values));
    let after = collapse_unclaimed_runs(&mask_all(js_trim_end(&after_raw), values));

    let mut context = String::new();
    if before_start > 0 {
        context.push('…');
    }
    context.push_str(&before);
    context.push_str(&mask_secret_value(value));
    context.push_str(&after);
    if after_end < line.len() {
        context.push('…');
    }
    context
}

/// Every value in `values`, replaced wherever it appears in `text`.
///
/// Used for the context window and for the **key name**, which is a
/// verbatim slice of the document and not the tidy identifier it looks
/// like. Every key pattern in the table begins `[A-Za-z0-9_-]*`, so the
/// key group swallows whatever word characters run up to the keyword —
/// and a token abutting the name ends up reported as part of it:
///
/// ```text
/// "key": "ghp_1234567890abcdefghijklmnopqrstuvwxyz----session_id"
/// ```
///
/// A complete credential, in a field nothing was masking.
pub(crate) fn mask_all(text: &str, values: &[String]) -> String {
    let mut masked = text.to_string();
    for value in values {
        // Asked before replacing rather than after. `replace` allocates a
        // new string whether or not it changed anything, and a document
        // with a thousand distinct values would pay that a thousand times
        // per finding — the scan's cost stops being proportional to the
        // document and starts being proportional to its square. Skipping
        // a replacement that would have changed nothing cannot change the
        // answer.
        if !masked.contains(value.as_str()) {
            continue;
        }
        masked = mask_within(&masked, value);
    }
    masked
}

/// Every distinct value, longest first — the order `mask_context`
/// depends on, prepared once for a whole document rather than per
/// finding.
pub(crate) fn masking_order(values: &[String]) -> Vec<String> {
    let mut ordered: Vec<String> = values.to_vec();
    // Length descending, then by content, so the order is total and the
    // output cannot depend on the order values happened to be found in.
    ordered.sort_by(|a, b| {
        b.encode_utf16()
            .count()
            .cmp(&a.encode_utf16().count())
            .then_with(|| a.cmp(b))
    });
    ordered.dedup();
    ordered
}

/// The longest run of source a context window will show verbatim.
///
/// Sixteen because every credential the table claims is longer than that,
/// and the identifiers a reader needs in order to place a finding —
/// `awsSecretAccessKey`, `DATABASE_PASSWORD`, `connection_string` — are
/// words, which this rule keeps whatever their length.
const MAX_RUN: usize = 16;

/// Where one token ends and the next begins.
///
/// `DATABASE_PASSWORD=hunter2` is a name and a value, not one long run, so
/// the separators a config or a language puts between them have to end a
/// token — otherwise the key name collapses along with the credential and
/// the context stops saying anything. `/` is deliberately **not** here: it
/// is what an AWS secret is full of, and splitting on it would leave
/// `bPxRfiCYEXAMPLEKEY` looking like a word.
fn ends_a_token(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '=' | ':'
                | ';'
                | ','
                | '\''
                | '"'
                | '`'
                | '('
                | ')'
                | '{'
                | '}'
                | '['
                | ']'
                | '<'
                | '>'
                | '&'
                | '|'
                | '?'
                | '!'
                | '\u{2026}'
        )
}

/// Whether a token is ordinary source rather than something with a
/// credential's shape.
///
/// Letters, `_`, `-`, `.` and `/` are what names and paths are made of:
/// `awsSecretAccessKey`, `DATABASE_PASSWORD`, `//registry.npmjs.org/`. A
/// digit in a token this long is what every credential in the table
/// carries and what none of those do.
///
/// A window that cuts through an undetected credential leaves a fragment
/// like `G/bPxRfiCYEXAMPLEKEY`, which reads as a name by this rule. That
/// is handled where it arises — the edge drops its partial token — rather
/// than by refusing `/` here, which would cost every import path and URL
/// its readability for a case the cut already covers.
fn reads_as_a_name(token: &str) -> bool {
    token.chars().all(|character| {
        character.is_alphabetic()
            || character == '_'
            || character == '-'
            || character == '.'
            || character == '/'
    })
}

/// Collapse anything in a context window that the detector did not claim
/// but that has a credential's shape.
///
/// Masking covers the values a document *yielded*. A credential the table
/// did not claim is in no finding, so no span covers it and no replacement
/// matches it — and the window reproduced it from source. The fuzzer
/// caught a complete AWS secret access key printed that way, in the
/// context of the finding beside it: never detected, so never masked, and
/// the harness could not even name it correctly because two values sharing
/// a prefix and a length share a preview.
///
/// Runs are judged between ellipses, not across them, so a piece already
/// blanked by a span cannot vouch for the source next to it.
pub(crate) fn collapse_unclaimed_runs(text: &str) -> String {
    let mut out = String::new();
    let mut token = String::new();
    for character in text.chars() {
        if ends_a_token(character) {
            out.push_str(&collapse_token(&token));
            token.clear();
            // Separators are kept as written: they are what make the window
            // read as the line of code it came from.
            out.push(character);
            continue;
        }
        token.push(character);
    }
    out.push_str(&collapse_token(&token));
    out
}

fn collapse_token(token: &str) -> String {
    let length = token.encode_utf16().count();
    if length >= MAX_RUN && !reads_as_a_name(token) {
        return format!("({length} chars)");
    }
    token.to_string()
}

/// Drop the partial token a window edge cut through.
///
/// The margin is counted in code units, so it lands wherever it lands —
/// usually inside a token. That fragment is the half of a credential the
/// window happened to reach: `wJalrXUtnFE` reads as a word, is under the
/// collapse threshold, and is eleven characters of a key the preview rule
/// would only ever show eight of. A whole token or nothing.
fn drop_leading_partial(window: &str) -> &str {
    match window
        .char_indices()
        .find(|(_, character)| ends_a_token(*character))
    {
        Some((offset, _)) => &window[offset..],
        None => "",
    }
}

fn drop_trailing_partial(window: &str) -> &str {
    match window
        .char_indices()
        .rev()
        .find(|(_, character)| ends_a_token(*character))
    {
        Some((offset, character)) => &window[..offset + character.len_utf8()],
        None => "",
    }
}

/// The byte offset `units` UTF-16 code units before `from`, floored to a
/// character boundary.
fn back_from(line: &str, from: usize, units: usize) -> usize {
    let mut seen = 0;
    for (offset, character) in line[..from].char_indices().rev() {
        seen += character.len_utf16();
        if seen > units {
            return offset + character.len_utf8();
        }
    }
    0
}

/// The byte offset `units` code units past `from`, or the end of the
/// line, whichever comes first.
///
/// A character that would take the window past `units` is left out
/// rather than included whole: an astral character is two code units,
/// and the two frontends have to cut in the same place or the same
/// document reads differently on each.
fn forward_from(line: &str, from: usize, units: usize) -> usize {
    let mut seen = 0;
    for (offset, character) in line[from..].char_indices() {
        if seen + character.len_utf16() > units {
            return from + offset;
        }
        seen += character.len_utf16();
    }
    line.len()
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

    /// **The leak this window and this ordering exist for.** Masking a
    /// finding's own value left every *other* credential on the line in
    /// the clear, and a line holding two credentials is what a compact
    /// JSON config looks like.
    #[test]
    fn a_context_masks_every_value_on_the_line_not_only_its_own() {
        let line = "DB_PASSWORD=hunter2hunter2 API_KEY=abcdefghijklmnopqrstuvwx";
        let values = masking_order(&[
            "hunter2hunter2".to_string(),
            "abcdefghijklmnopqrstuvwx".to_string(),
        ]);
        let context = mask_context(line, 12, 14, "hunter2hunter2", &values, &[]);
        assert!(!context.contains("hunter2hunter2"), "{context}");
        assert!(
            !context.contains("abcdefghijklmnopqrstuvwx"),
            "the neighbouring key survived: {context}"
        );
    }

    /// A line short enough to fit reads exactly as it did before the
    /// window existed: no ellipsis, same trim.
    #[test]
    fn a_short_line_is_not_windowed_at_all() {
        let line = "  DATABASE_PASSWORD=hunter2hunter2  ";
        let values = masking_order(&["hunter2hunter2".to_string()]);
        assert_eq!(
            mask_context(line, 20, 14, "hunter2hunter2", &values, &[]),
            "DATABASE_PASSWORD=hunter2… (14 chars)"
        );
    }

    /// The quadratic: a minified line is the whole file, and one context
    /// line per finding made the report grow with findings *times* line
    /// length. Ninety-eight megabytes of stdout for one file.
    #[test]
    fn a_long_line_is_cut_down_to_a_window_around_the_value() {
        let filler = "z".repeat(5_000);
        let line = format!("{filler} DATABASE_PASSWORD=hunter2hunter2 {filler}");
        let values = masking_order(&["hunter2hunter2".to_string()]);
        let context = mask_context(&line, 5_019, 14, "hunter2hunter2", &values, &[]);
        assert!(context.len() < 200, "{} bytes", context.len());
        assert!(context.starts_with('…'), "{context}");
        assert!(context.ends_with('…'), "{context}");
        assert!(context.contains("DATABASE_PASSWORD="), "{context}");
        assert!(!context.contains("hunter2hunter2"), "{context}");
    }

    /// A value longer than the window is still inside it, whole — a cut
    /// through a value leaves a fragment no mask matches, which is a
    /// partial disclosure dressed up as a redaction.
    #[test]
    fn a_value_longer_than_the_window_is_still_masked_entirely() {
        let value = "aB3xY7zQ9mK2pL5vN8wR4tS6".repeat(20);
        let line = format!("token = {value} trailing");
        let values = masking_order(std::slice::from_ref(&value));
        let context = mask_context(&line, 8, value.len(), &value, &values, &[]);
        assert!(!context.contains(&value), "{context}");
        assert!(context.contains("trailing"), "{context}");
    }

    /// Longest first, so a value that contains a shorter one is replaced
    /// whole instead of being broken into pieces by its own substring.
    #[test]
    fn the_masking_order_puts_the_longest_value_first() {
        let order = masking_order(&[
            "hunter2hunter2".to_string(),
            "hunter2hunter2hunter2".to_string(),
            "hunter2hunter2".to_string(),
        ]);
        assert_eq!(
            order,
            [
                "hunter2hunter2hunter2".to_string(),
                "hunter2hunter2".to_string()
            ]
        );
        let line = "a=hunter2hunter2hunter2 b=hunter2hunter2";
        let context = mask_context(line, 2, 21, "hunter2hunter2hunter2", &order, &[]);
        assert!(!context.contains("hunter2hunter2"), "{context}");
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
