/**
 * Bounded previews of detected secret values.
 *
 * The detection report is written into an editor buffer that a user may save,
 * paste into an issue, or commit. It previously rendered
 * `secret.value.substring(0, 20)`, which is a partial disclosure for a 40-char
 * AWS secret but the *complete* value for anything shorter — and the password
 * detector matches from 8 characters up, so most passwords landed in the
 * report in full, with no ellipsis to indicate otherwise. The surrounding
 * `context` line was worse: it is the raw source line, so
 * `DATABASE_PASSWORD=hunter2hunter2` appeared verbatim.
 *
 * Identifying a finding does not require the value. The report already gives
 * the file, line, column, key name, type and confidence; the preview only has
 * to let a reader confirm they are looking at the right string.
 *
 * These functions therefore never return a complete secret: the preview is
 * capped at 8 characters AND at half the value's length, and is always marked
 * as elided.
 */

const MAX_PREVIEW = 8;

/**
 * A preview that can never be the whole value.
 *
 * The length is included because it is what lets a reader tell two similar
 * findings apart without revealing more of either.
 */
export function maskSecretValue(value: string): string {
	if (value.length === 0) return '(empty)';

	// Below three characters any preview at all is the whole value, so give the
	// length only. Real findings are far longer than this — the password
	// detector matches from eight — but the property has to hold unconditionally
	// or it is not a property.
	if (value.length < 3) return `(${value.length} chars)`;

	const shown = Math.min(MAX_PREVIEW, Math.floor(value.length / 2));
	return `${value.slice(0, shown)}… (${value.length} chars)`;
}

/**
 * Redact every occurrence of `value` from a line of source before it is shown.
 *
 * Used for the context line, which is taken verbatim from the file and so
 * contains the secret it is providing context for.
 */
export function maskWithin(context: string, value: string): string {
	if (value.length === 0) return context;
	return context.split(value).join(maskSecretValue(value));
}
