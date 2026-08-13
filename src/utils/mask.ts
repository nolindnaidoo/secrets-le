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

/**
 * How much of the source line either side of the value the context keeps.
 *
 * A context line used to be the *whole* source line. On an ordinary file that
 * is a sentence; on a minified one it is the entire file, and a file with a
 * thousand findings on its single line produced a hundred megabytes of report
 * — the same line, a thousand times.
 */
const CONTEXT_MARGIN = 60;

/**
 * Every distinct value, longest first.
 *
 * Longest first is what makes the masking safe: a value that contains a
 * shorter one is replaced whole, rather than broken into pieces by its own
 * substring. Ties fall back to the content, so the order is total and the
 * output cannot depend on the order the values happened to be found in.
 */
export function maskingOrder(values: readonly string[]): readonly string[] {
	return [...new Set(values)].sort(
		(a, b) => b.length - a.length || (a < b ? -1 : a > b ? 1 : 0),
	);
}

/**
 * The context line for one finding: a bounded window of its source line, with
 * **every** detected value in it masked.
 *
 * The second half is the part that matters. Masking a finding's own value left
 * every *other* credential on that line in the clear:
 *
 *     connection_string = Server=prod;Database=app;Uid=admin;Pwd=secre… (10 chars);
 *
 * — the password is masked and the connection string it sits inside, itself a
 * reported finding, is printed whole. A line holding two credentials is not
 * exotic; it is what a compact JSON config looks like.
 *
 * `values` must come from `maskingOrder`. The Rust CLI computes this the same
 * way, character for character, and `scripts/check-detection-differential.ts`
 * holds the two implementations against each other over generated documents.
 */
/**
 * `line.slice(from, to)`, with any part overlapping a finding's span replaced
 * by a marker rather than shown.
 *
 * Overlap is what matters, not containment: a window edge can cut through a
 * finding, and the half inside the window is still credential text.
 */
function redactSpans(
	line: string,
	from: number,
	to: number,
	spans: readonly (readonly [number, number])[],
): string {
	let out = '';
	let cursor = from;
	for (const [rawStart, rawEnd] of spans) {
		const start = Math.max(rawStart, from);
		const end = Math.min(rawEnd, to);
		if (start >= end || end <= cursor) continue;
		if (start > cursor) out += line.slice(cursor, start);
		out += '…';
		cursor = end;
	}
	if (cursor < to) out += line.slice(cursor, to);
	return out;
}

export function maskContext(
	line: string,
	valueStart: number,
	valueLength: number,
	value: string,
	values: readonly string[],
	spans: readonly (readonly [number, number])[] = [],
): string {
	// Assembled from three parts rather than cut out and searched.
	//
	// Searching only works when the value is present in the window whole. A PEM
	// block is not: it runs past the end of its own line, so the line holds a
	// *prefix* of it, which no replacement matches — and the context came out
	// carrying seventeen hundred characters of key material in the clear.
	// Building the middle from the preview means the value's own text has
	// nowhere to appear from.
	const valueEnd = Math.min(valueStart + valueLength, line.length);
	const beforeStart = boundary(
		line,
		Math.max(0, valueStart - CONTEXT_MARGIN),
		1,
	);
	const afterEnd = boundary(
		line,
		Math.min(line.length, valueEnd + CONTEXT_MARGIN),
		-1,
	);

	// Masked by **span** and not only by text. A value is replaced by
	// searching for it, which needs it present whole — and a credential can be
	// reported only as part of a longer run, so the window shows a *prefix* of
	// a reported value that no replacement matches. A planted connection
	// string survived inside a 1,595-character database URL that way. Blanking
	// the span first means the window cannot show source overlapping any
	// finding, whatever the text is; the text pass after it still covers a
	// value repeated where the spans do not reach.
	const before = maskAll(
		trimStart(redactSpans(line, beforeStart, valueStart, spans)),
		values,
	);
	const after = maskAll(
		trimEnd(redactSpans(line, valueEnd, afterEnd, spans)),
		values,
	);

	return [
		beforeStart > 0 ? '…' : '',
		before,
		maskSecretValue(value),
		after,
		afterEnd < line.length ? '…' : '',
	].join('');
}

/**
 * `String.prototype.trim`, one end at a time. `trimStart`/`trimEnd` are the
 * same set JavaScript's `\s` uses, which is the set the Rust side spells out
 * by hand — `char::is_whitespace` there is not it.
 */
const trimStart = (text: string): string => text.trimStart();
const trimEnd = (text: string): string => text.trimEnd();

/**
 * Every value in `values`, replaced wherever it appears in `text`.
 *
 * Used for the context window and for the **key name**, which is a verbatim
 * slice of the document and not the tidy identifier it looks like. Every key
 * pattern in the table begins `[A-Za-z0-9_-]*`, so the key group swallows
 * whatever word characters run up to the keyword — and a token abutting the
 * name ends up reported as part of it:
 *
 *     "key": "ghp_1234567890abcdefghijklmnopqrstuvwxyz----session_id"
 *
 * A complete credential, in a field nothing was masking.
 */
export function maskAll(text: string, values: readonly string[]): string {
	let masked = text;
	for (const value of values) {
		// Asked before replacing rather than after. `split`/`join` builds a new
		// string whether or not it changed anything, and a document with a
		// thousand distinct values would pay that a thousand times per finding
		// — the scan's cost stops being proportional to the document and starts
		// being proportional to its square. Skipping a replacement that would
		// have changed nothing cannot change the answer.
		if (!masked.includes(value)) continue;
		masked = maskWithin(masked, value);
	}
	return masked;
}

/**
 * Nudge an index off the middle of a surrogate pair, in `direction`.
 *
 * An astral character is two code units. Slicing between them yields a lone
 * surrogate — which Rust cannot produce at all, so the two frontends would cut
 * the same document in different places.
 */
function boundary(line: string, index: number, direction: 1 | -1): number {
	const code = line.charCodeAt(index);
	const isLowSurrogate = code >= 0xdc00 && code <= 0xdfff;
	if (index <= 0 || index >= line.length || !isLowSurrogate) return index;
	return index + direction;
}
