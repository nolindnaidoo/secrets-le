import type { ConfidenceLevel } from '../types';

/**
 * Shared value heuristics used by every detector pattern. v1.x spread
 * per-pattern confidence lambdas and no placeholder filtering across 21
 * pattern entries; the same value could score differently depending on
 * which pattern found it.
 *
 * Intentional rejections (documented, not bugs):
 * - Template/placeholder values: `${VAR}`, `{{var}}`, `<your-key>`, and
 *   single-character runs (`xxxxxxxx`) are never secrets worth reporting.
 * - Bare `x.y.z` dotted triples are NOT JWTs. A JWT's header is base64
 *   JSON, which always starts with `eyJ` — anything else (version
 *   numbers, hostnames, module paths) is rejected. JWTs with non-JSON
 *   headers are missed; that trade kills the dominant false positive.
 * - GCP project ids (`project_id: my-project`) are identifiers, not
 *   credentials, and are not reported.
 */

/** True when a candidate value is a template placeholder, not a secret. */
export function looksLikePlaceholder(value: string): boolean {
	if (value.includes('${') || value.includes('{{')) return true;
	if (value.startsWith('<') && value.endsWith('>')) return true;
	// Single repeated character: xxxxxxxx, ********, ........
	if (value.length >= 4 && /^(.)\1+$/.test(value)) return true;
	return false;
}

/** Length-tiered confidence shared by key/value patterns. */
export function confidenceByLength(
	value: string,
	highAt: number,
	mediumAt: number,
): ConfidenceLevel {
	if (value.length >= highAt) return 'high';
	if (value.length >= mediumAt) return 'medium';
	return 'low';
}

/**
 * True when the value is shaped like a JWT: three base64url segments
 * with the `eyJ` (base64 of `{"`) header prefix.
 */
export function isJwtShaped(value: string): boolean {
	return /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);
}
