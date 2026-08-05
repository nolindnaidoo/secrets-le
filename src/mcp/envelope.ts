import type { DetectionResult } from '../types';

/**
 * The one result shape every tool returns.
 *
 * The engines across the family disagree — some async, some sync, six different
 * result envelopes. Normalising here rather than in the engines keeps the
 * characterization goldens untouched and the extension's behaviour unchanged.
 */
export interface ToolEnvelope<T> {
	readonly ok: boolean;
	readonly data: T;
	readonly diagnostics: readonly Diagnostic[];
	readonly meta: EnvelopeMeta;
}

export interface Diagnostic {
	readonly severity: 'warning' | 'error';
	readonly code: string;
	readonly message: string;
}

export interface EnvelopeMeta {
	readonly tool: string;
	readonly count: number;
	readonly truncated: boolean;
}

/** Above this an unbounded scan would flood an agent's context window. */
export const DEFAULT_MAX_RESULTS = 500;
export const MAX_MAX_RESULTS = 5000;

/**
 * `ok` is not `success`.
 *
 * `ok` reports whether the *scan* ran, not whether it found anything. A clean
 * document is `ok: true` with zero findings — reporting that as a failure would
 * have a model announce a problem that did not happen, and reporting a crashed
 * scan as a clean one would be far worse.
 */
export function isOk(diagnostics: readonly Diagnostic[]): boolean {
	return !diagnostics.some((d) => d.severity === 'error');
}

export function toDiagnostics(result: DetectionResult): readonly Diagnostic[] {
	const errors: Diagnostic[] = result.errors.map((e) => ({
		severity: 'error' as const,
		code: e.type,
		message: e.message,
	}));

	const warnings: Diagnostic[] = (result.warnings ?? []).map((message) => ({
		severity: 'warning' as const,
		code: 'warning',
		message,
	}));

	return [...errors, ...warnings];
}

/** Apply the result cap, reporting honestly whether anything was dropped. */
export function capped<T>(
	items: readonly T[],
	maxResults: number,
): { readonly items: readonly T[]; readonly truncated: boolean } {
	if (items.length <= maxResults) {
		return { items, truncated: false };
	}
	return { items: items.slice(0, maxResults), truncated: true };
}

export function envelope<T>(
	tool: string,
	data: T,
	count: number,
	diagnostics: readonly Diagnostic[],
	truncated: boolean,
): ToolEnvelope<T> {
	return {
		ok: isOk(diagnostics),
		data,
		diagnostics,
		meta: { tool, count, truncated },
	};
}

/** Read a bounded integer argument, rejecting values a tool cannot honour. */
export function readMaxResults(args: Record<string, unknown>): number {
	const raw = args.maxResults;
	if (raw === undefined) return DEFAULT_MAX_RESULTS;
	if (typeof raw !== 'number' || !Number.isInteger(raw) || raw < 1) {
		throw new Error('maxResults must be a positive integer');
	}
	return Math.min(raw, MAX_MAX_RESULTS);
}

/** Read a required string argument with a message naming the argument. */
export function readString(
	args: Record<string, unknown>,
	name: string,
): string {
	const value = args[name];
	if (typeof value !== 'string') {
		throw new Error(`${name} is required and must be a string`);
	}
	return value;
}
