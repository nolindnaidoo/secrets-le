/**
 * One file end to end, as the Rust CLI's `scan.rs` does it.
 *
 * Nothing here may emit a value. A finding leaves with a bounded preview from
 * `utils/mask` and a context line the engine has already masked against every
 * value in the document, the same two the shared MCP tool returns.
 */
import { readFileSync } from 'node:fs';
import { sep } from 'node:path';
import { detectSecretsInContent } from '../extraction/extract';
import { maskSecretValue } from '../utils/mask';
import type { DetectOptions } from './args';
import { decodeUtf8OrThrow, rustIoMessage, withoutBom } from './ioError';

export interface Finding {
	readonly type: string;
	readonly confidence: string;
	readonly key: string | null;
	readonly preview: string;
	readonly context: string | null;
	readonly line: number;
	readonly column: number;
	readonly description: string;
}

export interface Diagnostic {
	readonly severity: string;
	readonly code: string;
	readonly message: string;
}

export interface FileReport {
	readonly file: string;
	readonly findings: readonly Finding[];
	readonly diagnostics: readonly Diagnostic[];
	readonly summary: {
		readonly findings: number;
		readonly high: number;
		readonly medium: number;
		readonly low: number;
	};
}

function report(
	file: string,
	findings: readonly Finding[],
	diagnostics: readonly Diagnostic[],
): FileReport {
	const count = (level: string) =>
		findings.filter((finding) => finding.confidence === level).length;
	return Object.freeze({
		file,
		findings: Object.freeze(findings),
		diagnostics: Object.freeze(diagnostics),
		summary: Object.freeze({
			findings: findings.length,
			high: count('high'),
			medium: count('medium'),
			low: count('low'),
		}),
	});
}

/** A file that could not be read is named, never dropped. */
export function scanFile(path: string, options: DetectOptions): FileReport {
	const file = reportedPath(path);
	let bytes: Buffer;
	try {
		bytes = readFileSync(path);
	} catch (error) {
		return skipped(file, rustIoMessage(error));
	}
	let content: string;
	try {
		content = decodeUtf8OrThrow(bytes);
	} catch {
		return skipped(file, 'not UTF-8 text');
	}
	return scanContent(content, file, options);
}

function skipped(file: string, message: string): FileReport {
	return report(file, [], [{ severity: 'warning', code: 'skipped', message }]);
}

/** The byte-order mark is dropped here, so `--stdin` reads the same columns. */
export function scanContent(
	content: string,
	file: string,
	options: DetectOptions,
): FileReport {
	const result = detectSecretsInContent(withoutBom(content), {
		includeApiKeys: options.apiKeys,
		includePasswords: options.passwords,
		includeTokens: options.tokens,
		includePrivateKeys: options.privateKeys,
		sensitivity: options.sensitivity,
	});
	if (result.errors.length > 0) {
		return report(
			file,
			[],
			result.errors.map((error) => ({
				severity: 'error',
				code: 'incomplete',
				message: error.message,
			})),
		);
	}
	const findings = result.secrets.map((secret) =>
		Object.freeze({
			type: secret.type,
			confidence: secret.confidence,
			key: secret.key ?? null,
			preview: maskSecretValue(secret.value),
			context: secret.context ?? null,
			line: secret.position?.line ?? 0,
			column: secret.position?.column ?? 0,
			description: secret.description ?? '',
		}),
	);
	return report(file, findings, []);
}

/** `/` on Windows, as the crate spells a path in its report. */
export function reportedPath(path: string): string {
	return sep === '/' ? path : path.split(sep).join('/');
}

/** 0 clean, 1 findings, 2 could not answer: the worst outcome in the run. */
export function exitCode(
	reports: readonly FileReport[],
	strict: boolean,
): number {
	const has = (severity: string, code?: string) =>
		reports.some((each) =>
			each.diagnostics.some(
				(diagnostic) =>
					(code === undefined || diagnostic.code === code) &&
					(severity === '' || diagnostic.severity === severity),
			),
		);
	if (has('error')) return 2;
	if (strict && has('', 'skipped')) return 2;
	return reports.some((each) => each.summary.findings > 0) ? 1 : 0;
}

/** The one-line projection of a finding. Like the JSON, it carries no value. */
export function describe(file: FileReport, finding: Finding): string {
	const key = finding.key === null ? '' : ` ${finding.key}`;
	return `${file.file}:${finding.line}:${finding.column}  ${finding.type}${key}  ${finding.preview}  [${finding.confidence}]`;
}
