import type {
	DetectedSecret,
	DetectionResult,
	ParseError,
	SanitizationResult,
	SecretReplacement,
} from '../types';

import { detectSecrets } from './detectors';

/**
 * Detects secrets in content
 */
export function detectSecretsInContent(
	content: string,
	options: {
		readonly includeApiKeys?: boolean;
		readonly includePasswords?: boolean;
		readonly includeTokens?: boolean;
		readonly includePrivateKeys?: boolean;
		readonly sensitivity?: 'low' | 'medium' | 'high';
	} = {},
): DetectionResult {
	const startTime = Date.now();
	const lines = content.split('\n');
	const errors: ParseError[] = [];

	try {
		const secrets = detectSecrets(content, options);

		const processingTimeMs = Date.now() - startTime;

		return Object.freeze({
			success: true,
			secrets: Object.freeze(secrets),
			errors: Object.freeze(errors),
			warnings: Object.freeze([]),
			metadata: Object.freeze({
				totalLines: lines.length,
				processedLines: lines.length,
				processingTimeMs,
			}),
		});
	} catch (error) {
		const errorMessage = error instanceof Error ? error.message : String(error);
		const parseError: ParseError = {
			type: 'parse-error',
			message: `Detection failed: ${errorMessage}`,
			context: 'Secret detection',
		};

		return Object.freeze({
			success: false,
			secrets: Object.freeze([]),
			errors: Object.freeze([parseError]),
			warnings: Object.freeze([]),
		});
	}
}

/**
 * Deduplicates detected secrets
 */
export function deduplicateSecrets(
	secrets: readonly DetectedSecret[],
): readonly DetectedSecret[] {
	const seen = new Set<string>();
	const unique: DetectedSecret[] = [];

	for (const secret of secrets) {
		const key = `${secret.value}:${secret.type}`;
		if (!seen.has(key)) {
			seen.add(key);
			unique.push(secret);
		}
	}

	return Object.freeze(unique);
}

/**
 * Sanitizes content by replacing detected secrets with placeholders
 */
export function sanitizeContent(
	content: string,
	secrets: readonly DetectedSecret[],
	replaceWith: string = '***REDACTED***',
): SanitizationResult {
	const startTime = Date.now();
	const originalLength = content.length;
	const errors: ParseError[] = [];
	const replacements: SecretReplacement[] = [];

	try {
		// Replace by offset, end to start, so earlier offsets stay valid.
		// Overlapping detections (two patterns over the same span) collapse
		// to a single replacement; stale offsets are skipped, never guessed.
		const sortedSecrets = [...secrets].sort((a, b) => b.start - a.start);

		let sanitized = content;
		let lastReplacedStart = Number.POSITIVE_INFINITY;

		for (const secret of sortedSecrets) {
			if (secret.start < 0 || secret.end > content.length) continue;
			if (secret.end > lastReplacedStart) continue;
			if (content.slice(secret.start, secret.end) !== secret.value) continue;

			sanitized =
				sanitized.slice(0, secret.start) +
				replaceWith +
				sanitized.slice(secret.end);
			lastReplacedStart = secret.start;

			replacements.push(
				Object.freeze({
					original: secret.value,
					replaced: replaceWith,
					type: secret.type,
					position: secret.position,
				}),
			);
		}

		const sanitizedLength = sanitized.length;
		const processingTimeMs = Date.now() - startTime;

		return Object.freeze({
			success: true,
			sanitizedContent: sanitized,
			replacements: Object.freeze(replacements),
			errors: Object.freeze(errors),
			warnings: Object.freeze([]),
			metadata: Object.freeze({
				originalLength,
				sanitizedLength,
				replacementsCount: replacements.length,
				processingTimeMs,
			}),
		});
	} catch (error) {
		const errorMessage = error instanceof Error ? error.message : String(error);

		const parseError: ParseError = {
			type: 'parse-error',
			message: `Sanitization failed: ${errorMessage}`,
			context: 'Content sanitization',
		};

		return Object.freeze({
			success: false,
			sanitizedContent: content,
			replacements: Object.freeze([]),
			errors: Object.freeze([parseError]),
			warnings: Object.freeze([]),
		});
	}
}
