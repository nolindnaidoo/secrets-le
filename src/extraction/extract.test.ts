import { describe, expect, it } from 'vitest';
import type { DetectedSecret } from '../types';
import {
	deduplicateSecrets,
	detectSecretsInContent,
	formatDetectionResults,
	formatSanitizationResults,
	sanitizeContent,
} from './extract';

function secret(overrides: Partial<DetectedSecret> = {}): DetectedSecret {
	return Object.freeze({
		value: 'hunter2butlonger',
		type: 'password' as const,
		confidence: 'high' as const,
		start: 9,
		end: 25,
		position: { line: 1, column: 10 },
		context: 'PASSWORD=hunter2butlonger',
		key: 'password',
		description: 'Password',
		...overrides,
	});
}

describe('deduplicateSecrets', () => {
	it('keeps the first of each value/type pair', () => {
		const a = secret();
		const b = secret({ start: 40, end: 56, position: { line: 3, column: 1 } });
		const c = secret({ value: 'other-secret-value', start: 60, end: 78 });
		expect(deduplicateSecrets([a, b, c])).toEqual([a, c]);
	});
});

describe('sanitizeContent', () => {
	const content = 'PASSWORD=hunter2butlonger\nplain\n';

	it('replaces by exact offsets', () => {
		const detected = detectSecretsInContent(content).secrets;
		const result = sanitizeContent(content, detected);
		expect(result.sanitizedContent).toBe('PASSWORD=***REDACTED***\nplain\n');
		expect(result.replacements).toHaveLength(1);
	});

	it('skips stale offsets instead of guessing', () => {
		const stale = secret({ start: 9, end: 25, value: 'not-what-is-there' });
		const result = sanitizeContent(content, [stale]);
		expect(result.sanitizedContent).toBe(content);
		expect(result.replacements).toHaveLength(0);
	});

	it('collapses overlapping detections into one replacement', () => {
		const a = secret();
		const overlapping = secret({ start: 9, end: 25, type: 'token' });
		const result = sanitizeContent(content, [a, overlapping], '[X]');
		expect(result.sanitizedContent).toBe('PASSWORD=[X]\nplain\n');
		expect(result.replacements).toHaveLength(1);
	});
});

describe('formatDetectionResults', () => {
	it('reports a clean scan', () => {
		const output = formatDetectionResults(detectSecretsInContent('nothing'));
		expect(output).toContain('No secrets detected');
	});

	it('groups by file when filepaths are present', () => {
		const withPath = secret({ filepath: 'config/.env' });
		const output = formatDetectionResults({
			success: true,
			secrets: [withPath],
			errors: [],
			warnings: ['Skipped 1 file(s)'],
		});
		expect(output).toContain('config/.env');
		expect(output).toContain('PASSWORD');
		expect(output).toContain('Skipped 1 file(s)');
	});

	it('lists errors', () => {
		const output = formatDetectionResults({
			success: false,
			secrets: [],
			errors: [{ type: 'parse-error', message: 'boom', context: 'ctx' }],
		});
		expect(output).toContain('boom');
	});
});

describe('formatSanitizationResults', () => {
	it('summarizes replacements grouped by type', () => {
		const content = 'PASSWORD=hunter2butlonger\n';
		const result = sanitizeContent(
			content,
			detectSecretsInContent(content).secrets,
		);
		const output = formatSanitizationResults(result);
		expect(output).toContain('Sanitized 1 secret(s)');
		expect(output).toContain('PASSWORD');
		expect(output).toContain('***REDACTED***');
	});
});
