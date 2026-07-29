import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { DetectionResult, SanitizationResult } from '../types';
import { detectSecretsInContent, sanitizeContent } from './extract';

/**
 * Characterization tests: pin the CURRENT detection output per format,
 * including known bugs (multiline PEM blocks never detected by the
 * per-line loop, any x.y.z string flagged as a high-confidence JWT,
 * quoted JSON keys missed by key-based patterns, column pointing at the
 * key instead of the secret value, connection-string emitting the full
 * match as the value). Behavior changes must update these snapshots in
 * the same commit, so every output diff is explicit.
 */

const FIXTURES: readonly string[] = [
	'secrets.env',
	'secrets.json',
	'secrets.yaml',
	'secrets.js',
	'secrets.py',
	'secrets.ini',
	'multiline-key.pem',
	'jwt-lookalikes.txt',
];

function readFixture(name: string): string {
	return readFileSync(join(__dirname, '__fixtures__', name), 'utf8');
}

function normalizeDetection(result: DetectionResult): DetectionResult {
	if (!result.metadata) return result;
	return {
		...result,
		metadata: { ...result.metadata, processingTimeMs: 0 },
	};
}

function normalizeSanitization(result: SanitizationResult): SanitizationResult {
	if (!result.metadata) return result;
	return {
		...result,
		metadata: { ...result.metadata, processingTimeMs: 0 },
	};
}

describe('detection characterization', () => {
	for (const fixture of FIXTURES) {
		it(`${fixture} with default options`, () => {
			const result = detectSecretsInContent(readFixture(fixture));
			expect(normalizeDetection(result)).toMatchSnapshot();
		});
	}

	it('secrets.env at low sensitivity', () => {
		const result = detectSecretsInContent(readFixture('secrets.env'), {
			sensitivity: 'low',
		});
		expect(normalizeDetection(result)).toMatchSnapshot();
	});

	it('secrets.env at high sensitivity', () => {
		const result = detectSecretsInContent(readFixture('secrets.env'), {
			sensitivity: 'high',
		});
		expect(normalizeDetection(result)).toMatchSnapshot();
	});

	it('secrets.env with includeApiKeys disabled', () => {
		const result = detectSecretsInContent(readFixture('secrets.env'), {
			includeApiKeys: false,
		});
		expect(normalizeDetection(result)).toMatchSnapshot();
	});

	it('jwt-lookalikes.txt with includeTokens disabled', () => {
		const result = detectSecretsInContent(readFixture('jwt-lookalikes.txt'), {
			includeTokens: false,
		});
		expect(normalizeDetection(result)).toMatchSnapshot();
	});

	it('secrets.ini with includePasswords disabled', () => {
		const result = detectSecretsInContent(readFixture('secrets.ini'), {
			includePasswords: false,
		});
		expect(normalizeDetection(result)).toMatchSnapshot();
	});

	it('empty content', () => {
		const result = detectSecretsInContent('');
		expect(normalizeDetection(result)).toMatchSnapshot();
	});
});

describe('sanitization characterization', () => {
	it('secrets.env with default replacement', () => {
		const content = readFixture('secrets.env');
		const detection = detectSecretsInContent(content);
		const result = sanitizeContent(content, detection.secrets);
		expect(normalizeSanitization(result)).toMatchSnapshot();
	});

	it('secrets.ini with custom replacement', () => {
		const content = readFixture('secrets.ini');
		const detection = detectSecretsInContent(content);
		const result = sanitizeContent(content, detection.secrets, '[GONE]');
		expect(normalizeSanitization(result)).toMatchSnapshot();
	});
});
