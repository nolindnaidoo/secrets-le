import { beforeEach, describe, expect, it } from 'vitest';
import { _createDocument, _resetMockState } from '../__mocks__/vscode';
import { CONFIG_DEFAULTS } from '../config/config';
import type { Configuration } from '../types';
import { sanitizeErrorMessage } from './errors';
import { handleSafetyChecks } from './safety';

beforeEach(() => {
	_resetMockState();
});

function config(overrides: Partial<Configuration> = {}): Configuration {
	return Object.freeze({ ...CONFIG_DEFAULTS, ...overrides });
}

describe('sanitizeErrorMessage', () => {
	it('redacts user directories', () => {
		expect(sanitizeErrorMessage('ENOENT /Users/alice/dev/x.txt')).toBe(
			'ENOENT /Users/***/dev/x.txt',
		);
		expect(sanitizeErrorMessage('at /home/bob/app/y')).toBe(
			'at /home/***/app/y',
		);
		expect(sanitizeErrorMessage('C:\\Users\\carol\\z')).toBe(
			'C:\\Users\\***\\z',
		);
	});

	it('redacts credential-shaped fragments', () => {
		expect(sanitizeErrorMessage('failed: password=hunter2 oops')).toBe(
			'failed: password=*** oops',
		);
		expect(sanitizeErrorMessage('token: abc123 rejected')).toBe(
			'token=*** rejected',
		);
		expect(sanitizeErrorMessage('bad key=AKIA123')).toBe('bad key=***');
	});

	it('leaves clean messages untouched', () => {
		expect(sanitizeErrorMessage('plain failure')).toBe('plain failure');
	});
});

describe('handleSafetyChecks', () => {
	it('passes small clean documents', () => {
		const result = handleSafetyChecks(
			_createDocument({ content: 'API_KEY=x\n' }) as never,
			config(),
		);
		expect(result.proceed).toBe(true);
		expect(result.warnings).toEqual([]);
	});

	it('skips all checks when safety is disabled', () => {
		const result = handleSafetyChecks(
			_createDocument({ content: 'x'.repeat(2_000_000) }) as never,
			config({ safetyEnabled: false }),
		);
		expect(result.proceed).toBe(true);
	});

	it('blocks documents over the size threshold', () => {
		const result = handleSafetyChecks(
			_createDocument({ content: 'x'.repeat(2000) }) as never,
			config({ safetyFileSizeWarnBytes: 1000 }),
		);
		expect(result.proceed).toBe(false);
		expect(result.message).toContain('exceeds safety threshold');
	});

	it('warns on binary-looking content without blocking', () => {
		const result = handleSafetyChecks(
			_createDocument({ content: 'abc\x00def' }) as never,
			config(),
		);
		expect(result.proceed).toBe(true);
		expect(result.warnings[0]).toContain('binary');
	});

	it('warns on very long documents without blocking', () => {
		const result = handleSafetyChecks(
			_createDocument({ content: 'a\n'.repeat(10_001) }) as never,
			config(),
		);
		expect(result.proceed).toBe(true);
		expect(result.warnings[0]).toMatch(/lines/);
	});
});
