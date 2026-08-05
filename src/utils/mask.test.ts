import { describe, expect, it } from 'vitest';
import { maskSecretValue, maskWithin } from './mask';

describe('maskSecretValue', () => {
	it('never returns the whole value', () => {
		// The property that matters. The previous substring(0, 20) satisfied this
		// for a 40-char AWS secret and failed it for every shorter one.
		// Values of 3+ chars; below that no preview is emitted at all and the
		// "does not contain" check gets confused by single letters appearing in
		// the literal word "chars".
		const values = [
			'abc',
			'hunter2h', // 8 — the password detector's minimum
			'hunter2hunter2', // 14
			'Tr0ub4dor&3xKcd!!!', // 18
			'exactly-twenty-chars', // 20
			'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', // 40, AWS secret
		];
		for (const value of values) {
			expect(maskSecretValue(value)).not.toContain(value);
		}
	});

	it('shows at most half the value', () => {
		expect(maskSecretValue('hunter2hunter2')).toBe('hunter2… (14 chars)');
		expect(maskSecretValue('hunter2h')).toBe('hunt… (8 chars)');
	});

	it('caps the preview regardless of length', () => {
		const aws = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
		expect(maskSecretValue(aws)).toBe('wJalrXUt… (40 chars)');
	});

	it('always marks the value as elided', () => {
		expect(maskSecretValue('abcd')).toContain('…');
	});

	it('reports the true length so similar findings stay distinguishable', () => {
		expect(maskSecretValue('hunter2hunter2')).toContain('(14 chars)');
	});

	it('handles an empty value', () => {
		expect(maskSecretValue('')).toBe('(empty)');
	});

	it('emits no preview at all below three characters', () => {
		// Any preview of a one- or two-character value is the whole value.
		expect(maskSecretValue('x')).toBe('(1 chars)');
		expect(maskSecretValue('xy')).toBe('(2 chars)');
	});
});

describe('maskWithin', () => {
	it('redacts the secret from its own source line', () => {
		// context is the raw line from the file, so it contains the secret it is
		// providing context for.
		const line = 'DATABASE_PASSWORD=hunter2hunter2';
		const masked = maskWithin(line, 'hunter2hunter2');
		expect(masked).not.toContain('hunter2hunter2');
		expect(masked).toContain('DATABASE_PASSWORD=');
	});

	it('redacts every occurrence', () => {
		const line = 'a=secretvalue b=secretvalue';
		const masked = maskWithin(line, 'secretvalue');
		expect(masked).not.toContain('secretvalue');
	});

	it('leaves the line alone when the value is empty', () => {
		expect(maskWithin('KEY=', '')).toBe('KEY=');
	});
});
