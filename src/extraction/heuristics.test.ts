import { describe, expect, it } from 'vitest';
import {
	confidenceByLength,
	isJwtShaped,
	looksLikePlaceholder,
} from './heuristics';

describe('looksLikePlaceholder', () => {
	it('rejects template markers', () => {
		// biome-ignore lint/suspicious/noTemplateCurlyInString: literal placeholder is the input under test
		expect(looksLikePlaceholder('${API_KEY}')).toBe(true);
		expect(looksLikePlaceholder('{{ secret }}')).toBe(true);
		expect(looksLikePlaceholder('<your-api-key>')).toBe(true);
	});

	it('rejects single-character runs', () => {
		expect(looksLikePlaceholder('xxxxxxxxxx')).toBe(true);
		expect(looksLikePlaceholder('**********')).toBe(true);
	});

	it('accepts realistic secret values', () => {
		expect(looksLikePlaceholder('sk_live_abcdef123456')).toBe(false);
		expect(looksLikePlaceholder('hunter2butlonger')).toBe(false);
	});
});

describe('confidenceByLength', () => {
	it('tiers by the given cut-offs', () => {
		expect(confidenceByLength('a'.repeat(32), 32, 20)).toBe('high');
		expect(confidenceByLength('a'.repeat(20), 32, 20)).toBe('medium');
		expect(confidenceByLength('a'.repeat(10), 32, 20)).toBe('low');
	});
});

describe('isJwtShaped', () => {
	it('accepts three base64url segments with the eyJ header', () => {
		expect(
			isJwtShaped('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123-_'),
		).toBe(true);
	});

	it('rejects dotted triples without the JSON header', () => {
		expect(isJwtShaped('1.2.3')).toBe(false);
		expect(isJwtShaped('docs.example.com')).toBe(false);
		expect(isJwtShaped('lodash.debounce.min')).toBe(false);
	});
});
