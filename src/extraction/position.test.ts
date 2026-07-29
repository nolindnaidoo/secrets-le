import { describe, expect, it } from 'vitest';
import { createPositionIndex, lineTextAt } from './position';

describe('createPositionIndex', () => {
	const content = 'first\nsecond line\n\nfourth';
	const positionAt = createPositionIndex(content);

	it('maps offsets to 1-based line/column', () => {
		expect(positionAt(0)).toEqual({ line: 1, column: 1 });
		expect(positionAt(6)).toEqual({ line: 2, column: 1 });
		expect(positionAt(13)).toEqual({ line: 2, column: 8 });
		expect(positionAt(18)).toEqual({ line: 3, column: 1 });
		expect(positionAt(19)).toEqual({ line: 4, column: 1 });
	});

	it('clamps out-of-range offsets', () => {
		expect(positionAt(-5)).toEqual({ line: 1, column: 1 });
		expect(positionAt(9999).line).toBe(4);
	});

	it('handles empty content', () => {
		expect(createPositionIndex('')(0)).toEqual({ line: 1, column: 1 });
	});
});

describe('lineTextAt', () => {
	const content = 'first\nsecond line\nlast';

	it('returns the full line containing the offset', () => {
		expect(lineTextAt(content, 0)).toBe('first');
		expect(lineTextAt(content, 8)).toBe('second line');
		expect(lineTextAt(content, content.length)).toBe('last');
	});
});
