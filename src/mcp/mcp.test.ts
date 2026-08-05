import { EventEmitter } from 'node:events';
import { describe, expect, it } from 'vitest';
import type { DetectionResult } from '../types';
import { capped, isOk, readMaxResults, toDiagnostics } from './envelope';
import { TOOLS } from './tools';
import { createResponder, serve } from './transport';

/**
 * The MCP layer: the normalisation boundary, the tool table and the protocol.
 *
 * Everything else in the family is tested for what it returns. The property
 * that matters most here is what it must NOT return: `DetectedSecret.value` is
 * a live credential and `context` is the raw source line containing it, and
 * this server's output goes to whatever cloud model called the tool.
 */

const AWS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const DOCUMENT = `AWS_SECRET_ACCESS_KEY=${AWS_KEY}`;

const emptyResult: DetectionResult = Object.freeze({
	success: true,
	secrets: Object.freeze([]),
	errors: Object.freeze([]),
	warnings: Object.freeze([]),
});

const call = async (args: Record<string, unknown>) => {
	const tool = TOOLS[0];
	if (!tool) throw new Error('no tool');
	return (await tool.handler(args)) as {
		ok: boolean;
		data: {
			secrets: {
				type: string;
				key?: string;
				preview: string;
				context?: string;
				line?: number;
			}[];
		};
		meta: { count: number; truncated: boolean };
	};
};

describe('detect_secrets never returns a secret', () => {
	it('does not contain the value anywhere in its output', () => {
		// Serialising the whole envelope rather than checking known fields: a new
		// field added to DetectedSecret must not be able to smuggle the value out
		// through a path this test did not think to look at.
		return call({ content: DOCUMENT }).then((result) => {
			expect(result.data.secrets.length).toBeGreaterThan(0);
			expect(JSON.stringify(result)).not.toContain(AWS_KEY);
		});
	});

	it('masks the value inside the context line', async () => {
		const result = await call({ content: DOCUMENT });
		const context = result.data.secrets[0]?.context;
		if (context !== undefined) {
			expect(context).not.toContain(AWS_KEY);
		}
	});

	it('gives a preview that is never the whole value', async () => {
		const result = await call({ content: DOCUMENT });
		const preview = result.data.secrets[0]?.preview ?? '';
		expect(preview).not.toBe(AWS_KEY);
		expect(preview.length).toBeLessThan(AWS_KEY.length);
	});

	it('still reports enough to locate the finding', async () => {
		// Masking is only acceptable because the finding stays actionable: the
		// caller has the file, so type, key and position are enough.
		const result = await call({ content: DOCUMENT });
		const finding = result.data.secrets[0];
		expect(finding?.type).toBeTruthy();
		expect(finding?.key).toBe('aws_secret_access_key');
		expect(finding?.line).toBe(1);
	});

	it('reports a short secret by length rather than showing it', async () => {
		// The masking helper degrades to a length for values too short to preview
		// safely; the tool must not have a path that bypasses it.
		const result = await call({ content: 'PASSWORD=abcdefgh' });
		for (const finding of result.data.secrets) {
			expect(finding.preview).not.toBe('abcdefgh');
		}
	});
});

describe('envelope: ok reports the scan, not the findings', () => {
	it('is ok for a clean document', () => {
		expect(isOk(toDiagnostics(emptyResult))).toBe(true);
	});

	it('is not ok when the scan itself failed', () => {
		// A crashed scan reported as clean is the dangerous direction of this bug.
		expect(
			isOk(
				toDiagnostics({
					...emptyResult,
					errors: [{ type: 'parse-error', message: 'boom' }],
				}),
			),
		).toBe(false);
	});

	it('carries warnings through without failing the scan', () => {
		const diagnostics = toDiagnostics({
			...emptyResult,
			warnings: ['partial'],
		});
		expect(diagnostics[0]?.severity).toBe('warning');
		expect(isOk(diagnostics)).toBe(true);
	});
});

describe('envelope: result cap', () => {
	it('reports truncation honestly when it drops items', () => {
		const { items, truncated } = capped([1, 2, 3, 4, 5], 2);
		expect(items).toEqual([1, 2]);
		expect(truncated).toBe(true);
	});

	it('does not claim truncation when everything fits', () => {
		const { items, truncated } = capped([1, 2], 5);
		expect(items).toHaveLength(2);
		expect(truncated).toBe(false);
	});

	it('rejects a maxResults a tool cannot honour', () => {
		expect(() => readMaxResults({ maxResults: 0 })).toThrow(/positive integer/);
		expect(() => readMaxResults({ maxResults: 1.5 })).toThrow();
		expect(() => readMaxResults({ maxResults: 'ten' })).toThrow();
	});

	it('clamps an oversized request rather than refusing it', () => {
		expect(readMaxResults({ maxResults: 999999 })).toBe(5000);
	});
});

describe('tool table', () => {
	it('pins the tool names', () => {
		expect(TOOLS.map((t) => t.name)).toEqual(['detect_secrets']);
	});

	it('exposes no way to turn masking off', () => {
		// There must be no `includeValues`, `raw` or `unmasked` escape hatch: the
		// schema is closed, so anything not listed is rejected outright.
		const schema = TOOLS[0]?.inputSchema as {
			properties: Record<string, unknown>;
			additionalProperties: boolean;
		};
		expect(schema.additionalProperties).toBe(false);
		for (const name of Object.keys(schema.properties)) {
			expect(name).not.toMatch(/raw|unmask|plain|value/i);
		}
	});

	it('gives every tool a description and a closed schema', () => {
		for (const tool of TOOLS) {
			expect(tool.description.length).toBeGreaterThan(20);
			expect(tool.inputSchema.type).toBe('object');
			expect(typeof tool.handler).toBe('function');
		}
	});

	it('caps results by default rather than leaving it unbounded', () => {
		const schema = TOOLS[0]?.inputSchema as {
			properties: { maxResults: { default: number } };
		};
		expect(schema.properties.maxResults.default).toBe(500);
	});
});

describe('detect_secrets: arguments', () => {
	it('narrows the scan only on an explicit false', async () => {
		const all = await call({ content: DOCUMENT });
		const narrowed = await call({ content: DOCUMENT, includeApiKeys: false });
		expect(all.meta.count).toBeGreaterThanOrEqual(narrowed.meta.count);
	});

	it('rejects a sensitivity the engine does not have', async () => {
		await expect(
			call({ content: DOCUMENT, sensitivity: 'paranoid' }),
		).rejects.toThrow(/sensitivity must be one of/);
	});

	it('truncates at maxResults and says so', async () => {
		const content = Array.from(
			{ length: 10 },
			(_, i) => `API_KEY_${i}=sk_live_4eC39HqLyjWDarjtT1zdp7d${i}`,
		).join('\n');
		const result = await call({ content, maxResults: 3 });
		expect(result.meta.count).toBe(3);
		expect(result.meta.truncated).toBe(true);
	});

	it('requires content', async () => {
		await expect(call({})).rejects.toThrow(/content is required/);
	});
});

describe('protocol', () => {
	const respond = createResponder(
		{ name: 'secrets-le', version: '1.0.0' },
		TOOLS,
	);

	it('echoes the protocol version the client asked for', async () => {
		const reply = await respond({
			jsonrpc: '2.0',
			id: 1,
			method: 'initialize',
			params: { protocolVersion: '2024-11-05' },
		});
		expect(reply?.result?.protocolVersion).toBe('2024-11-05');
		expect(reply?.result?.serverInfo).toEqual({
			name: 'secrets-le',
			version: '1.0.0',
		});
	});

	it('does not reply to a notification', async () => {
		// A reply to a notification is the classic way to wedge a client.
		expect(
			await respond({ jsonrpc: '2.0', method: 'notifications/initialized' }),
		).toBeNull();
	});

	it('reports an unknown method as a JSON-RPC error', async () => {
		const reply = await respond({ jsonrpc: '2.0', id: 2, method: 'nope' });
		expect(reply?.error?.code).toBe(-32601);
	});

	it('reports an unknown tool without killing the connection', async () => {
		const reply = await respond({
			jsonrpc: '2.0',
			id: 3,
			method: 'tools/call',
			params: { name: 'no_such_tool', arguments: {} },
		});
		expect(reply?.error?.code).toBe(-32602);
	});

	it('returns a tool failure as a result, not a protocol error', async () => {
		// A model can read an isError result and correct itself; a JSON-RPC error
		// reads as "the server is broken".
		const reply = await respond({
			jsonrpc: '2.0',
			id: 4,
			method: 'tools/call',
			params: { name: 'detect_secrets', arguments: {} },
		});
		expect(reply?.error).toBeUndefined();
		expect(reply?.result?.isError).toBe(true);
	});
});

describe('serve: the stdio loop', () => {
	/** A fake stdin/stdout pair so the loop can be driven without a process. */
	function harness() {
		const input = new EventEmitter() as EventEmitter & {
			setEncoding?: (e: string) => void;
		};
		const written: string[] = [];
		const output = {
			write: (chunk: string) => {
				written.push(chunk);
				return true;
			},
		};
		serve(
			{ name: 'secrets-le', version: '1.0.0' },
			TOOLS,
			input as never,
			output as never,
		);
		const replies = () =>
			written
				.join('')
				.split('\n')
				.filter(Boolean)
				.map((l) => JSON.parse(l));
		return { input, replies };
	}

	const settle = () => new Promise((r) => setTimeout(r, 20));

	it('answers a request delivered as one line', async () => {
		const { input, replies } = harness();
		input.emit('data', '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n');
		await settle();
		expect(replies()[0]?.result?.tools).toHaveLength(1);
	});

	it('reassembles a request split across chunks', async () => {
		// stdin delivers whatever the OS gives it; a request arriving in two
		// pieces must not be dropped or double-parsed.
		const { input, replies } = harness();
		input.emit('data', '{"jsonrpc":"2.0","id":2,"me');
		input.emit('data', 'thod":"ping"}\n');
		await settle();
		expect(replies()[0]?.id).toBe(2);
	});

	it('handles several requests in one chunk', async () => {
		const { input, replies } = harness();
		input.emit(
			'data',
			'{"jsonrpc":"2.0","id":3,"method":"ping"}\n{"jsonrpc":"2.0","id":4,"method":"ping"}\n',
		);
		await settle();
		expect(replies().map((r) => r.id)).toEqual([3, 4]);
	});

	it('reports malformed JSON without dying', async () => {
		// One bad line from a client must not take the server down for everyone.
		const { input, replies } = harness();
		input.emit('data', 'not json at all\n');
		input.emit('data', '{"jsonrpc":"2.0","id":5,"method":"ping"}\n');
		await settle();
		expect(replies()[0]?.error?.code).toBe(-32700);
		expect(replies()[1]?.id).toBe(5);
	});

	it('rejects a payload that is not a JSON-RPC request', async () => {
		const { input, replies } = harness();
		input.emit('data', '{"hello":"world"}\n');
		await settle();
		expect(replies()[0]?.error?.code).toBe(-32700);
	});

	it('ignores blank lines', async () => {
		const { input, replies } = harness();
		input.emit('data', '\n\n{"jsonrpc":"2.0","id":6,"method":"ping"}\n');
		await settle();
		expect(replies()).toHaveLength(1);
	});

	it('writes nothing for a notification', async () => {
		const { input, replies } = harness();
		input.emit(
			'data',
			'{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
		);
		await settle();
		expect(replies()).toHaveLength(0);
	});
});
