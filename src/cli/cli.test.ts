import {
	mkdirSync,
	mkdtempSync,
	rmdirSync,
	unlinkSync,
	writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { afterAll, describe, expect, it } from 'vitest';
import { DEFAULT_OPTIONS, parse } from './args';
import { serve } from './mcp';
import { run } from './run';
import {
	exitCode,
	type FileReport,
	describe as line,
	scanContent,
} from './scan';
import { FLAGS, USAGE } from './usage';
import { collect } from './walk';

// Assembled, not written whole, so this file is not itself a finding.
const TOKEN = ['gh', 'p_', 'abcdefghijklmnopqrstuvwxyz0123456789'].join('');
const DOCUMENT = `GITHUB_TOKEN=${TOKEN}\n`;

describe('usage', () => {
	it('names every flag the parser accepts, and no other', () => {
		const named = new Set(
			USAGE.split(/\s+/)
				.filter((word) => word.startsWith('--'))
				.map((word) => word.replace(/[,.:;]+$/, ''))
				.filter((word) => word !== '--version' && word !== '--help'),
		);
		expect([...named].sort()).toEqual([...FLAGS].sort());
	});

	it('offers no way to print a value', () => {
		for (const flag of ['--show', '--reveal', '--no-mask', '--raw'])
			expect(() => parse([flag, 'x'])).toThrow('is not an option');
	});
});

describe('parse', () => {
	it('turns each detector off by its own switch', () => {
		const cli = parse(['--no-tokens', '--no-private-keys', 'x']);
		expect(cli.options).toEqual({
			...DEFAULT_OPTIONS,
			tokens: false,
			privateKeys: false,
		});
	});

	it('refuses what the crate refuses, in its words', () => {
		expect(() => parse(['--sensitivity'])).toThrow(
			'--sensitivity needs a level',
		);
		expect(() => parse(['--sensitivity', 'HIGH', 'x'])).toThrow(
			'HIGH is not a sensitivity; one of: low, medium, high',
		);
		expect(() => parse(['-', 'x'])).toThrow('- is not an option. Try --help.');
		expect(() => parse(['--stdin', 'x'])).toThrow('takes no file arguments');
		expect(() => parse([])).toThrow('name a file or a directory to scan');
		expect(parse(['constructor']).inputs).toEqual(['constructor']);
	});

	it('takes the value after --sensitivity even when it looks like a flag', () => {
		expect(() => parse(['--sensitivity', '--strict', 'x'])).toThrow(
			'--strict is not a sensitivity',
		);
	});
});

describe('scanContent', () => {
	it('writes the crate field order and never the value', () => {
		const report = scanContent(DOCUMENT, 'a.env', DEFAULT_OPTIONS);
		const json = JSON.stringify(report);
		expect(json).not.toContain(TOKEN);
		expect(json).toBe(
			'{"file":"a.env","findings":[{"type":"token","confidence":"high","key":"github_token","preview":"ghp_abcd… (40 chars)","context":"GITHUB_TOKEN=ghp_abcd… (40 chars)","line":1,"column":14,"description":"Generic token"}],"diagnostics":[],"summary":{"findings":1,"high":1,"medium":0,"low":0}}',
		);
	});

	it('drops a byte-order mark, so stdin and a file agree on columns', () => {
		const report = scanContent(`﻿${DOCUMENT}`, 'a.env', DEFAULT_OPTIONS);
		expect(report.findings[0]?.column).toBe(14);
	});
});

describe('exitCode', () => {
	const of = (findings: number, code?: string, severity = 'warning') =>
		({
			file: 'x',
			findings: [],
			diagnostics: code ? [{ severity, code, message: 'm' }] : [],
			summary: { findings, high: 0, medium: 0, low: 0 },
		}) as FileReport;

	it('reports the worst outcome, and fails a skipped file only under --strict', () => {
		expect(exitCode([of(0)], false)).toBe(0);
		expect(exitCode([of(1)], false)).toBe(1);
		expect(exitCode([of(1), of(0, 'skipped')], false)).toBe(1);
		expect(exitCode([of(0, 'skipped')], true)).toBe(2);
		expect(exitCode([of(1), of(0, 'incomplete', 'error')], false)).toBe(2);
	});

	it('describes a finding without its value', () => {
		const report = scanContent(DOCUMENT, 'a.env', DEFAULT_OPTIONS);
		const finding = report.findings[0];
		if (!finding) throw new Error('no finding');
		expect(line(report, finding)).toBe(
			'a.env:1:14  token github_token  ghp_abcd… (40 chars)  [high]',
		);
	});
});

describe('collect', () => {
	const root = mkdtempSync(join(tmpdir(), 'secrets-le-walk-'));
	const dirs = ['.git', 'node_modules', 'sub'];
	const files: Record<string, string> = {
		'.gitignore': '.env\nserver.pem\nnode_modules/\n',
		'.env': 'x',
		'server.pem': 'x',
		'node_modules/.npmrc': 'x',
		'a.txt': 'x',
		'sub/b.txt': 'x',
		'.hidden.txt': 'x',
	};
	for (const name of dirs) mkdirSync(join(root, name));
	for (const [name, content] of Object.entries(files))
		writeFileSync(join(root, name), content);

	afterAll(() => {
		for (const name of Object.keys(files)) unlinkSync(join(root, name));
		for (const name of [...dirs].reverse()) rmdirSync(join(root, name));
		rmdirSync(root);
	});

	const relative = (paths: readonly string[]) =>
		paths.map((path) => path.slice(root.length + 1).replaceAll('\\', '/'));

	it('counts what the rules kept out and names what looks like a credential', () => {
		const walked = collect([root], { hidden: false, respectIgnore: true });
		expect(relative(walked.files)).toEqual(['a.txt', 'sub/b.txt']);
		expect(walked.skipped).toBe(5);
		expect(relative(walked.skippedOfNote)).toEqual(['.env', 'server.pem']);
	});

	it('counts nothing when nothing was kept out', () => {
		const walked = collect([root], { hidden: true, respectIgnore: false });
		expect(walked.skipped).toBe(0);
		expect(walked.files).toHaveLength(7);
	});

	it('refuses a path that does not exist, naming it', () => {
		expect(() =>
			collect([join(root, 'missing')], { hidden: false, respectIgnore: true }),
		).toThrow(`${join(root, 'missing')}: `);
	});
});

describe('run', () => {
	const io = (input: Uint8Array) => {
		const out: string[] = [];
		const err: string[] = [];
		return {
			out,
			err,
			io: {
				stdout: (text: string) => out.push(text),
				stderr: (text: string) => err.push(text),
				stdoutIsTerminal: false,
				readStdin: async () => input,
				version: '9.9.9',
			},
		};
	};

	it('scans stdin, exits 1 on a finding, and prints no value', async () => {
		const { out, err, io: streams } = io(Buffer.from(DOCUMENT));
		expect(await run(['--stdin'], streams)).toBe(1);
		expect(`${out.join('')}${err.join('')}`).not.toContain(TOKEN);
		expect(err.join('')).toBe(
			'<stdin>:1:14  token github_token  ghp_abcd… (40 chars)  [high]\n1 finding in 1 file\n',
		);
	});

	it('refuses stdin that is not UTF-8', async () => {
		const { err, io: streams } = io(Buffer.from([0x70, 0xff]));
		expect(await run(['--stdin'], streams)).toBe(2);
		expect(err.join('')).toBe(
			'secrets-le: could not read stdin: stream did not contain valid UTF-8\n',
		);
	});

	it('answers --version only as the first argument', async () => {
		const { out, io: streams } = io(Buffer.alloc(0));
		expect(await run(['-V'], streams)).toBe(0);
		expect(out.join('')).toBe('secrets-le 9.9.9\n');
	});
});

describe('mcp', () => {
	const session = async (requests: readonly unknown[]) => {
		const written: string[] = [];
		const input = `${requests.map((request) => JSON.stringify(request)).join('\n')}\n`;
		const code = await serve(
			Readable.from([Buffer.from(input)]),
			(reply) => {
				written.push(reply);
				return undefined;
			},
			'9.9.9',
		);
		return { code, written };
	};

	it('sorts every key, as a serde_json Value does, and returns no value', async () => {
		const { written } = await session([
			{
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'detect_secrets', arguments: { content: DOCUMENT } },
			},
		]);
		const reply = written[0] ?? '';
		expect(
			reply.startsWith('{"id":1,"jsonrpc":"2.0","result":{"content":'),
		).toBe(true);
		expect(reply).not.toContain(TOKEN);
	});
});

describe('mcp: the crate framing', () => {
	// The protocol around the tools answers as the extension's server and
	// the crate's answer, so a client cannot tell the three apart by what it
	// sent. Replies are parsed: key order is the crate's concern, not this one.
	async function session(
		lines: readonly (string | Uint8Array)[],
	): Promise<{ status: number; replies: unknown[] }> {
		const written: string[] = [];
		const input = Readable.from(lines.map((item) => Buffer.from(item)));
		const status = await serve(
			input,
			(line) => {
				written.push(line);
				return undefined;
			},
			'9.9.9',
		);
		return { status, replies: written.map((line) => JSON.parse(line)) };
	}

	it("answers a malformed frame in the extension server's words and serves the next line", async () => {
		// A frame that is not JSON, or not UTF-8, was dropped without a word,
		// and a client lost every request it then waited on.
		const { status, replies } = await session([
			'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n',
			'{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
			'not json\n',
			Uint8Array.from([0x7b, 0xff, 0x7d, 0x0a]),
			'   \n',
			'{"jsonrpc":"2.0","id":2,"method":"nope"}\n',
		]);
		expect(status).toBe(0);
		expect(replies).toEqual([
			{
				jsonrpc: '2.0',
				id: 1,
				result: {
					protocolVersion: '2025-06-18',
					capabilities: { tools: {} },
					serverInfo: { name: 'secrets-le', version: '9.9.9' },
				},
			},
			{
				jsonrpc: '2.0',
				id: null,
				error: { code: -32700, message: 'Invalid JSON' },
			},
			{
				jsonrpc: '2.0',
				id: null,
				error: { code: -32700, message: 'Invalid JSON' },
			},
			{
				jsonrpc: '2.0',
				id: 2,
				error: { code: -32601, message: 'Unknown method: nope' },
			},
		]);
	});

	it('refuses malformed frames in the words the other two servers use, and a null id is a notification', async () => {
		const { replies } = await session([
			'{"id":1,"method":"ping"}\n',
			'{"jsonrpc":"1.0","id":2,"method":"ping"}\n',
			'[{"jsonrpc":"2.0","id":3,"method":"ping"}]\n',
			'{"jsonrpc":"2.0","id":null,"method":"ping"}\n',
			'{"jsonrpc":"2.0","id":4,"method":"notifications/initialized"}\n',
			'{"jsonrpc":"2.0","id":5,"method":"tools/call","params":5}\n',
			'{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nope"}}\n',
			'{"jsonrpc":"2.0","id":7,"method":"tools/call"}\n',
			'{"jsonrpc":"2.0","id":8,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}\n',
		]);
		const refused = {
			jsonrpc: '2.0',
			id: null,
			error: { code: -32700, message: 'Not a JSON-RPC 2.0 request' },
		};
		expect(replies).toEqual([
			refused,
			refused,
			refused,
			{
				jsonrpc: '2.0',
				id: 4,
				error: {
					code: -32601,
					message: 'Unknown method: notifications/initialized',
				},
			},
			{
				jsonrpc: '2.0',
				id: 5,
				error: { code: -32602, message: 'tools/call requires a string `name`' },
			},
			{
				jsonrpc: '2.0',
				id: 6,
				error: { code: -32602, message: 'Unknown tool: nope' },
			},
			{
				jsonrpc: '2.0',
				id: 7,
				error: { code: -32602, message: 'tools/call requires a string `name`' },
			},
			{
				jsonrpc: '2.0',
				id: 8,
				result: {
					capabilities: { tools: {} },
					protocolVersion: '2025-06-18',
					serverInfo: { name: 'secrets-le', version: '9.9.9' },
				},
			},
		]);
	});

	it('waits for the pipe to drain before reading the next frame', async () => {
		const lines: string[] = [];
		let drained = 0;
		const input = Readable.from([
			Buffer.from(
				'{"jsonrpc":"2.0","id":1,"method":"ping"}\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n',
			),
		]);
		const write = (line: string) => {
			lines.push(line);
			return new Promise<void>((resolve) =>
				setTimeout(() => {
					drained += 1;
					resolve();
				}, 1),
			);
		};
		await serve(input, write, '9.9.9');
		expect(lines).toHaveLength(2);
		expect(drained).toBe(2);
	});
});
