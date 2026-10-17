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
			(reply) => written.push(reply),
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

	it('answers no notification and no frame that is not JSON', async () => {
		const { written } = await session([
			{ jsonrpc: '2.0', method: 'notifications/initialized' },
			'not json',
			{ jsonrpc: '2.0', id: 2, method: 'ping' },
		]);
		expect(written).toEqual(['{"id":2,"jsonrpc":"2.0","result":{}}\n']);
	});

	it('ends with exit 2 on a line that is not UTF-8', async () => {
		const written: string[] = [];
		const code = await serve(
			Readable.from([Buffer.from([0x7b, 0xff, 0x7d, 0x0a])]),
			(reply) => written.push(reply),
			'9.9.9',
		);
		expect(code).toBe(2);
	});
});
