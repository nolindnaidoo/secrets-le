/**
 * `detect_secrets` is offered by BOTH servers — the npm one in
 * `src/mcp/tools.ts` and the Rust one in `crate/src/mcp/detect.rs`. One tool
 * name, one schema, two implementations. An agent asking that tool must get
 * the same answer whichever server it happens to reach, so the contract is
 * byte-identical output, not merely similar output.
 *
 * `crate/fixtures/mcp-detect-secrets.json` pins that over cases somebody
 * thought of. This generates them instead: hundreds of documents built by
 * combining a format, a value, and a wrapper, fed to both servers, compared
 * whole. The hand-written corpus cannot find the case nobody imagined; this
 * can.
 *
 * It also holds the property the product rests on, over every generated
 * document: **no answer from either server may contain a value it detected.**
 * Not the finding's own value, and not the one beside it on the same line —
 * that second case is a real leak this check found.
 *
 * What is NOT compared here: the CLI against the extension. Those are two
 * surfaces with two jobs — an editor showing one buffer, and a terminal
 * walking a tree for a CI step to fail on — and they are allowed to differ.
 * Deliberate divergences live in crate/SPEC.md. Only the shared tool is held
 * to byte-identity.
 *
 * Run: bun scripts/check-detection-differential.ts
 *   SECRETS_LE_DIFFERENTIAL_SEED=<n>  reproduce a specific failure
 *   SECRETS_LE_DIFFERENTIAL_CASES=<n> how many documents (default 600)
 *   SECRETS_LE_BIN=<path>             the Rust binary (default the release build)
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { detectSecrets } from '../src/extraction/detectors';
import { TOOLS } from '../src/mcp/tools';

const ROOT = join(import.meta.dir, '..');
const BINARY =
	process.env.SECRETS_LE_BIN ?? join(ROOT, 'crate', 'target', 'release', 'secrets-le');

const SEED = Number(process.env.SECRETS_LE_DIFFERENTIAL_SEED ?? 20260812);
const CASES = Number(process.env.SECRETS_LE_DIFFERENTIAL_CASES ?? 600);

/**
 * A named, seeded, entirely ordinary pseudo-random source, so a failing run
 * reproduces from one number. Mulberry32 — three lines, no dependency.
 */
function seeded(seed: number): () => number {
	let state = seed >>> 0;
	return () => {
		state = (state + 0x6d2b79f5) >>> 0;
		let t = state;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

/**
 * Every credential below is invented for this file. Nothing here is a real
 * key, and nothing is read from the machine running it.
 */
const VALUES: readonly string[] = [
	'hunter2hunter2',
	'hunter2hunter2hunter2',
	'aB3xY7zQ9mK2pL5vN8wR4tS6',
	'aB3xY7zQ9mK2pL5vN8wR4tS6aB3xY7zQ9mK2pL5v',
	'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
	'AKIAIOSFODNN7EXAMPLE',
	'ghp_1234567890abcdefghijklmnopqrstuvwxyz',
	'sk_live_abcdefghijklmnop1234',
	'sk_test_abcdefghijklmnop1234',
	'xoxb-1234567890-abcdefghij',
	'AIzaSyA1234567890abcdefghijklmnopqrstuvw',
	'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
	'postgres://user:pass@db.example.invalid:5432/app',
	'mongodb+srv://admin:letmein@cluster.example.invalid/db',
	'Server=prod;Database=app;Uid=admin;Pwd=secret123;',
	// Deliberate non-secrets: placeholders, version numbers, module paths.
	'${DATABASE_PASSWORD}',
	'{{secret}}',
	'<your-key-here>',
	'xxxxxxxxxxxxxxxxxxxx',
	'1.2.3',
	'src.utils.helper',
	// Awkward text: astral characters, combining marks, quotes.
	'p\u{1f3af}ssword\u{1f3af}value\u{1f3af}',
	'cafécafécafécafé',
	'value"with\'quotes-and_more',
];

const KEYS: readonly string[] = [
	'password',
	'DATABASE_PASSWORD',
	'db_password',
	'passwd',
	'pwd',
	'api_key',
	'apiKey',
	'APIKEY',
	'aws_secret_access_key',
	'AWS_SECRET_ACCESS_KEY',
	'access_token',
	'refresh_token',
	'oauth_token',
	'oauth2_token',
	'jwt',
	'json_web_token',
	'token',
	'secret_token',
	'session_id',
	'sessionid',
	'cookie',
	'set-cookie',
	'connection_string',
	'conn_string',
	'azure_account_key',
	'accountkey',
	'gcp_key',
	'google_cloud_key',
	// Names no detector claims, so a document can also be clean.
	'note',
	'label',
	'comment',
];

const PEM = [
	'-----BEGIN RSA PRIVATE KEY-----',
	'MIIEowIBAAKCAQEAxGqVvL3nOFakeKeyMaterialForTestsOnlyNotARealKey0',
	'-----END RSA PRIVATE KEY-----',
].join('\n');

/** How the key/value pair is dressed. */
type Wrapper = (key: string, value: string) => string;

const WRAPPERS: readonly (readonly [string, Wrapper])[] = [
	['bare', (k, v) => `${k}=${v}`],
	['spaced', (k, v) => `${k} = ${v}`],
	['double-quoted', (k, v) => `${k} = "${v}"`],
	['single-quoted', (k, v) => `${k} = '${v}'`],
	['json', (k, v) => `  "${k}": "${v}",`],
	['yaml', (k, v) => `${k}: ${v}`],
	['line-comment', (k, v) => `// ${k}=${v}`],
	['hash-comment', (k, v) => `# ${k}=${v}`],
	['block-comment', (k, v) => `/* ${k}: ${v} */`],
	['xml-attribute', (k, v) => `<config ${k}="${v}" />`],
	['mid-line', (k, v) => `const config = { ${k}: '${v}' }; // set at build time`],
	['header', (_k, v) => `Authorization: Bearer ${v}`],
	['indented', (k, v) => `        ${k}: ${v}`],
	// The shape that carried a real leak: two credentials on one line, so
	// each finding's context holds the other one.
	['two-on-a-line', (k, v) => `${k}=${v} api_key=abcdefghijklmnopqrstuvwx`],
	// The shape the context window exists for: a line far longer than the
	// window, with the value in the middle of it.
	[
		'long-line',
		(k, v) => `${'z'.repeat(200)} ${k}=${v} ${'y'.repeat(200)}`,
	],
	// An astral character right where the window is cut, which is where two
	// implementations counting code units differently would disagree.
	[
		'astral-at-the-window-edge',
		(k, v) => `${'\u{1f3af}'.repeat(40)} ${k}=${v} ${'\u{1f3af}'.repeat(40)}`,
	],
];

const PREAMBLES: readonly string[] = [
	'',
	'# generated file, do not edit\n',
	'﻿',
	'\r\n',
	'const total = 1 + 2;\n\n',
	'\u{1f3af} unicode ahead\n',
];

const TERMINATORS: readonly string[] = ['\n', '\r\n', '', '\n\n'];

interface Document {
	readonly name: string;
	readonly content: string;
	/** The value planted in it, for the never-leak check. */
	readonly planted: readonly string[];
}

function generate(count: number, seed: number): Document[] {
	const random = seeded(seed);
	const pick = <T>(list: readonly T[]): T =>
		list[Math.floor(random() * list.length)] as T;
	const documents: Document[] = [];

	for (let index = 0; index < count; index++) {
		const key = pick(KEYS);
		const value = pick(VALUES);
		const [wrapperName, wrapper] = pick(WRAPPERS);
		const preamble = pick(PREAMBLES);
		const terminator = pick(TERMINATORS);

		let body = wrapper(key, value);
		// Every so often, a PEM block as well — the one multiline pattern.
		if (random() < 0.08) body = `${body}\n${PEM}`;
		// And every so often, a second pair, to exercise dedupe and ordering.
		if (random() < 0.2) body = `${body}\n${pick(KEYS)} = ${pick(VALUES)}`;

		documents.push({
			name: `${index}:${wrapperName}:${key}`,
			content: `${preamble}${body}${terminator}`,
			planted: [value, 'abcdefghijklmnopqrstuvwx'],
		});
	}
	return documents;
}

/** JSON with object keys in a fixed order, so "identical" means identical. */
function canonical(value: unknown): string {
	if (value === null || typeof value !== 'object') return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
	const entries = Object.entries(value as Record<string, unknown>)
		.filter(([, item]) => item !== undefined)
		.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
	return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
}

/** Readable enough to act on, short enough to read. */
function show(text: string): string {
	const escaped = JSON.stringify(text);
	return escaped.length > 400 ? `${escaped.slice(0, 400)}…"` : escaped;
}

async function fromNpm(documents: readonly Document[]): Promise<string[]> {
	const tool = TOOLS.find((candidate) => candidate.name === 'detect_secrets');
	if (!tool) throw new Error('the npm server no longer offers detect_secrets');
	const answers: string[] = [];
	for (const document of documents) {
		answers.push(
			canonical(
				JSON.parse(
					JSON.stringify(
						await tool.handler({
							content: document.content,
							sensitivity: 'low',
						}),
					),
				),
			),
		);
	}
	return answers;
}

async function fromCrate(documents: readonly Document[]): Promise<string[]> {
	if (!existsSync(BINARY)) {
		throw new Error(
			`no binary at ${BINARY} — build it first: cd crate && cargo build --release`,
		);
	}
	const child = Bun.spawn([BINARY, 'mcp'], {
		stdin: 'pipe',
		stdout: 'pipe',
		stderr: 'pipe',
	});
	// Drained concurrently with the write. A few hundred replies are larger
	// than a pipe buffer, so writing everything first and reading afterwards
	// deadlocks the two processes against each other.
	const draining = new Response(child.stdout).text();

	const requests = documents
		.map((document, id) =>
			JSON.stringify({
				jsonrpc: '2.0',
				id,
				method: 'tools/call',
				params: {
					name: 'detect_secrets',
					arguments: { content: document.content, sensitivity: 'low' },
				},
			}),
		)
		.join('\n');
	child.stdin.write(`${requests}\n`);
	child.stdin.end();

	const stdout = await draining;
	await child.exited;

	const answers: string[] = new Array(documents.length);
	for (const line of stdout.split('\n')) {
		if (line.trim().length === 0) continue;
		const response = JSON.parse(line) as {
			id: number;
			result?: { structuredContent?: unknown };
			error?: unknown;
		};
		if (response.error !== undefined) {
			throw new Error(
				`the crate server refused document ${response.id}: ${JSON.stringify(response.error)}`,
			);
		}
		answers[response.id] = canonical(response.result?.structuredContent);
	}
	const missing = answers.findIndex((answer) => answer === undefined);
	if (missing !== -1) {
		throw new Error(
			`the crate server never answered document ${missing}: ${await new Response(child.stderr).text()}`,
		);
	}
	return answers;
}

const documents = generate(CASES, SEED);
console.log(
	`differential: ${documents.length} generated documents, seed ${SEED}, binary ${BINARY.replace(ROOT, '.')}`,
);

const [npm, crate] = await Promise.all([fromNpm(documents), fromCrate(documents)]);
const failures: string[] = [];

for (const [index, document] of documents.entries()) {
	if (npm[index] !== crate[index]) {
		failures.push(
			`the two detect_secrets servers disagree on "${document.name}"\n` +
				`  seed:     ${SEED} (reproduce with SECRETS_LE_DIFFERENTIAL_SEED=${SEED})\n` +
				`  document: ${show(document.content)}\n` +
				`  npm:      ${show(npm[index] ?? '')}\n` +
				`  crate:    ${show(crate[index] ?? '')}\n` +
				'  This is the SHARED tool. One name, one schema, two servers — a caller\n' +
				'  must not be able to tell which one it reached. This is a bug, not a\n' +
				'  surface difference.',
		);
		continue;
	}

	// The property the product rests on, over every generated document and on
	// both servers. Checked against the values actually detected, so a new
	// document shape that slips past the masking fails here rather than in
	// somebody's archived CI log.
	const detected = detectSecrets(document.content, { sensitivity: 'low' });
	for (const secret of detected) {
		if (secret.value.length === 0) continue;
		for (const [server, answer] of [
			['npm', npm[index]],
			['crate', crate[index]],
		] as const) {
			if (answer?.includes(secret.value)) {
				failures.push(
					`the ${server} server emitted a complete ${secret.type} value for "${document.name}"\n` +
						`  seed:     ${SEED}\n` +
						`  document: ${show(document.content)}\n` +
						`  answer:   ${show(answer)}\n` +
						'  A scanner that prints what it found has disclosed it to a CI log,\n' +
						'  which is archived and outlives the credential.',
				);
			}
		}
	}
}

if (failures.length > 0) {
	console.error(`\nDetection differential FAILED (${failures.length}):\n`);
	for (const failure of failures) console.error(`- ${failure}\n`);
	process.exit(1);
}
console.log(
	`OK: both detect_secrets servers answered identically for all ${documents.length} documents, and neither emitted a value.`,
);
