/**
 * Requires the npm command line to behave exactly as the Rust one does.
 *
 * Both install a command named `secrets-le`, so a person or a CI step cannot tell
 * which one they have. This is a different contract from
 * `check-extraction-parity.ts`, which holds the extension's engine equal to
 * the crate's: here the whole terminal surface is compared, the walk and what
 * it counts as excluded, the findings and their masking, the exit codes,
 * stdout and stderr byte for byte, and every reply `secrets-le mcp` writes,
 * byte for byte too.
 *
 * Every case runs both binaries over one generated tree with stdout piped,
 * which is how a script sees them. `--version` is compared too: every surface
 * carries one version, and two binaries of one name disagreeing about it is
 * the first thing a person comparing them would see.
 *
 * Run: bun run build:cli && cargo build --locked --manifest-path crate/Cargo.toml
 *      bun scripts/check-cli-parity.ts
 */
import { spawnSync } from 'node:child_process';
import {
	chmodSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	rmdirSync,
	symlinkSync,
	unlinkSync,
	writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const ROOT = join(import.meta.dir, '..');
const RUST =
	process.env.SECRETS_LE_BIN ??
	join(
		ROOT,
		'crate',
		'target',
		'debug',
		`secrets-le${process.platform === 'win32' ? '.exe' : ''}`,
	);
const NODE_CLI = join(ROOT, 'cli', 'cli.js');
/**
 * Node, by name, not `process.execPath`: this script runs under Bun, and the
 * package is run by Node wherever `npx` runs it. Bun's errors are not Node's.
 */
const NODE = process.env.NODE_BIN ?? 'node';

interface Case {
	readonly args: readonly string[];
	readonly stdin?: string | Buffer;
}

interface Outcome {
	readonly status: number | null;
	readonly stdout: string;
	readonly stderr: string;
}

for (const [label, path] of [
	['the Rust binary', RUST],
	['cli/cli.js', NODE_CLI],
] as const) {
	if (!existsSync(path)) {
		// The path is not printed: it can come from SECRETS_LE_BIN, and an
		// environment value is not something this script echoes into a log.
		console.error(`FAIL: ${label} is missing. Build it first.`);
		process.exit(1);
	}
}

const tree = mkdtempSync(join(tmpdir(), 'secrets-le-cli-parity-'));
const created: string[] = [];
const dirs: string[] = [tree];

function dir(relative: string): void {
	mkdirSync(join(tree, relative));
	dirs.push(join(tree, relative));
}

function file(relative: string, content: string | Buffer): void {
	writeFileSync(join(tree, relative), content);
	created.push(join(tree, relative));
}

function link(relative: string, target: string): void {
	// Windows grants symlinks to administrators and developer mode only, and
	// both binaries then see the same tree without the link.
	try {
		symlinkSync(target, join(tree, relative));
	} catch {
		return;
	}
	created.push(join(tree, relative));
}

const canLock = process.platform !== 'win32' && process.getuid?.() !== 0;

/**
 * Credentials shaped like real ones, assembled here rather than written
 * whole, so no scanner of this repository's own history mistakes the
 * source for a leak.
 */
const join2 = (...parts: string[]) => parts.join('');
const FAKE = {
	aws: join2('AKIA', 'IOSFODNN7', 'EXAMPLE'),
	awsSecret: join2('wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCYEXAMPLEKEY'),
	github: join2('gh', 'p_', 'abcdefghijklmnopqrstuvwxyz0123456789'),
	anthropic: join2('sk-', 'ant-', 'api03-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH'),
	openai: join2('sk-', 'proj-', 'abcdefghijklmnopqrstuvwxyz0123456789ABCD'),
	slack: join2('https://hooks.slack.com/services/', 'T00000000/B00000000/', 'XXXXXXXXXXXXXXXXXXXXXXXX'),
	jwt: join2(
		'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
		'.eyJzdWIiOiIxMjM0NTY3ODkwIn0',
		'.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
	),
	key: join2('-----BEGIN RSA ', 'PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy\n-----END RSA ', 'PRIVATE KEY-----'),
};

const CONFIG = [
	`AWS_ACCESS_KEY_ID=${FAKE.aws}`,
	`AWS_SECRET_ACCESS_KEY=${FAKE.awsSecret}`,
	`GITHUB_TOKEN=${FAKE.github}`,
	`ANTHROPIC_API_KEY=${FAKE.anthropic}`,
	`openai = "${FAKE.openai}"`,
	`webhook: ${FAKE.slack}`,
	`Authorization: Bearer ${FAKE.jwt}`,
	'password = "correct-horse-battery-staple"',
	'db = "postgres://admin:s3cretPassw0rd@db.example.com:5432/app"',
	'api_key = "your-api-key-here"',
	'token = "changeme"',
	'emoji 🎯 then password = "ünïcode-pässwörd-1234"',
	'',
].join('\n');

function build(): void {
	dir('repo');
	dir('repo/.git');
	dir('repo/.git/info');
	file('repo/.git/info/exclude', 'excluded.env\n');
	file('repo/.gitignore', 'ignored.txt\n*.pem\n.env\nsecrets/\n!keep.pem\n');
	file('repo/.ignore', 'dot-ignored.txt\n');
	file('repo/config.env', CONFIG);
	file('repo/app.ts', `const key = '${FAKE.anthropic}';\n// ${FAKE.github}\n`);
	file('repo/id.txt', `${FAKE.key}\n`);
	file('repo/clean.md', 'Nothing to see: password reset flow docs.\n');
	file('repo/crlf.env', `TOKEN=${FAKE.github}\r\nPASSWORD=hunter2hunter2hunter2\r\n`);
	file('repo/bom.env', `\uFEFFGITHUB_TOKEN=${FAKE.github}\n`);
	file('repo/empty.txt', '');
	file('repo/logo.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe]));
	file('repo/latin1.txt', Buffer.from([0x70, 0x77, 0x3d, 0xe9, 0x0a]));
	file('repo/ignored.txt', `TOKEN=${FAKE.github}\n`);
	file('repo/dot-ignored.txt', `TOKEN=${FAKE.github}\n`);
	file('repo/excluded.env', `TOKEN=${FAKE.github}\n`);
	file('repo/.env', `API_KEY=${FAKE.openai}\n`);
	file('repo/.env.local', `API_KEY=${FAKE.openai}\n`);
	file('repo/server.pem', `${FAKE.key}\n`);
	file('repo/keep.pem', `${FAKE.key}\n`);
	file('repo/.npmrc', '//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789\n');
	dir('repo/secrets');
	file('repo/secrets/credentials', `aws_secret_access_key = ${FAKE.awsSecret}\n`);
	dir('repo/node_modules');
	dir('repo/node_modules/pkg');
	file('repo/node_modules/pkg/.npmrc', 'x\n');
	file('repo/node_modules/pkg/index.js', `module.exports = '${FAKE.github}';\n`);
	dir('repo/nested');
	file('repo/nested/.gitignore', 'local.txt\n');
	file('repo/nested/local.txt', `TOKEN=${FAKE.github}\n`);
	file('repo/nested/kept.txt', `TOKEN=${FAKE.github}\n`);
	file('repo/ünïcode.txt', `password = "ünïcode-secret-value-99"\n`);
	link('repo/linked.env', 'config.env');
	link('repo/linked-dir', 'nested');
	dir('loose');
	file('loose/plain.txt', `TOKEN=${FAKE.github}\n`);
	dir('many');
	file('many/big.env', `${CONFIG}`.repeat(2000));
	if (canLock) {
		file('repo/locked.env', `TOKEN=${FAKE.github}\n`);
		chmodSync(join(tree, 'repo', 'locked.env'), 0o000);
		dir('closed');
		dir('closed/shut');
		file('closed/shut/inside.env', 'x\n');
		file('closed/open.env', `TOKEN=${FAKE.github}\n`);
		chmodSync(join(tree, 'closed', 'shut'), 0o000);
		dir('hidden-shut');
		file('hidden-shut/.gitignore', 'shut/\n');
		dir('hidden-shut/.git');
		dir('hidden-shut/shut');
		file('hidden-shut/shut/inside.env', 'x\n');
		file('hidden-shut/open.env', `TOKEN=${FAKE.github}\n`);
		chmodSync(join(tree, 'hidden-shut', 'shut'), 0o000);
	}
}

function cases(): readonly Case[] {
	const repo = join(tree, 'repo');
	const at = (name: string) => join(repo, name);
	const corpus = join(ROOT, 'crate', 'fixtures', 'documents');
	return [
		{ args: ['--help'] },
		{ args: ['-h'] },
		{ args: ['--version'] },
		{ args: ['-V'] },
		{ args: [repo, '--help'] },
		{ args: [] },
		{ args: [repo] },
		{ args: [`${repo}/`] },
		{ args: ['repo'] },
		{ args: ['./repo/nested/'] },
		{ args: [repo, '--hidden'] },
		{ args: [repo, '--no-ignore'] },
		{ args: [repo, '--hidden', '--no-ignore'] },
		{ args: [repo, '--strict'] },
		{ args: [repo, '--sensitivity', 'low'] },
		{ args: [repo, '--sensitivity', 'high'] },
		{ args: [repo, '--sensitivity', 'medium'] },
		{ args: [repo, '--sensitivity', 'HIGH'] },
		{ args: [repo, '--sensitivity', '--strict'] },
		{ args: [repo, '--sensitivity'] },
		{ args: [repo, '--no-api-keys'] },
		{ args: [repo, '--no-passwords'] },
		{ args: [repo, '--no-tokens'] },
		{ args: [repo, '--no-private-keys'] },
		{ args: [repo, '--no-api-keys', '--no-passwords', '--no-tokens', '--no-private-keys'] },
		{ args: [repo, '--no-token'] },
		{ args: [repo, '-'] },
		{ args: [repo, '--'] },
		{ args: [at('config.env')] },
		{ args: [at('config.env'), '--sensitivity', 'low'] },
		{ args: [at('app.ts'), at('id.txt'), at('clean.md')] },
		{ args: [at('crlf.env'), at('bom.env'), at('empty.txt')] },
		{ args: [at('logo.png'), at('latin1.txt')] },
		{ args: [at('latin1.txt'), '--strict'] },
		{ args: [at('ignored.txt'), at('.env'), at('server.pem')] },
		{ args: [at('config.env'), at('config.env')] },
		{ args: [at('nested'), at('nested/kept.txt')] },
		{ args: [at('linked.env')] },
		{ args: [at('linked-dir')] },
		{ args: [at('ünïcode.txt')] },
		{ args: [at('node_modules')] },
		{ args: [join(tree, 'loose')] },
		{ args: [join(tree, 'many')] },
		...(canLock
			? [
					{ args: [join(tree, 'closed')] },
					{ args: [join(tree, 'closed'), '--strict'] },
					{ args: [join(tree, 'hidden-shut')] },
					{ args: [join(tree, 'hidden-shut'), '--hidden', '--no-ignore'] },
					{ args: [at('locked.env')] },
					{ args: [at('locked.env'), '--strict'] },
				]
			: []),
		{ args: [join(tree, 'missing')] },
		{ args: [repo, join(tree, 'missing')] },
		{ args: ['--stdin'] },
		{ args: ['--stdin', repo] },
		{ args: ['--stdin'], stdin: CONFIG },
		{ args: ['--stdin', '--sensitivity', 'low'], stdin: CONFIG },
		{ args: ['--stdin'], stdin: `\uFEFF${CONFIG}` },
		{ args: ['--stdin'], stdin: Buffer.from([0x70, 0xff, 0x0a]) },
		{ args: ['--stdin'], stdin: '' },
		{ args: [corpus] },
		{ args: [corpus, '--sensitivity', 'low', '--hidden', '--no-ignore'] },
		{ args: [join(ROOT, 'src', 'extraction', '__fixtures__')] },
	];
}

function run(command: readonly string[], testCase: Case): Outcome {
	const [program, ...rest] = command as [string, ...string[]];
	const result = spawnSync(program, [...rest, ...testCase.args], {
		input: testCase.stdin ?? '',
		cwd: tree,
		maxBuffer: 256 * 1024 * 1024,
	});
	return {
		status: result.status,
		stdout: result.stdout.toString('utf8'),
		stderr: result.stderr.toString('utf8'),
	};
}

function compareCli(): string[] {
	const failures: string[] = [];
	for (const testCase of cases()) {
		const rust = run([RUST], testCase);
		const node = run([NODE, NODE_CLI], testCase);
		for (const field of ['status', 'stdout', 'stderr'] as const) {
			if (rust[field] === node[field]) continue;
			failures.push(
				`secrets-le ${testCase.args.join(' ')}\n  ${field} differs\n` +
					describeDifference(String(rust[field]), String(node[field])),
			);
		}
	}
	return failures;
}

function mcpLines(): readonly string[] {
	const repo = join(tree, 'repo');
	let id = 0;
	const request = (method: string, params?: unknown) =>
		JSON.stringify({
			jsonrpc: '2.0',
			id: ++id,
			method,
			...(params === undefined ? {} : { params }),
		});
	const call = (name: string, args?: unknown) =>
		request('tools/call', args === undefined ? { name } : { name, arguments: args });
	const detect = (args: Record<string, unknown>) => call('detect_secrets', args);
	const scan = (args: Record<string, unknown>) => call('secrets_le_scan', args);
	return [
		request('initialize', { protocolVersion: '2024-11-05' }),
		JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
		request('tools/list'),
		request('ping'),
		request('resources/list'),
		request('tools/call'),
		request('tools/call', { arguments: {} }),
		request('tools/call', null),
		call('no_such_tool', {}),
		JSON.stringify({ jsonrpc: '2.0', id: 'text-id', method: 'ping' }),
		JSON.stringify({ jsonrpc: '2.0', id: null, method: 'ping' }),
		JSON.stringify({ jsonrpc: '2.0', id: { b: 1, a: [2] }, method: 'ping' }),
		JSON.stringify({ id: 77, method: 'ping' }),
		JSON.stringify({ jsonrpc: '2.0', id: 78 }),
		'not json',
		'',
		'   ',
		'[1, 2]',
		`${request('ping')}\r`,
		detect({ content: CONFIG }),
		detect({ content: CONFIG, sensitivity: 'low', maxResults: 3 }),
		detect({ content: CONFIG, includeTokens: false, includeApiKeys: false }),
		detect({ content: CONFIG, sensitivity: 'extreme' }),
		detect({ content: CONFIG, maxResults: 0 }),
		detect({ content: `\uFEFF${CONFIG}` }),
		detect({ content: 7 }),
		detect({}),
		call('detect_secrets', null),
		call('detect_secrets', [1]),
		scan({ path: repo }),
		scan({ paths: [repo, join(tree, 'loose')], sensitivity: 'low' }),
		scan({ path: repo, hidden: true, ignored: true, sensitivity: 'high' }),
		scan({ path: repo, sensitivity: 'extreme' }),
		scan({ path: repo, sensitivity: 3 }),
		scan({ path: join(repo, 'config.env'), hidden: 'yes' }),
		scan({ paths: [] }),
		scan({ paths: [3] }),
		scan({ path: 3, paths: [join(repo, 'clean.md')] }),
		scan({}),
		scan({ path: join(tree, 'missing') }),
		...(canLock
			? [scan({ path: join(tree, 'closed') }), scan({ path: join(tree, 'hidden-shut') })]
			: []),
	];
}

function serve(command: readonly string[], input: string | Buffer): Outcome {
	const [program, ...rest] = command as [string, ...string[]];
	const result = spawnSync(program, [...rest, 'mcp'], { input, cwd: tree });
	return {
		status: result.status,
		stdout: result.stdout.toString('utf8'),
		stderr: result.stderr.toString('utf8'),
	};
}

function compareMcp(): string[] {
	const failures: string[] = [];
	const lines = mcpLines();
	const sessions: readonly (readonly [string, string | Buffer])[] = [
		['the whole session', `${lines.join('\n')}\n`],
		['a last line with no newline', lines[3] as string],
		[
			'a line that is not UTF-8',
			Buffer.concat([
				Buffer.from(`${lines[3]}\n`),
				Buffer.from([0x7b, 0xff, 0x7d, 0x0a]),
				Buffer.from(`${lines[3]}\n`),
			]),
		],
	];
	for (const [label, input] of sessions) {
		const rust = serve([RUST], input);
		const node = serve([NODE, NODE_CLI], input);
		for (const field of ['status', 'stdout', 'stderr'] as const) {
			if (rust[field] === node[field]) continue;
			failures.push(
				`secrets-le mcp, ${label}\n  ${field} differs\n` +
					describeDifference(String(rust[field]), String(node[field])),
			);
		}
	}
	return failures;
}

/** The first differing line, which is the one worth reading in a long output. */
function describeDifference(rust: string, node: string): string {
	const left = rust.split('\n');
	const right = node.split('\n');
	const index = left.findIndex((line, at) => line !== right[at]);
	const at = index === -1 ? left.length : index;
	const clip = (line: string | undefined) =>
		line === undefined || line.length <= 2000 ? line : `${line.slice(0, 2000)}…`;
	return `  line ${at + 1}\n  rust: ${clip(left[at])}\n  node: ${clip(right[at])}`;
}

function cleanUp(): void {
	const unlock: readonly (readonly [string, number])[] = [
		[join(tree, 'repo', 'locked.env'), 0o600],
		[join(tree, 'closed', 'shut'), 0o700],
		[join(tree, 'hidden-shut', 'shut'), 0o700],
	];
	for (const [path, mode] of unlock) if (existsSync(path)) chmodSync(path, mode);
	for (const path of created) unlinkSync(path);
	for (const path of [...dirs].reverse()) rmdirSync(path);
}

build();
let failures: string[];
try {
	failures = [...compareCli(), ...compareMcp()];
} finally {
	cleanUp();
}

if (failures.length > 0) {
	console.error(failures.join('\n\n'));
	console.error(`\nFAIL: ${failures.length} difference(s) between the npm and Rust CLIs`);
	process.exit(1);
}
console.log(
	`OK: the npm CLI matches the Rust CLI on ${cases().length} commands and ${mcpLines().length} MCP lines`,
);
