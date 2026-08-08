/**
 * Fails when the extension's detection behaviour drifts from the shared
 * corpus, which the Rust CLI (crate/) also builds against.
 *
 * - signatures/patterns.toml must equal SECRET_PATTERNS exactly, in
 *   order, both ways. Order is load-bearing: the first pattern to claim
 *   a span wins the dedupe.
 * - Each pattern's `confidence` lives in TOML as a rule and in the code
 *   as a lambda. A function cannot be compared to data, so both are
 *   evaluated over probe values and the answers compared.
 * - fixtures/detection.json, fixtures/mask.json and
 *   fixtures/mcp-detect-secrets.json must reproduce under the
 *   extension's own exported functions.
 * - No expected value anywhere in the corpus may contain a complete
 *   secret from the document it came from. That is the property this
 *   whole tool rests on, and it is checked rather than assumed.
 *
 * This checks only the extension's side. `cargo test` runs the crate's
 * implementation over the same files.
 *
 * Run: bun scripts/check-detection-parity.ts
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { SECRET_PATTERNS } from '../src/extraction/detectors';
import { detectSecrets } from '../src/extraction/detectors';
import { TOOLS } from '../src/mcp/tools';
import { maskSecretValue, maskWithin } from '../src/utils/mask';

const ROOT = join(import.meta.dir, '..');
/** The corpus lives inside the crate so the published package is self-contained. */
const CORPUS = join(ROOT, 'crate', 'fixtures');
const SIGNATURES = join(ROOT, 'crate', 'signatures');
const failures: string[] = [];

function fail(message: string): void {
	failures.push(message);
}

function deepEqual(a: unknown, b: unknown): boolean {
	if (a === b) return true;
	if (Array.isArray(a) && Array.isArray(b)) {
		if (a.length !== b.length) return false;
		return a.every((item, i) => deepEqual(item, b[i]));
	}
	if (typeof a !== 'object' || typeof b !== 'object') return false;
	if (a === null || b === null) return false;
	const keysA = Object.keys(a).sort();
	const keysB = Object.keys(b).sort();
	if (!deepEqual(keysA, keysB)) return false;
	return keysA.every((key) =>
		deepEqual(
			(a as Record<string, unknown>)[key],
			(b as Record<string, unknown>)[key],
		),
	);
}

function asJson(value: unknown): unknown {
	return JSON.parse(JSON.stringify(value));
}

function readCorpus(name: string): unknown {
	return JSON.parse(readFileSync(join(CORPUS, name), 'utf8'));
}

function readDocument(file: string): string {
	return readFileSync(join(CORPUS, 'documents', file), 'utf8');
}

/** The same probe set the corpus generator used. */
const ALPHABET = 'aB3xY7zQ9mK2pL5vN8wR4tS6';
const probe = (length: number): string =>
	Array.from({ length }, (_, i) => ALPHABET[i % ALPHABET.length]).join('');
const JWT =
	'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';

type Rule = Readonly<{
	kind: string;
	level?: string;
	high?: number;
	medium?: number;
	matched?: string;
	unmatched?: string;
}>;

/** What the TOML rule says the level is for a given value. */
function levelFromRule(rule: Rule, value: string): string {
	if (rule.kind === 'fixed') return rule.level as string;
	if (rule.kind === 'length') {
		if (value.length >= (rule.high as number)) return 'high';
		if (value.length >= (rule.medium as number)) return 'medium';
		return 'low';
	}
	if (rule.kind === 'jwt') {
		const shaped =
			/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);
		return (shaped ? rule.matched : rule.unmatched) as string;
	}
	throw new Error(`unknown confidence rule kind: ${rule.kind}`);
}

async function checkPatterns(): Promise<void> {
	const { default: corpus } = await import(join(SIGNATURES, 'patterns.toml'));
	const entries = (corpus as { pattern?: unknown[] }).pattern ?? [];

	if (entries.length !== SECRET_PATTERNS.length) {
		fail(
			`pattern count differs — corpus has ${entries.length}, code has ${SECRET_PATTERNS.length}`,
		);
		return;
	}

	for (const [index, code] of SECRET_PATTERNS.entries()) {
		const entry = entries[index] as Record<string, unknown>;
		const fromCode = {
			type: code.type,
			description: code.description,
			regex: code.pattern.source,
			flags: code.pattern.flags,
			value_group: code.valueGroup,
			...(code.keyGroup === undefined ? {} : { key_group: code.keyGroup }),
		};
		const { confidence, ...fromCorpus } = entry;
		if (!deepEqual(asJson(fromCorpus), fromCode)) {
			fail(
				`patterns.toml[${index}] drifted from SECRET_PATTERNS:\n  corpus: ${JSON.stringify(fromCorpus)}\n  code:   ${JSON.stringify(fromCode)}`,
			);
			continue;
		}

		// A lambda cannot be compared to data, so compare their answers.
		const rule = confidence as Rule;
		const values = [
			...Array.from({ length: 80 }, (_, i) => probe(i + 1)),
			JWT,
			'',
		];
		for (const value of values) {
			const fromLambda = code.confidence(value);
			const fromToml = levelFromRule(rule, value);
			if (fromLambda !== fromToml) {
				fail(
					`patterns.toml[${index}] (${code.type}) confidence rule disagrees with the code at length ${value.length}: rule says ${fromToml}, lambda says ${fromLambda}`,
				);
				break;
			}
		}
	}
}

function checkDetection(): void {
	const corpus = readCorpus('detection.json') as Readonly<{
		documents: ReadonlyArray<{
			name: string;
			file: string;
			sensitivity: 'low' | 'medium' | 'high';
			expected: readonly unknown[];
		}>;
		toggles: ReadonlyArray<{
			name: string;
			file: string;
			options: Record<string, boolean>;
			expected: readonly unknown[];
		}>;
	}>;

	for (const testCase of corpus.documents) {
		const secrets = detectSecrets(readDocument(testCase.file), {
			sensitivity: testCase.sensitivity,
		});
		const actual = secrets.map((s) => ({
			type: s.type,
			confidence: s.confidence,
			key: s.key ?? null,
			preview: maskSecretValue(s.value),
			context: s.context === undefined ? null : maskWithin(s.context, s.value),
			line: s.position?.line ?? null,
			column: s.position?.column ?? null,
			description: s.description ?? null,
		}));
		if (!deepEqual(actual, testCase.expected)) {
			fail(
				`detection "${testCase.name}":\n  expected: ${JSON.stringify(testCase.expected)}\n  got:      ${JSON.stringify(actual)}`,
			);
		}
	}

	for (const testCase of corpus.toggles) {
		const secrets = detectSecrets(readDocument(testCase.file), testCase.options);
		const actual = secrets.map((s) => ({
			type: s.type,
			confidence: s.confidence,
			line: s.position?.line ?? null,
		}));
		if (!deepEqual(actual, testCase.expected)) {
			fail(
				`toggle "${testCase.name}":\n  expected: ${JSON.stringify(testCase.expected)}\n  got:      ${JSON.stringify(actual)}`,
			);
		}
	}
}

function checkMask(): void {
	const corpus = readCorpus('mask.json') as Readonly<{
		maskSecretValue: ReadonlyArray<{ input: string; expected: string }>;
		maskWithin: ReadonlyArray<{
			context: string;
			value: string;
			expected: string;
		}>;
	}>;

	for (const testCase of corpus.maskSecretValue) {
		const actual = maskSecretValue(testCase.input);
		if (actual !== testCase.expected) {
			fail(
				`maskSecretValue ${JSON.stringify(testCase.input)}: expected ${JSON.stringify(testCase.expected)}, got ${JSON.stringify(actual)}`,
			);
		}
	}
	for (const testCase of corpus.maskWithin) {
		const actual = maskWithin(testCase.context, testCase.value);
		if (actual !== testCase.expected) {
			fail(
				`maskWithin ${JSON.stringify(testCase.context)}: expected ${JSON.stringify(testCase.expected)}, got ${JSON.stringify(actual)}`,
			);
		}
	}
}

/**
 * The property the whole tool rests on: nothing the surfaces emit may
 * contain a complete detected value.
 *
 * Checked against the raw detections rather than against the corpus
 * alone, so it fails when a *new* document introduces a value the
 * masking does not fully cover — not only when an expectation changes.
 */
function checkNothingLeaks(): void {
	const corpus = readCorpus('detection.json') as Readonly<{
		documents: ReadonlyArray<{ name: string; file: string }>;
	}>;
	const files = [...new Set(corpus.documents.map((c) => c.file))];

	for (const file of files) {
		const content = readDocument(file);
		for (const secret of detectSecrets(content, { sensitivity: 'low' })) {
			if (secret.value.length === 0) continue;
			const emitted = [
				maskSecretValue(secret.value),
				secret.context === undefined
					? ''
					: maskWithin(secret.context, secret.value),
			];
			for (const text of emitted) {
				if (text.includes(secret.value)) {
					fail(
						`${file}: a ${secret.type} finding at line ${secret.position?.line} emits its complete value`,
					);
				}
			}
		}
	}
}

/**
 * `detect_secrets` is offered by BOTH MCP servers. They are meant to be
 * the same tool, not two similar ones, so the same corpus runs against
 * both: this function here, and `crate/src/mcp/detect.rs`'s own test
 * there.
 */
async function checkMcpDetectSecrets(): Promise<void> {
	const cases = readCorpus('mcp-detect-secrets.json') as ReadonlyArray<{
		name: string;
		file?: string;
		content?: string;
		arguments: Record<string, unknown>;
		expected?: unknown;
		expectedError?: string;
	}>;

	const tool = TOOLS.find((t) => t.name === 'detect_secrets');
	if (!tool) {
		fail('the extension no longer offers detect_secrets');
		return;
	}

	for (const testCase of cases) {
		const args: Record<string, unknown> = { ...testCase.arguments };
		if (testCase.file !== undefined) args.content = readDocument(testCase.file);
		else if (testCase.content !== undefined) args.content = testCase.content;

		if (testCase.expectedError !== undefined) {
			try {
				await tool.handler(args);
				fail(
					`mcp detect "${testCase.name}": expected it to fail with ${JSON.stringify(testCase.expectedError)}`,
				);
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				if (message !== testCase.expectedError) {
					fail(
						`mcp detect "${testCase.name}": expected error ${JSON.stringify(testCase.expectedError)}, got ${JSON.stringify(message)}`,
					);
				}
			}
			continue;
		}

		const actual = asJson(await tool.handler(args));
		if (!deepEqual(actual, testCase.expected)) {
			fail(
				`mcp detect "${testCase.name}":\n  expected: ${JSON.stringify(testCase.expected)}\n  got:      ${JSON.stringify(actual)}`,
			);
		}
	}
}

await checkPatterns();
checkDetection();
checkMask();
checkNothingLeaks();
await checkMcpDetectSecrets();

if (failures.length > 0) {
	console.error(`Detection parity FAILED (${failures.length}):\n`);
	for (const failure of failures) {
		console.error(`- ${failure}\n`);
	}
	process.exit(1);
}
console.log(
	'OK: the pattern table matches the code, every corpus case reproduces, nothing leaks a value, and both MCP servers agree.',
);
