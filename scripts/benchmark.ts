/**
 * Measure real throughput. Run with `bun run benchmark`.
 *
 * Numbers are machine-specific, so the host is recorded alongside them and
 * they are never asserted in CI — a benchmark that gates a build just fails on
 * a slower runner. The point is a reproducible figure, not a pass/fail.
 *
 * Inputs are generated rather than checked in so the sizes are explicit and
 * the corpus cannot silently drift from what the numbers claim.
 */
import { cpus, totalmem } from 'node:os';
import { detectSecretsInContent } from '../src/extraction/extract';

interface Case {
	readonly label: string;
	readonly arg: string;
	readonly build: () => string;
}

const CASES: readonly Case[] = [
	{
		label: 'Source with credentials',
		arg: 'typescript',
		build: () =>
			Array.from({ length: 20_000 }, (_, i) =>
				`const cfg${i} = { apiKey: 'AKIA${String(i).padStart(16, '0')}', token: 'ghp_${String(i).padStart(36, 'a')}' };`,
			).join('\n'),
	},
	{
		label: 'Clean source',
		arg: 'typescript',
		build: () =>
			Array.from({ length: 40_000 }, (_, i) => `export const value${i} = compute(${i}) + offset;`).join('\n'),
	},
	{
		label: 'Env file',
		arg: 'dotenv',
		build: () =>
			Array.from({ length: 25_000 }, (_, i) => `VAR_${i}=plainvalue${i}`).join('\n'),
	},
];

async function run(content: string, _c: Case): Promise<number> {
	return detectSecretsInContent(content, {}).secrets.length;
}

const WARMUP = 2;
const RUNS = 7;

function median(xs: readonly number[]): number {
	const s = [...xs].sort((a, b) => a - b);
	const mid = Math.floor(s.length / 2);
	return s.length % 2
		? (s[mid] as number)
		: ((s[mid - 1] as number) + (s[mid] as number)) / 2;
}

async function main(): Promise<void> {
	const results: Array<Record<string, unknown>> = [];

	for (const c of CASES) {
		const content = c.build();
		const bytes = Buffer.byteLength(content, 'utf8');

		for (let i = 0; i < WARMUP; i++) await run(content, c);

		const durations: number[] = [];
		let count = 0;
		for (let i = 0; i < RUNS; i++) {
			const t0 = performance.now();
			count = await run(content, c);
			durations.push(performance.now() - t0);
		}

		const ms = median(durations);
		results.push({
			label: c.label,
			bytes,
			lines: content.split('\n').length,
			extracted: count,
			ms: Number(ms.toFixed(2)),
			perSecond: count > 0 ? Math.round(count / (ms / 1000)) : null,
			mbPerSecond: Number((bytes / 1_048_576 / (ms / 1000)).toFixed(1)),
		});
		console.log(
			`${c.label.padEnd(22)} ${(bytes / 1_048_576).toFixed(2)} MB  ${String(count).padStart(7)}  ${ms.toFixed(2)} ms`,
		);
	}

	const cpu = cpus()[0]?.model ?? 'unknown CPU';
	await Bun.write(
		'benchmark-results.json',
		`${JSON.stringify({ host: `${cpu}, ${Math.round(totalmem() / 1_073_741_824)} GB RAM, Node ${process.versions.node}`, runs: RUNS, results }, null, 2)}\n`,
	);
	console.log('\nwrote benchmark-results.json');
}

await main();
