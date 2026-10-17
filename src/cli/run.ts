/**
 * The terminal surface, as the Rust CLI's `cli.rs` runs it.
 *
 * stdout is protocol: one JSON report per line whenever something is reading
 * it, and nothing when it is a terminal, because the stderr summary already
 * shows every finding a person reads there.
 */
import { type Cli, parse } from './args';
import { decodeUtf8OrThrow, rustIoMessage } from './ioError';
import {
	describe,
	exitCode,
	type FileReport,
	reportedPath,
	scanContent,
	scanFile,
} from './scan';
import { USAGE } from './usage';
import { collect, type Walked } from './walk';

export interface RunIo {
	readonly stdout: (text: string) => void;
	readonly stderr: (text: string) => void;
	readonly stdoutIsTerminal: boolean;
	readonly readStdin: () => Promise<Uint8Array>;
	readonly version: string;
}

const NOTHING_WALKED: Walked = Object.freeze({
	files: [],
	skipped: 0,
	skippedOfNote: [],
});

export async function run(args: readonly string[], io: RunIo): Promise<number> {
	const first = args[0];
	if (first === '--help' || first === '-h') {
		io.stdout(`${USAGE}\n`);
		return 0;
	}
	if (first === '--version' || first === '-V') {
		io.stdout(`secrets-le ${io.version}\n`);
		return 0;
	}
	try {
		return await execute(parse(args), io);
	} catch (error) {
		io.stderr(
			`secrets-le: ${error instanceof Error ? error.message : String(error)}\n`,
		);
		return 2;
	}
}

async function execute(cli: Cli, io: RunIo): Promise<number> {
	let reports: FileReport[];
	let walked: Walked;
	let scanned: number;
	if (cli.stdin) {
		let content: string;
		try {
			content = decodeUtf8OrThrow(await io.readStdin());
		} catch (error) {
			throw new Error(`could not read stdin: ${rustIoMessage(error)}`);
		}
		reports = [scanContent(content, '<stdin>', cli.options)];
		walked = NOTHING_WALKED;
		scanned = 1;
	} else {
		walked = collect(cli.inputs, cli.walk);
		reports = walked.files.map((file) => scanFile(file, cli.options));
		scanned = walked.files.length;
	}

	if (!io.stdoutIsTerminal) {
		io.stdout(reports.map((each) => `${JSON.stringify(each)}\n`).join(''));
	}
	io.stderr(summary(reports, walked, scanned));
	return exitCode(reports, cli.strict);
}

export function summary(
	reports: readonly FileReport[],
	walked: Walked,
	scanned: number,
): string {
	const lines: string[] = [];
	let findings = 0;
	for (const each of reports) {
		for (const diagnostic of each.diagnostics)
			lines.push(`${each.file}: ${diagnostic.message}`);
		for (const finding of each.findings) {
			findings += 1;
			lines.push(describe(each, finding));
		}
	}
	for (const path of walked.skippedOfNote) {
		lines.push(
			`not scanned: ${reportedPath(path)} — excluded by .gitignore or the hidden rule, and its name says it holds credentials. --no-ignore --hidden reaches it.`,
		);
	}
	const others =
		walked.skipped === 0
			? ''
			: ` — ${walked.skipped - walked.skippedOfNote.length} others excluded by .gitignore or the hidden rule, mostly dependencies`;
	lines.push(
		`${plural(findings, 'finding', 'findings')} in ${plural(scanned, 'file', 'files')}${others}`,
	);
	return `${lines.join('\n')}\n`;
}

function plural(count: number, one: string, many: string): string {
	return `${count} ${count === 1 ? one : many}`;
}
