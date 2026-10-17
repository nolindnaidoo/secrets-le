/**
 * Turning what the caller named into the list of files to scan, as the Rust
 * CLI's `walk.rs` does with ripgrep's `ignore` crate.
 *
 * A file named explicitly is always scanned, ignore rules included: you asked
 * for it. Links are never followed. The list is sorted the way Rust sorts a
 * `PathBuf`, by component, so a report's lines are in the same order from
 * either binary.
 *
 * Each directory is walked twice, as the crate does: once as asked, and once
 * with every rule off, so the files the rules kept out can be counted and the
 * ones whose names say they hold credentials can be named. A directory either
 * walk cannot enter ends the run, as an error from the crate's walk does.
 */
import { type Dirent, readdirSync, statSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import type { WalkOptions } from './args';
import {
	type DirectoryRules,
	isIgnored,
	type RepositoryRules,
	repositoryRoot,
	repositoryRules,
	rulesFor,
} from './ignoreRules';
import { rustIoMessage } from './ioError';

export interface Walked {
	readonly files: readonly string[];
	/** How many files `.gitignore` or the hidden rule kept out. */
	readonly skipped: number;
	/** The kept-out files whose names say they probably hold a credential. */
	readonly skippedOfNote: readonly string[];
}

const PERMISSIVE: WalkOptions = Object.freeze({
	hidden: true,
	respectIgnore: false,
});

const VENDORED = Object.freeze([
	'node_modules',
	'.vscode-test',
	'vendor',
	'target',
	'dist',
	'build',
	'.venv',
	'site-packages',
]);
const CREDENTIAL_NAMES = Object.freeze([
	'.npmrc',
	'.netrc',
	'.pgpass',
	'credentials',
	'id_rsa',
	'id_ed25519',
]);
const CREDENTIAL_SUFFIXES = Object.freeze(['.pem', '.key', '.p12', '.pfx']);

/** Every file to scan, in a stable order. Throws the crate's refusal. */
export function collect(
	inputs: readonly string[],
	options: WalkOptions,
): Walked {
	const files: string[] = [];
	const ofNote: string[] = [];
	let skipped = 0;
	for (const input of inputs) {
		let isFile: boolean;
		try {
			isFile = statSync(input).isFile();
		} catch (error) {
			throw new Error(`${input}: ${rustIoMessage(error)}`);
		}
		if (isFile) {
			files.push(input);
			continue;
		}
		const walked = walkDirectory(input, options);
		files.push(...walked.files);
		skipped += walked.skipped;
		ofNote.push(...walked.skippedOfNote);
	}
	return Object.freeze({
		files: Object.freeze(sortAndDedupe(files)),
		skipped,
		skippedOfNote: Object.freeze(sortAndDedupe(ofNote)),
	});
}

function walkDirectory(root: string, options: WalkOptions): Walked {
	const files = filesUnder(root, options);
	// Counted by difference: how many files a caller might expect to have
	// been looked at and were not.
	const everything =
		options.respectIgnore || !options.hidden
			? filesUnder(root, PERMISSIVE)
			: files;
	const scanned = new Set(files);
	const skippedOfNote = everything.filter(
		(path) => !scanned.has(path) && isOfNote(path),
	);
	return {
		files,
		skipped: Math.max(0, everything.length - files.length),
		skippedOfNote,
	};
}

function isOfNote(path: string): boolean {
	const parts = path.split(sep === '\\' ? /[\\/]/ : '/');
	if (parts.some((part) => VENDORED.includes(part))) return false;
	const name = (parts.at(-1) ?? '').toLowerCase();
	return (
		name === '.env' ||
		name.startsWith('.env.') ||
		CREDENTIAL_SUFFIXES.some((suffix) => name.endsWith(suffix)) ||
		CREDENTIAL_NAMES.includes(name)
	);
}

interface Walk {
	readonly root: string;
	readonly options: WalkOptions;
	readonly repository: RepositoryRules | null;
	readonly files: string[];
}

function filesUnder(root: string, options: WalkOptions): string[] {
	const absolute = resolve(root);
	const repoRoot = options.respectIgnore ? repositoryRoot(absolute) : null;
	const walk: Walk = {
		root,
		options,
		repository: repoRoot ? repositoryRules(repoRoot) : null,
		files: [],
	};
	visit(walk, root, absolute, parentRules(absolute, options));
	return walk.files;
}

/** The crate's `parents(true)`: ignore files above the walk root count too. */
function parentRules(
	absolute: string,
	options: WalkOptions,
): readonly DirectoryRules[] {
	if (!options.respectIgnore) return [];
	const chain: DirectoryRules[] = [];
	let dir = dirname(absolute);
	while (dir !== dirname(dir)) {
		chain.unshift(rulesFor(dir, repositoryRoot(dir) !== null));
		dir = dirname(dir);
	}
	chain.unshift(rulesFor(dir, repositoryRoot(dir) !== null));
	return chain;
}

function visit(
	walk: Walk,
	shown: string,
	absolute: string,
	inherited: readonly DirectoryRules[],
): void {
	let entries: readonly Dirent[];
	try {
		entries = readdirSync(absolute, { withFileTypes: true });
	} catch (error) {
		// The `ignore` crate's error, under the root the crate names first.
		throw new Error(
			`${walk.root}: ${shown}: IO error for operation on ${shown}: ${rustIoMessage(error)}`,
		);
	}
	const chain = walk.options.respectIgnore
		? [...inherited, rulesFor(absolute, repositoryRoot(absolute) !== null)]
		: inherited;
	for (const entry of entries) {
		const entryShown = joinShown(shown, entry.name);
		const entryAbsolute = `${absolute}${sep}${entry.name}`;
		if (!walk.options.hidden && entry.name.startsWith('.')) continue;
		const isDir = entry.isDirectory();
		if (!isDir && !entry.isFile()) continue;
		if (
			walk.options.respectIgnore &&
			isIgnored(entryAbsolute, isDir, chain, walk.repository)
		)
			continue;
		if (isDir) visit(walk, entryShown, entryAbsolute, chain);
		else walk.files.push(entryShown);
	}
}

/** `PathBuf::join`: no separator is added after one that is already there. */
function joinShown(parent: string, name: string): string {
	if (parent.endsWith('/') || parent.endsWith(sep)) return `${parent}${name}`;
	return `${parent}${sep}${name}`;
}

type Component = readonly [rank: number, bytes: Buffer];

/**
 * A path as Rust compares it: by component, where `/` and `.` sort before a
 * name and a name compares by its bytes. Comparing the strings instead would
 * put `a.md` before `a/b.md`, because `.` is below `/` in ASCII.
 */
function components(path: string): readonly Component[] {
	const separators = sep === '\\' ? /[\\/]/ : /\//;
	const parts = path.split(separators);
	const found: Component[] = [];
	if (parts[0] === '' && parts.length > 1) found.push([1, Buffer.alloc(0)]);
	parts.forEach((part, index) => {
		if (!part) return;
		if (part === '.') {
			if (index === 0) found.push([2, Buffer.alloc(0)]);
			return;
		}
		found.push([part === '..' ? 3 : 4, Buffer.from(part)]);
	});
	return found;
}

function compareComponents(
	left: readonly Component[],
	right: readonly Component[],
): number {
	const shared = Math.min(left.length, right.length);
	for (let index = 0; index < shared; index++) {
		const [leftRank, leftBytes] = left[index] as Component;
		const [rightRank, rightBytes] = right[index] as Component;
		if (leftRank !== rightRank) return leftRank - rightRank;
		const order = Buffer.compare(leftBytes, rightBytes);
		if (order !== 0) return order;
	}
	return left.length - right.length;
}

/** The crate's sort, then `Vec::dedup`, which compares paths by component. */
function sortAndDedupe(paths: readonly string[]): string[] {
	const keyed = paths.map((path) => ({ path, key: components(path) }));
	keyed.sort((left, right) => compareComponents(left.key, right.key));
	return keyed
		.filter((item, index) => {
			const previous = keyed[index - 1];
			return !previous || compareComponents(previous.key, item.key) !== 0;
		})
		.map((item) => item.path);
}
