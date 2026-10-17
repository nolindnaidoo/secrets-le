/**
 * The command line, parsed as the Rust CLI parses it: strictly, in order, and
 * refusing rather than defaulting. A typo'd `--no-token` that quietly did
 * nothing would leave tokens in a scan the caller believed excluded them.
 */
import { FLAGS } from './usage';

export type Sensitivity = 'low' | 'medium' | 'high';

export interface DetectOptions {
	readonly apiKeys: boolean;
	readonly passwords: boolean;
	readonly tokens: boolean;
	readonly privateKeys: boolean;
	readonly sensitivity: Sensitivity;
}

export interface WalkOptions {
	readonly hidden: boolean;
	readonly respectIgnore: boolean;
}

export interface Cli {
	readonly strict: boolean;
	readonly inputs: readonly string[];
	readonly stdin: boolean;
	readonly options: DetectOptions;
	readonly walk: WalkOptions;
}

export const DEFAULT_OPTIONS: DetectOptions = Object.freeze({
	apiKeys: true,
	passwords: true,
	tokens: true,
	privateKeys: true,
	sensitivity: 'medium',
});

type Draft = { -readonly [K in keyof Cli]: Cli[K] };

const SWITCHES: Readonly<Record<string, (draft: Draft) => void>> =
	Object.freeze({
		'--stdin': (draft) => {
			draft.stdin = true;
		},
		'--strict': (draft) => {
			draft.strict = true;
		},
		'--hidden': (draft) => {
			draft.walk = { ...draft.walk, hidden: true };
		},
		'--no-ignore': (draft) => {
			draft.walk = { ...draft.walk, respectIgnore: false };
		},
		'--no-api-keys': (draft) => {
			draft.options = { ...draft.options, apiKeys: false };
		},
		'--no-passwords': (draft) => {
			draft.options = { ...draft.options, passwords: false };
		},
		'--no-tokens': (draft) => {
			draft.options = { ...draft.options, tokens: false };
		},
		'--no-private-keys': (draft) => {
			draft.options = { ...draft.options, privateKeys: false };
		},
	});

export function parse(args: readonly string[]): Cli {
	const draft: Draft = {
		strict: false,
		inputs: [],
		stdin: false,
		options: DEFAULT_OPTIONS,
		walk: { hidden: false, respectIgnore: true },
	};

	for (let index = 0; index < args.length; index++) {
		const arg = args[index] as string;
		if (arg.startsWith('-') && !FLAGS.includes(arg)) {
			throw new Error(`${arg} is not an option. Try --help.`);
		}
		if (arg === '--sensitivity') {
			index += 1;
			draft.options = {
				...draft.options,
				sensitivity: sensitivity(args[index]),
			};
			continue;
		}
		const toggle = Object.hasOwn(SWITCHES, arg) ? SWITCHES[arg] : undefined;
		if (toggle) {
			toggle(draft);
			continue;
		}
		draft.inputs = [...draft.inputs, arg];
	}

	if (draft.stdin && draft.inputs.length > 0) {
		throw new Error('reading from stdin takes no file arguments');
	}
	if (!draft.stdin && draft.inputs.length === 0) {
		throw new Error('name a file or a directory to scan. Try --help.');
	}
	return Object.freeze(draft);
}

function sensitivity(value: string | undefined): Sensitivity {
	if (value === undefined) throw new Error('--sensitivity needs a level');
	if (value === 'low' || value === 'medium' || value === 'high') return value;
	throw new Error(`${value} is not a sensitivity; one of: low, medium, high`);
}
