/**
 * Mock VS Code API for unit tests (aliased via vitest.config.ts).
 * Stateful pieces (config store, message log, command registry,
 * workspace file list) expose `_reset()`/`_set()` helpers prefixed with
 * underscore — test-only API.
 */

export interface WorkspaceFolder {
	readonly uri: Uri;
	readonly name: string;
	readonly index: number;
}

// ---------------------------------------------------------------- Uri

export class Uri {
	scheme: string;
	authority: string;
	path: string;
	query: string;
	fragment: string;

	constructor(
		scheme: string,
		authority: string,
		path: string,
		query: string,
		fragment: string,
	) {
		this.scheme = scheme;
		this.authority = authority;
		this.path = path;
		this.query = query;
		this.fragment = fragment;
	}

	get fsPath(): string {
		return this.path;
	}

	toString(_skipEncoding?: boolean): string {
		return `${this.scheme}://${this.authority}${this.path}`;
	}

	static file(path: string): Uri {
		return new Uri('file', '', path, '', '');
	}

	static parse(value: string): Uri {
		const match = value.match(/^(\w+):\/\/([^/]*)(.*)$/);
		if (match?.[1] && match[2] !== undefined && match[3] !== undefined) {
			return new Uri(match[1], match[2], match[3], '', '');
		}
		return new Uri('file', '', value, '', '');
	}
}

// ---------------------------------------------- positions and ranges

export class Position {
	constructor(
		public readonly line: number,
		public readonly character: number,
	) {}
}

export class Range {
	constructor(
		public readonly start: Position,
		public readonly end: Position,
	) {}
}

export class Selection extends Range {}

export class WorkspaceEdit {
	readonly replacements: Array<{ uri: Uri; range: Range; newText: string }> =
		[];

	replace(uri: Uri, range: Range, newText: string): void {
		this.replacements.push({ uri, range, newText });
	}
}

export class CancellationError extends Error {
	constructor() {
		super('Canceled');
		this.name = 'CancellationError';
	}
}

// ---------------------------------------------------------- documents

export interface MockDocumentInit {
	readonly content: string;
	readonly languageId?: string;
	readonly fileName?: string;
}

export function _createDocument(init: MockDocumentInit) {
	const content = init.content;
	const lines = content.split('\n');
	return {
		getText: () => content,
		languageId: init.languageId ?? 'plaintext',
		fileName: init.fileName ?? '/mock/document.txt',
		uri: Uri.file(init.fileName ?? '/mock/document.txt'),
		lineCount: lines.length,
		positionAt: (offset: number) => {
			let remaining = Math.max(0, Math.min(offset, content.length));
			for (let line = 0; line < lines.length; line++) {
				const length = (lines[line] ?? '').length;
				if (remaining <= length) return new Position(line, remaining);
				remaining -= length + 1;
			}
			return new Position(
				lines.length - 1,
				(lines[lines.length - 1] ?? '').length,
			);
		},
		lineAt: (line: number) => ({
			text: lines[line] ?? '',
			range: new Range(
				new Position(line, 0),
				new Position(line, (lines[line] ?? '').length),
			),
		}),
	};
}

export type MockDocument = ReturnType<typeof _createDocument>;

// ------------------------------------------------------ configuration

const configStore = new Map<string, unknown>();
const configUpdates: Array<{ key: string; value: unknown; target: unknown }> =
	[];

export function _setConfig(key: string, value: unknown): void {
	configStore.set(key, value);
}

export function _getConfigUpdates(): ReadonlyArray<{
	key: string;
	value: unknown;
	target: unknown;
}> {
	return configUpdates;
}

export const ConfigurationTarget = {
	Global: 1,
	Workspace: 2,
	WorkspaceFolder: 3,
};

type ConfigListener = (event: {
	affectsConfiguration: (section: string) => boolean;
}) => void;
const configListeners: ConfigListener[] = [];

export function _fireConfigChange(section: string): void {
	for (const listener of configListeners) {
		listener({
			affectsConfiguration: (candidate: string) =>
				section === candidate || section.startsWith(`${candidate}.`),
		});
	}
}

// ---------------------------------------------- workspace file store

export interface MockWorkspaceFile {
	readonly path: string;
	readonly content: string;
	readonly languageId?: string;
}

const workspaceFiles: MockWorkspaceFile[] = [];

export function _setWorkspaceFiles(files: readonly MockWorkspaceFile[]): void {
	workspaceFiles.length = 0;
	workspaceFiles.push(...files);
	workspace.workspaceFolders = [
		{ uri: Uri.file('/workspace'), name: 'workspace', index: 0 },
	];
}

// --------------------------------------------------------- workspace

export const workspace = {
	workspaceFolders: undefined as WorkspaceFolder[] | undefined,
	getWorkspaceFolder: (_uri: Uri) => undefined as WorkspaceFolder | undefined,
	asRelativePath: (uri: Uri | string, _includeFolder?: boolean): string => {
		const path = typeof uri === 'string' ? uri : uri.path;
		return path.startsWith('/workspace/')
			? path.slice('/workspace/'.length)
			: path;
	},
	findFiles: async (_pattern: string, _exclude?: unknown, maxResults?: number) =>
		workspaceFiles
			.slice(0, maxResults ?? workspaceFiles.length)
			.map((file) => Uri.file(file.path)),
	fs: {
		readFile: async (_uri: Uri) => new Uint8Array(),
		writeFile: async (_uri: Uri, _content: Uint8Array) => {},
		stat: async (uri: Uri) => {
			const file = workspaceFiles.find((f) => f.path === uri.path);
			return { type: 1, ctime: 0, mtime: 0, size: file?.content.length ?? 0 };
		},
	},
	getConfiguration: (section?: string) => ({
		get: <T>(key: string, defaultValue?: T): T | undefined => {
			const full = section ? `${section}.${key}` : key;
			return configStore.has(full)
				? (configStore.get(full) as T)
				: defaultValue;
		},
		update: async (key: string, value: unknown, target?: unknown) => {
			const full = section ? `${section}.${key}` : key;
			configStore.set(full, value);
			configUpdates.push({ key: full, value, target });
		},
	}),
	onDidChangeConfiguration: (listener: ConfigListener) => {
		configListeners.push(listener);
		return {
			dispose: () => {
				const index = configListeners.indexOf(listener);
				if (index >= 0) configListeners.splice(index, 1);
			},
		};
	},
	openTextDocument: async (
		target?: Uri | { content?: string; language?: string },
	) => {
		if (target instanceof Uri) {
			const file = workspaceFiles.find((f) => f.path === target.path);
			return _createDocument({
				content: file?.content ?? '',
				languageId: file?.languageId ?? 'plaintext',
				fileName: target.path,
			});
		}
		return _createDocument({
			content: target?.content ?? '',
			languageId: target?.language ?? 'plaintext',
		});
	},
	applyEdit: async (edit: WorkspaceEdit) => {
		// A hardcoded true made the rejected-edit path untestable, and that is
		// the path where sanitize would claim to have scrubbed a file it never
		// touched.
		appliedEdits.push(edit);
		return applyEditResult;
	},
};

export const appliedEdits: WorkspaceEdit[] = [];
let applyEditResult = true;

/** Make applyEdit resolve false, as it does for a read-only document. */
export function _setApplyEditResult(value: boolean): void {
	applyEditResult = value;
}

// ------------------------------------------------------------ window

export interface ShownMessage {
	readonly kind: 'info' | 'warning' | 'error';
	readonly message: string;
	readonly items: readonly unknown[];
}

const shownMessages: ShownMessage[] = [];
let activeTextEditor: { document: MockDocument } | undefined;
let warningResponder: ((items: unknown[]) => unknown) | undefined;

export function _shownMessages(): readonly ShownMessage[] {
	return shownMessages;
}

export function _setActiveEditor(document: MockDocument | undefined): void {
	activeTextEditor = document ? { document } : undefined;
}

export function _respondToWarning(
	responder: ((items: unknown[]) => unknown) | undefined,
): void {
	warningResponder = responder;
}

export const StatusBarAlignment = { Left: 1, Right: 2 };
export const ViewColumn = { Active: -1, Beside: -2, One: 1, Two: 2 };
export const ProgressLocation = {
	SourceControl: 1,
	Window: 10,
	Notification: 15,
};

export const window = {
	get activeTextEditor() {
		return activeTextEditor;
	},
	showInformationMessage: async (message: string, ...items: unknown[]) => {
		shownMessages.push({ kind: 'info', message, items });
		return undefined;
	},
	showWarningMessage: async (message: string, ...items: unknown[]) => {
		shownMessages.push({ kind: 'warning', message, items });
		return warningResponder?.(items);
	},
	showErrorMessage: async (message: string, ...items: unknown[]) => {
		shownMessages.push({ kind: 'error', message, items });
		return undefined;
	},
	showTextDocument: async (_document: unknown, _column?: unknown) => undefined,
	withProgress: async <T>(
		_options: unknown,
		task: (
			progress: { report: (value: unknown) => void },
			token: { isCancellationRequested: boolean },
		) => Promise<T>,
	): Promise<T> =>
		task(
			{
				report: (value: unknown) => {
					progressReports.push(value);
					// Lets a test cancel partway through a long operation, which is
					// the only way to reach the cancellation checks a progress task
					// makes between its steps.
					if (
						cancelAfterReports !== undefined &&
						progressReports.length >= cancelAfterReports
					) {
						cancellationToken.isCancellationRequested = true;
					}
				},
			},
			cancellationToken,
		),
	createOutputChannel: (_name: string) => {
		const linesOut: string[] = [];
		return {
			appendLine: (line: string) => linesOut.push(line),
			dispose: () => {},
			_lines: linesOut,
		};
	},
	createStatusBarItem: (_alignment?: unknown, _priority?: number) => ({
		text: '',
		tooltip: '',
		command: undefined as unknown,
		visible: false,
		show(): void {
			(this as { visible: boolean }).visible = true;
		},
		hide(): void {
			(this as { visible: boolean }).visible = false;
		},
		dispose: () => {},
	}),
};

// ---------------------------------------------------------- commands

const registeredCommands = new Map<string, (...args: unknown[]) => unknown>();

export function _registeredCommands(): ReadonlyMap<
	string,
	(...args: unknown[]) => unknown
> {
	return registeredCommands;
}

export const commands = {
	registerCommand: (id: string, handler: (...args: unknown[]) => unknown) => {
		registeredCommands.set(id, handler);
		return {
			dispose: () => {
				registeredCommands.delete(id);
			},
		};
	},
	executeCommand: async (id: string, ...args: unknown[]) => {
		const handler = registeredCommands.get(id);
		if (handler) return handler(...args);
		executedBuiltins.push({ id, args });
		return undefined;
	},
};

export const executedBuiltins: Array<{ id: string; args: unknown[] }> = [];

// --------------------------------------------------------------- env

const clipboard = { value: '' };
let clipboardError: Error | undefined;

/** Make the next clipboard write reject. */
export function _setClipboardError(error: Error | undefined): void {
	clipboardError = error;
}

export const env = {
	clipboard: {
		writeText: async (text: string) => {
			// The clipboard is the one output the OS can refuse — a remote or
			// headless session. Without a way to fail it, every handler for that
			// case was unreachable.
			if (clipboardError) throw clipboardError;
			clipboard.value = text;
		},
		readText: async () => clipboard.value,
	},
	openExternal: async (_uri: Uri) => true,
};

export function _clipboardText(): string {
	return clipboard.value;
}

// ------------------------------------------------- extension context

export function _createExtensionContext() {
	const globalStateStore = new Map<string, unknown>();
	return {
		subscriptions: [] as Array<{ dispose(): void }>,
		globalState: {
			get: <T>(key: string, defaultValue?: T): T | undefined =>
				globalStateStore.has(key)
					? (globalStateStore.get(key) as T)
					: defaultValue,
			update: async (key: string, value: unknown) => {
				globalStateStore.set(key, value);
			},
		},
	};
}

export type MockExtensionContext = ReturnType<typeof _createExtensionContext>;

// -------------------------------------------------------------- misc

export const FileType = {
	Unknown: 0,
	File: 1,
	Directory: 2,
	SymbolicLink: 64,
};

/** Reset all mutable mock state between tests. */
/** Progress values reported by the most recent withProgress task. */
const progressReports: unknown[] = [];

export function _progressReports(): readonly unknown[] {
	return progressReports;
}

const cancellationToken = { isCancellationRequested: false };
let cancelAfterReports: number | undefined;

/** Cancel the operation once it has reported progress `n` times. */
export function _cancelAfterProgress(n: number | undefined): void {
	cancelAfterReports = n;
}

/** Cancel before the task starts. */
export function _setCancelled(value: boolean): void {
	cancellationToken.isCancellationRequested = value;
}

export function _resetMockState(): void {
	clipboardError = undefined;
	applyEditResult = true;
	progressReports.length = 0;
	cancelAfterReports = undefined;
	cancellationToken.isCancellationRequested = false;
	configStore.clear();
	configUpdates.length = 0;
	configListeners.length = 0;
	shownMessages.length = 0;
	appliedEdits.length = 0;
	executedBuiltins.length = 0;
	registeredCommands.clear();
	workspaceFiles.length = 0;
	activeTextEditor = undefined;
	warningResponder = undefined;
	clipboard.value = '';
	workspace.workspaceFolders = undefined;
}

export const l10n = {
	t(message: string, ...args: unknown[]): string {
		if (args.length === 1 && typeof args[0] === 'object' && args[0] !== null) {
			const named = args[0] as Record<string, unknown>;
			return message.replace(/\{(\w+)\}/g, (whole, key) =>
				key in named ? String(named[key]) : whole,
			);
		}
		return message.replace(/\{(\d+)\}/g, (whole, index) => {
			const value = args[Number(index)];
			return value === undefined ? whole : String(value);
		});
	},
};
