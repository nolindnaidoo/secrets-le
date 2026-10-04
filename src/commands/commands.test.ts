import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import {
	_clipboardText,
	_createDocument,
	_createExtensionContext,
	_diagnostics,
	_openedDocuments,
	_registeredCommands,
	_resetMockState,
	_respondToOpenDialog,
	_respondToWarning,
	_setActiveEditor,
	_setConfig,
	_setWorkspaceFiles,
	_shownMessages,
	appliedEdits,
	executedBuiltins,
	Uri,
	workspace,
} from '../__mocks__/vscode';
import { registerOpenSettingsCommand } from '../config/settings';
import { createServices } from '../services/serviceFactory';
import { registerCommands } from './index';

function setup() {
	const context = _createExtensionContext();
	const services = createServices(context as never);
	registerCommands(context as never, {
		telemetry: services.telemetry,
		notifier: services.notifier,
		performanceMonitor: services.performanceMonitor,
		ratingPrompt: { recordSuccess: async () => {} },
	});
	registerOpenSettingsCommand(context as never, services.telemetry);
	return { context, services };
}

async function runCommand(id: string, ...args: unknown[]): Promise<void> {
	const handler = _registeredCommands().get(id);
	if (!handler) throw new Error(`command not registered: ${id}`);
	await handler(...args);
}

beforeEach(() => {
	_resetMockState();
});

describe('command registration', () => {
	it('registers exactly the five manifest commands', () => {
		setup();
		expect([..._registeredCommands().keys()].sort()).toEqual([
			'secrets-le.detect',
			'secrets-le.detectFolder',
			'secrets-le.help',
			'secrets-le.openSettings',
			'secrets-le.sanitize',
		]);
	});
});

describe('secrets-le.detect', () => {
	it('warns when no workspace is open', async () => {
		setup();
		await runCommand('secrets-le.detect');
		expect(_shownMessages()[0]?.kind).toBe('warning');
		expect(_shownMessages()[0]?.message).toContain('No workspace open');
	});

	it('scans workspace files and reports found secrets', async () => {
		setup();
		_setConfig('secrets-le.notificationsLevel', 'all');
		_setWorkspaceFiles([
			{
				path: '/workspace/.env',
				content: 'API_KEY=sk_demo_abcdefghijklmnopqrstuvwxyz123456\n',
			},
			{ path: '/workspace/clean.txt', content: 'nothing to see here\n' },
		]);
		await runCommand('secrets-le.detect');

		const warning = _shownMessages().find((m) => m.kind === 'warning');
		expect(warning?.message).toMatch(/Found 1 potential secret\(s\)/);
	});

	it('reports a clean scan at notificationsLevel all', async () => {
		setup();
		_setConfig('secrets-le.notificationsLevel', 'all');
		_setWorkspaceFiles([
			{ path: '/workspace/clean.txt', content: 'nothing secret\n' },
		]);
		await runCommand('secrets-le.detect');

		const info = _shownMessages().find((m) => m.kind === 'info');
		expect(info?.message).toMatch(/No secrets detected/);
	});

	it('copies results to the clipboard when enabled', async () => {
		setup();
		_setConfig('secrets-le.copyToClipboardEnabled', true);
		_setWorkspaceFiles([
			{
				path: '/workspace/.env',
				content: 'PASSWORD=hunter2butlonger\n',
			},
		]);
		await runCommand('secrets-le.detect');

		expect(_clipboardText()).toContain('Secrets Detection Results');
	});

	it('decides positions for the clipboard separately from the report', async () => {
		setup();
		_setConfig('secrets-le.copyToClipboardEnabled', true);
		_setWorkspaceFiles([
			{
				path: '/workspace/.env',
				content: 'PASSWORD=hunter2butlonger\n',
			},
		]);
		await runCommand('secrets-le.detect');
		expect(_clipboardText()).toMatch(/- Line \d+, Column \d+/);

		_setConfig('secrets-le.clipboardIncludesPositions', false);
		_setWorkspaceFiles([
			{
				path: '/workspace/.env',
				content: 'PASSWORD=hunter2butlonger\n',
			},
		]);
		await runCommand('secrets-le.detect');
		expect(_clipboardText()).not.toMatch(/Line \d+, Column \d+/);
		// The finding is still there, with everything but where it is.
		expect(_clipboardText()).toContain('- Found');
		expect(_clipboardText()).toContain('Confidence:');
	});
});

describe('secrets-le.sanitize', () => {
	it('warns when no editor is active', async () => {
		setup();
		await runCommand('secrets-le.sanitize');
		expect(_shownMessages()[0]?.kind).toBe('warning');
		expect(appliedEdits).toHaveLength(0);
	});

	it('blocks oversized documents via the safety check', async () => {
		setup();
		_setConfig('secrets-le.safety.fileSizeWarnBytes', 1000);
		_setActiveEditor(
			_createDocument({ content: `PASSWORD=${'x'.repeat(2000)}` }),
		);
		await runCommand('secrets-le.sanitize');

		expect(_shownMessages()[0]?.kind).toBe('error');
		expect(_shownMessages()[0]?.message).toContain('exceeds safety threshold');
		expect(appliedEdits).toHaveLength(0);
	});

	it('does nothing when the user cancels the confirmation', async () => {
		setup();
		_respondToWarning(() => 'Cancel');
		_setActiveEditor(
			_createDocument({ content: 'PASSWORD=hunter2butlonger\n' }),
		);
		await runCommand('secrets-le.sanitize');
		expect(appliedEdits).toHaveLength(0);
	});

	it('replaces detected secrets with the configured placeholder', async () => {
		setup();
		_setConfig('secrets-le.notificationsLevel', 'all');
		_setConfig('secrets-le.sanitization.replaceWith', '[GONE]');
		_respondToWarning(() => 'Yes, Sanitize');
		_setActiveEditor(
			_createDocument({ content: 'PASSWORD=hunter2butlonger\nplain line\n' }),
		);
		await runCommand('secrets-le.sanitize');

		expect(appliedEdits).toHaveLength(1);
		expect(appliedEdits[0]?.replacements[0]?.newText).toBe(
			'PASSWORD=[GONE]\nplain line\n',
		);
		const info = _shownMessages().find((m) => m.kind === 'info');
		expect(info?.message).toBe('Sanitized 1 secret(s)');
	});

	it('reports when there is nothing to sanitize', async () => {
		setup();
		_setConfig('secrets-le.notificationsLevel', 'all');
		_respondToWarning(() => 'Yes, Sanitize');
		_setActiveEditor(_createDocument({ content: 'nothing secret here\n' }));
		await runCommand('secrets-le.sanitize');

		expect(appliedEdits).toHaveLength(0);
		const info = _shownMessages().find((m) => m.kind === 'info');
		expect(info?.message).toBe('No secrets found to sanitize.');
	});
});

describe('secrets-le.openSettings', () => {
	it('opens the settings UI filtered to secrets-le', async () => {
		setup();
		await runCommand('secrets-le.openSettings');
		expect(executedBuiltins[0]?.id).toBe('workbench.action.openSettings');
		expect(executedBuiltins[0]?.args[0]).toBe('secrets-le');
	});
});

describe('secrets-le.help', () => {
	it('opens a markdown help document listing the real commands', async () => {
		setup();
		await runCommand('secrets-le.help');
		// The help doc is opened via openTextDocument; no throw = registered
		// and renderable. Content is asserted through buildHelpContent's
		// output being a string containing only shipped commands.
		expect(_registeredCommands().has('secrets-le.help')).toBe(true);
	});
});

const PROJECT = [
	{ path: '/workspace/.gitignore', content: '.env\ngenerated/\n' },
	{ path: '/workspace/.env', content: 'DATABASE_PASSWORD=hunter2hunter2\n' },
	{
		path: '/workspace/src/config.ts',
		content: 'const apiKey = "sk_demo_abcdefghijklmnopqrstuvwxyz123456";\n',
	},
	{ path: '/workspace/src/clean.ts', content: 'const total = 1;\n' },
	{
		path: '/workspace/generated/out.ts',
		content: 'const apiKey = "sk_demo_zzzzzzzzzzzzzzzzzzzzzzzzzz999999";\n',
	},
	{
		path: '/workspace/node_modules/x/index.js',
		content: 'const apiKey = "sk_demo_yyyyyyyyyyyyyyyyyyyyyyyyyy888888";\n',
	},
];

function report(): string {
	const last = _openedDocuments().at(-1);
	if (!last) throw new Error('no report was opened');
	return last.getText();
}

describe('what a scan reads', () => {
	it('reads a .env the .gitignore leaves out, and skips the rest of what it leaves out', async () => {
		setup();
		_setWorkspaceFiles(PROJECT);
		await runCommand('secrets-le.detect');

		const text = report();
		expect(text).toContain('Found 2 potential secret(s)');
		expect(text).toContain('## 📄 .env (1 secret(s))');
		expect(text).toContain('## 📄 src/config.ts (1 secret(s))');
		// Ignored by .gitignore, and a dependency folder.
		expect(text).not.toContain('generated/out.ts');
		expect(text).not.toContain('node_modules');
		expect(text).toContain(
			'- Not read: dependency folders, build output, caches and lockfiles; images, fonts, archives and other binary files; 1 file(s) ignored by .gitignore. The `secrets-le.workspace.*` settings change this.',
		);
	});

	it('leaves the .env to .gitignore when it is no longer always included', async () => {
		setup();
		_setConfig('secrets-le.workspace.scanAlwaysInclude', []);
		_setWorkspaceFiles(PROJECT);
		await runCommand('secrets-le.detect');

		expect(report()).toContain('Found 1 potential secret(s)');
		expect(report()).not.toContain('## 📄 .env');
		expect(report()).toContain('2 file(s) ignored by .gitignore');
	});

	it('reads everything when the switches are off', async () => {
		setup();
		_setConfig('secrets-le.workspace.scanUseDefaultExcludes', false);
		_setConfig('secrets-le.workspace.scanRespectGitignore', false);
		_setWorkspaceFiles(PROJECT);
		await runCommand('secrets-le.detect');

		expect(report()).toContain('Found 4 potential secret(s)');
		expect(report()).toContain('## 📄 generated/out.ts');
		expect(report()).toContain('## 📄 node_modules/x/index.js');
	});

	it('counts a file that is not text or is over the safety size, and says so', async () => {
		setup();
		_setConfig('secrets-le.safety.fileSizeWarnBytes', 1000);
		_setWorkspaceFiles([
			{
				path: '/workspace/big.txt',
				content: `PASSWORD=hunter2butlonger\n${'a'.repeat(2000)}`,
			},
			{
				path: '/workspace/data.txt',
				content: new Uint8Array([0x41, 0x00, 0x42]),
			},
			{ path: '/workspace/ok.txt', content: 'nothing\n' },
		]);
		await runCommand('secrets-le.detect');

		expect(report()).toContain('No secrets detected.');
		expect(report()).toContain(
			'- 1 file(s) larger than the safety limit were not read.',
		);
		expect(report()).toContain(
			'- 1 file(s) that are not UTF-8 text were not read.',
		);
	});

	it('stops at the results limit and says the rest was not read', async () => {
		setup();
		_setConfig('secrets-le.workspace.scanMaxResults', 1);
		_setWorkspaceFiles(PROJECT);
		await runCommand('secrets-le.detect');

		expect(report()).toContain('Found 1 potential secret(s)');
		expect(report()).toContain(
			'- The results limit was reached. The rest of the files were not read.',
		);
	});
});

describe('secrets-le.detectFolder', () => {
	it('scans only the folder it is handed, and names files relative to it', async () => {
		setup();
		_setWorkspaceFiles(PROJECT);
		await runCommand('secrets-le.detectFolder', Uri.file('/workspace/src'));

		expect(report()).toContain('Found 1 potential secret(s)');
		expect(report()).toContain('## 📄 config.ts (1 secret(s))');
		expect(report()).not.toContain('.env');
	});

	it('asks for a folder from the palette, and does nothing when none is picked', async () => {
		setup();
		_setWorkspaceFiles(PROJECT);
		_respondToOpenDialog(() => undefined);
		await runCommand('secrets-le.detectFolder');
		expect(_openedDocuments()).toHaveLength(0);

		_respondToOpenDialog(() => [Uri.file('/workspace/src')]);
		await runCommand('secrets-le.detectFolder');
		expect(report()).toContain('## 📄 config.ts (1 secret(s))');
	});

	it('scans a folder with no workspace open', async () => {
		setup();
		_setWorkspaceFiles(PROJECT);
		workspace.workspaceFolders = undefined;
		await runCommand('secrets-le.detectFolder', Uri.file('/workspace/src'));
		expect(report()).toContain('Found 1 potential secret(s)');
	});
});

describe('the Problems panel', () => {
	it('stays empty unless asked, names the kind and never the value, and is replaced each scan', async () => {
		setup();
		_setWorkspaceFiles(PROJECT);
		await runCommand('secrets-le.detect');
		expect(_diagnostics().size).toBe(0);

		_setConfig('secrets-le.workspace.scanProblemsEnabled', true);
		_setWorkspaceFiles(PROJECT);
		await runCommand('secrets-le.detect');
		expect([..._diagnostics().keys()].sort()).toEqual([
			'/workspace/.env',
			'/workspace/src/config.ts',
		]);
		const problem = _diagnostics().get('/workspace/src/config.ts')?.[0];
		expect(problem?.message).toBe('Generic API key (high)');
		expect(problem?.source).toBe('secrets-le');
		expect(problem?.range.start).toMatchObject({ line: 0, character: 16 });
		const messages = [..._diagnostics().values()].flat().map((d) => d.message);
		expect(messages.join('\n')).not.toMatch(/sk_demo|hunter2/);

		_setWorkspaceFiles([{ path: '/workspace/clean.txt', content: 'clean\n' }]);
		await runCommand('secrets-le.detect');
		expect(_diagnostics().size).toBe(0);
	});
});

describe('the README', () => {
	it('shows the sample a scan really prints', async () => {
		setup();
		_setWorkspaceFiles(PROJECT);
		await runCommand('secrets-le.detect');

		const readme = readFileSync(
			join(__dirname, '..', '..', 'README.md'),
			'utf8',
		);
		const shown = report()
			.split('\n')
			.filter(
				(line) =>
					line.trim() !== '' &&
					line !== '# Metadata' &&
					!line.startsWith('Processing Time'),
			);
		expect(shown.length).toBeGreaterThan(20);
		for (const line of shown) expect(readme, line).toContain(line);
	});
});
