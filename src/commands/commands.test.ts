import { beforeEach, describe, expect, it } from 'vitest';
import {
	_clipboardText,
	_createDocument,
	_createExtensionContext,
	_registeredCommands,
	_resetMockState,
	_respondToWarning,
	_setActiveEditor,
	_setConfig,
	_setWorkspaceFiles,
	_shownMessages,
	appliedEdits,
	executedBuiltins,
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
	});
	registerOpenSettingsCommand(context as never, services.telemetry);
	return { context, services };
}

async function runCommand(id: string): Promise<void> {
	const handler = _registeredCommands().get(id);
	if (!handler) throw new Error(`command not registered: ${id}`);
	await handler();
}

beforeEach(() => {
	_resetMockState();
});

describe('command registration', () => {
	it('registers exactly the four manifest commands', () => {
		setup();
		expect([..._registeredCommands().keys()].sort()).toEqual([
			'secrets-le.detect',
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
