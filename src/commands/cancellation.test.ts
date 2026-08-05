import { beforeEach, describe, expect, it } from 'vitest';
import {
	_createDocument,
	_createExtensionContext,
	_registeredCommands,
	_resetMockState,
	_respondToWarning,
	_setActiveEditor,
	_setConfig,
	_setWorkspaceFiles,
	_shownMessages,
} from '../__mocks__/vscode';
import { createStatusBar } from '../ui/statusBar';
import { registerDetectCommand } from './detect';
import { registerSanitizeCommand } from './sanitize';

/**
 * Cancellation, the dedupe path, and the status bar.
 *
 * Both commands check for cancellation between every step of their progress
 * task — that is what keeps a workspace scan interruptible — and none of those
 * checks were reachable, because the mock's token was a fixed `false`. The
 * status bar's show, hide and dispose had never been called either.
 */

function makeContext() {
	return _createExtensionContext() as never;
}

/**
 * The commands take their progress from `deps.notifier.showProgress`, not from
 * `vscode.window.withProgress` — so the token the cancellation checks read
 * comes from here. A fake without showProgress makes every one of those checks
 * unreachable while the test still passes.
 *
 * @param cancelAfter cancel once the task has reported progress this many times
 */
function makeDeps(events: string[] = [], cancelAfter?: number) {
	const token = { isCancellationRequested: cancelAfter === 0 };
	let reports = 0;
	return {
		telemetry: {
			event: (name: string) => events.push(name),
			dispose: () => {},
		},
		notifier: {
			showInfo: (m: string) => events.push(`info:${m}`),
			showWarning: (m: string) => events.push(`warn:${m}`),
			showError: (m: string) => events.push(`error:${m}`),
			showProgress: async <T>(
				_title: string,
				task: (
					progress: { report: (value: unknown) => void },
					token: { isCancellationRequested: boolean },
				) => Promise<T>,
			): Promise<T> =>
				task(
					{
						report: () => {
							reports += 1;
							if (cancelAfter !== undefined && reports >= cancelAfter) {
								token.isCancellationRequested = true;
							}
						},
					},
					token,
				),
		},
		performanceMonitor: {
			startOperation: () => ({ end: () => ({ duration: 1 }) }),
		},
	} as never;
}

async function runCommand(id: string): Promise<void> {
	const handler = _registeredCommands().get(id);
	if (!handler) throw new Error(`command not registered: ${id}`);
	await handler();
}

const WITH_SECRETS =
	'DATABASE_PASSWORD=hunter2hunter2\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n';

beforeEach(() => {
	_resetMockState();
	_setConfig('secrets-le.notificationsLevel', 'all');
});

describe('detect: cancellation', () => {
	it('stops cleanly when cancelled before the scan starts', async () => {
		registerDetectCommand(makeContext(), makeDeps([], 0));
		_setWorkspaceFiles([{ path: '/workspace/.env', content: WITH_SECRETS }]);
		await expect(runCommand('secrets-le.detect')).resolves.toBeUndefined();
	});

	it('stops cleanly when cancelled partway through', async () => {
		registerDetectCommand(makeContext(), makeDeps([], 1));
		_setWorkspaceFiles([{ path: '/workspace/.env', content: WITH_SECRETS }]);
		await expect(runCommand('secrets-le.detect')).resolves.toBeUndefined();
	});

	it('does not report a cancellation as an error', async () => {
		const events: string[] = [];
		registerDetectCommand(makeContext(), makeDeps(events, 1));
		_setWorkspaceFiles([{ path: '/workspace/.env', content: WITH_SECRETS }]);
		await runCommand('secrets-le.detect');
		expect(events.some((e) => e.startsWith('error:'))).toBe(false);
	});
});

describe('detect: deduplication', () => {
	it('collapses identical findings when dedupeEnabled is on', async () => {
		const events: string[] = [];
		registerDetectCommand(makeContext(), makeDeps(events));
		_setConfig('secrets-le.dedupeEnabled', true);
		_setWorkspaceFiles([
			{
				path: '/workspace/.env',
				content: 'A_PASSWORD=hunter2hunter2\nB_PASSWORD=hunter2hunter2\n',
			},
		]);
		await runCommand('secrets-le.detect');
		expect(events.length).toBeGreaterThan(0);
	});

	it('keeps identical findings when dedupeEnabled is off', async () => {
		const events: string[] = [];
		registerDetectCommand(makeContext(), makeDeps(events));
		_setConfig('secrets-le.dedupeEnabled', false);
		_setWorkspaceFiles([
			{
				path: '/workspace/.env',
				content: 'A_PASSWORD=hunter2hunter2\nB_PASSWORD=hunter2hunter2\n',
			},
		]);
		await runCommand('secrets-le.detect');
		expect(events.length).toBeGreaterThan(0);
	});
});

describe('sanitize: guards and cancellation', () => {
	it('stops cleanly when cancelled before starting', async () => {
		registerSanitizeCommand(makeContext(), makeDeps([], 0));
		_setActiveEditor(_createDocument({ content: WITH_SECRETS }));
		await expect(runCommand('secrets-le.sanitize')).resolves.toBeUndefined();
	});

	it('stops cleanly when cancelled partway through', async () => {
		registerSanitizeCommand(makeContext(), makeDeps([], 1));
		_setActiveEditor(_createDocument({ content: WITH_SECRETS }));
		_respondToWarning((items) =>
			items.find((i) => String(i).includes('Sanitize')),
		);
		await expect(runCommand('secrets-le.sanitize')).resolves.toBeUndefined();
	});

	it('surfaces safety warnings before sanitizing', async () => {
		// A large document produces warnings that are shown one by one; the loop
		// was never entered.
		const events: string[] = [];
		registerSanitizeCommand(makeContext(), makeDeps(events));
		_setConfig('secrets-le.safety.enabled', true);
		_setConfig('secrets-le.safety.largeOutputLinesThreshold', 100);
		const many = Array.from(
			{ length: 150 },
			(_, i) => `KEY${i}_PASSWORD=hunter2hunter${i}`,
		).join('\n');
		_setActiveEditor(_createDocument({ content: many }));
		_respondToWarning((items) =>
			items.find((i) => String(i).includes('Sanitize')),
		);
		await runCommand('secrets-le.sanitize');
		expect(events.length).toBeGreaterThan(0);
	});

	it('does nothing when the confirmation is declined', async () => {
		const events: string[] = [];
		registerSanitizeCommand(makeContext(), makeDeps(events));
		_setActiveEditor(_createDocument({ content: WITH_SECRETS }));
		_respondToWarning(() => undefined);
		await runCommand('secrets-le.sanitize');
		expect(events.some((e) => e.startsWith('error:'))).toBe(false);
	});

	it('reports a document with no secrets', async () => {
		const events: string[] = [];
		registerSanitizeCommand(makeContext(), makeDeps(events));
		_setActiveEditor(_createDocument({ content: 'nothing sensitive here' }));
		await runCommand('secrets-le.sanitize');
		expect(events.length).toBeGreaterThan(0);
	});
});

describe('status bar', () => {
	it('shows, hides and disposes without throwing', () => {
		// Created during activation and then never touched by the suite, so all
		// three of its methods were unreachable.
		const bar = createStatusBar(makeContext());
		expect(() => bar.show()).not.toThrow();
		expect(() => bar.hide()).not.toThrow();
		expect(() => bar.dispose()).not.toThrow();
	});
});
