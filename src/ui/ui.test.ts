import { beforeEach, describe, expect, it } from 'vitest';
import {
	_createExtensionContext,
	_fireConfigChange,
	_resetMockState,
	_setConfig,
	_shownMessages,
} from '../__mocks__/vscode';
import { createNotifier } from './notifier';
import { createStatusBar } from './statusBar';

beforeEach(() => {
	_resetMockState();
});

describe('notifier notificationsLevel gating', () => {
	it("shows everything at 'all'", () => {
		_setConfig('secrets-le.notificationsLevel', 'all');
		const notifier = createNotifier();
		notifier.showInfo('i');
		notifier.showWarning('w');
		notifier.showError('e');
		expect(_shownMessages().map((m) => m.kind)).toEqual([
			'info',
			'warning',
			'error',
		]);
	});

	it("suppresses info at 'important' (the default)", () => {
		const notifier = createNotifier();
		notifier.showInfo('i');
		notifier.showWarning('w');
		expect(_shownMessages().map((m) => m.kind)).toEqual(['warning']);
	});

	it("shows only errors at 'silent'", () => {
		_setConfig('secrets-le.notificationsLevel', 'silent');
		const notifier = createNotifier();
		notifier.showInfo('i');
		notifier.showWarning('w');
		notifier.showError('e');
		expect(_shownMessages().map((m) => m.kind)).toEqual(['error']);
	});
});

describe('status bar', () => {
	it('is visible by default and clicking runs detect', () => {
		const context = _createExtensionContext();
		createStatusBar(context as never);
		const item = context.subscriptions[0] as unknown as {
			visible: boolean;
			command: string;
			text: string;
		};
		expect(item.visible).toBe(true);
		expect(item.command).toBe('secrets-le.detect');
		expect(item.text).toContain('Secrets-LE');
	});

	it('hides when statusBar.enabled is turned off at runtime', () => {
		const context = _createExtensionContext();
		createStatusBar(context as never);
		const item = context.subscriptions[0] as unknown as { visible: boolean };
		expect(item.visible).toBe(true);

		_setConfig('secrets-le.statusBar.enabled', false);
		_fireConfigChange('secrets-le.statusBar.enabled');
		expect(item.visible).toBe(false);

		_setConfig('secrets-le.statusBar.enabled', true);
		_fireConfigChange('secrets-le.statusBar.enabled');
		expect(item.visible).toBe(true);
	});

	it('starts hidden when disabled in config', () => {
		_setConfig('secrets-le.statusBar.enabled', false);
		const context = _createExtensionContext();
		createStatusBar(context as never);
		const item = context.subscriptions[0] as unknown as { visible: boolean };
		expect(item.visible).toBe(false);
	});
});
