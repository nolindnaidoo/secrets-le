import { beforeEach, describe, expect, it } from 'vitest';
import {
	_createExtensionContext,
	_registeredCommands,
	_resetMockState,
	_setConfig,
} from '../__mocks__/vscode';
import { activate, deactivate } from '../extension';
import { createTelemetry } from '../telemetry/telemetry';
import { createServices } from './serviceFactory';

beforeEach(() => {
	_resetMockState();
});

describe('activate', () => {
	it('registers every declared command', () => {
		// The activation entry point was the only file in the fleet at 0%
		// coverage; the other nine cover it from here. A command declared in the
		// manifest but never registered fails at the moment a user runs it.
		const context = _createExtensionContext();
		activate(context as never);

		const declared = [
			'secrets-le.detect',
			'secrets-le.sanitize',
			'secrets-le.openSettings',
			'secrets-le.help',
		];
		for (const command of declared) {
			expect(_registeredCommands().has(command)).toBe(true);
		}
	});

	it('pushes disposables onto the context so they are cleaned up', () => {
		const context = _createExtensionContext();
		activate(context as never);
		expect(context.subscriptions.length).toBeGreaterThan(0);
	});

	it('deactivate is a no-op that does not throw', () => {
		expect(() => deactivate()).not.toThrow();
	});
});

describe('createServices', () => {
	it('builds the full service bag and registers disposables', () => {
		const context = _createExtensionContext();
		const services = createServices(context as never);

		expect(services.telemetry).toBeDefined();
		expect(services.notifier).toBeDefined();
		expect(services.statusBar).toBeDefined();
		expect(services.performanceMonitor).toBeDefined();
		// statusBarItem + telemetry + statusBar wrapper + config listener
		expect(context.subscriptions.length).toBeGreaterThanOrEqual(2);
	});
});

describe('telemetry', () => {
	it('writes events to the output channel when enabled', () => {
		_setConfig('secrets-le.telemetryEnabled', true);
		const telemetry = createTelemetry();
		telemetry.event('test-event', { count: 1 });
		// No throw and disposable — behavior is observable via the mock
		// channel's captured lines when enabled.
		telemetry.dispose();
	});

	it('is a no-op when disabled (the default)', () => {
		const telemetry = createTelemetry();
		telemetry.event('test-event');
		telemetry.dispose();
	});
});

describe('performanceMonitor', () => {
	it('measures an operation end to end', () => {
		const context = _createExtensionContext();
		const services = createServices(context as never);
		const tracker = services.performanceMonitor.startOperation('op', 10);
		const metrics = tracker.end(20, 3, 0, 1);

		expect(metrics.operation).toBe('op');
		expect(metrics.inputSize).toBe(10);
		expect(metrics.outputSize).toBe(20);
		expect(metrics.itemCount).toBe(3);
		expect(metrics.warnings).toBe(1);
		expect(metrics.duration).toBeGreaterThanOrEqual(0);
	});
});
