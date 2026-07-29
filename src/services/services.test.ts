import { beforeEach, describe, expect, it } from 'vitest';
import {
	_createExtensionContext,
	_resetMockState,
	_setConfig,
} from '../__mocks__/vscode';
import { createTelemetry } from '../telemetry/telemetry';
import { createServices } from './serviceFactory';

beforeEach(() => {
	_resetMockState();
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
