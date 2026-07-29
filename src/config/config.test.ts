import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { beforeEach, describe, expect, it } from 'vitest';
import { _resetMockState, _setConfig } from '../__mocks__/vscode';
import { CONFIG_DEFAULTS, getConfiguration } from './config';

/**
 * CONFIG_DEFAULTS must stay identical to the defaults declared in
 * package.json contributes.configuration — v1.x shipped with dead
 * settings and drifting defaults, so parity is asserted key by key.
 */
describe('config defaults parity with package.json', () => {
	const manifest = JSON.parse(
		readFileSync(join(__dirname, '..', '..', 'package.json'), 'utf8'),
	) as {
		contributes: {
			configuration: { properties: Record<string, { default: unknown }> };
		};
	};
	const props = manifest.contributes.configuration.properties;

	const KEY_MAP: Record<string, keyof typeof CONFIG_DEFAULTS> = {
		'secrets-le.copyToClipboardEnabled': 'copyToClipboardEnabled',
		'secrets-le.dedupeEnabled': 'dedupeEnabled',
		'secrets-le.notificationsLevel': 'notificationsLevel',
		'secrets-le.openResultsSideBySide': 'openResultsSideBySide',
		'secrets-le.detection.sensitivity': 'detectionSensitivity',
		'secrets-le.detection.includeApiKeys': 'detectionIncludeApiKeys',
		'secrets-le.detection.includePasswords': 'detectionIncludePasswords',
		'secrets-le.detection.includeTokens': 'detectionIncludeTokens',
		'secrets-le.detection.includePrivateKeys': 'detectionIncludePrivateKeys',
		'secrets-le.sanitization.replaceWith': 'sanitizationReplaceWith',
		'secrets-le.safety.enabled': 'safetyEnabled',
		'secrets-le.safety.fileSizeWarnBytes': 'safetyFileSizeWarnBytes',
		'secrets-le.statusBar.enabled': 'statusBarEnabled',
		'secrets-le.telemetryEnabled': 'telemetryEnabled',
		'secrets-le.workspace.scanPatterns': 'workspaceScanPatterns',
		'secrets-le.workspace.scanExcludes': 'workspaceScanExcludes',
		'secrets-le.workspace.scanMaxFiles': 'workspaceScanMaxFiles',
	};

	it('covers every declared setting', () => {
		expect(Object.keys(props).sort()).toEqual(Object.keys(KEY_MAP).sort());
	});

	for (const [manifestKey, defaultsKey] of Object.entries(KEY_MAP)) {
		it(`${manifestKey} default matches`, () => {
			expect(CONFIG_DEFAULTS[defaultsKey]).toEqual(props[manifestKey]?.default);
		});
	}
});

describe('getConfiguration read hardening', () => {
	beforeEach(() => {
		_resetMockState();
	});

	it('returns defaults when nothing is configured', () => {
		const config = getConfiguration();
		expect(config.notificationsLevel).toBe('important');
		expect(config.detectionSensitivity).toBe('medium');
		expect(config.workspaceScanMaxFiles).toBe(10_000);
	});

	it('rejects NaN and non-numeric threshold values', () => {
		_setConfig('secrets-le.safety.fileSizeWarnBytes', 'garbage');
		_setConfig('secrets-le.workspace.scanMaxFiles', Number.NaN);
		const config = getConfiguration();
		expect(config.safetyFileSizeWarnBytes).toBe(1_000_000);
		expect(config.workspaceScanMaxFiles).toBe(10_000);
	});

	it('clamps numbers below their manifest minimum', () => {
		_setConfig('secrets-le.safety.fileSizeWarnBytes', 1);
		expect(getConfiguration().safetyFileSizeWarnBytes).toBe(1000);
	});

	it('rejects wrong-typed booleans and strings', () => {
		_setConfig('secrets-le.copyToClipboardEnabled', 'yes');
		_setConfig('secrets-le.sanitization.replaceWith', 42);
		const config = getConfiguration();
		expect(config.copyToClipboardEnabled).toBe(false);
		expect(config.sanitizationReplaceWith).toBe('***REDACTED***');
	});

	it('rejects invalid enum values', () => {
		_setConfig('secrets-le.notificationsLevel', 'loud');
		_setConfig('secrets-le.detection.sensitivity', 'extreme');
		const config = getConfiguration();
		expect(config.notificationsLevel).toBe('important');
		expect(config.detectionSensitivity).toBe('medium');
	});

	it('rejects arrays containing non-strings', () => {
		_setConfig('secrets-le.workspace.scanPatterns', ['**/*.ts', 42]);
		expect(getConfiguration().workspaceScanPatterns).toEqual(['**/*']);
	});
});
