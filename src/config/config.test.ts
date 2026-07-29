import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CONFIG_DEFAULTS } from './config';

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
