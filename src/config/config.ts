import * as vscode from 'vscode';
import type { Configuration } from '../types';

/**
 * The defaults, exported for the parity gate.
 *
 * Nothing else imports this: `config.test.ts` asserts it matches every
 * default declared in package.json, which is the invariant that stops the
 * two drifting apart. The export is the seam that test needs.
 */
export const CONFIG_DEFAULTS = Object.freeze({
	clipboardIncludesPositions: true,
	copyToClipboardEnabled: false,
	dedupeEnabled: false,
	notificationsLevel: 'important' as const,
	openResultsSideBySide: true,
	detectionSensitivity: 'medium' as const,
	detectionIncludeApiKeys: true,
	detectionIncludePasswords: true,
	detectionIncludeTokens: true,
	detectionIncludePrivateKeys: true,
	sanitizationReplaceWith: '***REDACTED***',
	safetyEnabled: true,
	safetyFileSizeWarnBytes: 1_000_000,
	showPositions: true,
	statusBarEnabled: true,
	telemetryEnabled: false,
	workspaceScanPatterns: Object.freeze(['**/*']) as readonly string[],
	workspaceScanExcludes: Object.freeze([]) as readonly string[],
	// A project keeps its secrets in the .env files its .gitignore leaves
	// out. Those are the files this tool is run to look at.
	workspaceScanAlwaysInclude: Object.freeze([
		'**/.env',
		'**/.env.*',
	]) as readonly string[],
	workspaceScanMaxFiles: 10_000,
	workspaceScanMaxResults: 10_000,
	workspaceScanProblemsEnabled: false,
	workspaceScanRespectGitignore: true,
	workspaceScanSkipBinaryFiles: true,
	workspaceScanUseDefaultExcludes: true,
});

export function getConfiguration(): Configuration {
	const config = vscode.workspace.getConfiguration('secrets-le');

	return Object.freeze({
		clipboardIncludesPositions: readBoolean(
			config,
			'clipboardIncludesPositions',
			CONFIG_DEFAULTS.clipboardIncludesPositions,
		),
		copyToClipboardEnabled: readBoolean(
			config,
			'copyToClipboardEnabled',
			CONFIG_DEFAULTS.copyToClipboardEnabled,
		),
		dedupeEnabled: readBoolean(
			config,
			'dedupeEnabled',
			CONFIG_DEFAULTS.dedupeEnabled,
		),
		notificationsLevel: readNotificationLevel(config),
		openResultsSideBySide: readBoolean(
			config,
			'openResultsSideBySide',
			CONFIG_DEFAULTS.openResultsSideBySide,
		),
		detectionSensitivity: readSensitivity(config),
		detectionIncludeApiKeys: readBoolean(
			config,
			'detection.includeApiKeys',
			CONFIG_DEFAULTS.detectionIncludeApiKeys,
		),
		detectionIncludePasswords: readBoolean(
			config,
			'detection.includePasswords',
			CONFIG_DEFAULTS.detectionIncludePasswords,
		),
		detectionIncludeTokens: readBoolean(
			config,
			'detection.includeTokens',
			CONFIG_DEFAULTS.detectionIncludeTokens,
		),
		detectionIncludePrivateKeys: readBoolean(
			config,
			'detection.includePrivateKeys',
			CONFIG_DEFAULTS.detectionIncludePrivateKeys,
		),
		sanitizationReplaceWith: readString(
			config,
			'sanitization.replaceWith',
			CONFIG_DEFAULTS.sanitizationReplaceWith,
		),
		safetyEnabled: readBoolean(
			config,
			'safety.enabled',
			CONFIG_DEFAULTS.safetyEnabled,
		),
		safetyFileSizeWarnBytes: readNumber(
			config,
			'safety.fileSizeWarnBytes',
			CONFIG_DEFAULTS.safetyFileSizeWarnBytes,
			1000,
		),
		showPositions: readBoolean(
			config,
			'showPositions',
			CONFIG_DEFAULTS.showPositions,
		),
		statusBarEnabled: readBoolean(
			config,
			'statusBar.enabled',
			CONFIG_DEFAULTS.statusBarEnabled,
		),
		telemetryEnabled: readBoolean(
			config,
			'telemetryEnabled',
			CONFIG_DEFAULTS.telemetryEnabled,
		),
		workspaceScanPatterns: readStringArray(
			config,
			'workspace.scanPatterns',
			CONFIG_DEFAULTS.workspaceScanPatterns,
		),
		workspaceScanExcludes: readStringArray(
			config,
			'workspace.scanExcludes',
			CONFIG_DEFAULTS.workspaceScanExcludes,
		),
		workspaceScanMaxFiles: readNumber(
			config,
			'workspace.scanMaxFiles',
			CONFIG_DEFAULTS.workspaceScanMaxFiles,
			1,
		),
		workspaceScanAlwaysInclude: readStringArray(
			config,
			'workspace.scanAlwaysInclude',
			CONFIG_DEFAULTS.workspaceScanAlwaysInclude,
		),
		workspaceScanMaxResults: readNumber(
			config,
			'workspace.scanMaxResults',
			CONFIG_DEFAULTS.workspaceScanMaxResults,
			1,
		),
		workspaceScanProblemsEnabled: readBoolean(
			config,
			'workspace.scanProblemsEnabled',
			CONFIG_DEFAULTS.workspaceScanProblemsEnabled,
		),
		workspaceScanRespectGitignore: readBoolean(
			config,
			'workspace.scanRespectGitignore',
			CONFIG_DEFAULTS.workspaceScanRespectGitignore,
		),
		workspaceScanSkipBinaryFiles: readBoolean(
			config,
			'workspace.scanSkipBinaryFiles',
			CONFIG_DEFAULTS.workspaceScanSkipBinaryFiles,
		),
		workspaceScanUseDefaultExcludes: readBoolean(
			config,
			'workspace.scanUseDefaultExcludes',
			CONFIG_DEFAULTS.workspaceScanUseDefaultExcludes,
		),
	});
}

function readBoolean(
	config: vscode.WorkspaceConfiguration,
	key: string,
	defaultValue: boolean,
): boolean {
	const value = config.get(key, defaultValue);
	return typeof value === 'boolean' ? value : defaultValue;
}

function readNumber(
	config: vscode.WorkspaceConfiguration,
	key: string,
	defaultValue: number,
	minValue: number,
): number {
	const value = Number(config.get(key, defaultValue));
	if (!Number.isFinite(value)) {
		return defaultValue;
	}
	return Math.max(minValue, value);
}

function readString(
	config: vscode.WorkspaceConfiguration,
	key: string,
	defaultValue: string,
): string {
	const value = config.get(key, defaultValue);
	return typeof value === 'string' ? value : defaultValue;
}

function readStringArray(
	config: vscode.WorkspaceConfiguration,
	key: string,
	defaultValue: readonly string[],
): readonly string[] {
	const value = config.get(key, defaultValue);
	if (Array.isArray(value) && value.every((item) => typeof item === 'string')) {
		return Object.freeze([...value]);
	}
	return defaultValue;
}

export type NotificationLevel = 'all' | 'important' | 'silent';

export function isValidNotificationLevel(v: unknown): v is NotificationLevel {
	return v === 'all' || v === 'important' || v === 'silent';
}

function readNotificationLevel(
	config: vscode.WorkspaceConfiguration,
): NotificationLevel {
	const raw = config.get<string>(
		'notificationsLevel',
		CONFIG_DEFAULTS.notificationsLevel,
	);
	return isValidNotificationLevel(raw)
		? raw
		: CONFIG_DEFAULTS.notificationsLevel;
}

export type DetectionSensitivity = 'low' | 'medium' | 'high';

export function isValidSensitivity(v: unknown): v is DetectionSensitivity {
	return v === 'low' || v === 'medium' || v === 'high';
}

function readSensitivity(
	config: vscode.WorkspaceConfiguration,
): DetectionSensitivity {
	const raw = config.get<string>(
		'detection.sensitivity',
		CONFIG_DEFAULTS.detectionSensitivity,
	);
	return isValidSensitivity(raw) ? raw : CONFIG_DEFAULTS.detectionSensitivity;
}
