import type * as vscode from 'vscode';
import type { Configuration } from '../types';
import { createEnhancedError, type EnhancedError } from './errorHandling';

export interface SafetyResult {
	readonly proceed: boolean;
	readonly message: string;
	readonly error?: EnhancedError;
	readonly warnings: readonly string[];
}

export interface SafetyCheckOptions {
	readonly showProgress?: boolean;
	readonly allowOverride?: boolean;
	readonly customThresholds?: {
		readonly fileSizeBytes?: number;
		readonly lineCount?: number;
		readonly itemCount?: number;
	};
}

/**
 * Perform safety checks on a document before processing
 */
export function handleSafetyChecks(
	document: vscode.TextDocument,
	config: Configuration,
	options: SafetyCheckOptions = {},
): SafetyResult {
	// Skip safety checks if disabled
	if (!config.safetyEnabled) {
		return Object.freeze({
			proceed: true,
			message: '',
			warnings: Object.freeze([]),
		});
	}

	const content = document.getText();
	const fileSizeThreshold =
		options.customThresholds?.fileSizeBytes ?? config.safetyFileSizeWarnBytes;

	// Check file size
	const exceedsFileSize = content.length > fileSizeThreshold;
	if (exceedsFileSize) {
		const error = createEnhancedError(
			new Error(
				`File size (${content.length} bytes) exceeds safety threshold (${fileSizeThreshold} bytes)`,
			),
			'safety',
			{
				fileSize: content.length,
				threshold: fileSizeThreshold,
				fileName: document.fileName,
			},
			{
				recoverable: false,
				severity: 'high',
				suggestion:
					'Consider splitting the file or increasing the safety threshold in settings',
			},
		);

		return Object.freeze({
			proceed: false,
			message: error.userMessage,
			error,
			warnings: Object.freeze([]),
		});
	}

	// Collect warnings
	const warnings = collectSafetyWarnings(content, config, options);
	const hasWarnings = warnings.length > 0;
	const message = hasWarnings
		? `Safety checks passed with ${warnings.length} warnings`
		: 'Safety checks passed';

	return Object.freeze({
		proceed: true,
		message,
		warnings: Object.freeze(warnings),
	});
}

/**
 * Collect safety warnings without blocking
 */
function collectSafetyWarnings(
	content: string,
	_config: Configuration,
	options: SafetyCheckOptions,
): string[] {
	const warnings: string[] = [];
	const lines = content.split('\n');
	const lineCount = lines.length;

	// Warn about large line count
	const lineThreshold = options.customThresholds?.lineCount ?? 10000;
	if (lineCount > lineThreshold) {
		warnings.push(`File has ${lineCount} lines (threshold: ${lineThreshold})`);
	}

	// Warn if file appears to be binary or malformed
	const hasBinaryContent = content.includes('\x00');
	if (hasBinaryContent) {
		warnings.push('File may contain binary content');
	}

	return warnings;
}
