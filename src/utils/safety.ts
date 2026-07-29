import type * as vscode from 'vscode';
import type { Configuration } from '../types';

export interface SafetyResult {
	readonly proceed: boolean;
	readonly message: string;
	readonly warnings: readonly string[];
}

const LINE_COUNT_WARN_THRESHOLD = 10_000;

/**
 * Perform safety checks on a document before processing. Oversized files
 * block; large line counts and binary-looking content only warn.
 */
export function handleSafetyChecks(
	document: vscode.TextDocument,
	config: Configuration,
): SafetyResult {
	if (!config.safetyEnabled) {
		return Object.freeze({
			proceed: true,
			message: '',
			warnings: Object.freeze([]),
		});
	}

	const content = document.getText();
	const fileSizeThreshold = config.safetyFileSizeWarnBytes;

	if (content.length > fileSizeThreshold) {
		return Object.freeze({
			proceed: false,
			message:
				`File size (${content.length} bytes) exceeds safety threshold ` +
				`(${fileSizeThreshold} bytes). Consider splitting the file or ` +
				'increasing the safety threshold in settings.',
			warnings: Object.freeze([]),
		});
	}

	const warnings: string[] = [];
	const lineCount = content.split('\n').length;
	if (lineCount > LINE_COUNT_WARN_THRESHOLD) {
		warnings.push(
			`File has ${lineCount} lines (threshold: ${LINE_COUNT_WARN_THRESHOLD})`,
		);
	}
	if (content.includes('\x00')) {
		warnings.push('File may contain binary content');
	}

	return Object.freeze({
		proceed: true,
		message:
			warnings.length > 0
				? `Safety checks passed with ${warnings.length} warnings`
				: 'Safety checks passed',
		warnings: Object.freeze(warnings),
	});
}
