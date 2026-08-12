import type {
	DetectedSecret,
	DetectionResult,
	SanitizationResult,
	SecretReplacement,
} from '../types';
import { maskSecretValue } from '../utils/mask';

/**
 * Rendering detection and sanitization results as markdown.
 *
 * This is presentation, and it was living in `extraction/extract.ts` next to
 * the detection logic. Extraction now returns data and this module turns it
 * into the document the user reads — the two change for different reasons.
 */

/** Group items by a derived key, preserving insertion order. */
function groupBy<T>(
	items: readonly T[],
	key: (item: T) => string,
): Map<string, T[]> {
	const grouped = new Map<string, T[]>();
	for (const item of items) {
		const k = key(item);
		const existing = grouped.get(k) ?? [];
		existing.push(item);
		grouped.set(k, existing);
	}
	return grouped;
}

/** The lines describing one finding. */
function secretLines(secret: DetectedSecret): readonly string[] {
	const lines: string[] = [
		secret.position
			? `- Line ${secret.position.line}, Column ${secret.position.column}`
			: '- Found',
	];
	if (secret.key) lines.push(`  Key: ${secret.key}`);
	if (secret.description) lines.push(`  Type: ${secret.description}`);
	lines.push(`  Confidence: ${secret.confidence}`);
	lines.push(`  Value: ${maskSecretValue(secret.value)}`);
	// The context arrives masked and already bounded to a window around the
	// value, so there is nothing left here to redact or to cut.
	if (secret.context) lines.push(`  Context: ${secret.context}`);
	lines.push('');
	return lines;
}

/**
 * Type sections for a set of findings.
 *
 * Both the per-file and single-file arms rendered this identically, one copy
 * each, nested four levels deep inside the caller.
 */
function appendTypeGroups(
	lines: string[],
	secrets: readonly DetectedSecret[],
	heading: '##' | '###',
): void {
	for (const [type, group] of groupBy(secrets, (s) => s.type)) {
		lines.push(`${heading} ${type.toUpperCase()} (${group.length})`);
		lines.push('');
		for (const secret of group) {
			lines.push(...secretLines(secret));
		}
	}
}

/**
 * Formats detection results for display
 */
export function formatDetectionResults(result: DetectionResult): string {
	const lines: string[] = [];

	lines.push('# Secrets Detection Results');
	lines.push('');

	if (result.secrets.length === 0) {
		lines.push('✅ No secrets detected.');
	}

	if (result.secrets.length > 0) {
		lines.push(`⚠️ Found ${result.secrets.length} potential secret(s):`);
		lines.push('');

		// Group by filepath (workspace scan) or by type (single file).
		const hasFilePaths = result.secrets.some((s) => s.filepath);

		if (hasFilePaths) {
			const byFile = groupBy(result.secrets, (s) => s.filepath ?? '<unknown>');
			for (const [filepath, fileSecrets] of byFile) {
				lines.push(`## 📄 ${filepath} (${fileSecrets.length} secret(s))`);
				lines.push('');
				appendTypeGroups(lines, fileSecrets, '###');
			}
		}

		if (!hasFilePaths) {
			appendTypeGroups(lines, result.secrets, '##');
		}
	}

	if (result.errors.length > 0) {
		lines.push('');
		lines.push('---');
		lines.push('');
		lines.push('# Errors');
		lines.push('');
		for (const error of result.errors) {
			lines.push(`- ${error.message}`);
			if (error.context) {
				lines.push(`  ${error.context}`);
			}
		}
	}

	if (result.warnings && result.warnings.length > 0) {
		lines.push('');
		lines.push('---');
		lines.push('');
		lines.push('# Warnings');
		lines.push('');
		for (const warning of result.warnings) {
			lines.push(`- ${warning}`);
		}
	}

	if (result.metadata) {
		lines.push('');
		lines.push('---');
		lines.push('');
		lines.push('# Metadata');
		lines.push('');
		if (result.metadata.totalLines > 0) {
			lines.push(`Total Lines: ${result.metadata.totalLines}`);
			lines.push(`Processed Lines: ${result.metadata.processedLines}`);
		}
		lines.push(
			`Processing Time: ${result.metadata.processingTimeMs.toFixed(2)}ms`,
		);
	}

	return lines.join('\n');
}

/**
 * Formats sanitization results for display
 */
export function formatSanitizationResults(result: SanitizationResult): string {
	const lines: string[] = [];

	lines.push('# Content Sanitization Results');
	lines.push('');

	lines.push(
		result.success
			? `✅ Sanitized ${result.replacements.length} secret(s)`
			: '❌ Sanitization failed',
	);

	lines.push('');

	if (result.replacements.length > 0) {
		lines.push('## Replacements');
		lines.push('');

		// Group by type
		const byType = new Map<string, SecretReplacement[]>();
		for (const replacement of result.replacements) {
			const existing = byType.get(replacement.type) ?? [];
			existing.push(replacement);
			byType.set(replacement.type, existing);
		}

		for (const [type, replacements] of byType.entries()) {
			lines.push(`### ${type.toUpperCase()} (${replacements.length})`);
			lines.push('');
			for (const replacement of replacements) {
				lines.push(
					replacement.position
						? `- Line ${replacement.position.line}, Column ${replacement.position.column}`
						: '- Found',
				);
				lines.push(
					`  Original: ${replacement.original.substring(0, 30)}${
						replacement.original.length > 30 ? '...' : ''
					}`,
				);
				lines.push(`  Replaced: ${replacement.replaced}`);
				lines.push('');
			}
		}
	}

	if (result.errors.length > 0) {
		lines.push('');
		lines.push('---');
		lines.push('');
		lines.push('# Errors');
		lines.push('');
		for (const error of result.errors) {
			lines.push(`- ${error.message}`);
		}
	}

	if (result.metadata) {
		lines.push('');
		lines.push('---');
		lines.push('');
		lines.push('# Metadata');
		lines.push('');
		lines.push(`Original Length: ${result.metadata.originalLength}`);
		lines.push(`Sanitized Length: ${result.metadata.sanitizedLength}`);
		lines.push(`Replacements: ${result.metadata.replacementsCount}`);
		lines.push(
			`Processing Time: ${result.metadata.processingTimeMs.toFixed(2)}ms`,
		);
	}

	return lines.join('\n');
}
