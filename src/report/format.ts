import type {
	DetectedSecret,
	DetectionResult,
	SanitizationResult,
	SecretReplacement,
} from '../types';
import { maskSecretValue, maskWithin } from '../utils/mask';

/**
 * Rendering detection and sanitization results as markdown.
 *
 * This is presentation, and it was living in `extraction/extract.ts` next to
 * the detection logic. Extraction now returns data and this module turns it
 * into the document the user reads — the two change for different reasons.
 */

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

		// Group by filepath (if workspace scan) or by type (if single file)
		const hasFilePaths = result.secrets.some((s) => s.filepath);

		if (hasFilePaths) {
			// Group by filepath first, then by type
			const byFile = new Map<string, DetectedSecret[]>();
			for (const secret of result.secrets) {
				const filepath = secret.filepath ?? '<unknown>';
				const existing = byFile.get(filepath) ?? [];
				existing.push(secret);
				byFile.set(filepath, existing);
			}

			for (const [filepath, fileSecrets] of byFile.entries()) {
				lines.push(`## 📄 ${filepath} (${fileSecrets.length} secret(s))`);
				lines.push('');

				// Group secrets in this file by type
				const byType = new Map<string, DetectedSecret[]>();
				for (const secret of fileSecrets) {
					const existing = byType.get(secret.type) ?? [];
					existing.push(secret);
					byType.set(secret.type, existing);
				}

				for (const [type, secrets] of byType.entries()) {
					lines.push(`### ${type.toUpperCase()} (${secrets.length})`);
					lines.push('');

					for (const secret of secrets) {
						lines.push(
							secret.position
								? `- Line ${secret.position.line}, Column ${secret.position.column}`
								: '- Found',
						);
						if (secret.key) {
							lines.push(`  Key: ${secret.key}`);
						}
						if (secret.description) {
							lines.push(`  Type: ${secret.description}`);
						}
						lines.push(`  Confidence: ${secret.confidence}`);
						lines.push(`  Value: ${maskSecretValue(secret.value)}`);
						if (secret.context) {
							lines.push(
								`  Context: ${maskWithin(secret.context, secret.value).substring(0, 80)}`,
							);
						}
						lines.push('');
					}
				}
			}
		}

		if (!hasFilePaths) {
			// Group by type (single file mode)
			const byType = new Map<string, DetectedSecret[]>();
			for (const secret of result.secrets) {
				const existing = byType.get(secret.type) ?? [];
				existing.push(secret);
				byType.set(secret.type, existing);
			}

			for (const [type, secrets] of byType.entries()) {
				lines.push(`## ${type.toUpperCase()} (${secrets.length})`);
				lines.push('');

				for (const secret of secrets) {
					lines.push(
						secret.position
							? `- Line ${secret.position.line}, Column ${secret.position.column}`
							: '- Found',
					);
					if (secret.key) {
						lines.push(`  Key: ${secret.key}`);
					}
					if (secret.description) {
						lines.push(`  Type: ${secret.description}`);
					}
					lines.push(`  Confidence: ${secret.confidence}`);
					lines.push(`  Value: ${maskSecretValue(secret.value)}`);
					if (secret.context) {
						lines.push(
							`  Context: ${maskWithin(secret.context, secret.value).substring(0, 80)}`,
						);
					}
					lines.push('');
				}
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
