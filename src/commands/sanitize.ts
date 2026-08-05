import * as vscode from 'vscode';
import { getConfiguration } from '../config/config';
import {
	detectSecretsInContent,
	formatSanitizationResults,
	sanitizeContent,
} from '../extraction/extract';
import type { Telemetry } from '../telemetry/telemetry';
import type { Notifier } from '../ui/notifier';
import { sanitizeErrorMessage } from '../utils/errors';
import type { PerformanceMonitor } from '../utils/performance';
import { handleSafetyChecks } from '../utils/safety';

/**
 * Register command to sanitize secrets in active document
 */
export function registerSanitizeCommand(
	context: vscode.ExtensionContext,
	deps: {
		readonly telemetry: Telemetry;
		readonly notifier: Notifier;
		readonly performanceMonitor: PerformanceMonitor;
	},
): void {
	const disposable = vscode.commands.registerCommand(
		'secrets-le.sanitize',
		async () => {
			deps.telemetry.event('sanitize-command-invoked');

			const editor = vscode.window.activeTextEditor;
			if (!editor) {
				deps.notifier.showWarning(
					vscode.l10n.t('No active editor. Please open a file first.'),
				);
				return;
			}

			const config = getConfiguration();
			const document = editor.document;

			// Perform safety checks
			const safetyResult = handleSafetyChecks(document, config);
			if (!safetyResult.proceed) {
				deps.notifier.showError(safetyResult.message);
				deps.telemetry.event('sanitize-blocked-by-safety', {
					reason: safetyResult.message,
				});
				return;
			}

			// Show warnings if any
			if (safetyResult.warnings.length > 0) {
				for (const warning of safetyResult.warnings) {
					deps.notifier.showWarning(warning);
				}
			}

			// Confirm before sanitizing
			// Bound once and compared by reference. showWarningMessage returns the
			// label that was clicked, so a localized label compared against an
			// English literal reads as "declined" in every other language — here
			// that would make sanitizing impossible outside English.
			const confirmLabel = vscode.l10n.t('Yes, Sanitize');
			const confirm = await vscode.window.showWarningMessage(
				vscode.l10n.t(
					'This will replace detected secrets with placeholders. Continue?',
				),
				{ modal: true },
				confirmLabel,
				vscode.l10n.t('Cancel'),
			);

			if (confirm !== confirmLabel) {
				return;
			}

			// Process with progress indicator
			try {
				await deps.notifier.showProgress(
					'Sanitizing content...',
					async (progress, token) => {
						// Check for cancellation
						if (token.isCancellationRequested) {
							throw new vscode.CancellationError();
						}

						const content = document.getText();
						const perfTracker = deps.performanceMonitor.startOperation(
							'sanitize',
							content.length,
						);

						progress.report({
							message: vscode.l10n.t('Detecting secrets...'),
							increment: 30,
						});

						// Check for cancellation
						if (token.isCancellationRequested) {
							throw new vscode.CancellationError();
						}

						// First detect secrets
						const detectionResult = detectSecretsInContent(content, {
							includeApiKeys: config.detectionIncludeApiKeys,
							includePasswords: config.detectionIncludePasswords,
							includeTokens: config.detectionIncludeTokens,
							includePrivateKeys: config.detectionIncludePrivateKeys,
							sensitivity: config.detectionSensitivity,
						});

						// Check for cancellation
						if (token.isCancellationRequested) {
							throw new vscode.CancellationError();
						}

						if (detectionResult.secrets.length === 0) {
							deps.notifier.showInfo(
								vscode.l10n.t(vscode.l10n.t('No secrets found to sanitize.')),
							);
							perfTracker.end(0, 0, 0, 0);
							return;
						}

						progress.report({
							message: vscode.l10n.t(
								'Found {0} secret(s)...',
								detectionResult.secrets.length,
							),
							increment: 30,
						});

						// Check for cancellation
						if (token.isCancellationRequested) {
							throw new vscode.CancellationError();
						}

						// Sanitize content
						const sanitizationResult = sanitizeContent(
							content,
							detectionResult.secrets,
							config.sanitizationReplaceWith,
						);

						progress.report({
							message: vscode.l10n.t('Preparing sanitized content...'),
							increment: 30,
						});

						// Check for cancellation
						if (token.isCancellationRequested) {
							throw new vscode.CancellationError();
						}

						// End performance tracking
						const metrics = perfTracker.end(
							sanitizationResult.sanitizedContent.length,
							sanitizationResult.replacements.length,
							sanitizationResult.errors.length,
							sanitizationResult.warnings?.length || 0,
						);

						// Validate document is still valid before editing
						const activeEditor = vscode.window.activeTextEditor;
						if (
							!activeEditor ||
							activeEditor.document.uri.toString() !== document.uri.toString()
						) {
							throw new Error(
								'Document was closed or changed during sanitization',
							);
						}

						// Check for cancellation before applying edit
						if (token.isCancellationRequested) {
							throw new vscode.CancellationError();
						}

						// Replace current document. The end position is the real end of
						// the last line rather than Range(0,0,lineCount,0); both cover the
						// whole document — VS Code clamps the out-of-range position — but
						// this one says what it means without relying on that.
						const edit = new vscode.WorkspaceEdit();
						const fullRange = new vscode.Range(
							document.positionAt(0),
							document.lineAt(document.lineCount - 1).range.end,
						);
						edit.replace(
							document.uri,
							fullRange,
							sanitizationResult.sanitizedContent,
						);
						// applyEdit resolves false when the edit is rejected — a
						// read-only document, or one that changed underneath the
						// command. Dropping that value meant reporting "Sanitized N
						// secret(s)" over a file that still contains every credential,
						// which a user may then commit believing it was scrubbed.
						const applied = await vscode.workspace.applyEdit(edit);
						if (!applied) {
							throw new Error(
								vscode.l10n.t(
									'Could not sanitize the document: the edit was rejected. The file still contains the detected secrets.',
								),
							);
						}

						// Check for cancellation
						if (token.isCancellationRequested) {
							throw new vscode.CancellationError();
						}

						// Copy formatted report to clipboard if enabled
						if (config.copyToClipboardEnabled) {
							const formattedReport =
								formatSanitizationResults(sanitizationResult);
							// The document is already sanitized at this point, so a failed
							// clipboard copy must not be reported as "Sanitization failed".
							try {
								await vscode.env.clipboard.writeText(formattedReport);
							} catch (error) {
								const message =
									error instanceof Error ? error.message : 'Unknown error';
								deps.notifier.showWarning(
									vscode.l10n.t(
										'Could not copy the report to the clipboard: {0}',
										message,
									),
								);
							}
						}

						progress.report({
							message: vscode.l10n.t('Complete'),
							increment: 10,
						});

						// Track success
						deps.telemetry.event('sanitize-completed', {
							replacementsCount: sanitizationResult.replacements.length,
							duration: metrics.duration,
							fileSize: content.length,
						});

						// Show completion message
						deps.notifier.showInfo(
							`Sanitized ${sanitizationResult.replacements.length} secret(s)`,
						);
					},
				);
			} catch (error) {
				// Don't show error for user cancellation
				if (error instanceof vscode.CancellationError) {
					return;
				}
				const errorMessage = sanitizeErrorMessage(
					error instanceof Error ? error.message : String(error),
				);
				deps.notifier.showError(
					vscode.l10n.t('Sanitization failed: {0}', errorMessage),
				);
				deps.telemetry.event('sanitize-failed', {
					error: errorMessage,
				});
			}
		},
	);

	context.subscriptions.push(disposable);
}
