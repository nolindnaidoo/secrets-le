import * as vscode from 'vscode';
import { getConfiguration } from '../config/config';
import {
	deduplicateSecrets,
	formatDetectionResults,
} from '../extraction/extract';
import type { Telemetry } from '../telemetry/telemetry';
import type { DetectionResult } from '../types';
import type { Notifier } from '../ui/notifier';
import type { StatusBar } from '../ui/statusBar';
import type { PerformanceMonitor } from '../utils/performance';
import { scanWorkspaceForSecrets } from '../utils/workspaceScanner';

/**
 * Register command to detect secrets in workspace
 */
export function registerDetectCommand(
	context: vscode.ExtensionContext,
	deps: {
		readonly telemetry: Telemetry;
		readonly notifier: Notifier;
		readonly statusBar: StatusBar;
		readonly performanceMonitor: PerformanceMonitor;
	},
): void {
	const disposable = vscode.commands.registerCommand(
		'secrets-le.detect',
		async () => {
			deps.telemetry.event('detect-command-invoked');

			// Check if workspace is open
			if (
				!vscode.workspace.workspaceFolders ||
				vscode.workspace.workspaceFolders.length === 0
			) {
				deps.notifier.showWarning(
					'No workspace open. Please open a workspace folder first.',
				);
				return;
			}

			const config = getConfiguration();

			// Process with progress indicator
			try {
				await deps.notifier.showProgress(
					'Scanning workspace for secrets...',
					async (progress, token) => {
						const perfTracker = deps.performanceMonitor.startOperation(
							'detect',
							0,
						);

						progress.report({ message: 'Finding files...', increment: 10 });

						// Check for cancellation
						if (token.isCancellationRequested) {
							throw new vscode.CancellationError();
						}

						// Scan workspace for secrets
						const scanResult = await scanWorkspaceForSecrets({
							includeApiKeys: config.detectionIncludeApiKeys,
							includePasswords: config.detectionIncludePasswords,
							includeTokens: config.detectionIncludeTokens,
							includePrivateKeys: config.detectionIncludePrivateKeys,
							sensitivity: config.detectionSensitivity,
							patterns: config.workspaceScanPatterns,
							excludes: config.workspaceScanExcludes,
							maxFiles: config.workspaceScanMaxFiles,
							fileSizeLimit: config.safetyFileSizeWarnBytes,
						});

						progress.report({
							message: `Scanned ${scanResult.filesScanned} files...`,
							increment: 40,
						});

						// Check for cancellation
						if (token.isCancellationRequested) {
							throw new vscode.CancellationError();
						}

						// Apply deduplication if enabled
						let secrets = scanResult.secrets;
						if (config.dedupeEnabled && secrets.length > 0) {
							secrets = deduplicateSecrets(secrets);
							progress.report({
								message: 'Removing duplicates...',
								increment: 20,
							});
						}

						// Check for cancellation
						if (token.isCancellationRequested) {
							throw new vscode.CancellationError();
						}

						// Build detection result
						const result: DetectionResult = Object.freeze({
							success: true,
							secrets: Object.freeze(secrets),
							errors: scanResult.errors,
							warnings: Object.freeze(
								scanResult.filesSkipped > 0
									? [
											`Skipped ${scanResult.filesSkipped} file(s) (too large or binary)`,
										]
									: [],
							),
							metadata: Object.freeze({
								totalLines: 0, // Not tracked for workspace scans
								processedLines: 0,
								processingTimeMs: scanResult.totalProcessingTimeMs,
							}),
						});

						// Format results
						const formattedResult = formatDetectionResults(result);

						progress.report({ message: 'Preparing output...', increment: 20 });

						// End performance tracking
						const metrics = perfTracker.end(
							formattedResult.length,
							secrets.length,
							result.errors.length,
							result.warnings?.length || 0,
						);

						// Check for cancellation
						if (token.isCancellationRequested) {
							throw new vscode.CancellationError();
						}

						// Copy to clipboard if enabled
						if (config.copyToClipboardEnabled) {
							await vscode.env.clipboard.writeText(formattedResult);
							if (config.notificationsLevel === 'all') {
								deps.notifier.showInfo('Results copied to clipboard');
							}
						}

						// Check for cancellation
						if (token.isCancellationRequested) {
							throw new vscode.CancellationError();
						}

						// Open in new document
						const doc = await vscode.workspace.openTextDocument({
							content: formattedResult,
							language: 'markdown',
						});

						const viewColumn = config.openResultsSideBySide
							? vscode.ViewColumn.Beside
							: vscode.ViewColumn.Active;

						await vscode.window.showTextDocument(doc, viewColumn);

						// Track success
						deps.telemetry.event('detect-completed', {
							secretCount: secrets.length,
							duration: metrics.duration,
							filesScanned: scanResult.filesScanned,
							filesSkipped: scanResult.filesSkipped,
							sensitivity: config.detectionSensitivity,
						});

						// Show completion message based on notification level
						if (secrets.length > 0) {
							const message = `Found ${secrets.length} potential secret(s) in ${scanResult.filesScanned} file(s)`;
							if (config.notificationsLevel === 'all') {
								deps.notifier.showWarning(message);
							} else if (config.notificationsLevel === 'important') {
								deps.notifier.showWarning(message);
							}
						} else if (config.notificationsLevel === 'all') {
							deps.notifier.showInfo(
								`No secrets detected in workspace (${scanResult.filesScanned} files scanned)`,
							);
						}
					},
				);
			} catch (error) {
				// Don't show error for user cancellation
				if (error instanceof vscode.CancellationError) {
					return;
				}
				const errorMessage =
					error instanceof Error ? error.message : String(error);
				deps.notifier.showError(`Detection failed: ${errorMessage}`);
				deps.telemetry.event('detect-failed', {
					error: errorMessage,
				});
			}
		},
	);

	context.subscriptions.push(disposable);
}
