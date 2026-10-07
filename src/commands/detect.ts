import * as vscode from 'vscode';
import { getConfiguration } from '../config/config';
import { deduplicateSecrets } from '../extraction/extract';
import { formatDetectionResults } from '../report/format';
import type { Telemetry } from '../telemetry/telemetry';
import type { DetectedSecret, DetectionResult } from '../types';
import type { Notifier } from '../ui/notifier';
import { sanitizeErrorMessage } from '../utils/errors';
import type { PerformanceMonitor } from '../utils/performance';
import {
	type FileSecrets,
	scanWorkspaceForSecrets,
} from '../utils/workspaceScanner';
import { type ScanLimits, unreadNotes } from '../workspace/scan';

/**
 * Register command to detect secrets in workspace
 */
export function registerDetectCommand(
	context: vscode.ExtensionContext,
	deps: {
		readonly telemetry: Telemetry;
		readonly notifier: Notifier;
		readonly performanceMonitor: PerformanceMonitor;
	},
): void {
	const diagnostics = vscode.languages.createDiagnosticCollection('secrets-le');
	// With a folder, that folder. Without one, the whole workspace.
	const detect = async (root?: vscode.Uri) => {
		deps.telemetry.event(
			root === undefined
				? 'detect-command-invoked'
				: 'detect-folder-command-invoked',
		);

		// Check if workspace is open
		if (
			root === undefined &&
			(vscode.workspace.workspaceFolders ?? []).length === 0
		) {
			deps.notifier.showWarning(
				vscode.l10n.t(
					'No workspace open. Please open a workspace folder first.',
				),
			);
			return;
		}

		const config = getConfiguration();
		const limits: ScanLimits = {
			patterns: config.workspaceScanPatterns,
			excludes: config.workspaceScanExcludes,
			useDefaultExcludes: config.workspaceScanUseDefaultExcludes,
			skipBinaryFiles: config.workspaceScanSkipBinaryFiles,
			alwaysInclude: config.workspaceScanAlwaysInclude,
			maxFiles: config.workspaceScanMaxFiles,
			maxFileBytes: config.safetyEnabled
				? config.safetyFileSizeWarnBytes
				: undefined,
			respectGitignore: config.workspaceScanRespectGitignore,
		};

		// Process with progress indicator
		try {
			await deps.notifier.showProgress(
				'Scanning workspace for secrets...',
				async (progress, token) => {
					const perfTracker = deps.performanceMonitor.startOperation(
						'detect',
						0,
					);

					progress.report({
						message: vscode.l10n.t('Finding files...'),
						increment: 10,
					});

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
						root,
						limits,
						maxResults: config.workspaceScanMaxResults,
						token,
						onProgress: (done, total) =>
							progress.report({
								message: vscode.l10n.t('{0} of {1} files', done, total),
							}),
					});
					// A cancelled scan read part of the tree. Reporting that as
					// the project's secrets would understate it without saying so.
					if (scanResult.summary.cancelled) {
						throw new vscode.CancellationError();
					}
					const filesScanned = scanResult.summary.read;
					const filesSkipped =
						scanResult.summary.tooLarge + scanResult.summary.notText;

					// Each scan replaces the last one's problems, and a scan that
					// publishes none still clears them.
					publish(
						diagnostics,
						config.workspaceScanProblemsEnabled ? scanResult.files : [],
					);

					progress.report({
						message: vscode.l10n.t('Scanned {0} files...', filesScanned),
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
							message: vscode.l10n.t('Removing duplicates...'),
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
						// What the scan left unread, so a filtered scan is not
						// read as a full one.
						warnings: Object.freeze(
							unreadNotes(
								scanResult.summary,
								limits,
								'`secrets-le.workspace.*`',
							),
						),
						metadata: Object.freeze({
							totalLines: 0, // Not tracked for workspace scans
							processedLines: 0,
							processingTimeMs: scanResult.totalProcessingTimeMs,
						}),
					});

					// Format results
					const formattedResult = formatDetectionResults(
						result,
						config.showPositions,
					);

					progress.report({
						message: vscode.l10n.t('Preparing output...'),
						increment: 20,
					});

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
						// A clipboard that is unavailable must not fail the scan; the
						// report still opens below.
						try {
							// The copy is its own text: whether it carries positions is a separate setting.
							await vscode.env.clipboard.writeText(
								formatDetectionResults(
									result,
									config.clipboardIncludesPositions,
								),
							);
							deps.notifier.showInfo(
								vscode.l10n.t('Results copied to clipboard'),
							);
						} catch (error) {
							const message =
								error instanceof Error ? error.message : 'Unknown error';
							deps.notifier.showWarning(
								vscode.l10n.t(
									'Could not copy the results to the clipboard: {0}',
									message,
								),
							);
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
						filesScanned,
						filesSkipped,
						sensitivity: config.detectionSensitivity,
					});

					// Completion message; the notifier applies notificationsLevel
					if (secrets.length > 0) {
						deps.notifier.showWarning(
							`Found ${secrets.length} potential secret(s) in ${filesScanned} file(s)`,
						);
						return;
					}
					deps.notifier.showInfo(
						`No secrets detected in workspace (${filesScanned} files scanned)`,
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
				vscode.l10n.t('Detection failed: {0}', errorMessage),
			);
			deps.telemetry.event('detect-failed', {
				error: errorMessage,
			});
		}
	};

	context.subscriptions.push(
		diagnostics,
		vscode.commands.registerCommand('secrets-le.detect', async () => detect()),
		// The Explorer hands over the folder that was clicked. From the
		// palette there is none, and the command asks.
		vscode.commands.registerCommand(
			'secrets-le.detectFolder',
			async (picked?: vscode.Uri) => {
				const folder = picked ?? (await askForFolder());
				if (folder !== undefined) await detect(folder);
			},
		),
	);
}

async function askForFolder(): Promise<vscode.Uri | undefined> {
	const start = vscode.workspace.workspaceFolders?.[0]?.uri;
	const chosen = await vscode.window.showOpenDialog({
		canSelectFiles: false,
		canSelectFolders: true,
		canSelectMany: false,
		...(start === undefined ? {} : { defaultUri: start }),
		openLabel: vscode.l10n.t('Scan Folder'),
	});
	return chosen?.[0];
}

/**
 * The secrets, in the Problems panel.
 *
 * Only when asked for: the panel is shared with every other tool, and a
 * project's worth of findings hides whatever else is there.
 */
function publish(
	diagnostics: vscode.DiagnosticCollection,
	files: readonly FileSecrets[],
): void {
	diagnostics.clear();
	for (const { uri, secrets } of files) {
		const placed = secrets.flatMap((secret) =>
			secret.position === undefined ? [] : [problem(secret, secret.position)],
		);
		if (placed.length > 0) diagnostics.set(uri, placed);
	}
}

function problem(
	secret: DetectedSecret,
	position: { readonly line: number; readonly column: number },
): vscode.Diagnostic {
	const start = new vscode.Position(position.line - 1, position.column - 1);
	// A value that runs over lines, as a private key does, is marked at its
	// start. The message names the kind and never carries the value.
	const length = secret.value.includes('\n') ? 1 : secret.value.length;
	const diagnostic = new vscode.Diagnostic(
		new vscode.Range(start, start.translate(0, length)),
		`${secret.description ?? secret.type} (${secret.confidence})`,
		vscode.DiagnosticSeverity.Warning,
	);
	diagnostic.source = 'secrets-le';
	return diagnostic;
}
