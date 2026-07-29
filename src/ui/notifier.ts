import * as vscode from 'vscode';
import type {
	EnhancedError,
	ErrorRecoveryOptions,
} from '../utils/errorHandling';

function buildErrorMessage(
	error: EnhancedError,
	options?: ErrorRecoveryOptions,
): string {
	let fullMessage = error.userMessage;

	const hasSuggestion = Boolean(error.suggestion);
	if (hasSuggestion) {
		fullMessage += `\n\nSuggestion: ${error.suggestion}`;
	}

	const hasUserAction = Boolean(options?.userAction);
	if (hasUserAction) {
		fullMessage += `\n\nAction: ${options?.userAction}`;
	}

	return fullMessage;
}

export interface Notifier {
	showInfo(message: string): void;
	showWarning(message: string): void;
	showError(message: string): void;
	showEnhancedError(
		error: EnhancedError,
		options?: ErrorRecoveryOptions,
	): Promise<void>;
	showProgress<T>(
		title: string,
		task: (
			progress: vscode.Progress<{ message?: string; increment?: number }>,
			token: vscode.CancellationToken,
		) => Promise<T>,
	): Promise<T>;
}

export function createNotifier(): Notifier {
	return Object.freeze({
		showInfo(message: string): void {
			vscode.window.showInformationMessage(message);
		},
		showWarning(message: string): void {
			vscode.window.showWarningMessage(message);
		},
		showError(message: string): void {
			vscode.window.showErrorMessage(message);
		},
		async showEnhancedError(
			error: EnhancedError,
			options?: ErrorRecoveryOptions,
		): Promise<void> {
			const fullMessage = buildErrorMessage(error, options);

			if (error.severity === 'high') {
				await vscode.window.showErrorMessage(fullMessage, {
					modal: true,
					detail: error.message,
				});
				return;
			}

			if (error.severity === 'medium') {
				await vscode.window.showWarningMessage(fullMessage, {
					detail: error.message,
				});
				return;
			}

			await vscode.window.showInformationMessage(fullMessage, {
				detail: error.message,
			});
		},
		async showProgress<T>(
			title: string,
			task: (
				progress: vscode.Progress<{ message?: string; increment?: number }>,
				token: vscode.CancellationToken,
			) => Promise<T>,
		): Promise<T> {
			return vscode.window.withProgress(
				{
					location: vscode.ProgressLocation.Notification,
					title,
					cancellable: true,
				},
				task,
			);
		},
	});
}
