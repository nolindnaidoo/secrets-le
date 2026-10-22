import * as vscode from 'vscode';
import { guarded } from '../commands/guard';
import type { Telemetry } from '../telemetry/telemetry';
import { createNotifier } from '../ui/notifier';

/**
 * Register command to open extension settings
 */
export function registerOpenSettingsCommand(
	context: vscode.ExtensionContext,
	telemetry: Telemetry,
): void {
	const disposable = vscode.commands.registerCommand(
		'secrets-le.openSettings',
		guarded(createNotifier(), async () => {
			telemetry.event('settings-opened');
			await vscode.commands.executeCommand(
				'workbench.action.openSettings',
				'secrets-le',
			);
		}),
	);

	context.subscriptions.push(disposable);
}
