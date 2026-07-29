import * as vscode from 'vscode';
import { getConfiguration } from '../config/config';

export interface StatusBar {
	show(): void;
	hide(): void;
	dispose(): void;
}

export function createStatusBar(_context: vscode.ExtensionContext): StatusBar {
	const config = getConfiguration();
	const statusBarItem = vscode.window.createStatusBarItem(
		vscode.StatusBarAlignment.Right,
		100,
	);

	statusBarItem.text = '$(symbol-misc) Secrets-LE';
	statusBarItem.tooltip = 'Click to detect secrets';
	statusBarItem.command = 'secrets-le.detect';

	if (config.statusBarEnabled) {
		statusBarItem.show();
	}

	return Object.freeze({
		show(): void {
			statusBarItem.show();
		},
		hide(): void {
			statusBarItem.hide();
		},
		dispose(): void {
			statusBarItem.dispose();
		},
	});
}
