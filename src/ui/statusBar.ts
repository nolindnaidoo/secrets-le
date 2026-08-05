import * as vscode from 'vscode';
import { getConfiguration } from '../config/config';

export interface StatusBar {
	show(): void;
	hide(): void;
	dispose(): void;
}

export function createStatusBar(context: vscode.ExtensionContext): StatusBar {
	const statusBarItem = vscode.window.createStatusBarItem(
		vscode.StatusBarAlignment.Right,
		100,
	);

	statusBarItem.text = '$(symbol-misc) Secrets-LE';
	statusBarItem.tooltip = 'Click to detect secrets';
	statusBarItem.command = 'secrets-le.detect';
	context.subscriptions.push(statusBarItem);

	const applyVisibility = (): void => {
		if (getConfiguration().statusBarEnabled) {
			statusBarItem.show();
			return;
		}
		statusBarItem.hide();
	};
	applyVisibility();

	context.subscriptions.push(
		vscode.workspace.onDidChangeConfiguration((event) => {
			if (event.affectsConfiguration('secrets-le.statusBar.enabled')) {
				applyVisibility();
			}
		}),
	);

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
