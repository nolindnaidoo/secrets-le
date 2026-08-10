import * as vscode from 'vscode';
import type { Telemetry } from '../telemetry/telemetry';

/**
 * Register help command to show documentation
 */
export function registerHelpCommand(
	context: vscode.ExtensionContext,
	telemetry: Telemetry,
): void {
	const disposable = vscode.commands.registerCommand(
		'secrets-le.help',
		async () => {
			telemetry.event('help-opened');

			const helpContent = buildHelpContent();

			const doc = await vscode.workspace.openTextDocument({
				content: helpContent,
				language: 'markdown',
			});

			await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
		},
	);

	context.subscriptions.push(disposable);
}

function buildHelpContent(): string {
	return `# Secrets-LE Help

## Quick Start

1. Open a workspace folder
2. Run "Secrets-LE: Detect Secrets" to scan for secrets
3. Run "Secrets-LE: Sanitize Secrets" to replace them with placeholders

## Commands

**Detect**: Scan workspace for secrets (API keys, tokens, passwords, etc.)
**Sanitize**: Replace detected secrets in the active file with safe placeholders
**Settings**: Configure detection sensitivity and options

## Troubleshooting

**No secrets found?** Adjust sensitivity in settings
**Performance issues?** Reduce workspace scan limits in settings
**Need help?** Check Output panel for details

## Settings

Access via Command Palette: "Secrets-LE: Open Settings"
Key settings: Detection sensitivity, sanitization placeholder, safety checks

## Support

- GitHub Issues: https://github.com/nolindnaidoo/secrets-le/issues
- Documentation: https://github.com/nolindnaidoo/secrets-le#readme
- LE Tools: https://letools.dev

Enjoying it? A rating helps more than you'd think:
- Rate on VS Code Marketplace: https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.secrets-le&ssr=false#review-details
- Rate on Open VSX: https://open-vsx.org/extension/OffensiveEdge/secrets-le/reviews

Built by nolindnaidoo (https://github.com/nolindnaidoo) — MIT licensed.
`;
}
