import type * as vscode from 'vscode';
import type { Telemetry } from '../telemetry/telemetry';
import type { Notifier } from '../ui/notifier';
import type { PerformanceMonitor } from '../utils/performance';
import { registerDetectCommand } from './detect';
import { registerHelpCommand } from './help';
import { registerSanitizeCommand } from './sanitize';

/**
 * Command dependencies
 */
export interface CommandDependencies {
	readonly telemetry: Telemetry;
	readonly notifier: Notifier;
	readonly performanceMonitor: PerformanceMonitor;
}

/**
 * Register all extension commands
 * Centralizes command registration with dependency injection
 */
export function registerCommands(
	context: vscode.ExtensionContext,
	deps: CommandDependencies,
): void {
	// Register main commands
	registerDetectCommand(context, deps);
	registerSanitizeCommand(context, deps);

	// Register help command
	registerHelpCommand(context, deps.telemetry);
}
