import type * as vscode from 'vscode';
import { detectSecretsInContent } from '../extraction/extract';
import type { DetectedSecret, ParseError } from '../types';
import {
	listFiles,
	type ScanLimits,
	type ScanSummary,
	scanFiles,
} from '../workspace/scan';

export interface WorkspaceScanOptions {
	readonly includeApiKeys?: boolean;
	readonly includePasswords?: boolean;
	readonly includeTokens?: boolean;
	readonly includePrivateKeys?: boolean;
	readonly sensitivity?: 'low' | 'medium' | 'high';
	/** The folder to scan, or undefined for the whole workspace. */
	readonly root?: vscode.Uri | undefined;
	/** Which files are read, and how large one may be. */
	readonly limits: ScanLimits;
	/** The most secrets listed before the scan stops reading. */
	readonly maxResults: number;
	readonly token: vscode.CancellationToken;
	readonly onProgress?: (done: number, total: number) => void;
}

/** One file's secrets, with the file itself for whatever points back at it. */
export interface FileSecrets {
	readonly uri: vscode.Uri;
	readonly secrets: readonly DetectedSecret[];
}

export interface WorkspaceScanResult {
	readonly secrets: readonly DetectedSecret[];
	readonly files: readonly FileSecrets[];
	readonly errors: readonly ParseError[];
	/** What was read and what was left unread, for the report to say. */
	readonly summary: ScanSummary;
	readonly totalProcessingTimeMs: number;
}

/**
 * Scan a folder, or the whole workspace, for secrets.
 *
 * Files are read from disk as bytes, so an unsaved edit is not seen and a
 * file is never opened as a document. Which files are read is the shared
 * listing's decision, the same one the rest of the family makes.
 */
export async function scanWorkspaceForSecrets(
	options: WorkspaceScanOptions,
): Promise<WorkspaceScanResult> {
	const startTime = Date.now();
	const secrets: DetectedSecret[] = [];
	const files: FileSecrets[] = [];
	const errors: ParseError[] = [];
	const detection = {
		...(options.includeApiKeys !== undefined && {
			includeApiKeys: options.includeApiKeys,
		}),
		...(options.includePasswords !== undefined && {
			includePasswords: options.includePasswords,
		}),
		...(options.includeTokens !== undefined && {
			includeTokens: options.includeTokens,
		}),
		...(options.includePrivateKeys !== undefined && {
			includePrivateKeys: options.includePrivateKeys,
		}),
		...(options.sensitivity !== undefined && {
			sensitivity: options.sensitivity,
		}),
	};

	const listed = await listFiles(options.root, options.limits);
	const scanned = await scanFiles(
		options.root,
		listed.files,
		options.limits,
		options.token,
		options.onProgress ?? (() => {}),
		({ uri, file, text }) => {
			const result = detectSecretsInContent(text, detection);
			errors.push(...result.errors.map((err) => ({ ...err, filepath: file })));
			// The limit is on what the report lists, so the file that crosses
			// it is cut and the scan stops there.
			const kept = result.secrets
				.slice(0, options.maxResults - secrets.length)
				.map((secret) => Object.freeze({ ...secret, filepath: file }));
			if (kept.length > 0) {
				secrets.push(...kept);
				files.push({ uri, secrets: kept });
			}
			return secrets.length < options.maxResults;
		},
	);

	return Object.freeze({
		secrets: Object.freeze(secrets),
		files: Object.freeze(files),
		errors: Object.freeze(errors),
		summary: Object.freeze({
			...scanned,
			fileLimitReached: listed.fileLimitReached,
			ignored: listed.ignored,
		}),
		totalProcessingTimeMs: Date.now() - startTime,
	});
}
