/**
 * Core type definitions for the Secrets-LE extension
 */

export interface DetectionResult {
	readonly success: boolean;
	readonly secrets: readonly DetectedSecret[];
	readonly errors: readonly ParseError[];
	readonly warnings?: readonly string[] | undefined;
	readonly metadata?:
		| {
				readonly totalLines: number;
				readonly processedLines: number;
				readonly processingTimeMs: number;
		  }
		| undefined;
}

export interface DetectedSecret {
	readonly value: string;
	readonly type: SecretType;
	readonly confidence: ConfidenceLevel;
	/** Offsets of the value within the scanned content. */
	readonly start: number;
	readonly end: number;
	readonly position?:
		| {
				readonly line: number;
				readonly column: number;
		  }
		| undefined;
	readonly context?: string | undefined;
	readonly key?: string | undefined;
	readonly description?: string | undefined;
	readonly filepath?: string | undefined;
}

export type SecretType =
	| 'api-key'
	| 'password'
	| 'token'
	| 'jwt'
	| 'oauth-token'
	| 'private-key'
	| 'aws-key'
	| 'aws-secret'
	| 'azure-key'
	| 'azure-sas'
	| 'gcp-key'
	| 'database-url'
	| 'connection-string'
	| 'bearer-token'
	| 'access-token'
	| 'refresh-token'
	| 'session-id'
	| 'cookie'
	| 'ssh-key'
	| 'pgp-key'
	// Issuer-specific, recognised from the value's own prefix rather than
	// from the key name beside it. Naming the issuer is the point: a
	// generic `api-key` tells a reader to go and look, `openai-key` tells
	// them which credential to revoke and where.
	| 'anthropic-key'
	| 'docker-token'
	| 'gitlab-token'
	| 'mailgun-key'
	| 'npm-token'
	| 'openai-key'
	| 'pypi-token'
	| 'sendgrid-key'
	| 'sentry-token'
	| 'shopify-token'
	| 'square-token'
	| 'supabase-key'
	| 'terraform-token'
	| 'vault-token'
	| 'unknown';

export type ConfidenceLevel = 'low' | 'medium' | 'high';

export interface SanitizationResult {
	readonly success: boolean;
	readonly sanitizedContent: string;
	readonly replacements: readonly SecretReplacement[];
	readonly errors: readonly ParseError[];
	readonly warnings?: readonly string[] | undefined;
	readonly metadata?:
		| {
				readonly originalLength: number;
				readonly sanitizedLength: number;
				readonly replacementsCount: number;
				readonly processingTimeMs: number;
		  }
		| undefined;
}

export interface SecretReplacement {
	readonly original: string;
	readonly replaced: string;
	readonly type: SecretType;
	readonly position?:
		| {
				readonly line: number;
				readonly column: number;
		  }
		| undefined;
}

export interface ParseError {
	readonly type: 'parse-error';
	readonly message: string;
	readonly filepath?: string | undefined;
	readonly context?: string | undefined;
}

export interface Configuration {
	readonly copyToClipboardEnabled: boolean;
	readonly dedupeEnabled: boolean;
	readonly notificationsLevel: 'all' | 'important' | 'silent';
	readonly openResultsSideBySide: boolean;
	readonly detectionSensitivity: 'low' | 'medium' | 'high';
	readonly detectionIncludeApiKeys: boolean;
	readonly detectionIncludePasswords: boolean;
	readonly detectionIncludeTokens: boolean;
	readonly detectionIncludePrivateKeys: boolean;
	readonly sanitizationReplaceWith: string;
	readonly safetyEnabled: boolean;
	readonly safetyFileSizeWarnBytes: number;
	readonly statusBarEnabled: boolean;
	readonly telemetryEnabled: boolean;
	readonly workspaceScanPatterns: readonly string[];
	readonly workspaceScanExcludes: readonly string[];
	readonly workspaceScanMaxFiles: number;
}

export interface PerformanceMetrics {
	readonly operation: string;
	readonly startTime: number;
	readonly endTime: number;
	readonly duration: number;
	readonly inputSize: number;
	readonly outputSize: number;
	readonly itemCount: number;
	readonly memoryUsage: number;
	readonly cpuUsage: number;
	readonly warnings: number;
	readonly errors: number;
}
