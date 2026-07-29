/**
 * Secret detection over whole content.
 *
 * Every pattern runs against the full text with the `d` flag; positions
 * come from match.indices via the newline-offset index, so the reported
 * line/column point at the secret VALUE, not the start of the match.
 * v1.x matched line by line, which made the three multiline private-key
 * patterns unmatchable in practice (a PEM block never fits on one line).
 *
 * Key-based patterns accept optional quotes around the key name, so
 * JSON (`"apiKey": "..."`), YAML (`api_key: ...`), env (`API_KEY=...`)
 * and code (`apiKey = '...'`) all match the same way.
 *
 * Intentional rejections and misses are documented in heuristics.ts.
 * The v1.x "reversed format" api-key pattern (value before key name)
 * was dropped: it never matched real configs and doubled every scan.
 */

import type { ConfidenceLevel, DetectedSecret, SecretType } from '../types';
import {
	confidenceByLength,
	isJwtShaped,
	looksLikePlaceholder,
} from './heuristics';
import { createPositionIndex, lineTextAt } from './position';

interface SecretPattern {
	readonly type: SecretType;
	readonly pattern: RegExp;
	/** Capture group holding the secret value; 0 = whole match. */
	readonly valueGroup: number;
	/** Capture group holding the key name, when the pattern has one. */
	readonly keyGroup?: number;
	readonly confidence: (value: string) => ConfidenceLevel;
	readonly description: string;
}

const high = (): ConfidenceLevel => 'high';
const medium = (): ConfidenceLevel => 'medium';
const low = (): ConfidenceLevel => 'low';

/**
 * Key-based pattern prefix: an identifier ENDING in one of `names`
 * (compound keys like DATABASE_PASSWORD or db_password must match),
 * optionally quoted, followed by `:` or `=` and an optional quote.
 */
const key = (names: string): string =>
	`['"]?\\b([A-Za-z0-9_-]*(?:${names}))\\b['"]?\\s*[:=]\\s*['"]?`;

/**
 * Order matters: specific key patterns (oauth/access/refresh/jwt) come
 * before the generic token pattern; the first pattern to claim a span
 * wins dedupe.
 */
export const SECRET_PATTERNS: readonly SecretPattern[] = Object.freeze([
	// --- key-based patterns (keyGroup 1, valueGroup 2) -----------------
	{
		type: 'aws-secret',
		pattern: new RegExp(
			`${key('aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key|secretkey')}([A-Za-z0-9/+=]{40})(?!['"A-Za-z0-9/+=])`,
			'gid',
		),
		keyGroup: 1,
		valueGroup: 2,
		confidence: high,
		description: 'AWS Secret Access Key',
	},
	{
		type: 'access-token',
		pattern: new RegExp(
			`${key('access[_-]?token')}([A-Za-z0-9_\\-.]{20,})`,
			'gid',
		),
		keyGroup: 1,
		valueGroup: 2,
		confidence: high,
		description: 'Access token',
	},
	{
		type: 'refresh-token',
		pattern: new RegExp(
			`${key('refresh[_-]?token')}([A-Za-z0-9_\\-.]{20,})`,
			'gid',
		),
		keyGroup: 1,
		valueGroup: 2,
		confidence: high,
		description: 'Refresh token',
	},
	{
		type: 'oauth-token',
		pattern: new RegExp(
			`${key('oauth[_-]?(?:2[_-]?)?token')}([A-Za-z0-9_\\-.]{20,})`,
			'gid',
		),
		keyGroup: 1,
		valueGroup: 2,
		confidence: high,
		description: 'OAuth token',
	},
	{
		type: 'jwt',
		pattern: new RegExp(
			`${key('jwt|json[_-]?web[_-]?token')}([A-Za-z0-9_\\-.]{50,})`,
			'gid',
		),
		keyGroup: 1,
		valueGroup: 2,
		confidence: (v) => (isJwtShaped(v) ? 'high' : 'medium'),
		description: 'JWT token',
	},
	{
		type: 'api-key',
		pattern: new RegExp(
			`${key('api[_-]?key|apikey')}([A-Za-z0-9_-]{20,})`,
			'gid',
		),
		keyGroup: 1,
		valueGroup: 2,
		confidence: (v) => confidenceByLength(v, 32, 20),
		description: 'Generic API key',
	},
	{
		type: 'token',
		pattern: new RegExp(
			`${key('token|secret[_-]?token')}([A-Za-z0-9_\\-.]{20,})`,
			'gid',
		),
		keyGroup: 1,
		valueGroup: 2,
		confidence: (v) => confidenceByLength(v, 32, 20),
		description: 'Generic token',
	},
	{
		type: 'password',
		pattern: new RegExp(`${key('password|passwd|pwd')}([^\\s'";]{8,})`, 'gid'),
		keyGroup: 1,
		valueGroup: 2,
		confidence: (v) => confidenceByLength(v, 12, 8),
		description: 'Password',
	},
	{
		type: 'azure-key',
		pattern: new RegExp(
			`${key('azure[_-]?(?:account[_-]?)?key|accountkey')}([A-Za-z0-9+/]{32,}={0,2})`,
			'gid',
		),
		keyGroup: 1,
		valueGroup: 2,
		confidence: high,
		description: 'Azure account key',
	},
	{
		type: 'gcp-key',
		pattern: new RegExp(
			`${key('gcp[_-]?key|google[_-]?cloud[_-]?key')}([A-Za-z0-9_-]{12,})`,
			'gid',
		),
		keyGroup: 1,
		valueGroup: 2,
		confidence: medium,
		description: 'GCP/Google Cloud key',
	},
	{
		type: 'session-id',
		pattern: new RegExp(
			`${key('session[_-]?id|sessionid')}([A-Za-z0-9_-]{20,})`,
			'gid',
		),
		keyGroup: 1,
		valueGroup: 2,
		confidence: medium,
		description: 'Session ID',
	},
	{
		type: 'cookie',
		pattern: new RegExp(`${key('cookie|set-cookie')}([^\\s'";]{20,})`, 'gid'),
		keyGroup: 1,
		valueGroup: 2,
		confidence: low,
		description: 'Cookie value',
	},
	{
		type: 'connection-string',
		pattern: new RegExp(
			`${key('connection[_-]?string|conn[_-]?string')}([^\\s'"]{20,})`,
			'gid',
		),
		keyGroup: 1,
		valueGroup: 2,
		confidence: medium,
		description: 'Connection string',
	},

	// --- standalone patterns (valueGroup 1, no key required) -----------
	{
		type: 'aws-key',
		pattern: /\b(AKIA[0-9A-Z]{16})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'AWS Access Key ID',
	},
	{
		type: 'token',
		pattern:
			/\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'Known token prefix (GitHub/Slack/Stripe/Google)',
	},
	{
		type: 'bearer-token',
		pattern: /\bbearer\s+([A-Za-z0-9_\-.=]{20,})/dgi,
		valueGroup: 1,
		confidence: high,
		description: 'Bearer token',
	},
	{
		type: 'jwt',
		pattern:
			/\b(eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'JWT token (format only)',
	},
	{
		type: 'database-url',
		pattern:
			/\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp):\/\/[^\s'"@]+:[^\s'"@]+@[^\s'"]+)/dgi,
		valueGroup: 1,
		confidence: high,
		description: 'Database URL with embedded credentials',
	},
	{
		type: 'private-key',
		pattern:
			/-----BEGIN\s+(?:[A-Z][A-Z ]*\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----[\s\S]+?-----END\s+(?:[A-Z][A-Z ]*\s+)?PRIVATE\s+KEY(?:\s+BLOCK)?-----/dg,
		valueGroup: 0,
		confidence: high,
		description: 'Private key block (PEM)',
	},
]);

const API_KEY_TYPES: ReadonlySet<SecretType> = new Set([
	'api-key',
	'aws-key',
	'aws-secret',
	'gcp-key',
	'azure-key',
]);
const TOKEN_TYPES: ReadonlySet<SecretType> = new Set([
	'token',
	'jwt',
	'oauth-token',
	'bearer-token',
	'access-token',
	'refresh-token',
]);
const PRIVATE_KEY_TYPES: ReadonlySet<SecretType> = new Set([
	'private-key',
	'ssh-key',
	'pgp-key',
]);

/** PEM blocks carry their kind in the header; refine the reported type. */
function classifyPemBlock(block: string): SecretType {
	if (block.includes('OPENSSH')) return 'ssh-key';
	if (block.includes('PGP')) return 'pgp-key';
	return 'private-key';
}

export function detectSecrets(
	content: string,
	options: {
		readonly includeApiKeys?: boolean;
		readonly includePasswords?: boolean;
		readonly includeTokens?: boolean;
		readonly includePrivateKeys?: boolean;
		readonly sensitivity?: 'low' | 'medium' | 'high';
	} = {},
): readonly DetectedSecret[] {
	const {
		includeApiKeys = true,
		includePasswords = true,
		includeTokens = true,
		includePrivateKeys = true,
		sensitivity = 'medium',
	} = options;

	const positionAt = createPositionIndex(content);
	const secrets: DetectedSecret[] = [];
	const seen = new Set<string>();

	for (const pattern of SECRET_PATTERNS) {
		const resolvedType =
			pattern.valueGroup === 0 && pattern.type === 'private-key'
				? undefined // classified per match below
				: pattern.type;

		if (resolvedType && !included(resolvedType)) continue;

		pattern.pattern.lastIndex = 0;
		for (const match of content.matchAll(pattern.pattern)) {
			const indices = match.indices;
			if (!indices) continue;

			const valueSpan = indices[pattern.valueGroup];
			const value = match[pattern.valueGroup];
			if (!valueSpan || !value) continue;

			if (looksLikePlaceholder(value)) continue;

			const type = resolvedType ?? classifyPemBlock(value) ?? pattern.type;
			if (!resolvedType && !included(type)) continue;

			const confidence = pattern.confidence(value);
			if (sensitivity === 'high' && confidence !== 'high') continue;
			if (sensitivity === 'medium' && confidence === 'low') continue;

			const [start, end] = valueSpan;
			const dedupeKey = `${start}:${value}`;
			if (seen.has(dedupeKey)) continue;
			seen.add(dedupeKey);

			const keyName =
				pattern.keyGroup !== undefined
					? match[pattern.keyGroup]?.toLowerCase()
					: undefined;

			secrets.push(
				Object.freeze({
					value,
					type,
					confidence,
					start,
					end,
					position: positionAt(start),
					context: lineTextAt(content, start).trim(),
					key: keyName,
					description: pattern.description,
				}),
			);
		}
	}

	// Report in document order regardless of which pattern found what.
	secrets.sort((a, b) => a.start - b.start);
	return Object.freeze(secrets);

	function included(type: SecretType): boolean {
		if (API_KEY_TYPES.has(type)) return includeApiKeys;
		if (type === 'password') return includePasswords;
		if (TOKEN_TYPES.has(type)) return includeTokens;
		if (PRIVATE_KEY_TYPES.has(type)) return includePrivateKeys;
		return true;
	}
}
