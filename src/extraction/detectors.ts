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
	collapseUnclaimedRuns,
	maskAll,
	maskContext,
	maskingOrder,
} from '../utils/mask';
import {
	confidenceByLength,
	isJwtShaped,
	looksLikePlaceholder,
} from './heuristics';
import { createPositionIndex, lineAndOffset } from './position';

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
 *
 * The issuer-prefixed patterns lead for the same reason one level up. A
 * value that names its own issuer is more specific than a key name that
 * only says "token", and the two claim the same span: `NPM_TOKEN=npm_…`
 * matches the generic token pattern too, and whichever runs first is the
 * one reported. Running them first buys two things. The report names the
 * issuer, so a reader knows which credential to revoke. And the
 * confidence is the shape's rather than the length's — a 31-character
 * `sk-proj-…` under an `api_key` name grades `medium` by length and is
 * dropped by `--sensitivity high`, which is a live OpenAI key going
 * unreported by a run that asked for the certain findings only.
 */
export const SECRET_PATTERNS: readonly SecretPattern[] = Object.freeze([
	// --- issuer-prefixed values (valueGroup 1, no key required) --------
	//
	// Bounds are open at the top (`{20,}`, not `{20}`) even where the
	// issuer documents an exact length. The prefix is what makes these
	// specific; the length is not doing the work, and issuers lengthen
	// their tokens — GitLab's routable tokens and OpenAI's project keys
	// are both longer than the format they replaced. An exact bound would
	// have silently stopped matching on the day that shipped.
	{
		type: 'anthropic-key',
		pattern: /\b(sk-ant-[A-Za-z0-9_-]{24,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'Anthropic API key',
	},
	{
		type: 'openai-key',
		// The legacy form is `sk-` and exactly 48 alphanumerics; the
		// current ones carry a class prefix. `sk-` on its own is too weak
		// to match — it is the start of Stripe's `sk_live_` with a
		// different separator, and of any hyphenated identifier.
		pattern:
			/\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{48})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'OpenAI API key',
	},
	{
		type: 'gitlab-token',
		pattern: /\b(gl(?:pat|rt|dt)-[A-Za-z0-9_-]{20,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'GitLab access token',
	},
	{
		type: 'sendgrid-key',
		pattern: /\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{30,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'SendGrid API key',
	},
	{
		type: 'mailgun-key',
		// `key-` is an English word before a hyphen, so this is the one
		// issuer prefix in the table that is also ordinary text. Graded
		// medium for that reason: it still shows by default and is
		// dropped by `--sensitivity high`, which is where a maybe belongs.
		pattern: /\b(key-[0-9a-f]{32,})\b/dg,
		valueGroup: 1,
		confidence: medium,
		description: 'Mailgun API key',
	},
	{
		type: 'sentry-token',
		pattern: /\b(sntry[su]_[A-Za-z0-9+/=_-]{40,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'Sentry auth token',
	},
	{
		type: 'npm-token',
		pattern: /\b(npm_[A-Za-z0-9]{36,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'npm access token',
	},
	{
		type: 'pypi-token',
		// A PyPI token is a macaroon, and every one of them begins with
		// the base64 of its own service identifier — `AgE` is where that
		// starts, and is what separates a token from any other `pypi-`
		// prefixed string.
		pattern: /\b(pypi-AgE[A-Za-z0-9_-]{50,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'PyPI API token',
	},
	{
		type: 'docker-token',
		pattern: /\b(dckr_pat_[A-Za-z0-9_-]{20,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'Docker Hub access token',
	},
	{
		type: 'vault-token',
		// Service, batch and recovery tokens. The pre-1.10 form was `s.`
		// and 24 characters, which is also every `object.property` in a
		// minified bundle, and is deliberately not matched.
		pattern: /\b(hv[bsr]\.[A-Za-z0-9_-]{24,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'HashiCorp Vault token',
	},
	{
		type: 'terraform-token',
		// `.atlasv1.` carries all the specificity here; the bounds either
		// side only keep the pattern from matching a stray word.
		pattern: /\b([A-Za-z0-9]{10,20}\.atlasv1\.[A-Za-z0-9_-]{40,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'Terraform Cloud API token',
	},
	{
		type: 'supabase-key',
		// The personal access token and the secret half of the newer key
		// pair. `sb_publishable_` is deliberately absent: it is designed
		// to ship in a browser bundle, and reporting it is how a scanner
		// teaches people to ignore it.
		pattern:
			/\b(sbp_(?:v[0-9]_)?[0-9a-f]{40,}|sb_secret_[A-Za-z0-9_-]{16,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'Supabase secret key',
	},
	{
		type: 'shopify-token',
		pattern: /\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'Shopify access token',
	},
	{
		type: 'square-token',
		pattern: /\b(sq0(?:atp|csp|idp)-[A-Za-z0-9_-]{20,})\b/dg,
		valueGroup: 1,
		confidence: high,
		description: 'Square access token',
	},
	{
		type: 'azure-sas',
		// The signature alone is the credential, so it alone is the
		// value: everything before it is the policy the signature
		// authorises — resource, permissions, expiry — and reporting that
		// as a secret would mask a line the reader needs to see. `sv=` is
		// the storage service version, which is what makes this Azure's
		// rather than any signed URL's, and the bounded run between the
		// two is what keeps a crafted line from costing more than it
		// should.
		pattern:
			/\bsv=[0-9]{4}-[0-9]{2}-[0-9]{2}[^\s'"]{0,300}?[?&]sig=([A-Za-z0-9%+/]{20,})/dg,
		valueGroup: 1,
		confidence: high,
		description: 'Azure Storage SAS signature',
	},

	// --- key-based patterns (keyGroup 1, valueGroup 2) -----------------
	{
		type: 'aws-secret',
		pattern: new RegExp(
			`${key('aws[_-]?(?:secret[_-]?)?(?:access[_-]?)?key|secretkey')}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])`,
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

/**
 * Which `--no-…` switch each type answers to.
 *
 * Every type must appear in exactly one of these three or be a password:
 * `included` returns true for anything it does not recognise, so a type
 * left out here is one no switch can turn off — a `--no-api-keys` run
 * that still reports API keys. `detectors.test.ts` asserts the table's
 * types are all covered.
 */
/**
 * A connection string and a database URL are reported *because* they
 * carry a credential in the URI, so `includePasswords` is the switch a
 * caller reaches for. Both answered to none of the four before, and so
 * did `cookie` and `session-id`, which are bearer credentials and sit
 * under tokens.
 */
const PASSWORD_TYPES: ReadonlySet<SecretType> = new Set([
	'password',
	'connection-string',
	'database-url',
]);

const API_KEY_TYPES: ReadonlySet<SecretType> = new Set([
	'api-key',
	'aws-key',
	'aws-secret',
	'gcp-key',
	'azure-key',
	'azure-sas',
	'anthropic-key',
	'mailgun-key',
	'openai-key',
	'sendgrid-key',
	'supabase-key',
]);
const TOKEN_TYPES: ReadonlySet<SecretType> = new Set([
	'token',
	'jwt',
	'oauth-token',
	'bearer-token',
	'access-token',
	'refresh-token',
	'docker-token',
	'gitlab-token',
	'npm-token',
	'pypi-token',
	'sentry-token',
	'shopify-token',
	'square-token',
	'terraform-token',
	'vault-token',
	'cookie',
	'session-id',
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

			// Kept verbatim for now: the key is a slice of the document and can
			// carry a credential of its own, so it is masked in the same pass as
			// the context, once every value in the document is known.
			const keyName =
				pattern.keyGroup !== undefined ? match[pattern.keyGroup] : undefined;

			secrets.push({
				value,
				type,
				confidence,
				start,
				end,
				position: positionAt(start),
				// Filled in below, once every value in the document is known: a
				// context line holds whatever else sits beside the finding, and
				// masking only the finding's own value left those in the clear.
				context: undefined,
				key: keyName,
				description: pattern.description,
			});
		}
	}

	// Report in document order regardless of which pattern found what.
	secrets.sort((a, b) => a.start - b.start);

	const order = maskingOrder(secrets.map((secret) => secret.value));
	// Every finding's span as offsets into the document, mirroring the crate.
	const spans: readonly (readonly [number, number])[] = secrets.map(
		(secret) => [secret.start, secret.start + secret.value.length] as const,
	);
	return Object.freeze(
		secrets.map((secret) => {
			const [line, offset] = lineAndOffset(content, secret.start);
			// Every finding's span, rebased onto the line this context is cut
			// from, so the window can blank source that overlaps another
			// finding instead of relying on its text being present whole.
			const lineStart = secret.start - offset;
			const lineSpans = spans
				.filter(
					([from, to]) => to > lineStart && from < lineStart + line.length,
				)
				.map(
					([from, to]) =>
						[
							Math.max(0, from - lineStart),
							Math.min(line.length, to - lineStart),
						] as const,
				);
			return Object.freeze({
				...secret,
				// Masked before it is lowercased: the key is source text, so an
				// embedded value appears in it with the case it was written in.
				//
				// Collapsed as well as masked, for the same reason the context is:
				// every key pattern begins `[A-Za-z0-9_-]*`, so the key group runs
				// backwards over whatever abuts the keyword. When that is a
				// credential the table did not claim, no value covers it and the key
				// carried it whole — a GitHub token shipped inside
				// `ghp_…database_password`.
				key:
					secret.key === undefined
						? undefined
						: collapseUnclaimedRuns(maskAll(secret.key, order)).toLowerCase(),
				context: maskContext(
					line,
					offset,
					secret.value.length,
					secret.value,
					order,
					lineSpans,
				),
			});
		}),
	);

	function included(type: SecretType): boolean {
		if (API_KEY_TYPES.has(type)) return includeApiKeys;
		if (PASSWORD_TYPES.has(type)) return includePasswords;
		if (TOKEN_TYPES.has(type)) return includeTokens;
		if (PRIVATE_KEY_TYPES.has(type)) return includePrivateKeys;
		return true;
	}
}
