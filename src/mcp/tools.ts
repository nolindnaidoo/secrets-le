import { detectSecretsInContent } from '../extraction/extract';
import type { DetectedSecret } from '../types';
import { maskSecretValue } from '../utils/mask';
import {
	capped,
	DEFAULT_MAX_RESULTS,
	envelope,
	MAX_MAX_RESULTS,
	readMaxResults,
	readString,
	toDiagnostics,
} from './envelope';
import type { ToolDefinition } from './transport';

/**
 * The tools this server exposes.
 *
 * Names are a public API with no deprecation channel — once an agent's prompt
 * or memory references `detect_secrets`, renaming it breaks silently. They are
 * pinned by a golden test for that reason.
 *
 * **This server never returns a secret.** Everything else in the family hands
 * back what it extracted; here that would mean posting live credentials to
 * whatever cloud model called the tool, which is the exact opposite of what
 * this extension is for. `DetectedSecret.value` is the raw match, so it goes
 * through `utils/mask` here; `DetectedSecret.context` arrives already masked
 * — against every value in the document, not only this finding's — and there
 * is no option, flag or code path that turns either off.
 *
 * A finding is identifiable without its value: the type, confidence, key name
 * and position are enough to locate it in the file, and the caller has the file.
 */

// Advertised in the schema with its default visible, rather than silently
// enforced. A model that can see the cap can raise it when it genuinely needs
// more, and can read `meta.truncated` to know it should. A hidden cap just
// produces quietly incomplete answers.
const MAX_RESULTS_SCHEMA = {
	type: 'integer',
	minimum: 1,
	maximum: MAX_MAX_RESULTS,
	default: DEFAULT_MAX_RESULTS,
	description: `Cap on returned findings (default ${DEFAULT_MAX_RESULTS}). meta.truncated reports whether any were dropped.`,
};

const SENSITIVITIES = Object.freeze(['low', 'medium', 'high']);

/**
 * The only shape a finding leaves this server in.
 *
 * Written as an allow-list rather than a spread-and-delete: a new field on
 * `DetectedSecret` should have to be added here deliberately, not arrive in the
 * output because nobody remembered to strip it.
 */
function redact(secret: DetectedSecret): Record<string, unknown> {
	return {
		type: secret.type,
		confidence: secret.confidence,
		key: secret.key,
		preview: maskSecretValue(secret.value),
		// Already masked, and masked against *every* value in the document
		// rather than only this finding's — see utils/mask.maskContext.
		context: secret.context,
		line: secret.position?.line,
		column: secret.position?.column,
	};
}

function readSensitivity(
	args: Record<string, unknown>,
): 'low' | 'medium' | 'high' | undefined {
	const raw = args.sensitivity;
	if (raw === undefined) return undefined;
	if (typeof raw !== 'string' || !SENSITIVITIES.includes(raw)) {
		throw new Error(`sensitivity must be one of: ${SENSITIVITIES.join(', ')}`);
	}
	return raw as 'low' | 'medium' | 'high';
}

function readFlag(args: Record<string, unknown>, name: string): boolean {
	// Absent means "include", matching the extension's own defaults; only an
	// explicit false narrows the scan.
	return args[name] !== false;
}

function detect(args: Record<string, unknown>): Promise<unknown> {
	const content = readString(args, 'content');
	const maxResults = readMaxResults(args);
	const sensitivity = readSensitivity(args);

	const result = detectSecretsInContent(content, {
		includeApiKeys: readFlag(args, 'includeApiKeys'),
		includePasswords: readFlag(args, 'includePasswords'),
		includeTokens: readFlag(args, 'includeTokens'),
		includePrivateKeys: readFlag(args, 'includePrivateKeys'),
		...(sensitivity ? { sensitivity } : {}),
	});

	const { items, truncated } = capped(result.secrets.map(redact), maxResults);

	return Promise.resolve(
		envelope(
			'detect_secrets',
			{ secrets: items },
			items.length,
			toDiagnostics(result),
			truncated,
		),
	);
}

export const TOOLS: readonly ToolDefinition[] = Object.freeze([
	Object.freeze({
		name: 'detect_secrets',
		description:
			'Detect hardcoded secrets — API keys, passwords, tokens and private keys — in source or configuration text. Reports each finding by type, confidence, key name and 1-based position. Values are never returned: previews are truncated and length-annotated, and the surrounding context line has the secret masked out, so a finding can be located without the credential leaving the machine it was found on.',
		inputSchema: {
			type: 'object',
			properties: {
				content: {
					type: 'string',
					description: 'The text to scan.',
				},
				sensitivity: {
					type: 'string',
					enum: SENSITIVITIES,
					description:
						'Detection threshold. Higher sensitivity reports more low-confidence matches.',
				},
				includeApiKeys: {
					type: 'boolean',
					default: true,
					description: 'Include API key detectors.',
				},
				includePasswords: {
					type: 'boolean',
					default: true,
					description: 'Include password detectors.',
				},
				includeTokens: {
					type: 'boolean',
					default: true,
					description: 'Include token detectors.',
				},
				includePrivateKeys: {
					type: 'boolean',
					default: true,
					description: 'Include private key detectors.',
				},
				maxResults: MAX_RESULTS_SCHEMA,
			},
			required: ['content'],
			additionalProperties: false,
		},
		handler: detect,
	}),
]);
