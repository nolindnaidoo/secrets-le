import { describe, expect, it } from 'vitest';
import type { SecretType } from '../types';
import { maskSecretValue } from '../utils/mask';
import { detectSecrets, SECRET_PATTERNS } from './detectors';

/**
 * The issuer-prefixed detectors: the ones that recognise a credential
 * from the value's own prefix rather than from the key name beside it.
 *
 * EVERY VALUE IN THIS FILE IS INVENTED. Each matches this tool's pattern
 * for its issuer and deliberately misses the issuer's own exact format —
 * a different length, a missing service marker — so that nothing here is
 * a plausible credential and nothing here trips a push-protection rule.
 * `crate/fixtures/documents/provider-tokens.txt` follows the same rule
 * and the same shapes.
 */

interface Case {
	readonly issuer: string;
	readonly type: SecretType;
	readonly confidence: 'low' | 'medium' | 'high';
	/** Which `--no-…` family the finding answers to. */
	readonly family: 'apiKeys' | 'tokens';
	readonly value: string;
}

/**
 * Assembled from pieces rather than written out.
 *
 * The legacy OpenAI format is `sk-` and *exactly* 48 characters, and it
 * is the one shape in this file whose length is the issuer's own rather
 * than deliberately beside it. Splitting the literal keeps a 48-run out
 * of the repository, so committing this test cannot trip a scanner —
 * ours or anyone else's — while the value the test builds still
 * exercises the pattern.
 */
const OPENAI_LEGACY = `sk-${'EXAMPLEnotarealopenaikey'}${'0'.repeat(24)}`;

const CASES: readonly Case[] = [
	{
		issuer: 'Anthropic',
		type: 'anthropic-key',
		confidence: 'high',
		family: 'apiKeys',
		value: 'sk-ant-api03-EXAMPLEnotarealanthropickey00000',
	},
	{
		issuer: 'OpenAI (project)',
		type: 'openai-key',
		confidence: 'high',
		family: 'apiKeys',
		value: 'sk-proj-EXAMPLEnotarealopenaikey000000000000',
	},
	{
		issuer: 'OpenAI (legacy 48)',
		type: 'openai-key',
		confidence: 'high',
		family: 'apiKeys',
		value: OPENAI_LEGACY,
	},
	{
		issuer: 'OpenAI (service account)',
		type: 'openai-key',
		confidence: 'high',
		family: 'apiKeys',
		value: 'sk-svcacct-EXAMPLEnotarealopenaikey000000',
	},
	{
		issuer: 'GitLab',
		type: 'gitlab-token',
		confidence: 'high',
		family: 'tokens',
		value: 'glpat-EXAMPLEnotarealgitlab00',
	},
	{
		issuer: 'GitLab (runner)',
		type: 'gitlab-token',
		confidence: 'high',
		family: 'tokens',
		value: 'glrt-EXAMPLEnotarealgitlabrunner00',
	},
	{
		issuer: 'SendGrid',
		type: 'sendgrid-key',
		confidence: 'high',
		family: 'apiKeys',
		value:
			'SG.EXAMPLEnotarealsendgridselector1234.EXAMPLEnotarealsendgridsecret00000',
	},
	{
		issuer: 'Mailgun',
		type: 'mailgun-key',
		confidence: 'medium',
		family: 'apiKeys',
		value: 'key-deadbeefdeadbeefdeadbeefdeadbeefface',
	},
	{
		issuer: 'Sentry',
		type: 'sentry-token',
		confidence: 'high',
		family: 'tokens',
		value: 'sntrys_EXAMPLEnotarealsentryorgauthtoken00000000',
	},
	{
		issuer: 'npm',
		type: 'npm-token',
		confidence: 'high',
		family: 'tokens',
		value: 'npm_EXAMPLEnotarealnpmtoken00000000000000000',
	},
	{
		issuer: 'PyPI',
		type: 'pypi-token',
		confidence: 'high',
		family: 'tokens',
		value: 'pypi-AgENOTAREALpypitokenEXAMPLE0000000000000000000000000000',
	},
	{
		issuer: 'Docker Hub',
		type: 'docker-token',
		confidence: 'high',
		family: 'tokens',
		value: 'dckr_pat_EXAMPLEnotarealdockertoken00000000',
	},
	{
		issuer: 'HashiCorp Vault',
		type: 'vault-token',
		confidence: 'high',
		family: 'tokens',
		value: 'hvs.EXAMPLEnotarealvaulttoken00',
	},
	{
		issuer: 'Terraform Cloud',
		type: 'terraform-token',
		confidence: 'high',
		family: 'tokens',
		value:
			'EXAMPLEnotar.atlasv1.EXAMPLEnotarealterraformcloudtoken000000000000',
	},
	{
		issuer: 'Supabase (personal access token)',
		type: 'supabase-key',
		confidence: 'high',
		family: 'apiKeys',
		value: 'sbp_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefface',
	},
	{
		issuer: 'Supabase (secret key)',
		type: 'supabase-key',
		confidence: 'high',
		family: 'apiKeys',
		value: 'sb_secret_EXAMPLEnotarealsupabase00',
	},
	{
		issuer: 'Shopify',
		type: 'shopify-token',
		confidence: 'high',
		family: 'tokens',
		value: `shpat_${'deadbeef'.repeat(4)}`,
	},
	{
		issuer: 'Square',
		type: 'square-token',
		confidence: 'high',
		family: 'tokens',
		value: 'sq0atp-EXAMPLEnotarealsquare00',
	},
];

/** The Azure case is a query string, not a bare value, so it stands apart. */
const AZURE_SAS =
	'https://example.blob.core.windows.invalid/c/b?sv=2024-11-04&ss=b&srt=o&sp=r&se=2030-01-01T00:00:00Z&sig=EXAMPLEnotarealazuresas0000';
const AZURE_SIGNATURE = 'EXAMPLEnotarealazuresas0000';

describe('issuer-prefixed detectors', () => {
	for (const testCase of CASES) {
		it(`finds a ${testCase.issuer} credential standing on its own`, () => {
			// No key name anywhere on the line: the prefix is doing all the
			// work, which is the whole reason these patterns exist.
			const found = detectSecrets(`run --credential ${testCase.value}\n`);
			expect(found.map((s) => s.type)).toEqual([testCase.type]);
			expect(found[0]?.confidence).toBe(testCase.confidence);
			expect(found[0]?.value).toBe(testCase.value);
		});

		it(`reports a ${testCase.issuer} credential as its issuer, not as a generic key`, () => {
			// Under a key name the generic detectors also claim, the issuer
			// pattern must be the one that wins the dedupe — it runs first.
			const found = detectSecrets(`API_KEY=${testCase.value}\n`);
			expect(found.map((s) => s.type)).toEqual([testCase.type]);
		});

		it(`switches a ${testCase.issuer} credential off with its own family`, () => {
			const content = `run --credential ${testCase.value}\n`;
			const off = { apiKeys: 'includeApiKeys', tokens: 'includeTokens' }[
				testCase.family
			];
			expect(detectSecrets(content, { [off]: false })).toHaveLength(0);
			// And is untouched by the other three, so no switch is doing more
			// than it says.
			for (const other of [
				'includeApiKeys',
				'includePasswords',
				'includeTokens',
				'includePrivateKeys',
			].filter((name) => name !== off)) {
				expect(detectSecrets(content, { [other]: false })).toHaveLength(1);
			}
		});

		it(`never emits the ${testCase.issuer} value it found`, () => {
			const found = detectSecrets(`API_KEY=${testCase.value}\n`);
			const emitted = [
				maskSecretValue(found[0]?.value ?? ''),
				found[0]?.context ?? '',
				found[0]?.key ?? '',
			];
			for (const text of emitted) {
				expect(text).not.toContain(testCase.value);
			}
		});
	}

	it('finds an Azure SAS signature and reports only the signature', () => {
		const found = detectSecrets(`${AZURE_SAS}\n`);
		expect(found.map((s) => s.type)).toEqual(['azure-sas']);
		expect(found[0]?.value).toBe(AZURE_SIGNATURE);
		// The policy the signature authorises is not the credential, and a
		// reader needs to see it to judge the blast radius.
		expect(found[0]?.context).toContain('se=2030-01-01');
		expect(found[0]?.context).not.toContain(AZURE_SIGNATURE);
	});
});

describe('issuer prefixes deliberately not matched', () => {
	/**
	 * Each of these is a shape that was considered and refused. A test
	 * that passes by matching one of them is the false positive this
	 * whole table is trying not to produce.
	 */
	const REFUSED: ReadonlyArray<readonly [string, string]> = [
		['a bare sk- prefix, which is any hyphenated identifier', 'sk-abcdefghij'],
		[
			"Vault's pre-1.10 s. form, which is every object.property",
			'token = s.abcdefghijklmnopqrstuvwx',
		],
		[
			'a Supabase publishable key, which is designed to ship in a bundle',
			'sb_publishable_EXAMPLEnotarealsupabase00',
		],
		['a short key- string, which is ordinary text', 'cache-key-deadbeef'],
		[
			'a signed URL with no Azure storage version on it',
			'https://cdn.example.invalid/f?sig=EXAMPLEnotarealsignature0000',
		],
		[
			'a Terraform-shaped value with no atlasv1 marker',
			'EXAMPLEnotar.atlasv2.EXAMPLEnotarealterraformcloudtoken000000000000',
		],
	];

	for (const [why, content] of REFUSED) {
		it(`does not report ${why}`, () => {
			for (const secret of detectSecrets(content, { sensitivity: 'low' })) {
				expect(secret.type).not.toMatch(
					/^(anthropic|openai|gitlab|sendgrid|mailgun|sentry|npm|pypi|docker|vault|terraform|supabase|shopify|square|azure-sas)/,
				);
			}
		});
	}

	it("still reports Stripe's sk_live_ as the known-prefix token it is", () => {
		const found = detectSecrets(
			`stripe --key sk_live_${'EXAMPLEnotarealstripe0000'}\n`,
		);
		expect(found.map((s) => s.type)).toEqual(['token']);
	});
});

describe('the pattern table', () => {
	it('runs every issuer-prefixed pattern before the first key-name one', () => {
		const firstKeyName = SECRET_PATTERNS.findIndex(
			(pattern) => pattern.keyGroup !== undefined,
		);
		const issuers = new Set(CASES.map((testCase) => testCase.type));
		issuers.add('azure-sas');
		for (const type of issuers) {
			const at = SECRET_PATTERNS.findIndex((pattern) => pattern.type === type);
			expect(at).toBeGreaterThanOrEqual(0);
			expect(at).toBeLessThan(firstKeyName);
		}
	});

	it('has a case here for every issuer-prefixed pattern in it', () => {
		// A pattern added without a case would otherwise ship with its
		// family membership, its confidence and its shape all unasserted.
		const covered = new Set<string>([
			...CASES.map((testCase) => testCase.type),
			'azure-sas',
		]);
		const declared = SECRET_PATTERNS.slice(
			0,
			SECRET_PATTERNS.findIndex((pattern) => pattern.keyGroup !== undefined),
		).map((pattern) => pattern.type);
		expect([...new Set(declared)].sort()).toEqual([...covered].sort());
	});
});
