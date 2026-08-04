# Changelog

All notable changes to Secrets-LE will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.1] - 2026-08-03

### Changed

- Marketplace categories re-targeted for discovery. `Other` is dropped
  (65,992 extensions, no discovery value); each extension now sits in
  categories matching how it is actually used.

### Added

- Rating links in the in-extension help output, for both the VS Code
  Marketplace and Open VSX. Acquisitions exceed listing page views, so most
  users never see the listing's rating control; help is the surface they do
  reach.

## [2.0.0] - 2026-07-29

Full rehabilitation release. The headline: **v1.x VSIXes built from this
repo could not activate** — the build had no bundler while the package
excluded `node_modules`, so the extension crashed on load with
`Cannot find module 'vscode-nls'`. 2.0.0 ships a self-contained esbuild
bundle, verified by a packaging gate and a real extension-host
integration suite on every CI run.

### Fixed

- **Packaging**: `dist/extension.js` is now a single self-contained
  bundle (VSIX → 9 files). A bundle gate (static require scan + loading
  the bundle with `vscode` stubbed) blocks any regression. The old build
  also compiled a test file into `dist/`, shipping a `vitest` require.
- **Multi-line private keys were never detected.** The v1.x detector
  matched line by line, so its three BEGIN/END PEM patterns could not
  match a real key (a PEM block never fits on one line). Detection now
  runs over whole file content; RSA/EC, OpenSSH, and PGP blocks are
  detected and classified by header.
- **Sanitize replaced the wrong text in edge cases**: replacement
  searched by line/column proximity and fell back to first-occurrence
  `indexOf`. It now replaces by the exact detected offsets, skips stale
  offsets, and collapses overlapping detections into one replacement.
- **Whole-document edit range**: `Range(0, 0, lineCount, 0)` relied on
  VS Code clamping; the real end position is computed now.
- **Config**: non-numeric setting overrides no longer produce `NaN`
  thresholds; wrong-typed values are rejected instead of coerced; code
  fallbacks provably match manifest defaults (asserted by a parity test
  covering every declared key).
- **Status bar**: reacts to `statusBar.enabled` changes without reload.
- **Notifications**: `notificationsLevel` now governs every
  notification (`all` / `important` / `silent`); the sanitize flow
  previously ignored it entirely.
- **Error messages** redact home directories and credential-shaped
  fragments before display — an error embedding file content is exactly
  where a secret would leak.

### Changed — detection output

- **Positions point at the secret value** (real line/column via a
  newline-offset index), not at the start of the key name; every
  detection carries `start`/`end` offsets.
- **Quoted keys now match**: JSON (`"apiKey": "…"`) and quoted YAML/code
  assignments were invisible to every key-based v1.x pattern.
- **Compound key names match**: `DATABASE_PASSWORD`, `db_password`,
  `GITHUB_TOKEN` — the key stem matches as a suffix and the reported
  key is the full identifier.
- **JWT false positives are gone**: version numbers (`1.2.3`),
  hostnames (`docs.example.com`), and module paths no longer report as
  high-confidence JWTs. JWT-shaped values must start with `eyJ` (base64
  of `{"`); JWTs with non-JSON headers are knowingly missed.
- **New standalone detections** (no key name required): bare `AKIA…`
  AWS key ids; known token prefixes `ghp_`, `github_pat_`, `xox?-`,
  `sk_live_`/`sk_test_`, `AIza…`; database URLs carrying `user:pass@`
  credentials.
- **Placeholders are rejected**: `${VAR}`, `{{var}}`, `<your-key>`, and
  single-character runs are never reported.
- Password/cookie values stop at `;` so a match inside a connection
  string no longer swallows the following fields.
- Dropped: the "reversed format" api-key pattern (value before key
  name — never matched real configs) and GCP `project_id` as a secret
  (an identifier, not a credential).

### Removed

- Nine settings that were never read by any code path:
  `detection.enabled`, `sanitization.enabled`, `showParseErrors`,
  `safety.largeOutputLinesThreshold`, `safety.manyDocumentsThreshold`,
  and all four `performance.*` keys. 17 real settings remain, each with
  a consumer.
- The never-functional runtime localization layer (`vscode-nls` was
  configured without message bundles, so users saw the inline English
  defaults in every locale — those strings are now plain English).
- Dead modules and dead exports (output channel wrapper, sample format
  extractor, unused error/performance layers).

### Infrastructure

- esbuild bundle + bundle gate; tsc is typecheck-only and now covers
  tests; `.vscodeignore` is an allow-list.
- 105 unit tests against a stateful vscode mock (87% lines, thresholds
  enforced at 80/80/75/80) plus characterization goldens pinning
  detection output per format.
- Real extension-host integration suite; CI on 3 OSes runs lint →
  typecheck → coverage → build → bundle gate → package → integration
  and uploads the VSIX; manual release workflow publishes to the
  VS Code Marketplace and Open VSX.
- Engines `^1.90.0`; legacy `onCommand:` activation events removed.

## 1.x (condensed)

Versions 1.7.0–1.7.1 were the initial public releases. Their changelog
entries claimed features that did not exist (settings export/import/
reset commands, "13 languages coming", GitGuardian-level detection,
enterprise-grade error handling) and shipped packages that could not
activate; those entries are not reproduced here.
