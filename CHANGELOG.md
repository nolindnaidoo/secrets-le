# Changelog

All notable changes to Secrets-LE will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-08-05

### Added

- Runtime strings are localized, and this time they render. All 4 of them —
  notifications, status bar, quick-picks and prompts — go through
  `vscode.l10n` and ship as twelve translated bundles in `l10n/`. The v1.x
  line carried manifest catalogues that worked and runtime catalogues that
  never reached the screen: `vscode-nls` was configured without
  `__filename`, so every runtime string fell back to English while the VSIX
  looked correct.
- An integration test covering both localization mechanisms — manifest
  substitution, key parity across all thirteen catalogues, and placeholder
  integrity in every translation. A translation that silently drops `{0}`
  now fails the build instead of shipping a message with the value missing.

- Dependency review on pull requests, failing on a high-severity addition
  before Dependabot's auto-merge can act.

### Fixed

- A clipboard that could not be written failed the whole command. The report
  and the sanitized document are both already delivered by the time the copy
  runs, so an unavailable clipboard — a remote or headless session — was
  reported as "Detection failed" or "Sanitization failed". Both are now
  warnings.
- Sanitize could report success over a file it had not touched.
  `vscode.workspace.applyEdit` resolves `false` when an edit is rejected — a
  read-only document, or one that changed underneath the command — and that
  value was discarded, so "Sanitized N secret(s)" was shown for a file that
  still contained every credential. A user could reasonably commit it
  believing it was scrubbed. The rejection is now reported as a failure that
  says the secrets are still present.
- The detection report wrote detected secrets into the results document. The
  value line was `substring(0, 20)`, which is a partial disclosure for a
  40-character AWS secret but the *entire* value for anything shorter — and
  the password detector matches from eight characters, so most passwords
  appeared in full, with no ellipsis to suggest otherwise. The context line
  was worse: it is the raw source line, so `DATABASE_PASSWORD=hunter2hunter2`
  was reproduced verbatim. Both are now capped at eight characters and at half
  the value's length, always marked as elided, and the value is redacted from
  its own context line. The report still identifies every finding by file,
  line, column, key name, type and confidence — none of which required the
  credential itself.
- The activation entry point had no test and was the only file in the fleet at
  0% coverage; the other nine cover it from `services.test.ts`. A command
  declared in the manifest but never registered would have failed at the
  moment a user ran it. Now 100%.
- The sanitize confirmation, the workspace and editor guards and their button
  labels were never localized. The confirm label is now bound to a constant
  and compared by reference: `showWarningMessage` returns the label that was
  clicked, so localizing it without binding would have made sanitizing
  impossible to confirm outside English.
- The eight progress messages were never localized — progress text goes
  through `progress.report()` rather than a property the localization pass
  inspected.

### Changed

- Every `else` block is gone (9 of them), replaced by guard clauses and value
  expressions, per the code style in `AGENTS.md`.
- Report rendering moved out of `extraction/extract.ts` to `report/format.ts`.
  Building the markdown a user reads is presentation and was sitting next to
  the detection logic; the two change for different reasons. Extraction drops
  from 390 lines to 157.

- Test coverage raised from 74.58% to 76.58% of branches (83.92% to 86.63% of
  statements). Three files sat below one of the repo's own floors; none do
  now. Both commands check for cancellation between every step of their
  progress task — that is what keeps a workspace scan interruptible — and none
  of those checks were reachable, because the tests supplied a notifier
  without `showProgress` and so never ran the task at all. The status bar's
  show, hide and dispose had never been called either.


- CI gains fleet-wide checks that no single repo can perform: shared config is
  compared across all ten extensions, and every README link is verified —
  including Open VSX links, which are checked against the API because
  open-vsx.org answers HTTP 200 for extensions that do not exist.

## [2.0.1] - 2026-08-04

### Changed

- Marketplace categories re-targeted for discovery. `Other` is dropped
  (65,992 extensions, no discovery value); each extension now sits in
  categories matching how it is actually used.
- Search keywords widened to 30, targeting the terms users actually type
  rather than internal vocabulary.
- Toolchain moved to current: TypeScript 7, vitest 4, Biome 2.5.7,
  @types/node 26. `@types/vscode` is now pinned exactly to the
  `engines.vscode` floor — the caret had let the type surface drift 15
  minors ahead of the version actually supported.
- Runtime dependencies updated across majors where present: csv-parse 7,
  ini 7, js-yaml 5. Extraction output is unchanged, verified against the
  characterization goldens.
- Packaging no longer walks the npm tree (`vsce package --no-dependencies`).
  The bundle is self-contained, so the walk served no purpose and failed
  after any dependency change. Scrape-LE keeps it, since it genuinely
  ships `playwright-core`.
- Documentation claims corrected against the code. Removed: Numbers-LE
  "with statistics", EnvSync-LE "visual diffs", Regex-LE "live feedback",
  String-LE "and validation" — none of those features exist.

### Added

- Rating links in the in-extension help output, for both the VS Code
  Marketplace and Open VSX. Acquisitions exceed listing page views, so most
  users never see the listing's rating control; help is the surface they do
  reach.
- README now carries measured Performance and Testing sections, both
  generated rather than written — from `scripts/benchmark.ts` and from the
  coverage summary. CI fails if the coverage numbers drift from a real run.
- Coverage thresholds enforced at 75 lines / 80 functions / 60 branches /
  75 statements.
- CodeQL scanning, Dependabot with grouped weekly updates, and auto-merge
  limited to patch and minor devDependency bumps that pass CI.

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
