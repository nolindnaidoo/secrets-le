# AGENTS.md — Secrets-LE

Technical source of truth for this repo. README.md is the user-facing doc; this file is for anyone (human or agent) changing the code.

## What this is

A VS Code extension that scans the workspace for hardcoded secrets (API keys, tokens, passwords, PEM private keys, credentialed database URLs) and can replace detections in the active file with a placeholder. Detection is regex over whole file content — no parser, no network, no writes outside normal document edits.

## Architecture

```
extension.ts              activate(): createServices() -> registerCommands()
services/serviceFactory   createServices(context) -> { telemetry, notifier,
                          statusBar, performanceMonitor }
commands/                 one file per command; deps injected as a frozen bag
                          detect (workspace scan), sanitize (active file),
                          help, settings (in config/)
extraction/detectors.ts   THE single pattern table (SECRET_PATTERNS) +
                          detectSecrets() over whole content with the d flag
extraction/heuristics.ts  shared value heuristics: looksLikePlaceholder,
                          confidenceByLength, isJwtShaped
extraction/position.ts    offset -> {line, column} via newline index (1-based)
extraction/extract.ts     detectSecretsInContent, offset-based sanitizeContent,
                          result formatters
utils/                    errors (sanitizeErrorMessage), safety (size guards),
                          workspaceScanner (findFiles + per-file detection),
                          performance (operation timing for telemetry)
ui/                       notifier (window messages, gated by notificationsLevel:
                          all -> everything, important -> warn+error,
                          silent -> error only), statusBar
config/config.ts          getConfiguration() snapshot; CONFIG_DEFAULTS table
types.ts                  shared types only — no logic
```

Conventions: factory functions + `Object.freeze` (no classes), early returns, dependency bags typed inline at the consumer. Runtime strings are plain English; `package.nls.json` localizes **manifest** strings only (VS Code `%key%` substitution — do not add a runtime i18n layer without wiring real bundles).

## Invariants (things that were once broken — keep them true)

- **The bundle must be self-contained.** The VSIX ships `dist/extension.js` only; `scripts/check-bundle.js` (run in `vscode:prepublish` and CI) does a static require scan AND loads the bundle with `vscode` stubbed. esbuild uses `--main-fields=module,main`.
- **`CONFIG_DEFAULTS` must equal package.json defaults.** `config.test.ts` asserts parity over every declared setting — both directions; add new settings to both plus the KEY_MAP in the test.
- **Every declared setting must have a consumer.** v1 shipped nine no-op settings; don't add a setting without wiring it.
- **Detection behavior is pinned by golden snapshots** (`extraction/characterization.test.ts` + `__fixtures__/`). Any output change must update goldens in the same commit and be listed in the CHANGELOG.
- **Patterns run against whole content, never line by line.** The v1 per-line loop made multi-line PEM detection impossible. Positions come from `match.indices` (the value group), not the match start.
- **Value heuristics live in one place** (`extraction/heuristics.ts`). Never inline a placeholder check or confidence lambda in the pattern table.
- **Sanitization replaces by offsets** (`start`/`end` on `DetectedSecret`), skips stale offsets, and collapses overlapping spans — never search-and-replace by value.
- **nls catalogue parity:** `package.nls.json` (root, committed) and `src/i18n/package.nls.json` carry exactly the keys the manifest references. English only — do not claim other languages anywhere.
- **`vsce package` needs `--allow-package-secrets github`:** the README shows token-shaped examples on purpose; the flag is scoped to that one scanner class, keep it that way.
- **Fixture values must not match GitHub push-protection patterns.** A `sk_test_`/`sk_live_` prefix with a 24+ alphanumeric payload blocks the push in ANY commit — use `sk_demo_` (the detector's Stripe-prefix support is expressed in the pattern table, not in committed examples). The canonical AWS example pair (`AKIAIOSFODNN7EXAMPLE`) is allow-listed by GitHub and safe.

## Toolchain

- **Runtime targets:** `engines.vscode` is the supported floor and `@types/vscode` is pinned to it **exactly**. A caret there lets the type surface drift ahead of the version users actually run, so code compiles against APIs that are not there at runtime. Dependabot is configured to never bump it.
- **Build:** esbuild bundle (`bun run build`, `build:prod` minified). `tsc` is typecheck-only (`noEmit`) and covers test files. TypeScript 7.
- **Unit tests:** vitest 4; `vscode` aliased to `src/__mocks__/vscode.ts` (stateful mock with `_reset/_set` helpers). Coverage provider `v8`, thresholds enforced at **75 lines / 80 functions / 60 branches / 75 statements**. These are a floor to ratchet upward, never to lower so a build passes.
- **Integration tests:** `bun run test:integration` — `@vscode/test-cli` launches a real VS Code (config in `.vscode-test.mjs`, tests compiled via `tsconfig.it.json` to `out-test/`). That project targets `node16` module resolution; TypeScript 7 removed `node10`, which `"Node"` resolved to.
- **Installed-VSIX tests:** `bun run test:e2e-vsix` installs the built `.vsix` into a clean VS Code profile and drives it. This is the only test that exercises the artifact users receive, and it runs in CI.
- **Lint/format:** Biome (tabs, single quotes). `__fixtures__`/`__snapshots__` are exempt — formatting fixtures would corrupt goldens. `biome.json` is byte-identical across all ten repos; change it in one and copy it to the rest.
- **Packaging:** `bun run package` → `release/*.vsix`. `.vscodeignore` is an allow-list; the VSIX is ~9 files. Packaging uses `--no-dependencies`: the bundle is self-contained, so walking the npm tree served no purpose and broke after any dependency change.
- **Localization:** This extension is English-only — `src/i18n/` holds `package.nls.json` and nothing else. Adding a locale means adding the file **and** keeping it in key-parity with the base catalogue.

## Generated documentation

Two README sections are generated. Do not hand-edit the content between their markers.

- `bun run test:coverage && bun run coverage:readme` writes the Testing section from `coverage/coverage-summary.json`. CI runs `coverage:readme:check`, which fails when the committed numbers no longer match a real run — coverage is compared within 1 percentage point (it is not bit-identical across machines), while test counts are derived from source and must match exactly.
- `bun run benchmark && bun run perf:readme` writes the Performance section from a real run of the extraction entry point. This is **not** checked in CI: throughput is machine-specific, so a hosted runner would fail it for reasons that say nothing about the code. The host is printed with the numbers instead.

The pre-2.0 README carried hand-written test counts and throughput figures that drifted until they were false. Generating them is what stops that recurring.

## Security & automation

- **CodeQL** runs on push, PR and weekly (`javascript-typescript` + `actions`), configured in `.github/codeql-config.yml`. Test files and fixtures are excluded on purpose: they contain inputs that are supposed to look dangerous, and scanning them produces findings that can only ever be dismissed.
- **Dependabot** (`bun` ecosystem, not `npm` — the npm updater rewrites `package.json` without regenerating `bun.lock`, so its PRs can never pass the frozen-lockfile gate) opens grouped weekly PRs.
- **Auto-merge** is workflow-driven, not GitHub-native: `main` has no required status checks, so native auto-merge would land a PR before CI started. `dependabot-auto-merge.yml` waits for the CI run to conclude and merges only patch/minor **devDependency** updates. Runtime dependencies bundle into the shipped VSIX and always need a human.
- **Actions are pinned to commit SHAs.** A tag is mutable and this repo holds a publish token. The trailing `# vX.Y.Z` comment is what Dependabot reads and rewrites.
- **Branch safety:** a `main-safety` ruleset blocks deletion and force-push. Pushes to `main` are otherwise unrestricted by design.
- Secret scanning and push protection are enabled. `VSCE_PAT` and `OVSX_PAT` live in repo secrets and in Doppler (`extensions` / `prd`).

## Release

1. Bump `version` in package.json and write the CHANGELOG entry. The entry must describe what actually changed, including bug fixes — it ships inside the VSIX and renders on the listing page.
2. Regenerate the README sections (`coverage:readme`, and `perf:readme` if behaviour changed) and commit them.
3. CI green on all three OSes. That includes lint, typecheck, coverage, the bundle gate, packaging, integration tests, and the installed-VSIX e2e.
4. Tag the commit being released, so the tag is the artifact rather than an approximation of it.
5. Dispatch the `Release` workflow. It takes two independent opt-ins — `marketplace` (default **on**) and `openvsx` (default **off**) — because a version cannot be republished, so a run that publishes one registry and fails on the other is only recoverable by re-running with the failed target alone. It validates credentials before doing anything irreversible.

**Open VSX defaults off deliberately.** `ovsx publish` takes no namespace argument; it derives the namespace from `publisher` in the VSIX. Enabling it publishes to whatever `package.json` currently names, with no confirmation.

## Known limitations (documented, not bugs)

- Regex-based: obfuscated, split, or unconventionally named secrets are missed; entropy alone is never a trigger.
- JWTs must start with `eyJ` (base64 of `{"`); non-JSON-header JWTs are missed — the trade that kills `1.2.3`/hostname false positives.
- Key-based patterns need the key stem (`…password`, `…token`, `…api_key`) or a known value prefix; an anonymous high-entropy string is not reported.
- The password pattern stops at whitespace, quotes, and `;` — passwords containing those are truncated or missed.
- Workspace scan excludes are matched with a simplified glob→regex conversion, not full glob semantics.
