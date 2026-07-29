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

- **Build:** esbuild bundle (`bun run build`, `build:prod` minified). `tsc` is typecheck-only (`noEmit`) and covers test files.
- **Unit tests:** vitest; `vscode` aliased to `src/__mocks__/vscode.ts` (stateful mock: config store, message log, command registry, workspace file list, `_reset/_set` helpers). Coverage thresholds enforced: 80 lines / 80 funcs / 75 branches / 80 stmts.
- **Integration tests:** `bun run test:integration` — `@vscode/test-cli` launches a real VS Code against `test/integration/workspace/` (config in `.vscode-test.mjs`, tests compiled via `tsconfig.it.json` to `out-test/`). The extension id is derived from the manifest.
- **Lint/format:** Biome (tabs, single quotes). `__fixtures__`/`__snapshots__` are exempt (linter+formatter+assist) — formatting fixtures would corrupt goldens.
- **Packaging:** `bun run package` → `release/*.vsix`. `.vscodeignore` is an allow-list; the VSIX is ~9 files.

## Release

1. Bump `version` in package.json, add a CHANGELOG entry.
2. CI green on all 3 OSes (includes packaging + integration tests).
   Locally, `bun run package && bun run test:e2e-vsix` proves the actual
   VSIX installs and works in a clean VS Code profile.
3. `Release` workflow (manual dispatch) publishes to the VS Code Marketplace (`VSCE_PAT`) and Open VSX (`OVSX_PAT`) — Open VSX is what Cursor/VSCodium users install from. Locally: `bun run package` then `vsce publish` / `ovsx publish`.

## Known limitations (documented, not bugs)

- Regex-based: obfuscated, split, or unconventionally named secrets are missed; entropy alone is never a trigger.
- JWTs must start with `eyJ` (base64 of `{"`); non-JSON-header JWTs are missed — the trade that kills `1.2.3`/hostname false positives.
- Key-based patterns need the key stem (`…password`, `…token`, `…api_key`) or a known value prefix; an anonymous high-entropy string is not reported.
- The password pattern stops at whitespace, quotes, and `;` — passwords containing those are truncated or missed.
- Workspace scan excludes are matched with a simplified glob→regex conversion, not full glob semantics.
