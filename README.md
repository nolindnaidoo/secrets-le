<p align="center">
  <img src="src/assets/images/icon.png" alt="Secrets-LE Logo" width="96" height="96"/>
</p>
<h1 align="center">Secrets-LE: Zero Hassle Secret Detection</h1>
<p align="center">
  <b>Find hardcoded credentials across your workspace, then redact them in place</b><br/>
  <i>API keys, tokens, passwords, private keys — 100% local, nothing leaves your machine</i>
</p>

<p align="center">
  <a href="https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.secrets-le">
    <img src="https://img.shields.io/badge/Install%20from-VS%20Code-blue?style=for-the-badge&logo=visualstudiocode" alt="Install from VS Code Marketplace" />
  </a>
  <a href="https://letools.dev">
    <img src="https://img.shields.io/badge/LE%20Tools-letools.dev-blue?style=for-the-badge" alt="LE Tools" />
  </a>
</p>

---

<p align="center">
  <img src="src/assets/images/demo.gif" alt="Secrets-LE Demo" style="max-width: 100%; height: auto;" />
</p>

> **Useful?** A star or rating is how other developers find it —
> [★ GitHub](https://github.com/nolindnaidoo/secrets-le) ·
> [★ Marketplace](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.secrets-le&ssr=false#review-details) ·
> [★ Open VSX](https://open-vsx.org/extension/OffensiveEdge/secrets-le/reviews)

## What it does

Open a workspace, press `Ctrl+Alt+S` (`Cmd+Alt+S` on Mac), and every detected secret lands in a results document — grouped by file, with line/column positions pointing at the value itself. Run `Secrets-LE: Sanitize Secrets` to replace the secrets in the active file with a placeholder. Works in VS Code and in VS Code–based editors like Cursor and VSCodium (installable from Open VSX).

Detection is regex-based over the full text of each file, so it works on any text format — code, configs, `.env` files, YAML, JSON, logs. It is a pre-commit safety net, not a guarantee: a scanner built on patterns can miss secrets and can flag non-secrets. Review the results.

## What gets detected

| Category | Types |
|---|---|
| API keys & cloud credentials | Generic API keys (`api_key = …`), AWS Access Key IDs (`AKIA…`, no key name needed), AWS Secret Access Keys, Azure account keys, GCP/Google Cloud keys |
| Tokens | Generic tokens, bearer tokens, access/refresh tokens, OAuth tokens, JWTs (key-based or bare `eyJ…` form), known prefixes: GitHub `ghp_`/`github_pat_`, Slack `xox?-`, Stripe `sk_live_`/`sk_test_`, Google `AIza…` |
| Passwords | `password`/`passwd`/`pwd` values, including compound keys (`DATABASE_PASSWORD`) |
| Private keys | Multi-line PEM blocks — RSA/EC, OpenSSH, PGP |
| Connection data | Database URLs with embedded `user:pass@` credentials, connection strings, session IDs, cookies |

Key-based patterns accept quoted and unquoted keys, so JSON (`"apiKey": "…"`), YAML (`api_key: …`), env (`API_KEY=…`), and code (`apiKey = '…'`) all match.

**Intentional non-detections**: template placeholders (`${VAR}`, `{{var}}`, `<your-key>`, `xxxxxxxx`), version numbers and hostnames that merely look dotted (`1.2.3` is not a JWT), GCP project ids (identifiers, not credentials), and database URLs without embedded credentials.

**Known limitations**: detection is pattern-based — obfuscated, split, or unconventionally named secrets are missed; JWTs whose header isn't standard base64 JSON (`eyJ…`) are missed; a high-entropy string without a recognizable key name or prefix is not reported.

## Commands

| Command | Description |
|---|---|
| `Secrets-LE: Detect Secrets` (`Ctrl+Alt+S` / `Cmd+Alt+S`) | Scan the workspace and open a results document |
| `Secrets-LE: Sanitize Secrets` | Replace detected secrets in the active file (asks for confirmation first) |
| `Secrets-LE: Open Settings` | Open Secrets-LE settings |
| `Secrets-LE: Help` | Built-in documentation |

## Settings

| Setting | Default | Description |
|---|---|---|
| `secrets-le.detection.sensitivity` | `medium` | `low` reports everything, `medium` drops low-confidence matches, `high` keeps only high-confidence ones |
| `secrets-le.detection.includeApiKeys` | `true` | Detect API keys and cloud credentials |
| `secrets-le.detection.includePasswords` | `true` | Detect passwords |
| `secrets-le.detection.includeTokens` | `true` | Detect tokens and JWTs |
| `secrets-le.detection.includePrivateKeys` | `true` | Detect PEM private-key blocks |
| `secrets-le.sanitization.replaceWith` | `***REDACTED***` | Replacement text used by Sanitize |
| `secrets-le.workspace.scanPatterns` | `["**/*"]` | Glob patterns to scan |
| `secrets-le.workspace.scanExcludes` | node_modules, .git, dist, … | Glob patterns to skip |
| `secrets-le.workspace.scanMaxFiles` | `10000` | Cap on files scanned per run |
| `secrets-le.safety.enabled` | `true` | Guardrails for very large files |
| `secrets-le.safety.fileSizeWarnBytes` | `1000000` | Skip/refuse files above this size |
| `secrets-le.dedupeEnabled` | `false` | Collapse identical value+type detections in results |
| `secrets-le.copyToClipboardEnabled` | `false` | Also copy results to the clipboard |
| `secrets-le.openResultsSideBySide` | `true` | Open results beside the current editor |
| `secrets-le.notificationsLevel` | `important` | `all` = every notification, `important` = warnings + errors, `silent` = errors only |
| `secrets-le.statusBar.enabled` | `true` | Show the status bar item |
| `secrets-le.telemetryEnabled` | `false` | Local-only event log (see Privacy) |

## Languages

Twelve languages besides English:

German · Spanish · French · Indonesian · Italian · Japanese · Korean ·
Portuguese (Brazil) · Russian · Ukrainian · Vietnamese · Chinese (Simplified)

Both halves are covered — the manifest (command titles, setting names and
descriptions) and everything shown while the extension runs (notifications,
the status bar, quick-picks and prompts). The extension follows VS Code's
display language, so it matches whatever the editor is already set to; no
setting of its own.

## Privacy & security

- **No network access.** The extension never sends data anywhere. The `telemetryEnabled` setting only writes events to a local Output Channel you can inspect (`Secrets-LE Telemetry`).
- Error notifications redact home directories and credential-shaped fragments before display.
- Sanitize always asks for confirmation before editing your file, and edits are normal undo-able document edits.

## Development

```bash
bun install
bun run build            # esbuild bundle -> dist/extension.js
bun run typecheck        # tsc --noEmit (includes tests)
bun run test             # vitest unit suite
bun run test:integration # real VS Code extension host
bun run lint             # biome
bun run package          # VSIX into release/
```

Architecture and conventions live in [AGENTS.md](AGENTS.md). Changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## Performance

<!-- performance:start -->
| Input | Size | Found | Time | Rate | Scan speed |
| --- | --- | --- | --- | --- | --- |
| Source with credentials | 1.97 MB | 40,000 | 132.32 ms | 302,301/sec | 14.9 MB/s |
| Clean source | 1.92 MB | 0 | 70.88 ms | — | 27.2 MB/s |
| Env file | 0.60 MB | 0 | 21.88 ms | — | 27.4 MB/s |

Median of 7 runs after warmup, on Apple M5 Pro, 24 GB RAM, Node 24.3.0. Inputs are generated
by `scripts/benchmark.ts` rather than checked in, so the sizes above are
exactly what was measured. Reproduce with `bun run benchmark`.

These are machine-specific and are not asserted in CI — a benchmark that gates
a build only tells you how busy the runner was.
<!-- performance:end -->

## Testing

<!-- coverage:start -->
| Metric | Coverage |
| --- | --- |
| Statements | 90.78% |
| Branches | 79.45% |
| Functions | 95.37% |
| Lines | 91.81% |

142 test cases across 13 files, plus an integration suite that runs
in a real VS Code extension host and an end-to-end test that installs the
built `.vsix` into a clean profile.

Generated from `coverage/coverage-summary.json` by
`scripts/coverage-readme.js`; CI fails if this section drifts from a fresh
run. Reproduce with `bun run test:coverage`.
<!-- coverage:end -->

## More from the LE Family

Every tool in the family, one page: **[letools.dev](https://letools.dev)**

- **[String-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.string-le)** - Extract string values for i18n from JSON, YAML, CSV, TOML, INI, and .env
- **[Numbers-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.numbers-le)** - Extract numeric values from JSON, YAML, CSV, TOML, INI, and .env
- **[EnvSync-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.envsync-le)** - Spot missing keys across your .env files, with a markdown report
- **[Paths-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.paths-le)** - Extract file paths from JS/TS imports, JSON, HTML, CSS, TOML, CSV, and .env
- **[Regex-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.regex-le)** - Find, test, and validate regular expressions with ReDoS screening
- **[Scrape-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.scrape-le)** - Check whether a page is scrapeable before you write the scraper
- **[Colors-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.colors-le)** - Extract and analyze colors from CSS, SCSS, LESS, Stylus, HTML, JS/TS, and SVG
- **[URLs-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.urls-le)** - Extract URLs from documentation, configs, and code
- **[Dates-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.dates-le)** - Extract and analyze dates from logs, configs, and code

## Also by nolindnaidoo

**Rust**

- **[pixelcoords](https://github.com/nolindnaidoo/pixelcoords)** - Mark pixel-exact coordinates machines can use · [pixelcoords.dev](https://pixelcoords.dev)
- **[pixelactions](https://github.com/nolindnaidoo/pixelactions)** - Perform the interaction and confirm it landed · [pixelactions.dev](https://pixelactions.dev)

**Contact Developer** — [GitHub](https://github.com/nolindnaidoo) · [LinkedIn](https://www.linkedin.com/in/nolindnaidoo/)

## License

MIT © [nolindnaidoo](https://github.com/nolindnaidoo)
