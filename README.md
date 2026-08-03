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

## More from the LE Family

Every tool in the family, one page: **[letools.dev](https://letools.dev)**

- **[String-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.string-le)** - Extract user-visible strings for i18n and validation
- **[Numbers-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.numbers-le)** - Extract and analyze numeric data with statistics
- **[EnvSync-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.envsync-le)** - Keep .env files in sync with visual diffs
- **[Paths-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.paths-le)** - Extract file paths from imports and dependencies
- **[Regex-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.regex-le)** - Test and validate regex patterns with live feedback
- **[Scrape-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.scrape-le)** - Validate scraper targets before debugging
- **[Colors-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.colors-le)** - Extract and analyze colors from stylesheets
- **[URLs-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.urls-le)** - Extract URLs from any codebase with precision
- **[Dates-LE](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.dates-le)** - Extract temporal data from logs and APIs

## License

MIT © [nolindnaidoo](https://github.com/nolindnaidoo)
