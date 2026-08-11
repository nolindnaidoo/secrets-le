# Changelog

The Rust CLI and MCP server. The VS Code extension has its own
[CHANGELOG](../CHANGELOG.md) and its own version — the two products in
this repository release on their own cadence.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-08

First release. The extension's detection engine, ported and pinned
against a shared pattern table, over a tree instead of a buffer.

### Added

- **The detection engine**, reproducing the extension's output for every
  case in `fixtures/` — nineteen patterns across API keys, passwords,
  tokens and private keys, with the same sensitivity levels, the same
  family switches, and the same deliberate misses.
- **`signatures/patterns.toml`**, the pattern table as reviewable data,
  mirrored from `SECRET_PATTERNS` and checked in both directions.
  Order is preserved and asserted: the specific key patterns must
  precede the generic token one, or a `refresh_token` reports as a plain
  token.
- **The CLI**: JSON reports on stdout one per line, a human summary on
  stderr, and exit codes as the API — 0 nothing found, 1 findings, 2 the
  question was malformed. `--sensitivity`, `--no-api-keys`,
  `--no-passwords`, `--no-tokens`, `--no-private-keys`, `--stdin`,
  `--hidden`, `--no-ignore`.
- **The MCP server** (`secrets-le mcp`) with two tools: `detect_secrets`,
  shared byte-for-byte with the npm server and pinned by
  `fixtures/mcp-detect-secrets.json`, and `secrets_le_scan`.
- **Named warnings for skipped credential files.** `.gitignore` is
  honoured by default, which is where `.env` usually lives. Files whose
  names say they hold credentials are listed individually when skipped;
  everything else is a count. Vendored trees are excluded from the list.

### The rule that shaped it

**No surface emits a complete value** — not stdout, not stderr, not the
MCP envelope, not an error message — and there is no flag that changes
that. A scanner's output goes into a CI log, which is archived, often
world-readable, and outlives the credential.

The property is asserted four ways: exhaustively over value lengths 3 to
300, over every corpus document, over a real binary run against planted
credentials, and from the extension's side by the parity script.

[0.1.0]: https://github.com/nolindnaidoo/secrets-le/releases/tag/crate-v0.1.0

### Fixed

- **Scanning a repository was fifty times slower than it needed to be.**
  Thirteen of the nineteen patterns begin with `[A-Za-z0-9_-]*` before
  their keyword, which leaves a backtracking engine nothing to anchor
  on: it tries a variable-length run at every offset in every file.

  Each pattern now carries a prefilter — the same pattern with every
  lookaround removed, compiled by the DFA engine — and the real pattern
  runs only where that matches. Removing a lookaround can only widen
  what a pattern accepts, so the prefilter matches a superset and can
  never suppress a real finding; tests assert that property over the
  whole corpus rather than arguing it from the code, and the output is
  byte-identical on every repository it was checked against.

  A 456-file tree went from 8.55s to under a tenth of a second.

- **A leading byte-order mark is no longer part of the document.** Three
  invisible bytes, added by Notepad, Excel and a PowerShell redirect, and
  stripped by VS Code before the extension ever sees a file — so the two
  frontends read the same file differently. It shifted every column on
  line one, and before a `{` it made a structured parser reject the whole
  document, which is indistinguishable from a file with no findings in it.

- **A file that cannot be read no longer fails the run.** Every
  repository has a PNG, a zip and something the runner lacks permission
  for. Exiting 2 on those made the tool unusable in CI, which is the one
  place it is most worth running. Such a file is now named on stderr and
  carried in the report with a `skipped` diagnostic, and the exit code
  reflects what was found. `--strict` restores the old behaviour for a
  pipeline that wants zero tolerance.

  A detector that gives up part way through a file still fails without
  asking: reporting no findings for a file the scanner did not finish is
  the one failure mode a secret scanner cannot have, and it is now a
  different thing from a PNG rather than the same one.

- **A file that is not text is named rather than dropped.** It used to
  vanish from the report entirely, which reads to whoever ran it as
  "that file was clean".
