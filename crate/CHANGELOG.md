# Changelog

The Rust CLI and MCP server. The VS Code extension has its own
[CHANGELOG](../CHANGELOG.md) and its own version — the two products in
this repository release on their own cadence.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-14

Fifteen more providers, four kinds of finding that no switch could turn
off, and the speed and disclosure work that 0.1.1 was going to carry —
0.1.1 was never published, so it is folded in here rather than
advertised as a release nobody can install.

**A repository scan went from 8.55 seconds to under a tenth of a second,
and no finding that existed before it changed.** For a tool that exists
to find credentials, "faster" is only reassuring next to "and it still
finds exactly the same things", so that was the bar: byte-identical
output on every tree it was measured against, with the property asserted
in tests rather than argued from the diff. The new providers above are
the only reason a count moves.

Three of the fixes below are places where the tool could have printed a
credential. That is the one thing it must never do, and every one of
them was found by a check that now runs on every push — over generated
documents, not a fixed list of cases somebody thought of. Two claims are
now standing:

- **No finding ever carries a value the run detected.** Not its own, not
  the one beside it on the same line, and not one swallowed into a key
  name.
- **The cheap pattern that decides whether to run the real one can never
  skip a file the real one would have matched.** If it could, a
  credential would go unreported and the scan would still exit 0.

Still deliberately absent, and not on the way: entropy-based detection,
git-history scanning, and any network call — nothing here validates a
credential against the service it belongs to, because that would
transmit it.

### Added

- **Fifteen more providers.** OpenAI, Anthropic, GitLab, SendGrid,
  Mailgun, Sentry, npm, PyPI, Docker Hub, HashiCorp Vault, Terraform
  Cloud, Supabase, Shopify, Square and Azure SAS. The table goes from 19
  patterns to 34. A repository holding a live key from any of these
  could scan clean before this.

### Fixed

- **A credential could reach a report through the context line of the
  finding beside it.** Masking replaced a value by searching the window
  for it, which needs the value present whole — and a credential
  reported as *part* of a longer run leaves the window showing a prefix
  of that longer value, which nothing matches. The shorter credential
  inside it survived in the clear. The fuzzer found it at seed 20260812
  with a connection string inside a 1,595-character database URL, and
  `fixtures/`'s `secrets.ini` had been carrying a milder version of the
  same thing: `Server=prod;Database=app;Uid=admin;` printed beside the
  password it was masking, while being a reported finding itself.

  The context is now redacted **by span** before the text pass runs:
  every finding's offsets are rebased onto the line, and any part of the
  window overlapping one is blanked whatever its text happens to be. The
  text pass stays, and still covers a value repeated where no span
  reaches. Both frontends, since this is the shared `detect_secrets`
  tool — four corpus contexts move here and two in the extension's.

- **Four kinds of finding no switch could turn off.** `--no-passwords`
  left connection strings and database URLs in the report, and
  `--no-tokens` left cookies and session IDs, because anything the
  classifier did not recognise was included unconditionally. A
  connection string and a database URL are reported *because* they carry
  a credential in a URI, so they answer to `--no-passwords`; a cookie
  and a session ID are bearer credentials and answer to `--no-tokens`.
  The same four flags reach the shared `detect_secrets` tool as
  `includePasswords` and `includeTokens`, so both servers changed
  together.

- **Scanning a repository was fifty times slower than it needed to be.**
  Thirteen of the patterns then in the table begin with
  `[A-Za-z0-9_-]*` before
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

- **A context line printed the credential beside it.** Masking covered
  the finding's own value and nothing else, so two credentials on one
  line each disclosed the other:

  ```
  connection_string = Server=prod;Database=app;Uid=admin;Pwd=secre… (10 chars);
  ```

  — the password masked, and the connection string it sits inside, itself
  a reported finding, printed whole. A line holding two credentials is
  what a compact JSON config looks like, and the shared corpus had a case
  of it, checked in, for the whole release. Every detected value is now
  masked out of every context, longest first so a value containing a
  shorter one is replaced whole.

- **A context line printed key material when the value outran its line.**
  A PEM block does. The window was cut and then searched for the value,
  which is not present whole, so nothing was replaced — seventeen hundred
  characters of key material went out verbatim. The context is now
  assembled from the preview and the source either side of it, so the
  value's own text has nowhere to appear from.

- **A key name printed a credential.** Every key pattern begins
  `[A-Za-z0-9_-]*`, so the key group swallows whatever word characters
  run up to the keyword. A token abutting the name came back as part of
  it — `"key": "ghp_…----session_id"` — in the one field nothing was
  masking. Found by the fuzzer.

- **A report grew with findings times line length.** A context was the
  whole source line, and on a minified file that is the whole file: one
  file with sixteen hundred findings on its single line produced
  ninety-eight megabytes of stdout. Contexts are now a bounded window,
  sixty characters either side of the value.

- **`--stdin` and a path disagreed about the same document.** The
  byte-order mark was dropped when the document arrived as a path and
  kept when it arrived through a pipe, so `secrets-le config.env` and
  `secrets-le --stdin < config.env` answered with different columns and
  different context lines.

- **Report paths used the platform separator.** A Windows run answered
  `config\app.env` where every other platform answered `config/app.env`.
  A secret scanner's report is the thing a reviewer files, diffs and
  baselines, and a baseline taken on one platform was useless on the
  other. Now `/` everywhere — rewritten only where `\` is the separator,
  because on Unix it is an ordinary character in a filename, and with the
  extended-length prefix Windows adds to a canonical path removed.

- **The two `detect_secrets` servers trimmed differently.** JavaScript's
  whitespace set counts U+FEFF and Rust's does not, so a document
  beginning with a byte-order mark produced a context with three
  invisible bytes on one server and without them on the other. One tool
  name, one schema, two servers: a caller must not be able to tell which
  one it reached.

### Tested

Six checks were added to `ci-crate.yml`, each named after the class of
bug it catches. Every fix above was found by one of them.

- **`hazards`** — a byte-order mark, a lone CR, a NUL, a file that is not
  text, a symlink loop, a FIFO, a name Windows cannot hold, a line a
  megabyte long. On all three platforms, against the built binary, over a
  tree built at runtime because git cannot carry a FIFO to Windows. Every
  case asserts the process does not panic, does not hang, and exits 0, 1
  or 2 — never on a signal.
- **`platform`** — the report separator, `TZ` independence, case-folding
  filesystems, reserved Windows filenames, and a child that refuses stdin
  before the write finishes.
- **`differential`** — six hundred generated documents through *both*
  `detect_secrets` servers, requiring byte-identical envelopes, plus the
  prefilter soundness claim over a generated cross-product. If the
  relaxed pattern ever fails to match where the real one would, a
  credential goes unreported and the scan still exits clean.
- **`fuzz`** — sixty seconds over the detector table, seeded from the
  corpus. Fails on a panic, a hang, an exit outside 0/1/2, a detector
  that gives up on a document under 64 KB, a reported value appearing in
  what the run printed, a context past its documented bound, or a preview
  that does not match the document at the line and column it reports.
- **`budget`** — a wall-clock ceiling on a five-hundred-file tree at ten
  times the local measurement, and two linearity assertions: four times
  the tree within six times the time, and four times the findings on one
  long line within six times the time.
- **`coverage-matrix`** — one file per extension across a broad sample
  plus a dozen nothing knows, plus names with no extension at all. Every
  one must come back with a report line and its finding, because this
  crate's claim is that it reads everything.


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

[0.2.0]: https://crates.io/crates/secrets-le/0.2.0
[0.1.0]: https://crates.io/crates/secrets-le/0.1.0
