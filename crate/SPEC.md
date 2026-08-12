# secrets-le — Rust specification

A port of the [Secrets-LE](https://github.com/nolindnaidoo/secrets-le) VS
Code extension to a Rust CLI and MCP server: the same detection, over a
tree instead of a buffer, with an exit code a CI step can fail on.

**Parity first.** For detection, the extension is the reference
implementation. Anything this reports for a given document must match
what the extension reports for that document. A difference is a
regression until proven otherwise — not an improvement.

## The one question

**Is there a credential committed in here?**

Asked over a whole tree, answered before the commit rather than after the
disclosure.

## The rule everything else follows

**A tool that finds secrets must not become the thing that leaks them.**

The extension's detector carries the matched value internally, and every
surface it has masks the value before a human or a model ever sees it.
This crate inherits that and tightens it, because a CLI has a failure
mode an editor does not: **its output goes to a CI log.** A CI log is
archived, is often world-readable in a public repository, is scraped, and
outlives the credential. A scanner that prints what it found into one has
leaked every secret it detected to a wider audience than the commit
would have.

So, without exception and without a flag:

- **No surface ever emits a complete secret.** Not stdout, not stderr,
  not the MCP envelope, not a diagnostic, not an error message.
- **A preview is capped at eight characters *and* at half the value's
  length**, and always carries the value's length. Half-length is what
  makes the cap hold for short values: an eight-character cap on an
  eight-character password is the password.
- **The context line carries no value — not its own, and not its
  neighbour's.** See below.
- **The key name is masked too.** Every key pattern begins
  `[A-Za-z0-9_-]*`, so the key group swallows whatever word characters
  run up to the keyword — and a token abutting the name is reported as
  part of it. The key is source text, not the tidy identifier it looks
  like.
- **There is no `--show-values`, no `--unsafe`, no environment variable.**
  A flag that turns this off is a flag that ends up in someone's CI
  config. A caller who needs the value has the file; the report says
  which file, which line, which column and which key.

A property test asserts the whole of it: for any input value, no string
this crate emits contains that value.

### The context line

A context is **a bounded window of the source line** — sixty UTF-16 code
units either side of the value, with an ellipsis wherever the line
continues past the cut — and the value itself is never in it: the middle
is the preview, assembled rather than searched for. Three things forced
that shape, all of them found by the checks in `ci-crate.yml`:

- A context used to be the whole source line. On a minified file that is
  the whole file, and one context per finding made a report grow with
  findings *times* line length: a single file with sixteen hundred
  findings on one line produced ninety-eight megabytes of stdout.
- Masking only the finding's **own** value left every other credential on
  that line in the clear. `connection_string = Server=...;Pwd=secret;`
  reported the password masked and printed the connection string it sits
  inside — itself a reported finding — whole. A line holding two
  credentials is what a compact JSON config looks like.
- A value can run past the end of its own line; a PEM block does. Cutting
  a window and searching it for the value found nothing to replace,
  because the line holds only a prefix — so seventeen hundred characters
  of key material went out verbatim.

**What a context line can still contain.** Every value the scan detected
is masked out of the window. Text the scan did *not* detect is not a
secret as far as this tool knows, and the window is source, so a
credential this tool deliberately misses — a JWT with a non-JSON header,
a GCP project id — can appear in one. That is the price of a context line
existing at all, and it is bounded: sixty characters either side, never
the whole file. A pipeline that will not pay it has the file, line,
column and key without ever reading `context`.

## Why this is not a remediation tool

The extension has a `sanitize` command that rewrites secrets in place.
This does not, in v1, and the reason is not scope: **rewriting a file
that contains a live credential is the most destructive operation this
codebase could offer**, and it needs a confirmation story — what it
touches, what it backs up, what happens on a partial write, what happens
when the "secret" was a false positive in a test fixture. That design is
owed before the code.

Detection exits 1. What you do about it is yours.

## Shape

**One crate.** Self-contained: no published `-core`, no shared crate with
the rest of the family, and nothing holding this code equal to the
similar files in the sibling repos. Where they agree it is because the
same answer was right twice; where they diverge that is the point.

```
crate/
├── src/
│   ├── detect/       pure: the pattern table, heuristics, masking,
│   │                 positions. No filesystem, pub(crate).
│   ├── walk.rs       ignore-aware tree walking
│   ├── scan.rs       one file end to end — the only path either surface calls
│   ├── cli.rs        the terminal surface
│   └── mcp/          the agent surface
└── signatures/       the pattern table, mirrored out of the extension
    fixtures/         behaviour cases both frontends reproduce
```

**`detect/` touches no filesystem**, carries the **90% line coverage
floor per module**, and is where masking lives — so the property that no
value escapes is testable without a disk.

**Both surfaces are one implementation.** `cli.rs` and `mcp/` both call
`scan.rs`. A contract test asserts they agree on the same tree.

## Detection — parity scope

### The pattern table is data

`signatures/patterns.toml` mirrors `SECRET_PATTERNS` entry for entry, in
order, and the parity script asserts the two are equal **both ways**.
This is the crate's data-mirror case, and it matters more here than
anywhere else in the family: a pattern table that silently drifts is a
scanner that stops finding a class of credential while still reporting
success.

**Order is load-bearing.** Specific key patterns (oauth, access, refresh,
jwt) run before the generic token pattern, and the first pattern to claim
a span wins the dedupe. The corpus preserves order, and a test asserts
it.

Each entry carries its regex verbatim, its capture groups, its
description, and its confidence **as a rule rather than a lambda**: a
fixed level, a length tiering (`high` at N, `medium` at M), or the JWT
shape test. Three kinds, enumerated, because a function cannot be
mirrored into data and checked.

### Ported as-is, including what it deliberately misses

- **A bare `x.y.z` dotted triple is not a JWT.** A JWT header is base64
  JSON and always begins `eyJ`; anything else is a version number, a
  hostname or a module path. JWTs with non-JSON headers are missed. That
  trade kills the dominant false positive and is kept.
- **Template placeholders are never secrets**: `${VAR}`, `{{var}}`,
  `<your-key>`, and any run of a single repeated character.
- **GCP project ids are identifiers, not credentials**, and are not
  reported.
- **Key patterns match compound names**: `DATABASE_PASSWORD` and
  `db_password` both match the `password` family, because the pattern
  anchors on an identifier *ending* in the name.
- **PEM blocks are re-classified from their header** — `OPENSSH` becomes
  `ssh-key`, `PGP` becomes `pgp-key`, everything else `private-key`.

### Sensitivity

Three levels, filtering on the confidence a pattern assigned:
`high` keeps only high-confidence findings, `medium` (the default) drops
low, `low` keeps everything. Identical to the extension.

## Output contract

**stdout is protocol. stderr is human.** One JSON report per line, one
line per file examined. Every value in both is masked.

```json
{
  "file": "config/app.env",
  "findings": [
    {
      "type": "password",
      "confidence": "high",
      "key": "database_password",
      "preview": "hunter2h… (16 chars)",
      "context": "DATABASE_PASSWORD=hunter2h… (16 chars)",
      "line": 4,
      "column": 19,
      "description": "Password"
    }
  ],
  "diagnostics": [],
  "summary": { "findings": 1, "high": 1, "medium": 0, "low": 0 }
}
```

### Exit codes are the API

- **0** — nothing found, or nothing found above the sensitivity floor.
- **1** — at least one finding.
- **2** — the question was malformed: an unknown flag, an unreadable
  input, a path that does not exist.

A run over many files exits with the worst outcome in it. **Exit 1 is not
an error** — it is the tool answering "yes, there is one".

## The CLI surface

```
usage: secrets-le [options] <file|dir>...
       secrets-le [options] --stdin
       secrets-le mcp
       secrets-le --version | --help

Options:
  --sensitivity <low|medium|high>   detection threshold (default medium)
  --no-api-keys                     skip the API-key detectors
  --no-passwords                    skip the password detectors
  --no-tokens                       skip the token detectors
  --no-private-keys                 skip the private-key detectors
  --stdin                           read one document from stdin
  --hidden                          scan hidden files and directories too
  --no-ignore                       scan files that .gitignore excludes
```

**`.gitignore` is honoured by default, and that is a deliberate risk.**
A secret in an ignored file is not going to be committed, which is the
threat this tool exists for — but a secret in an ignored file is still a
secret on the disk. `--no-ignore` is the answer, and the human summary
says how many files were skipped so the number is never invisible.

## The MCP surface

Two tools, both returning `{ ok, data, diagnostics, meta }`.

- **`detect_secrets` belongs to both servers.** The npm server
  (`src/mcp/tools.ts`) and this one offer the same tool: same schema,
  same envelope, byte-identical output — including identical masking.
  `fixtures/mcp-detect-secrets.json` runs against both.
- **`secrets_le_scan` is this server's own**: it takes files or
  directories, walks them, and returns the same masked reports the CLI
  writes.

**Refusals speak the caller's vocabulary.** No message here names a
command-line flag.

## Non-goals

- **It does not rewrite files.** See "Why this is not a remediation tool".
- **It does not touch the network.** No credential validation, no
  "is this key live" check — that would transmit the secret, and to a
  third party.
- **It does not read git history.** Scanning previous commits is a
  different tool with a different traversal; conflating them would make
  "clean" ambiguous about what was actually examined.
- **It has no entropy detector.** High-entropy string detection produces
  a false-positive rate that needs per-repository tuning to be usable,
  and an untuned one trains people to ignore the output.

## Not in v1

- **`--fix` / redaction in place**, with the confirmation story it needs.
- **Entropy-based detection**, behind an explicit opt-in.
- **Git history scanning.**
- **A baseline file** for accepting known findings.

## Files that cannot be read

Exit 2 means the *question* was malformed — an unknown flag, an
unreadable format name, a path that does not exist. It does not mean one
file in fifty thousand was a PNG.

A file that is not UTF-8 text, or that cannot be opened, is:

- named on stderr,
- carried in the JSON report with a `skipped` diagnostic saying why,
- and left out of the exit code.

`--strict` turns any skipped file back into exit 2, for a pipeline that
wants zero tolerance. What is never allowed is the third option: a file
that silently vanishes from the report, which reads to whoever ran it as
a file that was clean.

## The byte-order mark

A leading BOM is stripped before extraction — **whether the document
arrives as a path or through a pipe**. It is three invisible bytes that
Notepad, Excel and a PowerShell redirect all add, and that VS Code
removes before the extension sees a document — so leaving it in means
the two frontends read the same file differently. It shifts every column
on the first line, and in a structured format it can lose the document
entirely.

`secrets-le config.env` and `secrets-le --stdin < config.env` are the
same question about the same document and must answer the same way. They
did not: only the path route dropped the mark.

A BOM anywhere other than the start is a zero-width no-break space and
belongs to the text.

## Deliberate divergences

Two surfaces, two jobs. The extension is **IDE-first** — one open buffer,
a person reading results in an editor. This is **terminal-first** — a
tree, an exit code, a pipeline. Each works the way its own use case
expects, so the walk, `--strict`, `--sensitivity`, the exit codes and
JSON Lines are this side's and are not drift.

What is **not** allowed to differ is the tool both servers offer.
`detect_secrets` is one name, one schema, two implementations: same
document text in, byte-identical envelope out. A caller must not be able
to tell which server it reached.
`../scripts/check-detection-differential.ts` holds them against each
other over hundreds of generated documents, and
`fixtures/mcp-detect-secrets.json` pins the hand-written cases.

Divergences that are deliberate live here, with their reason:

- **`--stdin` strips a leading byte-order mark; `detect_secrets` does
  not.** `--stdin` reads a *document*, which arrived from a file through
  a pipe and carries whatever that file carried. `detect_secrets` takes
  text a caller already has in hand, and its contract is byte-identity
  with the npm server, which does not strip either. Both are checked.
- **`js_trim` rather than `str::trim`.** JavaScript's whitespace set is
  not Rust's: it counts U+FEFF, which Rust does not, and skips U+0085,
  which Rust counts. Using Rust's would have been a divergence rather
  than a choice, and the differential found it as one.

## The measured limits

Stated because a limit nobody wrote down is a surprise:

- **The backtracking budget covers a line of about a million word
  characters, and not more.** Thirteen patterns begin `[A-Za-z0-9_-]*`,
  and the engine saves a backtrack frame per character of an unbroken
  run, so a crafted run of that size exhausts the stack. Measured, not
  guessed: 800,000 answers, a million refuses. A megabyte of *ordinary*
  minified JavaScript is punctuated every few characters and scans in a
  sixth of a second. The refusal is the honest outcome — the report says
  the file was not fully scanned and the run exits 2, rather than
  reporting a clean file the scanner never finished.
- **A scan is linear in the size of the tree**, and `ci-crate.yml`'s
  `budget` job asserts it: four times the tree, at most six times the
  time.
