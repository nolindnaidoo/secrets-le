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
- **The context line is masked too.** It is the raw source line, so it
  contains the credential it is providing context for. Every occurrence
  of the value is replaced by the same bounded preview.
- **There is no `--show-values`, no `--unsafe`, no environment variable.**
  A flag that turns this off is a flag that ends up in someone's CI
  config. A caller who needs the value has the file; the report says
  which file, which line, which column and which key.

A property test asserts the whole of it: for any input value, no string
this crate emits contains that value.

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
the rest of the family. Code two crates in the family both need is
copied, with a drift check — the family's existing idiom.

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
