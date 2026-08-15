# secrets-le (CLI) — engineering standards

This is the source of truth for how code in `crate/` is written, tested,
and reviewed. It applies to every contributor, human or AI-assisted. CI
(`.github/workflows/ci-crate.yml`) enforces the mechanical parts;
reviewers enforce the rest. [SPEC.md](SPEC.md) defines the product
behavior — verdicts, exit codes, the parity scope; this file is how the
code gets there. The extension at the repo root is a separate TypeScript
product with its own `AGENTS.md`.

## What this project is

The command-line and MCP frontend of Secrets-LE: find hardcoded
credentials across a tree, and report where each one is without ever
reporting what it is. One
product, two frontends, one repository: the corpus (`fixtures/`) is
shared with the VS Code extension, and CI fails when either side drifts
from it.

**Status: released.** Every format, both surfaces, the resolver and the
test layers below are built and green. Releases go out through
`release-crate.yml`, which is dispatch-only and refuses a version that
crates.io already carries, has no changelog entry, would ship a tarball
missing its own corpus, or whose corpus the extension no longer
reproduces.

## Layout

```
crate/src/
├── detect/      pure: the pattern table, heuristics, masking,
│                positions. No filesystem, pub(crate).
├── walk.rs      ignore-aware tree walking
├── scan.rs      one file end to end — the only path either surface calls
├── cli.rs       the terminal surface
└── mcp/         the agent surface
```

- **`detect/` touches no filesystem.** It takes document text and a
  format and returns paths, so the entire detection layer tests from a
  fixture file — no temp directories, no flake. It carries the **75%
  line coverage floor per module**, enforced by the `coverage` job. A
  `std::fs` call appearing there is a bug, and the `policy` job greps
  for one.
- **`resolve.rs` is the only module allowed to touch the filesystem.**
  Everything it claims is checkable by hand against the same filesystem;
  a claim that is not does not belong there.
- **Both surfaces are one implementation.** `cli.rs` and `mcp/` both call
  `audit.rs`. A surface that grows its own copy of a rule is a bug, and
  a contract test asserts the two return identical reports for the same
  tree.
- **`walk.rs` selects, it does not decide.** Its one rule — a file named
  explicitly is read whatever the ignore rules say — is why intent beats
  configuration.
- Keep modules flat. No layers, registries, managers, or services. No
  trait with a single implementation.

## Decisions already made (do not relitigate)

- **No surface emits a complete value, and no flag changes that.** The
  raw match lives only inside `detect`'s loop; `Finding` has no value
  field and must never grow one. A scanner's output goes into a CI log,
  which is archived, often world-readable, and outlives the credential —
  so printing a finding would disclose it more widely than the commit
  would have. `--show-values` is not a feature request; it is the bug.
- **One crate, self-contained.** No published `-core`, no shared crate
  with the family. Code two crates both need is copied with a drift
  check — the family's existing idiom.
- **The pattern table is data, and order is load-bearing.**
  `signatures/patterns.toml` mirrors `SECRET_PATTERNS` entry for entry,
  in order, because the first pattern to claim a span wins the dedupe.
  Confidence lives there as a *rule*; the parity script evaluates the
  rule and the extension's lambda over probe values and fails when they
  disagree.
- **`fancy-regex`, not `regex`.** One pattern uses a negative lookahead
  that `regex` cannot express, and rewriting it would change what the
  scanner finds — the one thing a security tool must not do quietly.
- **JavaScript's `\b` and `\s`, spelled out.** Rust's `\b` is
  Unicode-aware and JavaScript's is ASCII, so `passwordé=…` would have
  silently *missed* a credential the extension reports. `(?-u:\b)` is
  rejected by this engine, so the boundary is written as lookarounds.
- **The backtracking budget is raised, not removed.** The default is
  exhausted by an ordinary `bun.lock`; a budget that cannot be exhausted
  is a scanner a crafted file can hang. The refusal it produces is
  honest — the report says the file was not fully scanned and the run
  exits 2.
- **Every file is scanned, whatever its extension.** A scanner that only
  looked at extensions it recognised would report a clean tree next to a
  `.bak` full of passwords.
- **A non-UTF-8 file is skipped, not failed.** A repository is full of
  images; failing on each would make the tool unusable, and there is no
  hardcoded credential in a PNG.
- **`.gitignore` is honoured by default**, and the risk is made visible
  rather than argued away: credential-shaped names are listed
  individually when skipped, everything else is a count, and vendored
  trees are excluded from the list because six `.npmrc` files from a
  downloaded editor bundle is how a warning becomes noise.
- **Nothing is rewritten.** The extension's `sanitize` has no equivalent
  here and will not until its confirmation story is designed.
- **stdout is protocol, stderr is human. There is no `--json` flag.**
- **Parity scope is detection only** — `src/extraction/**` and
  `src/utils/mask.ts`. Commands, UI, i18n and the config reader are
  extension concerns. The walker and the CLI have no extension
  equivalent and are outside parity in the other direction.

## Control-flow style

Flat over nested, guards over branches — the same rules as pixelcoords,
pixelactions and scrape-le:

- **No statement-position `else`.** Guard clauses and early `return`
  (`if !ok { return ... }` / `let Some(x) = ... else { return }`), then
  fall through to the happy path.
- **Value-position `if/else` is fine** — `let x = if cond { a } else
  { b }` is Rust's ternary.
- **`match` is fine and preferred** over any chain of condition tests on
  the same value; use match guards instead of `if/else` inside arms.
- Prefer combinators where they read cleanly: `bool::then_some`,
  `Option::map/filter/is_some_and`, `?`.
- No nesting deeper than two levels inside a function; extract a named
  helper instead.

## Hard rules

- **No inline `#[allow(...)]`** — CI greps and fails the build. Either
  fix the lint or add a visible, commented relaxation to
  `[lints.clippy]` in `Cargo.toml`.
- **Clippy pedantic, deny warnings.** `cargo clippy --all-targets --
  -D warnings` must pass exactly as CI runs it.
- **No async runtime.** This tool reads files and asks the filesystem
  about them. There is nothing to await.
- **`unsafe` is forbidden crate-wide** (`[lints.rust]`).
- **Dependencies are a cost**, and more so here: every crate in the tree
  is code that runs over the user's credentials. Each is justified by a
  comment in `Cargo.toml`. Justify any addition; prefer the standard
  library; prefer what is already there.
- **No network, ever.** No credential validation, no "is this key live"
  check — that would transmit the secret, to a third party. No
  telemetry.
- **Nothing writes.** No `--fix`, no rewriting, no temp files outside
  the test helpers. Rewriting a file holding a live credential is the
  most destructive thing this codebase could offer.
- **Strict parsing, never silent defaults.** An unrecognised flag, a
  format that does not resolve, an input that does not exist: all are
  errors with actionable messages. A typo'd `--stict` that silently did
  nothing would report a clean audit that never ran the check asked for.
- **Refuse rather than guess.** A file that cannot be read, or a pattern
  that exhausts its budget, is reported and the run exits 2 — never a
  clean result that quietly skipped something. In a secret scanner,
  overstating coverage is the whole failure mode.
- **Refusals speak the caller's vocabulary.** An MCP caller has no
  command line; no message aimed at one mentions `--no-resolve` or any
  other flag. A test asserts no MCP output contains `--`.
- **`detect_secrets` belongs to both servers.** The npm server
  (`src/mcp/tools.ts`) and this one offer the same tool: same schema,
  same envelope, byte-identical output. `fixtures/mcp-detect-secrets.json`
  runs against both, so changing one without the other fails a build.
  Every tool here returns that envelope — `{ ok, data, diagnostics,
  meta }` — where `ok` means the check ran, never that the answer was
  yes.

## The corpus contract

`fixtures/` lives inside this crate so the published package is
self-contained — `cargo package` cannot reach above its own directory.
The corpus is **not** needed to build the binary; that was checked
rather than assumed, by deleting it from an unpacked tarball and
building. It is needed to *verify*: `cargo test` on the published crate
runs every corpus case, so a consumer can check the parity claims
instead of trusting them. That is why it ships, and the release workflow
asserts it is in the tarball. It is still shared ground: the extension
reads the same files.
`../scripts/check-detection-parity.ts` (the `parity` job in
`ci-crate.yml`) fails when the extension drifts. Changing a document or
an expectation is a behavior change for **both** frontends and needs a
CHANGELOG entry.

Where the two must disagree, the disagreement is written down in
SPEC.md and a test asserts what each side actually answers. There is no
other sanctioned way to differ.

## Testing

The bar, enforced by review:

- **`detect/`: 75% line coverage floor per module.** Everything in it is
  pure; if something is hard to test there, the design is wrong. Per
  module rather than the crate total, because a total lets one module
  slide while the others carry it.
- **The never-leak property is tested six ways**, and a change that
  weakens any of them is the change to refuse: exhaustively over value
  lengths 3–300 in `detect/mask.rs`, over every corpus document in
  `detect/corpus.rs`, against a real binary run with planted credentials
  in `tests/contracts.rs`, from the extension's side in the parity
  script, over generated documents through both MCP servers in
  `../scripts/check-detection-differential.ts`, and over mutated
  documents in `tests/fuzz.rs`. `detect_values` exists only under
  `#[cfg(test)]` so the property can be checked at all.

  **The property is about every value in the document, not the
  finding's own.** Masking a finding's own value and nothing else left
  the credential beside it in the clear — which is what a compact JSON
  config looks like — and left the key name, which is source text with
  `[A-Za-z0-9_-]*` in front of it, untouched. Both shipped in the
  corpus.
- **The parity corpus is embedded.** Every `fixtures/` case runs as a
  unit test; the expected values are the extension's answers.
- **Exit codes belong in `tests/contracts.rs`.** They are the API —
  callers branch on them — so they are pinned by tests that drive the
  built binary against a temporary tree: no network, no privileged
  operation, so they run everywhere on every push. A new refusal adds
  its case there.
- **Anything needing the real filesystem to misbehave is
  `tests/scenarios.rs`** — symlink loops, unreadable directories, case
  folding — gated behind `SECRETS_LE_SCENARIOS` and run by CI on all three
  OSes. A skipped scenario is never reported as a pass; each one says
  plainly that it did not run.
- **Every bug fix ships with a regression test** that fails before the
  fix. The `escapes-root` bug that fired on every relative path is the
  cautionary one: every unit test passed, because every one of them
  built its own canonical root. Run the binary, not only the tests.
- Tests are deterministic: no clocks, no randomness, and **no filesystem
  in `detect/` tests** — everything there runs from the corpus.

## Verification — the definition of done

All of it, exactly as CI runs it, before every push:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
bun ../scripts/check-detection-parity.ts   # when detection changed
```

CI additionally builds on macOS, Windows and Linux, checks the Rust 1.88
minimum version, runs `cargo audit`, the no-inline-`#[allow]` and
no-filesystem-in-`detect/` policy jobs, the per-module coverage floor,
the gated scenarios, and parity — including on extension-side edits to
`src/detection/**`, so neither frontend can drift green.

Six further jobs exist because something real got through. Each is named
after the class of bug it catches, and each has caught one:

| job | what it holds |
|---|---|
| `hazards` | a byte-order mark, a lone CR, a NUL, a file that is not text, a symlink loop, a FIFO, a name Windows cannot hold. Three platforms, against the built binary, over a tree built at runtime. No panic, no hang, exit 0/1/2 — never a signal. |
| `platform` | report paths use `/` everywhere; the suite does not read `TZ`; case-folding filesystems do not double-report; reserved Windows names do not end the walk; a child that refuses stdin still answers with its exit code. |
| `differential` | both `detect_secrets` servers, byte-identical over generated documents, and the prefilter soundness claim over a generated cross-product. |
| `fuzz` | sixty seconds over the detector table. No panic, no hang, no refusal under 64 KB, no reported value in the output, no context past its bound, and every preview cut from the offsets its finding reports. |
| `budget` | a wall-clock ceiling at ten times the local measurement, and linearity: four times the input inside six times the time. |
| `coverage-matrix` | one file per extension across a broad sample plus a dozen nothing knows — this crate's claim is that it reads everything. |

Run them locally the way CI does:

```bash
cargo test --locked --test hazards
cargo test --locked --test platform
cargo test --locked --test coverage_matrix
cargo test --locked --bin secrets-le prefilter_soundness
SECRETS_LE_FUZZ_SECONDS=60 cargo test --release --locked --test fuzz
SECRETS_LE_BUDGET=1 cargo test --release --locked --test budget -- --test-threads=1
bun ../scripts/check-detection-differential.ts   # needs a --release build
```

A change is not done because it compiles; it is done when it is tested,
linted, documented where behavior changed (README / CHANGELOG / SPEC /
this file), and honest — claims in docs must match the code.

## Commits and pull requests

The repo root's convention applies unchanged (root `AGENTS.md`):
conventional prefix, imperative subject, body carrying the *why* —
enforced by the `commit-msg` hook and the `Commit messages` CI job.
One concern per change; if docs describe the thing you changed, update
them in the same commit. Release tags are `crate-v*`, and a release
goes out by dispatching `release-crate.yml` with its publish opt-in —
never by pushing a tag, because a crates.io version can never be
reused.
