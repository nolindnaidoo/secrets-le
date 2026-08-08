# Instructions for AI coding assistants

Read [AGENTS.md](AGENTS.md) first — it is the engineering-standards
document for this crate and the source of truth for layout, control-flow
style, the settled decisions, testing requirements, and the definition
of done. [SPEC.md](SPEC.md) defines the product behavior. AGENTS.md wins
on any conflict. The extension at the repo root is a separate product
with its own `CLAUDE.md`.

- Before declaring any change complete, run exactly what CI runs:
  `cargo fmt --all --check`,
  `cargo clippy --all-targets -- -D warnings`,
  `cargo test --locked`. All three must pass — and
  `bun ../scripts/check-detection-parity.ts` when detection changed.
- Never add inline `#[allow(...)]` — CI fails the build on it. Fix the
  lint, or add a commented relaxation to `[lints.clippy]` in
  `Cargo.toml`.
- New logic goes in `detect/` when it is pure (it must then be
  unit-tested, 90% module coverage floor), and in `walk.rs` / `scan.rs`
  only when it needs the filesystem. A `std::fs` call in `detect/` fails
  a CI job.
- **Nothing may emit a value.** `Finding` has no value field and must
  never grow one; the raw match lives only inside the detection loop.
  Before adding any output, ask what a CI log would have captured.
- `fixtures/` is shared with the extension — changing it changes both
  frontends and needs a CHANGELOG entry. The extension is the reference
  implementation for detection; a difference is a regression until
  SPEC.md says otherwise.
- Write regression tests for every bug you fix; keep unit tests free of
  clocks, randomness, and the filesystem outside `resolve`/`walk`/
  `audit`.
- **Run the binary, not only the tests.** Two defects here were invisible
  to the whole suite: the `aws-secret` pattern exhausted its backtracking
  budget on an ordinary `bun.lock`, so every repository with a lockfile
  exited 2; and the skipped-file warning fired on six vendored `.npmrc`
  files per repository, which is how a useful warning becomes noise. Both
  were found by running the binary over seven real repositories.
