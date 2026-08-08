# The shared corpus

These files are the contract between the two frontends of Secrets-LE:
the VS Code extension at the repository root, and the Rust CLI and MCP
server in this crate. **Both read them, and CI fails when either side
drifts.**

They live inside `crate/` because `cargo package` cannot reach above its
own directory, and `cargo test` on the published crate runs them — which
is what lets someone who installed the binary verify the parity claims
and the never-leak property rather than trust them.

| File | What it pins |
|---|---|
| `../signatures/patterns.toml` | The detection table, mirrored from `SECRET_PATTERNS`, in order. |
| `documents/` | The source documents both sides scan. |
| `detection.json` | Every finding, **already masked**, per document per sensitivity, plus the detector-family switches. |
| `mask.json` | `maskSecretValue` and `maskWithin` over the inputs most likely to drift. |
| `mcp-detect-secrets.json` | The `detect_secrets` MCP tool, which **both** servers offer and must answer identically. |

## Findings are recorded masked

`detection.json` holds previews and masked context lines, never raw
values. The corpus therefore doubles as the masking contract: a change
that widened a preview would fail here before it reached a user.

The documents themselves contain fake credentials — that is what makes
them useful — but nothing derived from them carries a value.

## Who checks what

- `bun ../../scripts/check-detection-parity.ts` runs the **extension's**
  exported functions over these files, and additionally asserts that no
  detected value survives into anything it emits.
- `cargo test` runs the **crate's** implementation over the same files,
  from `src/detect/corpus.rs`.

Neither side may be the sole author of a case. A change here is a
behaviour change for both frontends and needs a CHANGELOG entry.
