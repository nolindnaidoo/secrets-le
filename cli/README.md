# secrets-le

Find hardcoded credentials in a codebase and report where each one is,
never what it is: the pre-commit check, the CI gate on a pull request, the
audit of a repository someone is about to open-source.

```bash
npx secrets-le .
npx secrets-le --sensitivity high src/ > findings.jsonl
git diff | npx secrets-le --stdin
```

The command it installs is `secrets-le`, the same command line as the Rust
crate [`secrets-le`](https://crates.io/crates/secrets-le), and it behaves
identically: same flags, same walk, same findings, same output, same exit
codes. Install whichever toolchain you already have.

## What it reports

Provider keys such as AWS, Anthropic, OpenAI, GitHub and Stripe-style
tokens, generic API keys, passwords, connection strings, private keys and
JWTs, in any text file. A finding carries its type,
confidence, key name, position and a bounded preview. **No output ever
carries the value**: the preview is truncated and length-annotated, the
context line is masked, and there is no flag that turns either off.

Directories are walked the way ripgrep walks them: `.gitignore`, `.ignore`
and hidden files are respected unless you pass `--no-ignore` or `--hidden`.
What they kept out is counted, and an excluded file whose name says it holds
credentials, such as `.env` or `server.pem`, is named.

## Output

stdout carries one JSON report per file whenever it is piped or redirected,
and nothing when it is a terminal. stderr lists every finding.

```text
$ secrets-le app.env clean.md
app.env:1:14  token github_token  ghp_abcd… (40 chars)  [high]
1 finding in 2 files
```

```json
{"file":"app.env","findings":[{"type":"token","confidence":"high","key":"github_token","preview":"ghp_abcd… (40 chars)","context":"GITHUB_TOKEN=ghp_abcd… (40 chars)","line":1,"column":14,"description":"Generic token"}],"diagnostics":[],"summary":{"findings":1,"high":1,"medium":0,"low":0}}
```

Columns count UTF-16 code units, as an editor does.

A file that is not UTF-8 text, or that cannot be opened, is named on stderr
and carried in its report as `skipped`. It does not fail the run on its
own.

## Exit codes

- **0**: nothing found.
- **1**: findings.
- **2**: the question was malformed, a directory could not be walked, or
  `--strict` and a file could not be read.

For a run over many files, the exit code is the worst outcome in it.

## For agents

`secrets-le mcp` serves the Model Context Protocol on stdio with two tools:
`detect_secrets` for a document's text and `secrets_le_scan` for files and
directories. Neither ever returns a credential. Hosts that want the
document tool alone can install
[`secrets-le-mcp`](https://www.npmjs.com/package/secrets-le-mcp).

`secrets-le --help` lists every option.

MIT licensed. Part of [letools](https://letools.dev/tools/secrets-le).
