<h1 align="center">secrets-le</h1>

<p align="center">
  <b>Find hardcoded credentials in a codebase, and never print one</b><br/>
  <i>API keys, passwords, tokens, private keys — located, never disclosed</i>
</p>

<p align="center">
  <a href="https://crates.io/crates/secrets-le">
    <img src="https://img.shields.io/crates/v/secrets-le.svg" alt="secrets-le on crates.io" />
  </a>
  <a href="https://crates.io/crates/secrets-le">
    <img src="https://img.shields.io/crates/d/secrets-le.svg" alt="crates.io downloads" />
  </a>
  <a href="https://github.com/nolindnaidoo/secrets-le/actions/workflows/ci-crate.yml">
    <img src="https://github.com/nolindnaidoo/secrets-le/actions/workflows/ci-crate.yml/badge.svg" alt="Build Status" />
  </a>
  <img src="https://img.shields.io/badge/rustc-1.88+-93450a.svg" alt="MSRV: Rust 1.88+" />
  <a href="https://github.com/nolindnaidoo/secrets-le/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" />
  </a>
  <a href="https://letools.dev/tools/secrets-le">
    <img src="https://img.shields.io/badge/web-letools.dev-00A0FF.svg" alt="letools.dev" />
  </a>
</p>

> **Useful?** A star is how other developers find it —
> [★ GitHub](https://github.com/nolindnaidoo/secrets-le) ·
> [letools.dev/tools/secrets-le](https://letools.dev/tools/secrets-le)

## The rule this is built around

**A tool that finds secrets must not become the thing that leaks them.**

A scanner's output goes into a CI log. That log is archived, is often
world-readable on a public repository, is scraped, and outlives the
credential. A scanner that prints what it found has disclosed every
secret it detected to a wider audience than the commit would have.

So, without exception and without a flag:

- **No output ever contains a complete value.** Not stdout, not stderr,
  not the MCP envelope, not an error message.
- **A preview is capped at eight characters *and* at half the value's
  length**, and carries the length. Half-length is what makes the cap
  hold for short values — an eight-character cap on an eight-character
  password is the password.
- **The context line is masked too**, because it is the raw source line
  and therefore contains the credential it is providing context for.
- **There is no `--show-values`.** A flag that turns this off is a flag
  that ends up in someone's CI config.

A test plants credentials, runs the real binary, and asserts that not
one of them appears anywhere in stdout or stderr. Another asserts the
property exhaustively over value lengths 3 to 300. You can run both
yourself: `cargo test` works from the published crate.

## Sixty seconds

```bash
secrets-le .                          # scan a tree
secrets-le --sensitivity high .       # only high-confidence findings
secrets-le --no-ignore --hidden .     # reach .env and everything git ignores
cat config.env | secrets-le --stdin
```

```
./config/app.env:1:19  password database_password  hunter2h… (21 chars)  [high]
./config/app.env:2:19  aws-key  AKIAIOSF… (20 chars)  [high]
./src/client.js:1:13  token  ghp_1234… (40 chars)  [high]
3 findings in 2 files
```

The exit code is the answer: **0 nothing found · 1 findings · 2 the
question was malformed.** So `secrets-le .` is a CI step as it stands.

## Install

| Route | Command | Worth knowing |
|---|---|---|
| **cargo** | `cargo install secrets-le` | Any platform, needs **Rust 1.88+**. |
| **From source** | `git clone https://github.com/nolindnaidoo/secrets-le`<br>`cd secrets-le/crate && cargo build --release` | The same build CI runs. |

No runtime, no network, nothing written. It reads files and reports
positions.

## What it looks for

Thirty-four patterns across four families — API keys, passwords, tokens and
private keys. Nineteen are named issuers: Anthropic, OpenAI, GitHub,
GitLab, Slack, Stripe, Google, SendGrid, Mailgun, Sentry, npm, PyPI,
Docker Hub, HashiCorp Vault, Terraform Cloud, Supabase, Shopify, Square
and Azure SAS. The rest cover AWS access keys and secrets, Azure and GCP
keys, bearer tokens, JWTs, OAuth/access/refresh tokens, session ids,
cookies, database URLs with embedded credentials, and PEM private-key
blocks (re-classified as SSH or PGP from their header).

The table lives in
[`signatures/patterns.toml`](https://github.com/nolindnaidoo/secrets-le/blob/main/crate/signatures/patterns.toml)
— reviewable without reading Rust, and mirrored from the extension's own
table by a check that runs in both directions.

**Every file is scanned, whatever its extension.** A scanner that only
looked at the extensions it recognised would report a clean tree while
sitting next to a `.bak` full of passwords.

### What it deliberately does not report

Ported from the extension as decisions, not oversights:

- **A bare `x.y.z` triple is not a JWT.** A JWT header is base64 JSON and
  always begins `eyJ`. Version numbers, hostnames and module paths are
  the dominant false positive, and this kills them — at the cost of
  missing JWTs with non-JSON headers.
- **Template placeholders are never secrets**: `${VAR}`, `{{var}}`,
  `<your-key>`, and any run of one repeated character.
- **GCP project ids are identifiers**, not credentials.

### A false positive you will see

`token: vscode.CancellationToken` is reported as a token, because the
generic key pattern matches an identifier ending in `token` followed by
twenty-plus characters. It is the extension's behaviour, verified
against it, and kept — **parity is the contract, and a scanner whose two
frontends disagree is worse than one with a known noisy pattern.**
`--sensitivity high` drops most of this class.

## Options

```
--sensitivity <level>   low, medium (default) or high. Higher reports
                        fewer, more certain findings.
--no-api-keys           skip the API-key detectors
--no-passwords          skip the password detectors
--no-tokens             skip the token detectors
--no-private-keys       skip the private-key detectors
--strict                exit 2 if any file could not be read, rather
                        than reporting it and carrying on
--stdin                 read one document from stdin
--hidden                scan hidden files and directories too
--no-ignore             scan files that .gitignore excludes
```

The four `--no-*` toggles narrow what runs. They cannot widen it: there
is no flag that turns masking off, and none that prints a value.

## `.gitignore` is honoured, and that is a real risk

By default the walk skips what git ignores, which is where `.env` usually
lives. A secret in an ignored file will not be committed — the threat
this tool exists for — but it is still a secret on the disk.

Two things keep that from being invisible. Files whose *names* say they
hold credentials (`.env`, `.env.*`, `*.pem`, `*.key`, `.npmrc`,
`id_rsa`, …) are **named individually** when they are skipped. Everything
else is a count at the end of the summary. `--no-ignore --hidden` reaches
all of it.

The named list excludes vendored trees — `node_modules`, `.vscode-test`,
`vendor` and friends — because six `.npmrc` files from inside a
downloaded editor bundle is how a useful warning becomes noise. Measured
on seven real repositories.

## In CI

```yaml
- name: No hardcoded credentials
  run: secrets-le --no-ignore --hidden .
```

Exit 1 fails the step on a finding. Exit 2 means the tool could not
answer — an unreadable file or directory — and fails it too, because a
scan that silently skipped something is worse than no scan.

## As an MCP server

```bash
secrets-le mcp
```

Two tools, both returning `{ ok, data, diagnostics, meta }`, both masked:

- **`detect_secrets`** — content in, findings out. Touches no filesystem.
  The npm server ships the same tool with byte-identical output; one
  corpus runs against both.
- **`secrets_le_scan`** — files or directories in, the same masked
  reports the CLI writes.

The masking matters most here: the caller is often a hosted model, so
returning a value would post live credentials to a third party — a worse
disclosure than the commit this tool prevents.

## What it will not do

- **It does not rewrite files.** Rewriting a file that holds a live
  credential is the most destructive thing this codebase could offer, and
  it needs a confirmation story that is owed before the code.
- **It does not validate credentials.** Checking whether a key is live
  means transmitting it, to a third party.
- **It does not read git history.** That is a different traversal, and
  conflating them would make "clean" ambiguous about what was examined.
- **It has no entropy detector.** An untuned one produces a
  false-positive rate that trains people to ignore the output.

Full behaviour is in
[SPEC.md](https://github.com/nolindnaidoo/secrets-le/blob/main/crate/SPEC.md).

## The other four ways to run it

| Where | What you get | Install |
|---|---|---|
| **VS Code** | Detection and in-place sanitising, in your editor | [Marketplace](https://marketplace.visualstudio.com/items?itemName=nolindnaidoo.secrets-le) |
| **Cursor, VSCodium, Windsurf** | The same extension | [Open VSX](https://open-vsx.org/extension/OffensiveEdge/secrets-le) |
| **Any MCP agent, via Node** | `detect_secrets` over stdio | `npx secrets-le-mcp` · [npm](https://www.npmjs.com/package/secrets-le-mcp) |
| **Zed** | The MCP server as a context server | [add it by hand](https://zed.dev/docs/ai/mcp) *(no listing yet)* |

The extension is the one that can *fix* what it finds; this binary only
reports. All sixteen LE tools are on **[letools.dev](https://letools.dev)**.

## Documentation

| What | Where |
|---|---|
| What this tool is allowed to say — scope, output contract, refusals, non-goals | [SPEC.md](https://github.com/nolindnaidoo/secrets-le/blob/main/crate/SPEC.md) |
| How the code is written and held together — architecture, invariants, the gates | [AGENTS.md](https://github.com/nolindnaidoo/secrets-le/blob/main/crate/AGENTS.md) |
| The VS Code extension this shares its extraction with | [README.md](https://github.com/nolindnaidoo/secrets-le/blob/main/README.md) |
| What changed | [CHANGELOG.md](https://github.com/nolindnaidoo/secrets-le/blob/main/crate/CHANGELOG.md) |
| The tool's page, and the other fifteen | [letools.dev/tools/secrets-le](https://letools.dev/tools/secrets-le) |

## More from the LE family

Sixteen single-purpose tools for the work in front of every model. Each ships
a Rust CLI and an MCP server. One page: **[letools.dev](https://letools.dev)**

**Get it out**

- **[String-LE](https://letools.dev/tools/string-le)** — Extract every string in a codebase, with its position, so a person can read them
- **[Numbers-LE](https://letools.dev/tools/numbers-le)** — Extract every hardcoded number in a codebase, so a person can check them
- **[Units-LE](https://letools.dev/tools/units-le)** — Extract every quantity with its unit, normalized, and refuse the ambiguous ones by name
- **[Dates-LE](https://letools.dev/tools/dates-le)** — Extract every date and timestamp, and the exact instant each one resolves to
- **[IDs-LE](https://letools.dev/tools/ids-le)** — Extract every UUID, ULID, NanoID, ObjectId and Snowflake, and decode the time inside
- **[IPs-LE](https://letools.dev/tools/ips-le)** — Extract every IP address, CIDR block and MAC, normalized and classified by scope
- **[URLs-LE](https://letools.dev/tools/urls-le)** — Extract every URL in a codebase, with its protocol and exact position
- **[Paths-LE](https://letools.dev/tools/paths-le)** — Extract every file path in a codebase, and say whether it still points at anything
- **[Colors-LE](https://letools.dev/tools/colors-le)** — Extract every color in a codebase, and say which ones are not in your palette

**Check it**

- **[Regex-LE](https://letools.dev/tools/regex-le)** — Find every regex in a codebase, and report which can be driven into catastrophic backtracking
- **[Versions-LE](https://letools.dev/tools/versions-le)** — Find where one dependency is constrained differently across a repository's manifests
- **[i18n-LE](https://letools.dev/tools/i18n-le)** — Identify the i18n library a project uses, then audit its catalogs by that library's rules
- **[Scrape-LE](https://letools.dev/tools/scrape-le)** — Check whether a page is scrapeable before the scraper is written, and say when it cannot tell

**Guard it**

- **[Secrets-LE](https://letools.dev/tools/secrets-le)** — Find hardcoded credentials in a codebase, and never print one into the report
- **[EnvSync-LE](https://letools.dev/tools/envsync-le)** — Compare the dotenv files in a tree, and say which keys are missing from which
- **[Unicode-LE](https://letools.dev/tools/unicode-le)** — Find the Unicode that hides meaning — bidi controls, invisibles, homoglyphs, mixed scripts

Each stands on its own: no shared crate, no published core. Where two of them
agree, it is because the same answer was right twice.

**Contact** — [nolindnaidoo.com](https://nolindnaidoo.com) · [GitHub](https://github.com/nolindnaidoo) · [LinkedIn](https://www.linkedin.com/in/nolindnaidoo/)

## Also by nolindnaidoo

**Rust** — pixelcoords and pixelactions are one loop: pixelcoords answers
*where*, pixelactions *acts* there. Their own tools, their own voice — not
part of the LE family.

- **[pixelcoords](https://github.com/nolindnaidoo/pixelcoords)** — Freeze your screen, mark regions, get pixel-exact coordinates and crops
  [pixelcoords.dev](https://pixelcoords.dev) · [crates.io](https://crates.io/crates/pixelcoords) · [docs.rs](https://docs.rs/pixelcoords)
- **[pixelactions](https://github.com/nolindnaidoo/pixelactions)** — Consume human-verified coordinates, perform the interaction, confirm it landed
  [pixelactions.dev](https://pixelactions.dev) · [crates.io](https://crates.io/crates/pixelactions) · [docs.rs](https://docs.rs/pixelactions)

## License

MIT — see [LICENSE](https://github.com/nolindnaidoo/secrets-le/blob/main/LICENSE).
