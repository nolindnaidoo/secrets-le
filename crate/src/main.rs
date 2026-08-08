//! Secrets-LE: find hardcoded credentials in a codebase, and never
//! print one.
//!
//! Two products live in this repository. The VS Code extension at the
//! root is the reference implementation for detection; this crate is the
//! terminal and agent frontend. `SPEC.md` draws the line between them,
//! `signatures/patterns.toml` is the table both build against, and
//! `fixtures/` keeps them honest.
//!
//! The rule that governs every surface: **a tool that finds secrets must
//! not become the thing that leaks them.** No output path here — stdout,
//! stderr, the MCP envelope, a diagnostic, an error message — ever
//! carries a complete value, and there is no flag that changes that.

mod cli;
mod detect;
mod mcp;
mod scan;
mod walk;

#[cfg(test)]
mod testing;

fn main() -> std::process::ExitCode {
    cli::run()
}
