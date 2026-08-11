//! The agent surface: the same scan over the Model Context Protocol on
//! stdio, so a model can ask whether a tree holds credentials instead of
//! being handed the files and reading them itself.
//!
//! Three rules govern it. Two the family's MCP surfaces established:
//!
//! - **A finding is not an error.** A file full of credentials comes
//!   back as an ordinary result carrying `ok: true` — the check ran.
//!   Only a malformed question is a protocol error. A model that reads a
//!   finding as a broken tool retries instead of reacting.
//! - **Refusals speak the caller's vocabulary.** An MCP caller has no
//!   command line, so no message here mentions a flag.
//!
//! And one this server does not share with the rest of the family:
//!
//! - **Nothing here ever returns a credential.** The caller is very
//!   often a hosted model, so handing back a value would post live
//!   secrets to a third party — a worse disclosure than the commit this
//!   tool exists to prevent. Every finding is masked before it reaches
//!   the envelope, and a test asserts it over the whole corpus.
//!
//! Read-only by construction: nothing on this surface writes.

pub(crate) mod detect;

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::{Value, json};

use crate::detect::{Confidence, Options};
use crate::scan;
use crate::walk::{self, WalkOptions};

const PROTOCOL_VERSION: &str = "2025-06-18";

/// JSON-RPC error codes, from the spec.
const INVALID_PARAMS: i64 = -32602;
const METHOD_NOT_FOUND: i64 = -32601;

pub(crate) fn serve() -> ExitCode {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            return ExitCode::from(2);
        };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            // A frame that is not JSON has no id to answer against;
            // dropping it is the only honest option.
            continue;
        };
        let Some(response) = handle(&request) else {
            continue; // a notification: no reply
        };
        if writeln!(stdout, "{response}").is_err() || stdout.flush().is_err() {
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

fn handle(request: &Value) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request.get("method")?.as_str()?;
    // Notifications carry no id and get no reply.
    id.as_ref()?;

    let result = match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "secrets-le", "version": env!("CARGO_PKG_VERSION") },
        })),
        "tools/list" => Ok(json!({ "tools": tool_definitions() })),
        "tools/call" => call_tool(request.get("params")),
        "ping" => Ok(json!({})),
        other => Err((
            METHOD_NOT_FOUND,
            format!("this server does not implement {other}"),
        )),
    };

    Some(match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": code, "message": message },
        }),
    })
}

fn tool_definitions() -> Value {
    json!([
        detect::definition(),
        {
            "name": "secrets_le_scan",
            "description": "Scan files or directories for hardcoded credentials and report where \
                            each one is. Reads the filesystem; never writes to it, and never \
                            returns a credential — previews are truncated and length-annotated \
                            and context lines are masked. Findings are a normal result, not an \
                            error.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "a file or directory to scan" },
                    "paths": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "several files or directories, instead of `path`",
                    },
                    "sensitivity": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                        "description": "Detection threshold. Higher sensitivity reports more \
                                        low-confidence matches.",
                    },
                    "hidden": {
                        "type": "boolean",
                        "default": false,
                        "description": "Scan hidden files and directories too.",
                    },
                    "ignored": {
                        "type": "boolean",
                        "default": false,
                        "description": "Scan files excluded by .gitignore too. A credential in \
                                        an ignored file will not be committed, but it is still \
                                        on the disk.",
                    },
                },
            },
        },
    ])
}

fn call_tool(params: Option<&Value>) -> Result<Value, (i64, String)> {
    let params = params.ok_or((INVALID_PARAMS, "no tool call was supplied".to_string()))?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((INVALID_PARAMS, "the tool call named no tool".to_string()))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match name {
        "detect_secrets" => Ok(match detect::run(&arguments) {
            Ok(result) => tool_result(&result),
            Err(message) => tool_failure(&message),
        }),
        "secrets_le_scan" => Ok(match scan_tool(&arguments) {
            Ok(result) => tool_result(&result),
            Err(message) => tool_failure(&message),
        }),
        other => Err((
            INVALID_PARAMS,
            format!("this server offers no tool named {other}"),
        )),
    }
}

fn scan_tool(arguments: &Value) -> Result<Value, String> {
    let inputs = requested_paths(arguments)?;
    let sensitivity = match arguments.get("sensitivity").and_then(Value::as_str) {
        None | Some("medium") => Confidence::Medium,
        Some("low") => Confidence::Low,
        Some("high") => Confidence::High,
        Some(_) => return Err("sensitivity must be one of: low, medium, high".to_string()),
    };
    let options = Options {
        sensitivity,
        ..Options::default()
    };
    let walk_options = WalkOptions {
        hidden: arguments
            .get("hidden")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        respect_ignore: !arguments
            .get("ignored")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    };

    let walked = walk::collect(&inputs, &walk_options)?;
    let reports: Vec<Value> = walked
        .files
        .iter()
        .map(|file| scan::scan_file(file, options))
        .map(|report| serde_json::to_value(&report).expect("a report serializes"))
        .collect();

    let findings: u64 = reports
        .iter()
        .map(|report| report["summary"]["findings"].as_u64().unwrap_or(0))
        .sum();

    let mut diagnostics = Vec::new();
    // Named first, because these are the ones where "skipped" is
    // dangerous. The bare count is mostly dependencies and a model given
    // only that number will report a clean repository.
    for path in &walked.skipped_of_note {
        diagnostics.push(warning(
            "skipped",
            &format!(
                "{} was not scanned — excluded by .gitignore or the hidden rule, and its name \
                 says it holds credentials. Ask for ignored and hidden files to reach it.",
                path.display()
            ),
        ));
    }
    if walked.skipped > walked.skipped_of_note.len() {
        diagnostics.push(warning(
            "skipped",
            &format!(
                "{} further file(s) were excluded by .gitignore or the hidden rule, mostly \
                 dependencies; a credential in one is still on the disk",
                walked.skipped - walked.skipped_of_note.len()
            ),
        ));
    }
    for report in reports.iter().filter(|report| {
        report["diagnostics"]
            .as_array()
            .is_some_and(|list| list.iter().any(|d| d["severity"] == "error"))
    }) {
        diagnostics.push(warning(
            "unreadable",
            &format!(
                "{} could not be scanned, so this run does not cover it",
                report["file"].as_str().unwrap_or("a file")
            ),
        ));
    }

    let count = reports.len();
    Ok(envelope(
        "secrets_le_scan",
        &json!({ "reports": reports, "findings": findings }),
        count,
        &diagnostics,
        false,
    ))
}

fn requested_paths(arguments: &Value) -> Result<Vec<PathBuf>, String> {
    if let Some(path) = arguments.get("path").and_then(Value::as_str) {
        return Ok(vec![PathBuf::from(path)]);
    }
    if let Some(items) = arguments.get("paths").and_then(Value::as_array) {
        let paths: Vec<PathBuf> = items
            .iter()
            .filter_map(|item| item.as_str().map(PathBuf::from))
            .collect();
        if paths.is_empty() {
            return Err("the list of paths was empty".to_string());
        }
        return Ok(paths);
    }
    Err("no file or directory was supplied to scan".to_string())
}

/// The one result shape every tool returns, matching the npm server's
/// envelope field for field.
///
/// **`ok` reports whether the scan ran, not whether it was clean.** A
/// file full of credentials is the answer, not a failure to produce one.
pub(crate) fn envelope(
    tool: &str,
    data: &Value,
    count: usize,
    diagnostics: &[Value],
    truncated: bool,
) -> Value {
    let ok = !diagnostics
        .iter()
        .any(|diagnostic| diagnostic["severity"].as_str() == Some("error"));
    json!({
        "ok": ok,
        "data": data,
        "diagnostics": diagnostics,
        "meta": { "tool": tool, "count": count, "truncated": truncated },
    })
}

fn tool_result(envelope: &Value) -> Value {
    let text = serde_json::to_string_pretty(envelope).expect("an envelope serializes");
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": envelope,
        "isError": false,
    })
}

fn warning(code: &str, message: &str) -> Value {
    json!({ "severity": "warning", "code": code, "message": message })
}

fn tool_failure(message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": message }],
        "isError": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TempTree;

    fn request(method: &str, params: &Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
    }

    fn call(name: &str, arguments: &Value) -> Value {
        handle(&request(
            "tools/call",
            &json!({ "name": name, "arguments": arguments }),
        ))
        .expect("a reply")
    }

    #[test]
    fn initialize_answers_with_the_protocol_version() {
        let response = handle(&request("initialize", &json!({}))).expect("a reply");
        assert_eq!(response["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(response["result"]["serverInfo"]["name"], "secrets-le");
    }

    #[test]
    fn tools_list_offers_both_tools() {
        let response = handle(&request("tools/list", &json!({}))).expect("a reply");
        let tools = response["result"]["tools"].as_array().expect("tools");
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert_eq!(names, ["detect_secrets", "secrets_le_scan"]);
    }

    #[test]
    fn a_notification_gets_no_reply() {
        assert!(handle(&json!({ "jsonrpc": "2.0", "method": "initialized" })).is_none());
    }

    #[test]
    fn an_unknown_method_is_a_protocol_error() {
        let response = handle(&request("does/not/exist", &json!({}))).expect("a reply");
        assert_eq!(response["error"]["code"], METHOD_NOT_FOUND);
    }

    #[test]
    fn an_unknown_tool_is_a_protocol_error() {
        assert_eq!(
            call("secrets_le_redact", &json!({}))["error"]["code"],
            INVALID_PARAMS
        );
    }

    #[test]
    fn a_missing_argument_is_a_tool_failure_not_a_protocol_error() {
        let response = call("secrets_le_scan", &json!({}));
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["isError"], true);
    }

    #[test]
    fn a_finding_is_an_ordinary_result() {
        let tree = TempTree::new("mcp-scan");
        tree.write("app.env", "DATABASE_PASSWORD=hunter2hunter2\n");
        let response = call(
            "secrets_le_scan",
            &json!({ "path": tree.path().to_string_lossy() }),
        );
        let envelope = &response["result"]["structuredContent"];
        assert_eq!(response["result"]["isError"], false);
        assert_eq!(envelope["ok"], true, "a finding is not a broken tool");
        assert_eq!(envelope["data"]["findings"], 1);
    }

    /// The property, on the surface most likely to hand data to a third
    /// party.
    #[test]
    fn a_scan_answer_never_carries_a_value() {
        let tree = TempTree::new("mcp-noleak");
        let value = "hunter2hunter2hunter2";
        tree.write("app.env", &format!("DATABASE_PASSWORD={value}\n"));
        let response = call(
            "secrets_le_scan",
            &json!({ "path": tree.path().to_string_lossy(), "sensitivity": "low" }),
        );
        let rendered = serde_json::to_string(&response).expect("serializes");
        assert!(!rendered.contains(value), "{rendered}");
    }

    #[test]
    fn a_skipped_file_is_reported_rather_than_silently_dropped() {
        let tree = TempTree::new("mcp-skipped");
        tree.mkdir(".git");
        tree.write(".gitignore", ".env\n");
        tree.write(".env", "DATABASE_PASSWORD=hunter2hunter2\n");
        let response = call(
            "secrets_le_scan",
            &json!({ "path": tree.path().to_string_lossy() }),
        );
        let envelope = &response["result"]["structuredContent"];
        assert_eq!(envelope["data"]["findings"], 0);
        assert_eq!(
            envelope["diagnostics"][0]["code"], "skipped",
            "a clean answer that skipped the .env must say so"
        );
    }

    #[test]
    fn a_path_that_does_not_exist_is_a_tool_failure() {
        assert_eq!(
            call("secrets_le_scan", &json!({ "path": "/no/such/place-xyz" }))["result"]["isError"],
            true
        );
    }

    /// Refusals speak the caller's vocabulary.
    #[test]
    fn no_message_mentions_a_command_line_flag() {
        let definitions = serde_json::to_string(&tool_definitions()).expect("serializes");
        assert!(!definitions.contains("--"), "{definitions}");

        let tree = TempTree::new("mcp-vocabulary");
        tree.mkdir(".git");
        tree.write(".gitignore", ".env\n");
        tree.write(".env", "PASSWORD=hunter2hunter2\n");
        for arguments in [
            json!({}),
            json!({ "paths": [] }),
            json!({ "path": "/no/such/place-xyz" }),
            json!({ "path": tree.path().to_string_lossy() }),
        ] {
            let rendered =
                serde_json::to_string(&call("secrets_le_scan", &arguments)).expect("serializes");
            assert!(!rendered.contains("--"), "{rendered}");
        }
    }

    #[test]
    fn every_tool_returns_the_same_envelope_shape() {
        let tree = TempTree::new("mcp-envelope");
        tree.write("a.env", "x=1\n");
        for result in [
            call("detect_secrets", &json!({ "content": "x = 1" })),
            call(
                "secrets_le_scan",
                &json!({ "path": tree.path().to_string_lossy() }),
            ),
        ] {
            let envelope = &result["result"]["structuredContent"];
            assert!(envelope["ok"].is_boolean(), "{envelope}");
            assert!(!envelope["data"].is_null(), "{envelope}");
            assert!(envelope["diagnostics"].is_array(), "{envelope}");
            assert!(envelope["meta"]["tool"].is_string(), "{envelope}");
            assert!(envelope["meta"]["count"].is_number(), "{envelope}");
            assert!(envelope["meta"]["truncated"].is_boolean(), "{envelope}");
        }
    }
}
