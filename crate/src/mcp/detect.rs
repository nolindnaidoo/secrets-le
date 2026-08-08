//! `detect_secrets` — the tool **both** servers offer.
//!
//! The npm server (`src/mcp/tools.ts`) and this one are meant to be the
//! same tool, not two similar ones: same schema, same envelope,
//! byte-identical output, **and identical masking**.
//! `fixtures/mcp-detect-secrets.json` runs against both.
//!
//! The masking matters more on this surface than on any other in the
//! family. Everything else here hands back what it extracted; doing that
//! with credentials would mean posting live secrets to whatever cloud
//! model called the tool, which is the exact opposite of what this
//! extension is for. A finding is identifiable without its value — the
//! type, confidence, key name and position locate it, and the caller has
//! the file.

use serde_json::{Map, Value, json};

use crate::detect::{self, Confidence, Options};
use crate::scan::confidence_name;

/// Result caps, in units of "what fits in a context window". Identical
/// to the npm server's.
const DEFAULT_MAX_RESULTS: usize = 500;
const MAX_MAX_RESULTS: usize = 5000;

const SENSITIVITIES: [&str; 3] = ["low", "medium", "high"];

pub(crate) fn definition() -> Value {
    json!({
        "name": "detect_secrets",
        "description": "Detect hardcoded secrets — API keys, passwords, tokens and private keys — \
                        in source or configuration text. Reports each finding by type, confidence, \
                        key name and 1-based position. Values are never returned: previews are \
                        truncated and length-annotated, and the surrounding context line has the \
                        secret masked out, so a finding can be located without the credential \
                        leaving the machine it was found on.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": { "type": "string", "description": "The text to scan." },
                "sensitivity": {
                    "type": "string",
                    "enum": SENSITIVITIES,
                    "description": "Detection threshold. Higher sensitivity reports more \
                                    low-confidence matches.",
                },
                "includeApiKeys": {
                    "type": "boolean",
                    "default": true,
                    "description": "Include API key detectors.",
                },
                "includePasswords": {
                    "type": "boolean",
                    "default": true,
                    "description": "Include password detectors.",
                },
                "includeTokens": {
                    "type": "boolean",
                    "default": true,
                    "description": "Include token detectors.",
                },
                "includePrivateKeys": {
                    "type": "boolean",
                    "default": true,
                    "description": "Include private key detectors.",
                },
                "maxResults": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_MAX_RESULTS,
                    "default": DEFAULT_MAX_RESULTS,
                    "description": format!(
                        "Cap on returned findings (default {DEFAULT_MAX_RESULTS}). \
                         meta.truncated reports whether any were dropped."
                    ),
                },
            },
            "required": ["content"],
            "additionalProperties": false,
        },
    })
}

/// The only shape a finding leaves this server in.
///
/// Written as an allow-list rather than serializing the finding: a new
/// field on `Finding` should have to be added here deliberately, not
/// arrive in the output because nobody remembered to strip it. That is
/// the npm server's reasoning too, and it is why `description` — which
/// the CLI reports — is absent from this surface.
fn redact(finding: &detect::Finding) -> Value {
    let mut entry = Map::new();
    entry.insert("type".to_string(), json!(finding.kind));
    entry.insert(
        "confidence".to_string(),
        json!(confidence_name(finding.confidence)),
    );
    // Omitted rather than null when the pattern had no key group, which
    // is what `JSON.stringify` does with `undefined`.
    if let Some(key) = &finding.key {
        entry.insert("key".to_string(), json!(key));
    }
    entry.insert("preview".to_string(), json!(finding.preview));
    if let Some(context) = &finding.context {
        entry.insert("context".to_string(), json!(context));
    }
    entry.insert("line".to_string(), json!(finding.position.line));
    entry.insert("column".to_string(), json!(finding.position.column));
    Value::Object(entry)
}

pub(crate) fn run(arguments: &Value) -> Result<Value, String> {
    let content = arguments
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| "content is required and must be a string".to_string())?;
    let max_results = read_max_results(arguments)?;

    let defaults = Options::default();
    let flag = |name: &str, fallback: bool| {
        arguments
            .get(name)
            .and_then(Value::as_bool)
            .unwrap_or(fallback)
    };
    let options = Options {
        api_keys: flag("includeApiKeys", defaults.api_keys),
        passwords: flag("includePasswords", defaults.passwords),
        tokens: flag("includeTokens", defaults.tokens),
        private_keys: flag("includePrivateKeys", defaults.private_keys),
        sensitivity: read_sensitivity(arguments)?.unwrap_or(defaults.sensitivity),
    };

    let findings = detect::detect(content, options)?;
    let mut secrets: Vec<Value> = findings.iter().map(redact).collect();

    let truncated = secrets.len() > max_results;
    secrets.truncate(max_results);
    let count = secrets.len();

    Ok(super::envelope(
        "detect_secrets",
        &json!({ "secrets": secrets }),
        count,
        &[],
        truncated,
    ))
}

fn read_sensitivity(arguments: &Value) -> Result<Option<Confidence>, String> {
    let Some(raw) = arguments.get("sensitivity") else {
        return Ok(None);
    };
    match raw.as_str() {
        Some("low") => Ok(Some(Confidence::Low)),
        Some("medium") => Ok(Some(Confidence::Medium)),
        Some("high") => Ok(Some(Confidence::High)),
        _ => Err(format!(
            "sensitivity must be one of: {}",
            SENSITIVITIES.join(", ")
        )),
    }
}

/// Clamp quietly, reject loudly — the npm server's asymmetry. A
/// nonsensical value is a bug in the caller it needs to hear about; a
/// merely excessive one is a caller asking for everything.
fn read_max_results(arguments: &Value) -> Result<usize, String> {
    let Some(raw) = arguments.get("maxResults") else {
        return Ok(DEFAULT_MAX_RESULTS);
    };
    let invalid = "maxResults must be a positive integer".to_string();
    let value = raw.as_u64().ok_or(invalid.clone())?;
    if value < 1 {
        return Err(invalid);
    }
    Ok((value as usize).min(MAX_MAX_RESULTS))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::detect::corpus::document;

    const CASES: &str = include_str!("../../fixtures/mcp-detect-secrets.json");

    #[derive(Debug, Deserialize)]
    struct Case {
        name: String,
        file: Option<String>,
        content: Option<String>,
        arguments: Value,
        expected: Option<Value>,
        #[serde(rename = "expectedError")]
        expected_error: Option<String>,
    }

    #[test]
    fn every_shared_case_answers_identically() {
        let cases: Vec<Case> = serde_json::from_str(CASES).expect("the corpus is valid JSON");
        assert!(!cases.is_empty(), "the corpus is empty");

        for case in cases {
            let mut arguments = case.arguments.clone();
            let content = case
                .file
                .as_deref()
                .map(document)
                .map(str::to_string)
                .or(case.content);
            if let Some(content) = content {
                arguments["content"] = json!(content);
            }

            match (case.expected, case.expected_error) {
                (_, Some(expected)) => {
                    let error = run(&arguments).expect_err(&case.name);
                    assert_eq!(error, expected, "{}", case.name);
                }
                (Some(expected), None) => {
                    let actual = run(&arguments).expect(&case.name);
                    assert_eq!(actual, expected, "{}", case.name);
                }
                (None, None) => panic!("{} pins neither a result nor an error", case.name),
            }
        }
    }

    /// The reason this surface exists in the form it does.
    #[test]
    fn no_answer_ever_carries_a_value() {
        for (name, content) in crate::detect::corpus::documents() {
            let envelope = run(&json!({ "content": content, "sensitivity": "low" }))
                .expect("the patterns hold");
            let rendered = serde_json::to_string(&envelope).expect("serializes");
            for value in crate::detect::detect_values(
                content,
                Options {
                    sensitivity: Confidence::Low,
                    ..Options::default()
                },
            )
            .expect("the patterns hold")
            {
                assert!(
                    !rendered.contains(&value),
                    "{name}: a detected value survived into the MCP answer"
                );
            }
        }
    }

    /// The tool name is a public API with no deprecation channel.
    #[test]
    fn the_tool_name_is_pinned() {
        assert_eq!(definition()["name"], "detect_secrets");
    }

    #[test]
    fn a_fractional_cap_is_refused() {
        let error = run(&json!({ "content": "x", "maxResults": 1.5 })).expect_err("a refusal");
        assert_eq!(error, "maxResults must be a positive integer");
    }

    #[test]
    fn an_unknown_sensitivity_is_refused_by_name() {
        let error =
            run(&json!({ "content": "x", "sensitivity": "paranoid" })).expect_err("a refusal");
        assert!(error.contains("low, medium, high"), "{error}");
    }
}
