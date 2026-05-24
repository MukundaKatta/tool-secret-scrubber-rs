//! # tool-secret-scrubber
//!
//! Strip secrets from LLM tool args and outputs before they hit your logs.
//!
//! Agents log a lot. Tool args, tool outputs, full request bodies, full
//! response bodies. Eventually one of those payloads contains an API key,
//! a JWT, a Stripe secret, or an AWS access key, and it lands in your
//! log aggregator unredacted.
//!
//! [`scrub`] walks an arbitrary [`serde_json::Value`] and replaces
//! matched values with a fixed placeholder. The structure shape is
//! preserved so downstream tools still parse cleanly.
//!
//! ## Quick example
//!
//! ```
//! use serde_json::json;
//! use tool_secret_scrubber::scrub;
//!
//! let payload = json!({
//!     "tool": "send_email",
//!     "args": {
//!         "to": "alice@example.com",
//!         "auth_token": "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
//!         "header": "Authorization: Bearer abcdef1234567890abcdef1234567890",
//!     },
//! });
//! let safe = scrub(payload);
//! assert_eq!(safe["args"]["to"], "alice@example.com");
//! assert!(safe["args"]["auth_token"].as_str().unwrap().starts_with("[REDACTED:"));
//! assert!(safe["args"]["header"].as_str().unwrap().contains("[REDACTED:bearer]"));
//! ```
//!
//! ## Detects, by default
//!
//! - Anthropic keys             `sk-ant-api03-...`
//! - OpenAI keys                `sk-...`, `sk-proj-...`
//! - Google API keys            `AIza...`
//! - Stripe keys (live/test)    `sk_live_...`, `sk_test_...`, `rk_live_...`
//! - GitHub tokens              `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`
//! - JWTs                       `eyJ...`
//! - AWS access key ids         `AKIA...`, `ASIA...`
//! - AWS secret access keys     by adjacent key name
//! - Bearer tokens              `Bearer <opaque>`
//! - Slack tokens               `xox[abprs]-...`
//!
//! ## Sensitive field names
//!
//! Even values that don't match a pattern get fully redacted when stored
//! under a recognised sensitive key (case-insensitive): `password`,
//! `api_key`, `authorization`, `aws_secret_access_key`, `private_key`,
//! and similar. See [`SECRET_KEY_NAMES`].
//!
//! ## Customising
//!
//! ```
//! use serde_json::json;
//! use tool_secret_scrubber::{Pattern, Scrubber, DEFAULT_PATTERNS};
//!
//! let mut patterns = DEFAULT_PATTERNS.to_vec();
//! patterns.push(Pattern::new("internal", r"INTL-[A-Z0-9]{6}").unwrap());
//! let scrubber = Scrubber::new()
//!     .with_patterns(patterns)
//!     .with_placeholder("[REDACTED:{name}]");
//!
//! let out = scrubber.scrub(json!("ref=INTL-ABC123"));
//! assert!(out.as_str().unwrap().contains("[REDACTED:internal]"));
//! ```
//!
//! ## Implementation note
//!
//! This crate uses the [`regex`] crate for pattern matching. That gives a
//! cleaner custom-pattern API (`Pattern::new(name, regex_string)`) than
//! hand-rolling a matcher for nine documented forms plus user-supplied
//! patterns. The only other runtime dep is [`serde_json`], which is the
//! natural Rust analog of the Python library's "arbitrary JSON-like value".

#![deny(missing_docs)]

mod pattern;
mod report;
mod scrubber;

pub use pattern::{default_patterns, Pattern, DEFAULT_PATTERNS, SECRET_KEY_NAMES};
pub use report::ScrubReport;
pub use scrubber::Scrubber;

use serde_json::Value;

/// Scrub a JSON value using the default patterns and sensitive key names.
///
/// Convenience wrapper around [`Scrubber::default`] for the common case
/// where you don't need a custom pattern set or a report.
///
/// The input value is consumed and a new value is returned; the shape
/// (objects/arrays/scalars) is preserved.
///
/// ```
/// use serde_json::json;
/// use tool_secret_scrubber::scrub;
///
/// let safe = scrub(json!({"password": "hunter2"}));
/// assert!(safe["password"].as_str().unwrap().starts_with("[REDACTED:"));
/// ```
pub fn scrub(value: Value) -> Value {
    Scrubber::default().scrub(value)
}
