//! End-to-end checks. Mirrors the Python `test_scrubber.py` scenarios.

use serde_json::{json, Value};
use tool_secret_scrubber::{
    default_patterns, scrub, Pattern, ScrubReport, Scrubber, DEFAULT_PATTERNS, SECRET_KEY_NAMES,
};

// ---- pattern catches -------------------------------------------------------

#[test]
fn anthropic_key_is_redacted() {
    let s = format!("auth=sk-ant-api03-{} trailing", "A".repeat(60));
    let out = scrub(Value::String(s));
    let out = out.as_str().unwrap().to_string();
    assert!(!out.contains("sk-ant-api03"), "leak: {out}");
    assert!(out.contains("[REDACTED:anthropic_key]"));
    assert!(out.ends_with(" trailing"));
}

#[test]
fn openai_key_is_redacted() {
    let s = format!("sk-proj-{}", "a".repeat(40));
    let out = scrub(Value::String(s)).as_str().unwrap().to_string();
    assert!(!out.contains("sk-proj-"), "leak: {out}");
    assert!(out.contains("[REDACTED:openai_key]"));
}

#[test]
fn google_api_key_is_redacted() {
    let s = format!("key=AIza{}", "A".repeat(35));
    let out = scrub(Value::String(s)).as_str().unwrap().to_string();
    assert!(!out.contains("AIza"), "leak: {out}");
    assert!(out.contains("[REDACTED:google_api_key]"));
}

#[test]
fn stripe_key_is_redacted() {
    let s = format!("tok=sk_live_{}", "x".repeat(24));
    let out = scrub(Value::String(s)).as_str().unwrap().to_string();
    assert!(!out.contains("sk_live_"), "leak: {out}");
    assert!(out.contains("[REDACTED:stripe_key]"));
}

#[test]
fn github_token_is_redacted() {
    let s = format!("ghp_{}", "Z".repeat(36));
    let out = scrub(Value::String(s)).as_str().unwrap().to_string();
    assert!(!out.contains("ghp_"), "leak: {out}");
    assert!(out.contains("[REDACTED:github_token]"));
}

#[test]
fn aws_access_key_id_is_redacted() {
    let s = format!("AKIA{}", "A".repeat(16));
    let out = scrub(Value::String(s)).as_str().unwrap().to_string();
    assert!(!out.contains("AKIA"), "leak: {out}");
    assert!(out.contains("[REDACTED:aws_access_key_id]"));
}

#[test]
fn jwt_is_redacted() {
    let s = "Authorization: eyJabc12345.eyJpayload99.signature123".to_string();
    let out = scrub(Value::String(s)).as_str().unwrap().to_string();
    assert!(!out.contains("eyJ"), "leak: {out}");
    assert!(out.contains("[REDACTED:jwt]"));
}

#[test]
fn bearer_token_is_redacted() {
    let payload = format!("Authorization: Bearer {}", "a".repeat(30));
    let out = scrub(Value::String(payload)).as_str().unwrap().to_string();
    assert!(out.contains("[REDACTED:bearer]"));
    assert!(!out.contains(&"a".repeat(30)));
}

#[test]
fn bearer_token_is_case_insensitive() {
    let payload = format!("authorization: bearer {}", "b".repeat(30));
    let out = scrub(Value::String(payload)).as_str().unwrap().to_string();
    assert!(out.contains("[REDACTED:bearer]"), "got: {out}");
}

#[test]
fn slack_token_is_redacted() {
    // Synthetic shape, not a real token format — matches our regex without
    // tripping GitHub's Slack-token scanner on push.
    let s = "xoxb-PLACEHOLDERPLACEHOLDER".to_string();
    let out = scrub(Value::String(s)).as_str().unwrap().to_string();
    assert!(out.contains("[REDACTED:slack_token]"));
}

// ---- structural walking ---------------------------------------------------

#[test]
fn walks_nested_object_and_array() {
    let bearer_header = format!("Authorization: Bearer {}", "b".repeat(30));
    let payload = json!({
        "args": {
            "headers": [
                bearer_header,
                "X-Custom: harmless",
            ],
        },
        "result": "ok",
    });
    let out = scrub(payload);
    let header0 = out["args"]["headers"][0].as_str().unwrap();
    assert!(header0.contains("[REDACTED:bearer]"), "got: {header0}");
    assert_eq!(out["args"]["headers"][1], "X-Custom: harmless");
    assert_eq!(out["result"], "ok");
}

#[test]
fn arrays_preserve_array_shape() {
    // serde_json maps Python tuples to arrays; this is the natural Rust analog.
    let leaky = format!("sk-ant-api03-{}", "A".repeat(40));
    let payload = json!([leaky, "ok"]);
    let out = scrub(payload);
    assert!(out.is_array());
    assert!(out[0].as_str().unwrap().contains("[REDACTED"));
    assert_eq!(out[1], "ok");
}

#[test]
fn non_string_values_pass_through_unchanged() {
    let payload = json!({
        "n": 42,
        "f": 1.5,
        "b": true,
        "none": null,
    });
    let out = scrub(payload.clone());
    assert_eq!(out, payload);
}

#[test]
fn does_not_mutate_input() {
    let leaky = format!("sk-ant-api03-{}", "A".repeat(40));
    let payload = json!({"token": leaky});
    let snapshot = payload.clone();
    let _scrubbed = scrub(payload.clone());
    assert_eq!(payload, snapshot);
}

// ---- key-name redaction ---------------------------------------------------

#[test]
fn key_name_password_redacts_value_even_if_innocent() {
    let out = scrub(json!({"password": "hunter2"}));
    let pw = out["password"].as_str().unwrap();
    assert!(pw.starts_with("[REDACTED:"));
    assert!(!pw.contains("hunter2"));
}

#[test]
fn key_name_authorization_redacts_value() {
    let out = scrub(json!({"Authorization": "anything-goes"}));
    let v = out["Authorization"].as_str().unwrap();
    assert!(v.starts_with("[REDACTED:"));
}

#[test]
fn key_name_match_is_case_insensitive() {
    let out = scrub(json!({"API_KEY": "abc123"}));
    let v = out["API_KEY"].as_str().unwrap();
    assert!(v.starts_with("[REDACTED:"), "got: {v}");
}

#[test]
fn empty_secret_field_stays_empty() {
    let out = scrub(json!({"password": ""}));
    assert_eq!(out["password"], "");
}

// ---- reporting -------------------------------------------------------------

#[test]
fn scrub_with_report_counts_redactions() {
    let s = Scrubber::default();
    let payload = json!({
        "a": format!("sk-ant-api03-{}", "A".repeat(40)),
        "b": format!("Bearer {}", "z".repeat(30)),
    });
    let (_, report): (Value, ScrubReport) = s.scrub_with_report(payload);
    assert_eq!(report.redactions, 2);
    assert_eq!(report.by_pattern.get("anthropic_key"), Some(&1));
    assert_eq!(report.by_pattern.get("bearer"), Some(&1));
}

#[test]
fn report_counts_field_name_redaction_separately() {
    let s = Scrubber::default();
    let payload = json!({"password": "hunter2", "note": "harmless"});
    let (_, report) = s.scrub_with_report(payload);
    assert_eq!(report.redactions, 1);
    assert_eq!(report.by_pattern.get("key_name:password"), Some(&1));
}

// ---- custom patterns + custom secret keys ----------------------------------

#[test]
fn custom_pattern_extra_match() {
    let mut patterns = default_patterns();
    patterns.push(Pattern::new("internal", r"INTL-[A-Z0-9]{6}").unwrap());
    let s = Scrubber::new().with_patterns(patterns);
    let out = s.scrub(json!("ref=INTL-ABC123 plus normal text"));
    let s = out.as_str().unwrap();
    assert!(s.contains("[REDACTED:internal]"), "got: {s}");
}

#[test]
fn custom_secret_keys_replace_defaults() {
    let s = Scrubber::new().with_secret_keys(["my_thing"]);
    let out = s.scrub(json!({"my_thing": "value", "password": "still-leaks"}));
    let v = out["my_thing"].as_str().unwrap();
    assert!(
        v.starts_with("[REDACTED:"),
        "my_thing should be redacted: {v}"
    );
    // password is no longer in the configured set; "still-leaks" does not
    // match any of the default *value* patterns, so it survives.
    assert_eq!(out["password"], "still-leaks");
}

#[test]
fn default_patterns_static_matches_constructor() {
    assert_eq!(DEFAULT_PATTERNS.len(), default_patterns().len());
    for (a, b) in DEFAULT_PATTERNS.iter().zip(default_patterns().iter()) {
        assert_eq!(a.name, b.name);
    }
}

#[test]
fn secret_key_names_list_is_not_empty() {
    assert!(!SECRET_KEY_NAMES.is_empty());
    assert!(SECRET_KEY_NAMES.contains(&"authorization"));
    assert!(SECRET_KEY_NAMES.contains(&"aws_secret_access_key"));
}

#[test]
fn custom_placeholder_template() {
    let s = Scrubber::new().with_placeholder("<<{name}>>");
    let leaky = format!("sk-ant-api03-{}", "A".repeat(40));
    let out = s.scrub(Value::String(leaky));
    let v = out.as_str().unwrap();
    assert!(v.contains("<<anthropic_key>>"), "got: {v}");
}

#[test]
fn multiple_hits_in_one_string_each_counted() {
    let s = Scrubber::default();
    let combined = format!(
        "first=sk-ant-api03-{} second=sk-ant-api03-{}",
        "A".repeat(40),
        "B".repeat(40)
    );
    let (out, report) = s.scrub_with_report(Value::String(combined));
    let v = out.as_str().unwrap();
    assert_eq!(v.matches("[REDACTED:anthropic_key]").count(), 2);
    assert_eq!(report.by_pattern.get("anthropic_key"), Some(&2));
    assert_eq!(report.redactions, 2);
}

// ---- no false positives / edge cases ---------------------------------------

#[test]
fn innocent_text_is_left_untouched() {
    let s = Scrubber::default();
    let payload = json!({
        "message": "hello world, nothing secret here",
        "count": "12345",
        "url": "https://example.com/path?q=1",
    });
    let (out, report) = s.scrub_with_report(payload.clone());
    assert_eq!(out, payload);
    assert_eq!(report.redactions, 0);
    assert!(report.by_pattern.is_empty());
}

#[test]
fn pattern_new_rejects_invalid_regex() {
    // An unbalanced group is not a valid regex and must surface as an error
    // rather than panic.
    let result = Pattern::new("bad", r"(unclosed");
    assert!(result.is_err());
}

#[test]
fn redaction_preserves_surrounding_multibyte_text() {
    // Byte-offset slicing must not split a multibyte char when secrets sit
    // between non-ASCII text.
    let leaky = format!("sk-ant-api03-{}", "A".repeat(40));
    let s = format!("café {leaky} naïve");
    let out = scrub(Value::String(s)).as_str().unwrap().to_string();
    assert!(out.starts_with("café "), "got: {out}");
    assert!(out.ends_with(" naïve"), "got: {out}");
    assert!(out.contains("[REDACTED:anthropic_key]"));
    assert!(!out.contains("sk-ant-api03"));
}
