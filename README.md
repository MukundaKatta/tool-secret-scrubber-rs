# tool-secret-scrubber

[![Crates.io](https://img.shields.io/crates/v/tool-secret-scrubber.svg)](https://crates.io/crates/tool-secret-scrubber)
[![Documentation](https://docs.rs/tool-secret-scrubber/badge.svg)](https://docs.rs/tool-secret-scrubber)
[![License](https://img.shields.io/crates/l/tool-secret-scrubber.svg)](https://crates.io/crates/tool-secret-scrubber)

**Strip secrets from LLM tool args and outputs before they hit your logs.**

```rust
use serde_json::json;
use tool_secret_scrubber::scrub;

let safe = scrub(json!({
    "tool": "send_email",
    "args": {
        "to": "alice@example.com",
        "auth_token": "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "body": "Authorization: Bearer eyJabc12345.eyJpayload.signature_xyz",
    },
}));
// -> {"tool": "send_email", "args": {
//     "to": "alice@example.com",
//     "auth_token": "[REDACTED:auth_token]",
//     "body": "Authorization: [REDACTED:bearer]"
// }}
```

Catches by default:

| Pattern | Example |
|---|---|
| Anthropic keys | `sk-ant-api03-...` |
| OpenAI keys | `sk-...`, `sk-proj-...` |
| Google API keys | `AIza...` |
| Stripe keys | `sk_live_...`, `sk_test_...`, `rk_live_...` |
| GitHub tokens | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` |
| AWS access key IDs | `AKIA...`, `ASIA...` |
| JWTs | `eyJ...` |
| Bearer tokens | `Bearer <opaque>` |
| Slack tokens | `xox[abprs]-...` |

Plus a list of sensitive **field names** (`password`, `api_key`, `authorization`, `aws_secret_access_key`, `private_key`, ...) — values in those fields get redacted regardless of whether they look secret-y.

## Why

Most LLM observability libraries log tool args verbatim. That's fine until a tool gets an API key in its args and your log aggregator becomes a credential dump. `tool-secret-scrubber` is the function you wrap around your structured logger so you never have to find out which tool was the leaky one.

Walks objects, arrays, scalars; preserves shape; never mutates input.

## Install

```toml
[dependencies]
tool-secret-scrubber = "0.1"
serde_json = "1"
```

## Use

Top-level convenience:

```rust
use serde_json::json;
use tool_secret_scrubber::scrub;

let safe = scrub(json!({"password": "hunter2"}));
assert_eq!(safe["password"], "[REDACTED:password]");
```

Customise patterns and field names:

```rust
use serde_json::json;
use tool_secret_scrubber::{default_patterns, Pattern, Scrubber};

let mut patterns = default_patterns();
patterns.push(Pattern::new("internal", r"INTL-[A-Z0-9]{6}").unwrap());

let s = Scrubber::new()
    .with_patterns(patterns)
    .with_secret_keys(["my_thing", "password"]);

let (safe, report) = s.scrub_with_report(json!({
    "my_thing": "value",
    "ref": "INTL-ABC123",
}));
println!("{} redactions, by pattern: {:?}", report.redactions, report.by_pattern);
```

`scrub_with_report` returns `(scrubbed_value, ScrubReport)` so you can count how many redactions happened and feed that into a metric.

## What it does NOT do

- No log shipping. Just a pure function over `serde_json::Value`.
- No tokenizer / no entropy classifier. Pattern + field-name catches only.
- No async / no I/O.

## Dependencies

Two runtime deps: [`serde_json`] for the value type and [`regex`] for
matching. Sibling to the Python [`tool-secret-scrubber`][py] library.

[`serde_json`]: https://docs.rs/serde_json
[`regex`]: https://docs.rs/regex
[py]: https://pypi.org/project/tool-secret-scrubber/

## License

MIT OR Apache-2.0
