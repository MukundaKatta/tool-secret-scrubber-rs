//! Named regex patterns for known secret formats.
//!
//! Each [`Pattern`] is a compiled regex paired with a name. The name shows
//! up in the placeholder (`[REDACTED:{name}]`) and in [`ScrubReport`]
//! counts.
//!
//! [`DEFAULT_PATTERNS`] returns the same nine patterns the Python
//! `tool_secret_scrubber` library ships with. [`SECRET_KEY_NAMES`] returns
//! the field-name list that triggers whole-value redaction regardless of
//! pattern match.
//!
//! [`ScrubReport`]: crate::ScrubReport

use regex::Regex;

/// A named regex pattern.
///
/// The `name` is used in the placeholder string and in [`ScrubReport`]
/// counts. The `regex` is the compiled pattern.
///
/// Construct via [`Pattern::new`].
///
/// [`ScrubReport`]: crate::ScrubReport
#[derive(Debug, Clone)]
pub struct Pattern {
    /// Display name for the pattern. Appears in the placeholder.
    pub name: String,
    /// Compiled regex.
    pub regex: Regex,
}

impl Pattern {
    /// Compile a new named pattern.
    ///
    /// Returns an error if the regex is invalid.
    ///
    /// ```
    /// use tool_secret_scrubber::Pattern;
    ///
    /// let p = Pattern::new("internal", r"INTL-[A-Z0-9]{6}").unwrap();
    /// assert_eq!(p.name, "internal");
    /// ```
    pub fn new(name: impl Into<String>, pat: &str) -> Result<Self, regex::Error> {
        Ok(Self {
            name: name.into(),
            regex: Regex::new(pat)?,
        })
    }
}

/// Built-in patterns for well-known secret formats.
///
/// Returns a fresh `Vec<Pattern>` on each call so callers can mutate it
/// (e.g. push a custom pattern) without affecting other scrubbers.
///
/// Detects:
///
/// - `anthropic_key`    — `sk-ant-api{2-digits}-{40+ url-safe chars}`
/// - `openai_key`       — `sk-` or `sk-proj-` followed by 20+ url-safe chars
/// - `google_api_key`   — `AIza` plus 35 url-safe chars
/// - `stripe_key`       — `sk_`/`rk_`/`pk_` `live_`/`test_` plus 16+ alnum
/// - `github_token`     — `gh[pousr]_` plus 20+ alnum
/// - `aws_access_key_id` — `AKIA` or `ASIA` plus exactly 16 [0-9A-Z]
/// - `jwt`              — three dot-separated base64url segments starting `eyJ`
/// - `bearer`           — case-insensitive `Bearer ` plus 20+ token chars
/// - `slack_token`      — `xox[abprs]-` plus 10+ chars
///
/// Patterns are unwrapped because they are crate-internal literals that
/// have been compile-tested.
pub fn default_patterns() -> Vec<Pattern> {
    vec![
        Pattern::new("anthropic_key", r"sk-ant-api\d{2}-[A-Za-z0-9_\-]{40,}")
            .expect("anthropic_key pattern compiles"),
        Pattern::new("openai_key", r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")
            .expect("openai_key pattern compiles"),
        Pattern::new("google_api_key", r"AIza[0-9A-Za-z_\-]{35}")
            .expect("google_api_key pattern compiles"),
        Pattern::new("stripe_key", r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}")
            .expect("stripe_key pattern compiles"),
        Pattern::new("github_token", r"gh[pousr]_[A-Za-z0-9]{20,}")
            .expect("github_token pattern compiles"),
        Pattern::new("aws_access_key_id", r"(?:AKIA|ASIA)[0-9A-Z]{16}")
            .expect("aws_access_key_id pattern compiles"),
        Pattern::new(
            "jwt",
            r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}",
        )
        .expect("jwt pattern compiles"),
        Pattern::new("bearer", r"(?i)Bearer\s+[A-Za-z0-9_\-.=]{20,}")
            .expect("bearer pattern compiles"),
        Pattern::new("slack_token", r"xox[abprs]-[A-Za-z0-9-]{10,}")
            .expect("slack_token pattern compiles"),
    ]
}

/// Lazily-built shared default patterns.
///
/// Use [`default_patterns`] when you want an owned `Vec<Pattern>` you can
/// modify. This static is exposed so docs and tests can refer to a single
/// canonical list without recompiling the regexes on every access.
pub static DEFAULT_PATTERNS: std::sync::LazyLock<Vec<Pattern>> =
    std::sync::LazyLock::new(default_patterns);

/// Field-name list. A value stored under any of these keys is redacted
/// in full (regardless of whether it matches a pattern), provided the
/// value is a non-empty string.
///
/// Key comparison is case-insensitive.
pub const SECRET_KEY_NAMES: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "bearer_token",
    "private_key",
    "client_secret",
    "aws_secret_access_key",
    "secret_access_key",
    "x-api-key",
    "authorization",
];
