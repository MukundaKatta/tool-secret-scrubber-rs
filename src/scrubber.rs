//! Walk a JSON value and replace secret-y substrings.
//!
//! See [`Scrubber`] for the main entrypoint and the top-level [`scrub`]
//! convenience function in the crate root.
//!
//! [`scrub`]: crate::scrub

use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::pattern::{default_patterns, Pattern, SECRET_KEY_NAMES};
use crate::report::ScrubReport;

/// Default placeholder template. `{name}` is replaced with the pattern
/// name or the lowercased key name (prefixed with `key_name:`-style logic
/// elided in the visible placeholder, so a `password` field becomes
/// `[REDACTED:password]`).
const DEFAULT_PLACEHOLDER: &str = "[REDACTED:{name}]";

/// Configurable secret scrubber.
///
/// Build one with [`Scrubber::default`] for the bundled patterns and key
/// names, or use [`Scrubber::new`] / the `with_*` builders to customise.
///
/// ```
/// use serde_json::json;
/// use tool_secret_scrubber::Scrubber;
///
/// let s = Scrubber::default();
/// let out = s.scrub(json!({"password": "hunter2"}));
/// assert_eq!(out["password"], "[REDACTED:password]");
/// ```
pub struct Scrubber {
    patterns: Vec<Pattern>,
    secret_keys: HashSet<String>,
    placeholder: String,
}

impl Default for Scrubber {
    fn default() -> Self {
        Self::new()
    }
}

impl Scrubber {
    /// Construct with the bundled defaults: [`default_patterns`] and
    /// [`SECRET_KEY_NAMES`].
    ///
    /// [`default_patterns`]: crate::pattern::default_patterns
    /// [`SECRET_KEY_NAMES`]: crate::SECRET_KEY_NAMES
    pub fn new() -> Self {
        Self {
            patterns: default_patterns(),
            secret_keys: SECRET_KEY_NAMES.iter().map(|k| k.to_lowercase()).collect(),
            placeholder: DEFAULT_PLACEHOLDER.to_string(),
        }
    }

    /// Replace the pattern list. Useful for extending the defaults:
    ///
    /// ```
    /// use tool_secret_scrubber::{default_patterns, Pattern, Scrubber};
    ///
    /// let mut patterns = default_patterns();
    /// patterns.push(Pattern::new("internal", r"INTL-[A-Z0-9]{6}").unwrap());
    /// let _ = Scrubber::new().with_patterns(patterns);
    /// ```
    pub fn with_patterns(mut self, patterns: Vec<Pattern>) -> Self {
        self.patterns = patterns;
        self
    }

    /// Replace the sensitive-field-name list. Comparison is
    /// case-insensitive; the entries are lowercased on assignment.
    pub fn with_secret_keys<I, S>(mut self, keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.secret_keys = keys
            .into_iter()
            .map(|s| s.as_ref().to_lowercase())
            .collect();
        self
    }

    /// Replace the placeholder template. Occurrences of `{name}` are
    /// substituted with the pattern (or key) name at scrub time.
    pub fn with_placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.placeholder = placeholder.into();
        self
    }

    /// Scrub a value and discard the report.
    ///
    /// The input is consumed and a freshly-built value is returned;
    /// callers can re-clone the input first if they need to keep it.
    pub fn scrub(&self, value: Value) -> Value {
        let mut report = ScrubReport::default();
        self.walk(value, None, &mut report)
    }

    /// Scrub a value and return `(scrubbed, report)`.
    pub fn scrub_with_report(&self, value: Value) -> (Value, ScrubReport) {
        let mut report = ScrubReport::default();
        let out = self.walk(value, None, &mut report);
        (out, report)
    }

    // ---- internals -------------------------------------------------------

    fn walk(&self, value: Value, parent_key: Option<&str>, report: &mut ScrubReport) -> Value {
        match value {
            Value::Object(map) => {
                let mut out = Map::with_capacity(map.len());
                for (k, v) in map {
                    let scrubbed = self.walk(v, Some(&k), report);
                    out.insert(k, scrubbed);
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(
                items
                    .into_iter()
                    .map(|v| self.walk(v, parent_key, report))
                    .collect(),
            ),
            Value::String(s) => Value::String(self.scrub_str(&s, parent_key, report)),
            // numbers / bool / null pass through
            other => other,
        }
    }

    fn scrub_str(&self, s: &str, parent_key: Option<&str>, report: &mut ScrubReport) -> String {
        // Whole-value redaction if the surrounding key name is sensitive.
        if let Some(key) = parent_key {
            let lower = key.to_lowercase();
            if self.secret_keys.contains(&lower) {
                if s.is_empty() {
                    return String::new();
                }
                report.bump(&format!("key_name:{lower}"));
                return self.format_placeholder(&lower);
            }
        }

        let mut out = s.to_string();
        for p in &self.patterns {
            // Build the replacement string once per pattern; each match
            // bumps the report counter.
            //
            // We can't use `Regex::replace_all` with a closure that
            // captures `report` mutably *and* uses its return value
            // because the closure signature is `FnMut(&Captures) -> String`
            // — that's fine for `&mut` capture. But the borrow checker
            // wants the closure not to borrow `out` while we read from it.
            // Easiest: collect match ranges first, then rebuild the string.
            let matches: Vec<(usize, usize)> = p
                .regex
                .find_iter(&out)
                .map(|m| (m.start(), m.end()))
                .collect();
            if matches.is_empty() {
                continue;
            }
            let replacement = self.format_placeholder(&p.name);
            let mut rebuilt = String::with_capacity(out.len());
            let mut last_end = 0usize;
            for (start, end) in &matches {
                rebuilt.push_str(&out[last_end..*start]);
                rebuilt.push_str(&replacement);
                last_end = *end;
                report.bump(&p.name);
            }
            rebuilt.push_str(&out[last_end..]);
            out = rebuilt;
        }
        out
    }

    fn format_placeholder(&self, name: &str) -> String {
        self.placeholder.replace("{name}", name)
    }
}
