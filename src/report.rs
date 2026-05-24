//! Per-scrub redaction count.
//!
//! [`ScrubReport`] is produced by [`Scrubber::scrub_with_report`] alongside
//! the scrubbed value. It carries a total count plus a per-pattern
//! breakdown so callers can feed it into a metric.
//!
//! [`Scrubber::scrub_with_report`]: crate::Scrubber::scrub_with_report

use std::collections::HashMap;

/// Count of redactions performed during one scrub call.
///
/// Field-name redactions are tracked under the key `"key_name:<lowercased
/// field name>"`. Pattern redactions are tracked under the pattern name.
#[derive(Debug, Default, Clone)]
pub struct ScrubReport {
    /// Total number of redactions (pattern hits + key-name hits).
    pub redactions: usize,
    /// Per-source breakdown of redactions.
    ///
    /// Keys are pattern names (`anthropic_key`, `bearer`, ...) or
    /// `key_name:<field>` for field-name redactions.
    pub by_pattern: HashMap<String, usize>,
}

impl ScrubReport {
    /// Increment counters for one redaction sourced from `name`.
    pub(crate) fn bump(&mut self, name: &str) {
        self.redactions += 1;
        *self.by_pattern.entry(name.to_string()).or_insert(0) += 1;
    }
}
