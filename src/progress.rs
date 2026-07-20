//! Progress reporting for long-running work.
//!
//! Wraps an optional [`indicatif::ProgressBar`]. When disabled (piped output,
//! verbose mode, `--no-stop`, or a dry run) it renders nothing, so scripts and
//! verbose logs are never polluted with control characters.
//!
//! Two shapes are offered:
//! - a **byte bar** with an ETA, for the destruction pipeline where the total
//!   amount of work is known up front (file sizes × pass count);
//! - a **byte spinner**, for free-space wiping where the total is unknown until
//!   the volume fills.

use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// A thin, always-safe-to-call progress handle.
pub struct Progress {
    bar: Option<ProgressBar>,
}

impl Progress {
    /// A determinate byte bar over `total_bytes`. If `enabled` is false the bar
    /// is hidden and every method becomes a no-op.
    pub fn bar(total_bytes: u64, enabled: bool) -> Self {
        if !enabled || total_bytes == 0 {
            return Progress { bar: None };
        }
        let bar = ProgressBar::new(total_bytes);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner} {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta}) {wide_bar}",
            )
            .unwrap_or_else(|_| ProgressStyle::default_bar()),
        );
        Progress { bar: Some(bar) }
    }

    /// An indeterminate byte spinner (used by free-space wiping). Hidden when
    /// `enabled` is false.
    pub fn spinner(message: &str, enabled: bool) -> Self {
        if !enabled {
            return Progress { bar: None };
        }
        let bar = ProgressBar::new_spinner();
        bar.set_style(
            ProgressStyle::with_template("{spinner} {msg}: {bytes} written ({bytes_per_sec})")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        bar.set_message(message.to_string());
        bar.enable_steady_tick(Duration::from_millis(120));
        Progress { bar: Some(bar) }
    }

    /// A disabled handle that never draws anything.
    pub fn hidden() -> Self {
        Progress { bar: None }
    }

    /// Advance by `n` bytes. No-op when disabled.
    pub fn inc(&self, n: u64) {
        if let Some(bar) = &self.bar {
            bar.inc(n);
        }
    }

    /// Finish and clear the bar. No-op when disabled.
    pub fn finish(&self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_progress_is_a_noop() {
        // Must not panic and must draw nothing when disabled.
        let p = Progress::bar(1000, false);
        p.inc(500);
        p.finish();

        let p = Progress::hidden();
        p.inc(1);
        p.finish();
    }

    #[test]
    fn zero_total_disables_bar() {
        // A zero-length workload should not create a live bar.
        let p = Progress::bar(0, true);
        p.inc(0);
        p.finish();
    }
}
