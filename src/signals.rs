//! Global interrupt state and signal handling.
//!
//! First SIGINT/SIGTERM: request a graceful stop. Long-running write loops
//! poll [`interrupted`] between chunks/passes, finish the current write
//! safely, and then move on to rename+delete so the target is still destroyed.
//!
//! Second SIGINT/SIGTERM: force immediate termination from within the signal
//! handler using `_exit`, which is async-signal-safe.

use std::sync::atomic::{AtomicUsize, Ordering};

static INTERRUPT_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Install handlers for SIGINT and SIGTERM. Safe to call once at startup.
pub fn install() {
    // SAFETY: the registered handler only performs async-signal-safe work
    // (an atomic fetch_add and, on the second signal, libc::_exit).
    unsafe {
        let _ = signal_hook::low_level::register(signal_hook::consts::SIGINT, on_signal);
        let _ = signal_hook::low_level::register(signal_hook::consts::SIGTERM, on_signal);
    }
}

fn on_signal() {
    let prev = INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);
    if prev >= 1 {
        // Second (or later) signal: force immediate exit. 130 = 128 + SIGINT.
        // _exit is async-signal-safe (unlike std::process::exit).
        unsafe { libc::_exit(130) };
    }
}

/// True once at least one interrupt has been received.
pub fn interrupted() -> bool {
    INTERRUPT_COUNT.load(Ordering::SeqCst) >= 1
}

/// Test-only helper to reset state between unit tests.
#[cfg(test)]
pub fn reset_for_test() {
    INTERRUPT_COUNT.store(0, Ordering::SeqCst);
}

/// Test-only helper to simulate a first interrupt.
#[cfg(test)]
pub fn raise_for_test() {
    INTERRUPT_COUNT.fetch_add(1, Ordering::SeqCst);
}
