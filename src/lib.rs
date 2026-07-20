//! `override` — secure file-destruction library.
//!
//! Public surface used by the `override` binary and the integration tests.
//! See the module docs and the README for the full design.

pub mod cli;
pub mod crypto;
pub mod freespace;
pub mod fswarn;
pub mod overwrite;
pub mod pipeline;
pub mod progress;
pub mod resilience;
pub mod signals;
pub mod source;

/// I/O chunk size for streaming reads/writes (1 MiB). Keeps memory bounded for
/// arbitrarily large files while remaining efficient.
pub const CHUNK: usize = 1 << 20;
