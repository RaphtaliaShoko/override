//! Byte sources for overwrite passes: either the OS CSPRNG or a user-supplied
//! file streamed, in a wrap-around fashion, with bounded memory.

use crate::CHUNK;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// Produces bytes to fill overwrite buffers.
pub enum ByteSource {
    /// Cryptographically secure OS RNG.
    Csprng,
    /// A file read repeatedly (wrapping) to cover files of any size.
    SourceFile(SourceFile),
}

/// A user-supplied source file, streamed with **bounded memory**.
///
/// The file is read one window (up to [`CHUNK`] bytes) at a time; when the end
/// is reached the read position wraps back to the start (`seek`). This fixes the
/// audit's M-1: the previous implementation slurped the entire source into a
/// `Vec` up front, so a huge file — or worse, an endless character device such
/// as `/dev/urandom` (a documented example) — grew memory without bound until
/// the process was OOM-killed and the target was left intact.
///
/// Two behaviors fall out of streaming:
///   * memory stays bounded by one window regardless of source size, and
///   * an endless, non-seekable source like `/dev/urandom` never hits EOF, so it
///     is simply read forever (fresh bytes per window) rather than buffered.
///
/// A small source that fits within one window is cached and then cycled purely
/// in memory, so tiny sources don't degenerate into a per-byte syscall storm.
pub struct SourceFile {
    file: File,
    /// The current window of source bytes (`buf[pos..len]` are unconsumed).
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    /// The whole file fit in one window; cycle `buf[0..len]` in memory.
    cached: bool,
    /// The source can no longer yield bytes (vanished/emptied mid-run); the
    /// remainder of each fill is then drawn from the CSPRNG so the overwrite
    /// pass still completes with unpredictable bytes rather than stalling.
    exhausted: bool,
}

impl SourceFile {
    fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let mut sf = SourceFile {
            file,
            buf: vec![0u8; CHUNK],
            pos: 0,
            len: 0,
            cached: false,
            exhausted: false,
        };
        // Prime the first window (from offset 0) and reject an empty regular
        // file up front — there would be nothing to write.
        sf.refill()?;
        if sf.len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("source file '{}' is empty", path.display()),
            ));
        }
        // If the first window did not fill the buffer, EOF was reached, so the
        // whole file is now in `buf` and we can cycle it in memory. Otherwise the
        // file is at least one window long: keep streaming it.
        sf.cached = sf.len < sf.buf.len();
        Ok(sf)
    }

    /// Read one window (up to `buf.len()` bytes) from the current file position
    /// into `buf`, resetting `pos`/`len`. Stops at a full buffer or EOF.
    fn refill(&mut self) -> io::Result<()> {
        self.pos = 0;
        self.len = 0;
        while self.len < self.buf.len() {
            match self.file.read(&mut self.buf[self.len..]) {
                Ok(0) => break, // EOF for this window
                Ok(n) => self.len += n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Ensure at least one unconsumed byte is available at `buf[pos]`, refilling
    /// or wrapping as needed. Marks the source `exhausted` if it can yield
    /// nothing even after wrapping to the start.
    fn ensure_available(&mut self) {
        if self.exhausted || self.pos < self.len {
            return;
        }
        if self.cached {
            // Whole file lives in `buf`; cycle it without touching the disk.
            self.pos = 0;
            return;
        }
        // Read the next window; on EOF, wrap to the start and read once more.
        if self.refill().is_err() {
            self.exhausted = true;
            return;
        }
        if self.len == 0 {
            if self.file.seek(SeekFrom::Start(0)).is_err() || self.refill().is_err() {
                self.exhausted = true;
                return;
            }
            if self.len == 0 {
                // Source became empty mid-run; stop relying on it.
                self.exhausted = true;
            }
        }
    }

    /// Fill `dest` with source bytes, streaming/wrapping as required.
    fn fill(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        while written < dest.len() {
            self.ensure_available();
            if self.exhausted {
                // The source dried up; complete the pass with CSPRNG bytes so a
                // rare mid-run source failure never leaves a chunk unwritten.
                OsRng.fill_bytes(&mut dest[written..]);
                return;
            }
            let take = (dest.len() - written).min(self.len - self.pos);
            dest[written..written + take].copy_from_slice(&self.buf[self.pos..self.pos + take]);
            self.pos += take;
            written += take;
        }
    }
}

impl ByteSource {
    /// CSPRNG-backed source (the default).
    pub fn csprng() -> Self {
        ByteSource::Csprng
    }

    /// Build a source that repeats the bytes of `path`, streamed with bounded
    /// memory (see [`SourceFile`]). An empty source file is rejected.
    pub fn from_file(path: &Path) -> io::Result<Self> {
        Ok(ByteSource::SourceFile(SourceFile::open(path)?))
    }

    /// Fill `buf` with bytes from this source.
    pub fn fill(&mut self, buf: &mut [u8]) {
        match self {
            ByteSource::Csprng => {
                // OsRng draws directly from the OS CSPRNG (getrandom).
                OsRng.fill_bytes(buf);
            }
            ByteSource::SourceFile(sf) => sf.fill(buf),
        }
    }

    /// Is this a deterministic (non-random) source?
    pub fn is_file(&self) -> bool {
        matches!(self, ByteSource::SourceFile(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn source_file_wraps_around() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"ABC").unwrap();
        tmp.flush().unwrap();

        let mut src = ByteSource::from_file(tmp.path()).unwrap();
        let mut buf = [0u8; 7];
        src.fill(&mut buf);
        // "ABC" repeated: A B C A B C A
        assert_eq!(&buf, b"ABCABCA");

        // Continues from where it left off (pos = 1 -> 'B').
        let mut buf2 = [0u8; 2];
        src.fill(&mut buf2);
        assert_eq!(&buf2, b"BC");
    }

    #[test]
    fn empty_source_file_rejected() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        assert!(ByteSource::from_file(tmp.path()).is_err());
    }

    #[test]
    fn csprng_fills_buffer() {
        let mut src = ByteSource::csprng();
        let mut buf = [0u8; 64];
        src.fill(&mut buf);
        // Astronomically unlikely to be all zeros.
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn source_larger_than_window_streams_and_wraps() {
        // A source strictly larger than one internal window (CHUNK) exercises the
        // streaming path (not the in-memory cache) and the seek-based wrap, with
        // memory bounded to one window regardless of how much is drawn.
        let size = CHUNK + 100;
        let content: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&content).unwrap();
        tmp.flush().unwrap();

        let mut src = ByteSource::from_file(tmp.path()).unwrap();

        // Draw more than twice the file so it must wrap around twice.
        let draw = size * 2 + 50;
        let mut out = vec![0u8; draw];
        src.fill(&mut out);

        for (i, b) in out.iter().enumerate() {
            assert_eq!(*b, content[i % size], "mismatch at offset {i}");
        }
    }

    #[test]
    fn many_small_fills_stay_consistent_across_wraps() {
        // Repeated small fills from a tiny cached source must produce the same
        // continuous wrap-around stream as one big fill would.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"xyz").unwrap();
        tmp.flush().unwrap();

        let mut src = ByteSource::from_file(tmp.path()).unwrap();
        let expected = b"xyz";
        let mut seen = Vec::new();
        for _ in 0..10 {
            let mut b = [0u8; 1];
            src.fill(&mut b);
            seen.push(b[0]);
        }
        for (i, b) in seen.iter().enumerate() {
            assert_eq!(*b, expected[i % expected.len()], "byte {i}");
        }
    }

    /// `/dev/urandom` (a documented `--source` example) must be read as a bounded
    /// stream of fresh entropy, never buffered without end (audit M-1).
    #[test]
    #[cfg(target_os = "linux")]
    fn dev_urandom_source_is_bounded_and_not_repeated() {
        let path = Path::new("/dev/urandom");
        if !path.exists() {
            return;
        }
        let mut src = ByteSource::from_file(path).unwrap();
        // Draw more than one window; this must return promptly with bounded
        // memory (the bug slurped the device into RAM until OOM).
        let mut a = vec![0u8; CHUNK + 4096];
        src.fill(&mut a);
        assert!(a.iter().any(|&b| b != 0), "should not be all zeros");
        // A second window must be fresh entropy, not a repeat of the first.
        assert_ne!(
            &a[..4096],
            &a[CHUNK..CHUNK + 4096],
            "consecutive windows should differ (fresh streaming)"
        );
    }
}
