//! Byte sources for overwrite passes: either the OS CSPRNG or a user-supplied
//! file read in a streaming, wrap-around fashion.

use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Produces bytes to fill overwrite buffers.
pub enum ByteSource {
    /// Cryptographically secure OS RNG.
    Csprng,
    /// A file read repeatedly (wrapping) to cover files of any size.
    SourceFile {
        path: PathBuf,
        data: Vec<u8>,
        pos: usize,
    },
}

impl ByteSource {
    /// CSPRNG-backed source (the default).
    pub fn csprng() -> Self {
        ByteSource::Csprng
    }

    /// Build a source that repeats the bytes of `path`. The file is loaded
    /// once; reads wrap around when the end is reached. An empty source file
    /// is rejected (there would be nothing to write).
    pub fn from_file(path: &Path) -> io::Result<Self> {
        let mut data = Vec::new();
        File::open(path)?.read_to_end(&mut data)?;
        if data.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("source file '{}' is empty", path.display()),
            ));
        }
        Ok(ByteSource::SourceFile {
            path: path.to_path_buf(),
            data,
            pos: 0,
        })
    }

    /// Fill `buf` with bytes from this source.
    pub fn fill(&mut self, buf: &mut [u8]) {
        match self {
            ByteSource::Csprng => {
                // OsRng draws directly from the OS CSPRNG (getrandom).
                OsRng.fill_bytes(buf);
            }
            ByteSource::SourceFile { data, pos, .. } => {
                let mut written = 0;
                while written < buf.len() {
                    if *pos >= data.len() {
                        *pos = 0;
                    }
                    let take = (buf.len() - written).min(data.len() - *pos);
                    buf[written..written + take].copy_from_slice(&data[*pos..*pos + take]);
                    written += take;
                    *pos += take;
                }
            }
        }
    }

    /// Is this a deterministic (non-random) source?
    pub fn is_file(&self) -> bool {
        matches!(self, ByteSource::SourceFile { .. })
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
}
