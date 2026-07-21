//! Encryption phase: crypto-shredding.
//!
//! Each pass generates a fresh random ChaCha20-Poly1305 key, encrypts the
//! file's current bytes in place, then zeroizes the key. Once the key is gone
//! the ciphertext is cryptographically inaccessible.
//!
//! IMPORTANT scope note. The target's plaintext already exists on disk before
//! we run, so this pass only helps if writing the ciphertext back *physically
//! overwrites the plaintext blocks*. That holds on media/filesystems where a
//! logical overwrite rewrites the same physical block (ext4/xfs on
//! non-remapped storage), and there this pass is effective. It does NOT hold on
//! copy-on-write/log-structured filesystems or SSD flash-translation layers,
//! where the write can be redirected to freshly allocated blocks and the
//! original plaintext survives regardless of the discarded key. On those media
//! the in-place crypto-shred has the *same* physical limitation as the
//! overwrite passes -- it is not a substitute for physical erasure (see
//! `fswarn`, `docs/crypto.md`, `docs/filesystems.md`).
//!
//! The file is processed in fixed-size chunks so files of any size use bounded
//! memory. Each chunk is authenticated-encrypted with a per-chunk nonce; we
//! write back only the ciphertext (same length as the plaintext, since
//! ChaCha20 is a stream cipher) so the overwrite is strictly in place -- on
//! non-remapped storage the original plaintext blocks are physically rewritten
//! rather than reallocated. The 16-byte authentication tag is intentionally
//! discarded with the key, because the data is never meant to be decrypted
//! again.

use crate::signals;
use crate::CHUNK;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use zeroize::Zeroize;

/// Build a 12-byte nonce from a chunk index. Each pass uses a fresh key, so a
/// simple monotonic counter nonce is unique per (key, chunk) as required.
fn nonce_from_index(index: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&index.to_le_bytes());
    *Nonce::from_slice(&n)
}

/// Perform one in-place encryption pass over an already-open file.
///
/// The key is generated here, used, and zeroized before returning. It is never
/// returned, logged, or written anywhere.
///
/// When `verify` is set, each ciphertext chunk is read back from the file and
/// compared against what we just wrote *before* moving on. This is a
/// page-cache-level read-back (distinct from the end-of-pass `sync_all`): it
/// catches a silent short write or filesystem/logic error, so a chunk that did
/// not actually land is reported as a failure rather than being treated as a
/// completed crypto-shred. On mismatch the pass returns an error.
///
/// `on_chunk` is invoked with the number of plaintext bytes processed for each
/// chunk, so callers can drive a progress bar without this module knowing about
/// one.
pub fn encrypt_pass(
    file: &mut File,
    len: u64,
    verify: bool,
    on_chunk: &mut dyn FnMut(u64),
) -> io::Result<()> {
    // Fresh 256-bit key from the OS CSPRNG, held in a zeroizing buffer.
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| io::Error::other(format!("cipher init: {e}")))?;
    // The raw key bytes are no longer needed once the cipher holds them.
    key.zeroize();

    let mut buf = vec![0u8; CHUNK];
    // Scratch buffer used only for read-back verification; holds ciphertext
    // briefly, so it is scrubbed alongside `buf` at the end.
    let mut check = if verify { vec![0u8; CHUNK] } else { Vec::new() };
    let mut offset: u64 = 0;
    let mut index: u64 = 0;

    let result = (|| {
        while offset < len {
            let this = std::cmp::min(CHUNK as u64, len - offset) as usize;

            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut buf[..this])?;

            let nonce = nonce_from_index(index);
            // Authenticated encryption in place; the tag is dropped on purpose.
            cipher
                .encrypt_in_place_detached(&nonce, b"", &mut buf[..this])
                .map_err(|e| io::Error::other(format!("encrypt chunk: {e}")))?;

            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&buf[..this])?;

            if verify {
                // Read the bytes back and confirm the write landed intact.
                file.seek(SeekFrom::Start(offset))?;
                file.read_exact(&mut check[..this])?;
                if check[..this] != buf[..this] {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("ciphertext verification failed at offset {offset}"),
                    ));
                }
            }

            offset += this as u64;
            index += 1;
            on_chunk(this as u64);

            // A graceful interrupt lets the current (already-written) chunk
            // stand and stops the pass; the file remains fully overwritten up
            // to `offset`, and later phases still run.
            if signals::interrupted() {
                break;
            }
        }
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();

    // Best-effort scrub of any plaintext/ciphertext lingering in the buffers.
    buf.zeroize();
    check.zeroize();
    // `cipher` (holding the key) is dropped here; the chacha20poly1305 crate
    // zeroizes its internal key material on drop.
    drop(cipher);

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn encryption_preserves_length_and_changes_content() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let plaintext = vec![0xAAu8; 5000];
        tmp.write_all(&plaintext).unwrap();
        tmp.flush().unwrap();

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(tmp.path())
            .unwrap();
        encrypt_pass(&mut file, plaintext.len() as u64, true, &mut |_| {}).unwrap();

        let mut after = Vec::new();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_end(&mut after).unwrap();

        // Same length (in-place stream-cipher overwrite)...
        assert_eq!(after.len(), plaintext.len());
        // ...but the plaintext is gone.
        assert_ne!(after, plaintext);
    }

    #[test]
    fn verify_counts_every_byte_via_callback() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        // Two full chunks + a partial one, to exercise the chunk loop.
        let total = crate::CHUNK * 2 + 123;
        tmp.write_all(&vec![0x11u8; total]).unwrap();
        tmp.flush().unwrap();

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(tmp.path())
            .unwrap();

        let mut counted: u64 = 0;
        encrypt_pass(&mut file, total as u64, true, &mut |n| counted += n).unwrap();
        // The read-back verification passed (no error) and the callback saw the
        // whole file.
        assert_eq!(counted, total as u64);
    }

    #[test]
    fn zeroize_actually_scrubs_key_material() {
        // Locks the scrubbing contract we rely on in `encrypt_pass`: after
        // `.zeroize()` the buffer must be all zeros. `zeroize` performs volatile
        // writes with a compiler fence, so this is NOT elided even under the
        // release profile (`lto = true`, `opt-level = 3`) -- which is exactly
        // why the crate is used instead of a plain assignment the optimizer
        // could remove. Guards against someone silently swapping it out.
        let mut key = [0xAAu8; 32];
        assert!(key.iter().all(|&b| b == 0xAA));
        key.zeroize();
        assert!(key.iter().all(|&b| b == 0), "zeroize left non-zero bytes");
    }

    #[test]
    fn encryption_of_empty_file_is_noop() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(tmp.path())
            .unwrap();
        // Must not panic or error on a zero-length file.
        encrypt_pass(&mut file, 0, true, &mut |_| {}).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
    }
}
