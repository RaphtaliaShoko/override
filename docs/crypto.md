# Encryption phase (crypto-shredding)

Crypto-shredding encrypts the file in place with a fresh random key, then throws
the key away, so the *ciphertext* left behind is cryptographically unrecoverable.

> **Scope — read this.** The target's plaintext already exists on disk before
> `override` runs. Encrypting it in place only helps if writing the ciphertext
> back **physically overwrites the plaintext blocks**. That holds where a
> logical overwrite rewrites the same physical block (ext4/xfs on non-remapped
> media). It does **not** hold on copy-on-write/log-structured filesystems or
> SSD flash-translation layers, where the write can be redirected to new blocks
> and the original plaintext survives regardless of the discarded key. On those
> media the in-place crypto-shred has the **same physical limitation as the
> overwrite passes** — it is one defense-in-depth layer, not a substitute for
> physical erasure. See [filesystems.md](filesystems.md).

See also: [architecture.md](architecture.md) (where this phase sits in the
pipeline), [filesystems.md](filesystems.md) (the SSD/CoW limitation),
[security.md](security.md).

---

## How it works

- Scheme: **ChaCha20-Poly1305** (AEAD) via the audited `chacha20poly1305` crate.
- Each pass generates a fresh **256-bit key** from the OS CSPRNG (`getrandom`),
  builds the cipher, and immediately zeroizes the raw key bytes.
- The file is processed in **1 MiB chunks** (bounded memory for any file size).
  Each chunk is authenticated-encrypted with a per-chunk counter nonce (unique
  per key, since every pass uses a new key).
- Because ChaCha20 is a stream cipher, the ciphertext is the **same length** as
  the plaintext, so it is written back **strictly in place** (same logical
  offsets). On non-remapped storage this rewrites the original plaintext blocks
  rather than reallocating new ones; on CoW/SSD-remapped storage the write may
  still land on new blocks (see the scope note above). The
  16-byte authentication tag is intentionally **discarded** together with the
  key (the data is never meant to be decrypted again; using an AEAD scheme still
  satisfies the "modern authenticated encryption" requirement and gives a clean,
  well-reviewed primitive).
- The key is wrapped in `zeroize::Zeroizing` / scrubbed with `.zeroize()`, and
  the working buffer is zeroized after each pass. **The key is never written to
  disk, logged, or printed — not even under `--verbose`.** `zeroize` performs
  **volatile writes with a compiler fence**, so the scrub is *not* elided even
  under the release profile (`lto = true`, `opt-level = 3`) — that is precisely
  why the crate is used instead of a plain assignment the optimizer could remove.
  A unit test (`zeroize_actually_scrubs_key_material`) locks this contract.

- **Read-back verification (default on).** After each ciphertext chunk is
  written, it is read back and compared against what was written *before* the
  loop advances. If a write silently did not land (a short write, a lying
  filesystem, or a logic error), the pass fails loudly rather than letting the
  file be treated as a completed crypto-shred. This is a page-cache-level
  read-back — distinct from, and cheaper than, the end-of-pass `fsync`. Disable it
  with `--no-verify` if you need the speed (not recommended for serious use).

Once the key is gone the ciphertext is cryptographically inaccessible. On media
where the write reached the original blocks, that is the end of the plaintext;
where it did not (CoW/SSD, per the scope note), the overwrite passes face the
identical limitation, so on such media prefer the whole-disk measures in
[filesystems.md](filesystems.md). The overwrite/rename/delete phases are
defense-in-depth against implementation slips and metadata leakage.
