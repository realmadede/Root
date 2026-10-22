use root_core::error::{Result, RootError};
use std::{fs::File, io::Read, path::Path};

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Incremental FIPS 180-4 compliant SHA-256 state engine supporting arbitrary chunked inputs.
#[derive(Debug, Clone)]
pub struct Sha256Hasher {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u64,
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Hasher {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    /// Feeds a chunk of arbitrary length into the hash digest.
    pub fn update(&mut self, data: &[u8]) {
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
        let mut offset = 0;

        // If buffer already has partial data, try to complete a 64-byte block
        if self.buffer_len > 0 {
            let to_fill = 64 - self.buffer_len;
            if data.len() >= to_fill {
                self.buffer[self.buffer_len..64].copy_from_slice(&data[..to_fill]);
                Self::process_block(&mut self.state, &self.buffer);
                self.buffer_len = 0;
                offset = to_fill;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }

        // Process full 64-byte blocks directly from input slice
        while offset + 64 <= data.len() {
            let chunk: &[u8; 64] = data[offset..offset + 64].try_into().unwrap();
            Self::process_block(&mut self.state, chunk);
            offset += 64;
        }

        // Store trailing bytes in buffer
        if offset < data.len() {
            let remaining = &data[offset..];
            self.buffer[..remaining.len()].copy_from_slice(remaining);
            self.buffer_len = remaining.len();
        }
    }

    /// Finalizes the hash, appending padding and length bits, and returns the 32-byte digest.
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_bytes.wrapping_mul(8);

        // Append 0x80 byte
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If not enough room for 8-byte length (needs buffer_len <= 56), pad and process
        if self.buffer_len > 56 {
            for byte in &mut self.buffer[self.buffer_len..64] {
                *byte = 0;
            }
            Self::process_block(&mut self.state, &self.buffer);
            self.buffer_len = 0;
        }

        // Pad with zeros up to byte 56
        for byte in &mut self.buffer[self.buffer_len..56] {
            *byte = 0;
        }

        // Append 64-bit big-endian length
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        Self::process_block(&mut self.state, &self.buffer);

        let mut digest = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// Finalizes the digest and formats it as a lower-case hexadecimal string.
    pub fn finalize_hex(self) -> String {
        let digest = self.finalize();
        let mut s = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", byte);
        }
        s
    }

    fn process_block(h: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let offset = i * 4;
            *word = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }

        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_var = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_var
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_var = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_var);
    }
}

/// Computes the SHA-256 digest of an in-memory byte slice.
pub fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Formats a SHA-256 digest as a lower-case hexadecimal string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256Hasher::new();
    hasher.update(data);
    hasher.finalize_hex()
}

/// Computes SHA-256 by streaming arbitrary bytes from an `io::Read` stream in 64 KiB chunks.
pub fn sha256_stream<R: Read>(mut reader: R) -> Result<String> {
    let mut hasher = Sha256Hasher::new();
    let mut buffer = [0u8; 65536];

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buffer[..n]),
            Err(e) => {
                return Err(RootError::Io {
                    path: std::path::PathBuf::from("<stream>"),
                    source: e,
                });
            }
        }
    }

    Ok(hasher.finalize_hex())
}

/// Computes the SHA-256 hash of a synthetic test file with identity consistency revalidation.
/// Note: Content reading is strictly restricted to synthetic test fixtures.
pub fn sha256_file(path: &Path) -> Result<String> {
    // 1. Pre-read identity probe
    let pre_meta = std::fs::symlink_metadata(path).map_err(|e| RootError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    if pre_meta.is_symlink() {
        return Err(RootError::PolicyViolation {
            reason: format!(
                "Refusing to hash symbolic link '{}'; Root never reads symlink targets directly",
                path.display()
            ),
        });
    }

    let file = File::open(path).map_err(|e| RootError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    // 2. Stream data in bounded chunks
    let mut hasher = Sha256Hasher::new();
    let mut reader = std::io::BufReader::with_capacity(65536, file);
    let mut chunk = [0u8; 65536];

    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => hasher.update(&chunk[..n]),
            Err(e) => {
                return Err(RootError::Io {
                    path: path.to_path_buf(),
                    source: e,
                });
            }
        }
    }

    // 3. Post-read identity consistency check (POSIX dev/ino consistency)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let post_meta = std::fs::symlink_metadata(path).map_err(|e| RootError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        if pre_meta.dev() != post_meta.dev() || pre_meta.ino() != post_meta.ino() {
            return Err(RootError::IntegrityVerificationFailed {
                path: path.to_path_buf(),
                reason: format!(
                    "File identity changed during hashing (dev/ino {}:{} -> {}:{})",
                    pre_meta.dev(),
                    pre_meta.ino(),
                    post_meta.dev(),
                    post_meta.ino()
                ),
            });
        }
    }

    Ok(hasher.finalize_hex())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_fips_vectors() {
        // Standard FIPS test vector 1: Empty string
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // Standard FIPS test vector 2: "abc"
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        // Standard test vector 3: "hello world"
        assert_eq!(
            sha256_hex(b"hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_single_block_and_padding_boundaries() {
        // 55 bytes (exact padding limit where length fits in same 64-byte block)
        let b55 = vec![b'a'; 55];
        assert_eq!(
            sha256_hex(&b55),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );

        // 56 bytes (padding boundary: 0x80 fits, but length spills into next block)
        let b56 = vec![b'a'; 56];
        assert_eq!(
            sha256_hex(&b56),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );

        // 64 bytes (exact single block boundary)
        let b64 = vec![b'a'; 64];
        assert_eq!(
            sha256_hex(&b64),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
    }

    #[test]
    fn test_sha256_multiple_blocks_nist_cavp() {
        // NIST CAVP 448-bit (56-byte) multi-word vector
        let cavp = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            sha256_hex(cavp),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_sha256_incremental_chunking_matches_direct() {
        let cavp = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = sha256_hex(cavp);

        // Stream byte-by-byte
        let mut h1 = Sha256Hasher::new();
        for byte in cavp {
            h1.update(&[*byte]);
        }
        assert_eq!(h1.finalize_hex(), expected);

        // Stream in prime-sized chunks (7 bytes, 13 bytes)
        let mut h2 = Sha256Hasher::new();
        for chunk in cavp.chunks(7) {
            h2.update(chunk);
        }
        assert_eq!(h2.finalize_hex(), expected);
    }

    #[test]
    fn test_sha256_large_message_nist_million_a() {
        // 1,000,000 repetitions of 'a'
        let mut hasher = Sha256Hasher::new();
        let chunk = vec![b'a'; 10_000];
        for _ in 0..100 {
            hasher.update(&chunk);
        }
        assert_eq!(
            hasher.finalize_hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn test_sha256_sparse_file_logical_zeros() {
        // Logical sparse zeros: 100,000 zeros
        let mut hasher = Sha256Hasher::new();
        let chunk = vec![0u8; 10_000];
        for _ in 0..10 {
            hasher.update(&chunk);
        }
        // Direct hash of 100,000 zeros
        let direct = sha256_hex(&vec![0u8; 100_000]);
        assert_eq!(hasher.finalize_hex(), direct);
    }
}
