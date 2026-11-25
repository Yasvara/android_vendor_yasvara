// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust FIPS-180-4 SHA-256, IEEE 802.3 CRC32, hex codecs, and optional
//! platform C verifier hook (BoringSSL RSA-2048/4096 PKCS#1v1.5 / PSS on Android).

use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicPtr, Ordering};

/// Optional platform hardware-accelerated SHA-256 callbacks (BoringSSL ARMv8 `sha256-ce` on Android).
pub type PlatformSha256OneshotFn =
    unsafe extern "C" fn(data: *const u8, len: usize, out32: *mut u8);
pub type PlatformSha256InitFn = unsafe extern "C" fn(ctx_buf: *mut c_void);
pub type PlatformSha256UpdateFn =
    unsafe extern "C" fn(ctx_buf: *mut c_void, data: *const u8, len: usize);
pub type PlatformSha256FinalFn = unsafe extern "C" fn(ctx_buf: *mut c_void, out32: *mut u8);

static PLATFORM_SHA256_ONESHOT: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static PLATFORM_SHA256_INIT: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static PLATFORM_SHA256_UPDATE: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static PLATFORM_SHA256_FINAL: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

/// Register hardware-accelerated SHA-256 hooks (BoringSSL `SHA256*` backed by ARMv8 Crypto Extensions).
pub fn register_platform_sha256(
    oneshot: PlatformSha256OneshotFn,
    init: PlatformSha256InitFn,
    update: PlatformSha256UpdateFn,
    final_fn: PlatformSha256FinalFn,
) {
    PLATFORM_SHA256_ONESHOT.store(oneshot as *mut (), Ordering::Release);
    PLATFORM_SHA256_INIT.store(init as *mut (), Ordering::Release);
    PLATFORM_SHA256_UPDATE.store(update as *mut (), Ordering::Release);
    PLATFORM_SHA256_FINAL.store(final_fn as *mut (), Ordering::Release);
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Streaming FIPS-180-4 SHA-256 hasher (automatically accelerates via BoringSSL `sha256-ce`
/// on Android when platform hooks are registered; pure-Rust fallback with zero external crates!).
#[derive(Clone)]
pub struct Sha256 {
    hw_ctx: Option<[u64; 32]>,
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        let init_ptr = PLATFORM_SHA256_INIT.load(Ordering::Acquire);
        let upd_ptr = PLATFORM_SHA256_UPDATE.load(Ordering::Acquire);
        let fin_ptr = PLATFORM_SHA256_FINAL.load(Ordering::Acquire);
        let hw_ctx = if !init_ptr.is_null() && !upd_ptr.is_null() && !fin_ptr.is_null() {
            let mut ctx = [0u64; 32];
            // SAFETY: `init_ptr` was registered via `register_platform_sha256` and `ctx` is a
            // 256-byte 8-byte-aligned buffer checked by static_assert(sizeof(SHA256_CTX) <= 256).
            let init_fn: PlatformSha256InitFn = unsafe { std::mem::transmute(init_ptr) };
            unsafe { init_fn(ctx.as_mut_ptr() as *mut c_void) };
            Some(ctx)
        } else {
            None
        };
        Self {
            hw_ctx,
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    #[inline]
    fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
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
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if let Some(ref mut ctx) = self.hw_ctx {
            if !data.is_empty() {
                let upd_ptr = PLATFORM_SHA256_UPDATE.load(Ordering::Acquire);
                // SAFETY: `upd_ptr` was validated non-null in `Sha256::new()`.
                let upd_fn: PlatformSha256UpdateFn = unsafe { std::mem::transmute(upd_ptr) };
                unsafe { upd_fn(ctx.as_mut_ptr() as *mut c_void, data.as_ptr(), data.len()) };
            }
            return;
        }
        self.total_len += data.len() as u64;
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let blk = self.buf;
                Self::compress(&mut self.state, &blk);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let blk: [u8; 64] = data[..64].try_into().unwrap();
            Self::compress(&mut self.state, &blk);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Feed `len` zero bytes without allocating a large buffer.
    pub fn update_zeros(&mut self, mut len: u64) {
        const ZERO_CHUNK: [u8; 4096] = [0u8; 4096];
        while len > 0 {
            let take = (len as usize).min(ZERO_CHUNK.len());
            self.update(&ZERO_CHUNK[..take]);
            len -= take as u64;
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        if let Some(mut ctx) = self.hw_ctx {
            let fin_ptr = PLATFORM_SHA256_FINAL.load(Ordering::Acquire);
            let mut out = [0u8; 32];
            // SAFETY: `fin_ptr` was validated non-null in `Sha256::new()`.
            let fin_fn: PlatformSha256FinalFn = unsafe { std::mem::transmute(fin_ptr) };
            unsafe { fin_fn(ctx.as_mut_ptr() as *mut c_void, out.as_mut_ptr()) };
            return out;
        }
        let bit_len = self.total_len.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 56 {
            for b in &mut self.buf[self.buf_len..64] {
                *b = 0;
            }
            let blk = self.buf;
            Self::compress(&mut self.state, &blk);
            self.buf_len = 0;
        }
        for b in &mut self.buf[self.buf_len..56] {
            *b = 0;
        }
        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let blk = self.buf;
        Self::compress(&mut self.state, &blk);
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    pub fn finalize_hex(self) -> String {
        hex_encode(&self.finalize())
    }
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let ptr = PLATFORM_SHA256_ONESHOT.load(Ordering::Acquire);
    if !ptr.is_null() {
        let mut out = [0u8; 32];
        // SAFETY: `ptr` was stored from a valid `PlatformSha256OneshotFn`.
        let f: PlatformSha256OneshotFn = unsafe { std::mem::transmute(ptr) };
        unsafe { f(data.as_ptr(), data.len(), out.as_mut_ptr()) };
        return out;
    }
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

pub fn sha256_prefix16(data: &[u8]) -> [u8; 16] {
    let full = sha256_bytes(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let mut f = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize_hex())
}

pub fn sha256_reader_exact(r: &mut impl Read, mut len: u64) -> Result<[u8; 32], String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    while len > 0 {
        let take = (len as usize).min(buf.len());
        r.read_exact(&mut buf[..take])
            .map_err(|e| format!("read_exact ({take} B): {e}"))?;
        h.update(&buf[..take]);
        len -= take as u64;
    }
    Ok(h.finalize())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    let b = hex.trim().as_bytes();
    if b.len() % 2 != 0 {
        return Err(format!("odd hex length: {}", b.len()));
    }
    let val = |c: u8| -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("invalid hex char: 0x{c:02x}")),
        }
    };
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks_exact(2) {
        out.push((val(pair[0])? << 4) | val(pair[1])?);
    }
    Ok(out)
}

/// IEEE 802.3 CRC32 (matches zlib/PNG/Ethernet) for compact POD headers.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320u32 & mask);
        }
    }
    !crc
}

/// C callback type for platform RSA-2048/4096 OTA payload metadata verification
/// (implemented in `boot_control_shim.cpp` via BoringSSL against `/system/etc/security/otacerts.zip`).
/// Returns `1` on valid signature, `0` on invalid signature, `< 0` on error.
pub type PlatformRsaVerifyFn = unsafe extern "C" fn(
    digest_ptr: *const u8,
    digest_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
    otacerts_path: *const u8,
    otacerts_path_len: usize,
) -> i32;

static PLATFORM_RSA_VERIFY: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

/// Register the BoringSSL signature verification callback from C++ (`pasangd`).
pub fn register_platform_rsa_verifier(func: PlatformRsaVerifyFn) {
    PLATFORM_RSA_VERIFY.store(func as *mut (), Ordering::Release);
}

/// Verify a payload metadata SHA-256 digest against one or more candidate RSA signatures.
pub fn verify_metadata_signatures(
    digest: &[u8; 32],
    signatures: &[Vec<u8>],
    otacerts_path: &Path,
    allow_dev_key: bool,
) -> Result<bool, String> {
    let ptr = PLATFORM_RSA_VERIFY.load(Ordering::Acquire);
    if ptr.is_null() {
        if allow_dev_key {
            return Ok(false);
        }
        return Err(
            "No platform RSA verifier registered (pass allow_dev_key=true on dev host/userdebug)"
                .into(),
        );
    }
    if signatures.is_empty() {
        if allow_dev_key {
            return Ok(false);
        }
        return Err("Payload contains no metadata signatures".into());
    }
    // SAFETY: `ptr` was stored from a valid `PlatformRsaVerifyFn` via `register_platform_rsa_verifier`.
    let verify_fn: PlatformRsaVerifyFn = unsafe { std::mem::transmute(ptr) };
    let cert_bytes = otacerts_path.to_string_lossy();
    let cb = cert_bytes.as_bytes();
    for sig in signatures {
        // SAFETY: all slices are valid for the duration of the FFI call.
        let rc = unsafe {
            verify_fn(
                digest.as_ptr(),
                digest.len(),
                sig.as_ptr(),
                sig.len(),
                cb.as_ptr(),
                cb.len(),
            )
        };
        if rc == 1 {
            return Ok(true);
        }
    }
    if allow_dev_key {
        Ok(false)
    } else {
        Err(format!(
            "OTA metadata signature verification failed against {}",
            otacerts_path.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_nist_vectors() {
        assert_eq!(
            hex_encode(&sha256_bytes(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_encode(&sha256_bytes(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex_encode(&sha256_bytes(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn test_sha256_zeros_and_crc32() {
        let mut h = Sha256::new();
        h.update_zeros(8192);
        assert_eq!(h.finalize(), sha256_bytes(&vec![0u8; 8192]));
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_hex_roundtrip() {
        let orig = [0x00u8, 0x0f, 0xa5, 0xff, 0x42];
        let enc = hex_encode(&orig);
        assert_eq!(enc, "000fa5ff42");
        assert_eq!(hex_decode(&enc).unwrap(), orig);
    }
}
