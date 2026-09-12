//! The small set of primitives the agent needs, implemented from their
//! specifications so the workspace stays dependency-free.
//!
//! | primitive        | spec        | used by                                  |
//! |------------------|-------------|------------------------------------------|
//! | SHA-256          | FIPS 180-4  | request-token HMAC, SCRAM, key ids       |
//! | SHA-1            | FIPS 180-4  | WebSocket `Sec-WebSocket-Accept` only    |
//! | MD5              | RFC 1321    | PostgreSQL legacy `md5` auth only        |
//! | HMAC             | RFC 2104    | tokens, SCRAM                            |
//! | PBKDF2           | RFC 8018    | SCRAM-SHA-256                            |
//! | Base64 / Base64url | RFC 4648  | tokens, WebSocket, SCRAM                 |
//!
//! SHA-1 and MD5 appear ONLY where a wire protocol mandates them. Neither is
//! used for anything security-bearing in ServerOS; see `docs/SECURITY.md`.

#![forbid(unsafe_code)]

pub mod base64;
pub mod md5;
pub mod sha1;
pub mod sha256;

pub use base64::{b64_decode, b64_encode, b64url_decode, b64url_encode};
pub use md5::md5;
pub use sha1::sha1;
pub use sha256::{Sha256, sha256};

use std::io::Read;

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner = inner.finish();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner);
    outer.finish()
}

/// PBKDF2-HMAC-SHA256 (RFC 8018) producing exactly 32 bytes, which is all
/// SCRAM-SHA-256 needs.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut salted = Vec::with_capacity(salt.len() + 4);
    salted.extend_from_slice(salt);
    salted.extend_from_slice(&1u32.to_be_bytes()); // block index 1

    let mut u = hmac_sha256(password, &salted);
    let mut out = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for i in 0..32 {
            out[i] ^= u[i];
        }
    }
    out
}

/// Compare two byte strings without leaking their contents through timing.
///
/// Length is not secret here (token lengths are fixed by construction), but an
/// early return on the first differing byte would be.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Cryptographically secure random bytes from the kernel.
///
/// `/dev/urandom` is the right source on Linux: after the pool is initialised
/// (guaranteed long before a service starts) it is identical to `getrandom(2)`
/// without the syscall-availability dance.
pub fn random_bytes(len: usize) -> std::io::Result<Vec<u8>> {
    let mut f = std::fs::File::open("/dev/urandom")?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// Lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
