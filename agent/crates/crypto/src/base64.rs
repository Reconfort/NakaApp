//! Base64 and Base64url (RFC 4648).
//!
//! The URL-safe, unpadded variant is what the request tokens use, so that a
//! token is a single opaque word that survives headers, logs and query strings
//! without escaping.

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64_encode(data: &[u8]) -> String {
    encode_with(data, STD, true)
}

/// URL-safe, no `=` padding.
pub fn b64url_encode(data: &[u8]) -> String {
    encode_with(data, URL, false)
}

fn encode_with(data: &[u8], table: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(table[((n >> 18) & 63) as usize] as char);
        out.push(table[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(table[((n >> 6) & 63) as usize] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(table[(n & 63) as usize] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    decode_with(s, false)
}

/// Accepts both padded and unpadded input, and both alphabets, because tokens
/// can arrive from clients that pad.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    decode_with(s, true)
}

fn decode_with(s: &str, url: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(s.len() * 3 / 4);

    for &b in s.as_bytes() {
        if b == b'=' {
            break;
        }
        if b == b'\n' || b == b'\r' {
            continue;
        }
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' if !url => 62,
            b'/' if !url => 63,
            // Accept both alphabets when decoding url-safe input: some clients
            // helpfully "fix" the encoding for us.
            b'-' => 62,
            b'_' => 63,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;

        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }

    // Leftover bits must be zero padding, not data.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}
