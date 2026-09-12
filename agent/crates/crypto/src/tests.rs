//! Every primitive is checked against published vectors. A hand-written hash
//! that is subtly wrong is worse than no hash at all, because it fails only
//! when it meets the other side of the wire.

use super::*;

fn hex(b: &[u8]) -> String {
    hex_encode(b)
}

#[test]
fn sha256_fips_vectors() {
    assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(
        hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn sha256_million_a() {
    // The FIPS long-message vector. Also exercises the multi-block path.
    let mut h = Sha256::new();
    let chunk = vec![b'a'; 1000];
    for _ in 0..1000 {
        h.update(&chunk);
    }
    assert_eq!(hex(&h.finish()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

#[test]
fn sha256_incremental_matches_one_shot() {
    // Feed the same message in every awkward split and confirm the buffered
    // path agrees with the one-shot path.
    let msg: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
    let expected = sha256(&msg);
    for split in [1usize, 63, 64, 65, 127, 128, 129, 500] {
        let mut h = Sha256::new();
        for part in msg.chunks(split) {
            h.update(part);
        }
        assert_eq!(h.finish(), expected, "split at {split}");
    }
}

#[test]
fn sha256_block_boundary_lengths() {
    // Lengths where padding either just fits or spills into a second block.
    for len in [0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128] {
        let msg = vec![b'x'; len];
        let mut h = Sha256::new();
        h.update(&msg);
        let a = h.finish();
        let b = sha256(&msg);
        assert_eq!(a, b, "len {len}");
    }
    // Spot-check one against a known value: 56 bytes forces a second block.
    assert_eq!(
        hex(&sha256(&vec![b'a'; 56])),
        "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
    );
}

#[test]
fn sha1_vectors() {
    assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(
        hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
}

#[test]
fn sha1_drives_the_rfc6455_handshake() {
    // RFC 6455 §1.3 worked example. If this passes, the WebSocket upgrade
    // handshake is correct by construction.
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let accept = b64_encode(&sha1(format!("{key}{guid}").as_bytes()));
    assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

#[test]
fn md5_vectors() {
    assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(hex(&md5(b"message digest")), "f96b697d7cb7938d525a2f31aaf161d0");
    assert_eq!(
        hex(&md5(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
        "57edf4a22be3c955ac49da2e2107b67a"
    );
}

#[test]
fn hmac_sha256_rfc4231_vectors() {
    let k1 = [0x0bu8; 20];
    assert_eq!(
        hex(&hmac_sha256(&k1, b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    // Key longer than the 64-byte block, which exercises the key-hashing path.
    let k4 = [0xaau8; 131];
    assert_eq!(
        hex(&hmac_sha256(&k4, b"Test Using Larger Than Block-Size Key - Hash Key First")),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn pbkdf2_sha256_vectors() {
    // RFC 7914 §11 / widely published PBKDF2-HMAC-SHA256 vectors, dkLen = 32.
    assert_eq!(
        hex(&pbkdf2_hmac_sha256(b"password", b"salt", 1)),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
    assert_eq!(
        hex(&pbkdf2_hmac_sha256(b"password", b"salt", 2)),
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
    );
    assert_eq!(
        hex(&pbkdf2_hmac_sha256(b"password", b"salt", 4096)),
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
    );
}

#[test]
fn base64_rfc4648_vectors() {
    let cases = [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];
    for (plain, encoded) in cases {
        assert_eq!(b64_encode(plain.as_bytes()), encoded, "encode {plain:?}");
        assert_eq!(b64_decode(encoded).unwrap(), plain.as_bytes(), "decode {encoded:?}");
    }
}

#[test]
fn base64url_is_unpadded_and_safe() {
    // 0xFB 0xEF 0xBE contains both of the characters that differ between
    // alphabets, so this catches an accidental standard-alphabet encode.
    let data = [0xfbu8, 0xef, 0xbe];
    assert_eq!(b64_encode(&data), "++++");
    assert_eq!(b64url_encode(&data), "----");

    let data2 = [0xffu8, 0xff, 0xff];
    assert_eq!(b64url_encode(&data2), "____");

    let odd = [1u8, 2, 3, 4, 5];
    let enc = b64url_encode(&odd);
    assert!(!enc.contains('='), "url encoding must not pad: {enc}");
    assert_eq!(b64url_decode(&enc).unwrap(), odd);
}

#[test]
fn base64url_decode_accepts_padded_and_either_alphabet() {
    let data = [0xfbu8, 0xef, 0xbe, 0x01];
    let url = b64url_encode(&data);
    let std_padded = b64_encode(&data);
    assert_eq!(b64url_decode(&url).unwrap(), data);
    assert_eq!(b64url_decode(&std_padded).unwrap(), data);
}

#[test]
fn base64_rejects_garbage() {
    assert!(b64_decode("!!!!").is_none());
    assert!(b64_decode("Zm9v YmFy").is_none(), "spaces are not valid");
    // Trailing bits that are not zero indicate a corrupted token.
    assert!(b64url_decode("Zh").is_none());
}

#[test]
fn base64_round_trips_arbitrary_lengths() {
    for len in 0..200usize {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + 13) as u8).collect();
        assert_eq!(b64_decode(&b64_encode(&data)).unwrap(), data, "std len {len}");
        assert_eq!(b64url_decode(&b64url_encode(&data)).unwrap(), data, "url len {len}");
    }
}

#[test]
fn hex_round_trips() {
    let data: Vec<u8> = (0u8..=255).collect();
    assert_eq!(hex_decode(&hex_encode(&data)).unwrap(), data);
    assert_eq!(hex_decode("AABBcc").unwrap(), vec![0xaa, 0xbb, 0xcc]);
    assert!(hex_decode("abc").is_none(), "odd length");
    assert!(hex_decode("zz").is_none(), "non-hex");
}

#[test]
fn constant_time_eq_is_correct() {
    assert!(constant_time_eq(b"", b""));
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"ab"));
    // Differing only in the first byte must behave the same as differing only
    // in the last; we can't time it here, but we can confirm both are rejected.
    assert!(!constant_time_eq(b"Xbc", b"abc"));
}

#[test]
fn random_bytes_are_the_right_length_and_not_constant() {
    let a = random_bytes(32).expect("/dev/urandom must be readable");
    let b = random_bytes(32).expect("/dev/urandom must be readable");
    assert_eq!(a.len(), 32);
    assert_ne!(a, b, "two 32-byte draws must not be equal");
    assert!(a.iter().any(|&x| x != a[0]), "output must not be a constant fill");
    assert_eq!(random_bytes(0).unwrap().len(), 0);
}
