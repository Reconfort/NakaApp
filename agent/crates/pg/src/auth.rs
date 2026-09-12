//! Authentication: SCRAM-SHA-256 (RFC 5802 + RFC 7677), legacy `md5`, and
//! cleartext.
//!
//! # Why this module is the careful one
//!
//! Everything else in the crate is framing. This is the part where getting a
//! detail subtly wrong still *works* against a cooperative server while
//! silently removing the protection the mechanism exists to provide. Two checks
//! in particular are easy to skip and must not be:
//!
//!   * **The combined nonce must start with our client nonce.** SCRAM's replay
//!     and downgrade resistance rests on the client contributing entropy the
//!     server cannot choose. A server that returns a nonce of its own choosing
//!     can replay a captured exchange; if we do not compare, we never notice.
//!   * **The server signature must verify.** SCRAM is mutual authentication.
//!     `v=` proves the peer knows `StoredKey`'s sibling `ServerKey`, i.e. that
//!     it really is the database and not something sitting on the socket
//!     harvesting `ClientProof`s. Skipping the check turns mutual auth into
//!     one-way auth without any visible symptom.
//!
//! Both are implemented, and both have tests that fail closed.
//!
//! # Channel binding
//!
//! `SCRAM-SHA-256-PLUS` binds the exchange to the TLS channel. The agent has no
//! TLS (see [`crate::client`] for why: it only ever talks to a database on the
//! same host), so there is no channel to bind to and we cannot offer `-PLUS`
//! honestly. When a server offers *only* `-PLUS` we say exactly that, in a
//! sentence an administrator can act on, rather than falling back to something
//! weaker. Downgrading silently would be the bug.
//!
//! # SASLprep
//!
//! RFC 7677 requires the password to be prepared with SASLprep (RFC 4013, a
//! profile of stringprep) before it reaches PBKDF2. Full SASLprep needs Unicode
//! NFKC normalisation, bidirectional-text checks and the stringprep tables —
//! several hundred kilobytes of data for a case that essentially never arises
//! on a database password. [`saslprep`] implements the practical subset: it
//! **rejects** prohibited control characters and passes everything else through
//! **unchanged**. Non-ASCII passwords are therefore used verbatim rather than
//! normalised, which matches what PostgreSQL's own libpq does; a password that
//! only differs by normalisation form will fail to authenticate, and that is a
//! visible, diagnosable failure rather than a silent mangling.

use serveros_crypto::{
    b64_decode, b64_encode, constant_time_eq, hex_encode, hmac_sha256, md5, pbkdf2_hmac_sha256,
    random_bytes, sha256,
};

use crate::error::PgError;

/// The only SASL mechanism the agent implements.
pub const SCRAM_SHA_256: &str = "SCRAM-SHA-256";
/// The channel-binding variant, which we detect but cannot speak.
pub const SCRAM_SHA_256_PLUS: &str = "SCRAM-SHA-256-PLUS";

/// Minimum PBKDF2 iteration count we will accept from a server.
///
/// RFC 7677 sets 4096 as the floor and PostgreSQL's default is far higher
/// (`scram_iterations`, 4096 by default in 16). A server asking for fewer is
/// either broken or trying to make an offline attack on the captured proof
/// cheap, so we refuse rather than comply.
pub const MIN_ITERATIONS: u32 = 4096;

/// Bytes of client nonce. RFC 5802 requires "sufficient" entropy without
/// naming a number; 18 bytes is 144 bits and base64s to exactly 24 characters
/// with no padding, which is what libpq uses.
const CLIENT_NONCE_BYTES: usize = 18;

/// GS2 header for "no channel binding, no authorization identity".
///
/// The trailing `,,` matters: the first comma ends the channel-binding flag and
/// the second ends the (absent) authzid. This exact string is what gets base64d
/// into the `c=` attribute of the client-final message.
const GS2_HEADER: &str = "n,,";

/// Pick the SASL mechanism to use from the list the server offered.
///
/// Prefers plain `SCRAM-SHA-256` whenever it is available; returns
/// [`PgError::ChannelBindingRequired`] when only `-PLUS` is on offer.
pub fn select_mechanism(offered: &[String]) -> Result<&'static str, PgError> {
    if offered.iter().any(|m| m == SCRAM_SHA_256) {
        return Ok(SCRAM_SHA_256);
    }
    if offered.iter().any(|m| m == SCRAM_SHA_256_PLUS) {
        return Err(PgError::ChannelBindingRequired);
    }
    Err(PgError::Protocol(format!(
        "the server offered SASL mechanisms {offered:?}, none of which the agent implements"
    )))
}

/// Reject passwords SASLprep prohibits; pass everything else through unchanged.
///
/// See the module docs for the scope of this implementation. Returning a
/// borrow rather than an owned `String` is deliberate: it makes it structurally
/// impossible for this function to modify the password.
pub fn saslprep(password: &str) -> Result<&str, PgError> {
    for ch in password.chars() {
        let c = ch as u32;
        let prohibited = match c {
            // RFC 3454 C.2.1 — ASCII control characters.
            0x00..=0x1F | 0x7F => true,
            // RFC 3454 C.2.2 — non-ASCII control characters.
            0x80..=0x9F | 0x06DD | 0x070F | 0x180E | 0x200C | 0x200D | 0x2028 | 0x2029 => true,
            0x2060..=0x2064 | 0x206A..=0x206F | 0xFEFF => true,
            // RFC 3454 C.6 — inappropriate for plain text.
            0xFFF9..=0xFFFD => true,
            // RFC 3454 C.9 — tagging characters.
            0xE0001 | 0xE0020..=0xE007F => true,
            _ => false,
        };
        if prohibited {
            return Err(PgError::UnsupportedPassword(
                "it contains a control or formatting character that SASLprep forbids",
            ));
        }
    }
    Ok(password)
}

/// Legacy `md5` authentication (PostgreSQL's own scheme, not a standard one).
///
/// The wire response is `"md5" + hex(md5(hex(md5(password + username)) +
/// salt))`. The inner digest is what the server stores in `pg_authid`; the
/// outer one binds it to the four-byte per-connection salt so the stored value
/// is not directly replayable.
///
/// This is weak — it is unsalted-per-user MD5 underneath — and PostgreSQL has
/// deprecated it. We implement it because plenty of running clusters still have
/// `md5` lines in `pg_hba.conf` and refusing to connect would not make them
/// safer. [`crate::client`] only ever uses it over loopback or a unix socket.
pub fn md5_password(password: &str, user: &str, salt: [u8; 4]) -> String {
    let mut inner = Vec::with_capacity(password.len() + user.len());
    inner.extend_from_slice(password.as_bytes());
    inner.extend_from_slice(user.as_bytes());
    let inner_hex = hex_encode(&md5(&inner));

    let mut outer = Vec::with_capacity(32 + 4);
    outer.extend_from_slice(inner_hex.as_bytes());
    outer.extend_from_slice(&salt);
    format!("md5{}", hex_encode(&md5(&outer)))
}

/// Client side of one SCRAM-SHA-256 exchange.
///
/// Single use: build it, send [`ScramClient::client_first`], feed the
/// server-first to [`ScramClient::client_final`], then check the server-final
/// with [`ScramClient::verify_server_final`].
pub struct ScramClient {
    /// The nonce we generated, which the server must echo as a prefix.
    client_nonce: String,
    /// `n=<user>,r=<nonce>` — the client-first message without the GS2 header,
    /// which is the first third of the `AuthMessage`.
    client_first_bare: String,
    /// Filled in by `client_final`, checked by `verify_server_final`.
    expected_server_signature: Option<[u8; 32]>,
}

impl ScramClient {
    /// Start an exchange with a fresh random nonce.
    ///
    /// The `n=` attribute is sent as `*`. PostgreSQL ignores it entirely — the
    /// username that matters was already sent in the StartupMessage — and RFC
    /// 5802 would otherwise require us to SASLprep and comma-escape it.
    pub fn new() -> Result<Self, PgError> {
        let nonce = b64_encode(&random_bytes(CLIENT_NONCE_BYTES)?);
        Ok(Self::with_parameters("*", &nonce))
    }

    /// Build an exchange with a caller-chosen username attribute and nonce.
    ///
    /// Exists so the published RFC 7677 §3 vectors can be reproduced exactly;
    /// production code wants [`ScramClient::new`]. Passing a predictable nonce
    /// removes SCRAM's replay protection, so this is not a shortcut to take.
    pub fn with_parameters(username_attr: &str, client_nonce: &str) -> Self {
        ScramClient {
            client_nonce: client_nonce.to_string(),
            client_first_bare: format!("n={username_attr},r={client_nonce}"),
            expected_server_signature: None,
        }
    }

    /// The client-first message, `n,,n=...,r=...`.
    pub fn client_first(&self) -> String {
        format!("{GS2_HEADER}{}", self.client_first_bare)
    }

    /// Consume the server-first message and produce the client-final message.
    ///
    /// Performs the nonce-prefix and iteration-count checks described in the
    /// module docs, and stashes the server signature we will require later.
    pub fn client_final(&mut self, server_first: &[u8], password: &str) -> Result<String, PgError> {
        let server_first = std::str::from_utf8(server_first)
            .map_err(|_| PgError::ScramFailed("the server-first message was not valid UTF-8"))?;
        let password = saslprep(password)?;

        let attrs = Attributes::parse(server_first)?;
        let combined_nonce = attrs
            .get('r')
            .ok_or(PgError::ScramFailed("the server-first message has no nonce"))?;
        let salt_b64 = attrs
            .get('s')
            .ok_or(PgError::ScramFailed("the server-first message has no salt"))?;
        let iterations_text = attrs
            .get('i')
            .ok_or(PgError::ScramFailed("the server-first message has no iteration count"))?;

        // The downgrade check. `starts_with` is the right comparison: the
        // combined nonce is our nonce followed by the server's, and both halves
        // are public, so there is nothing here to leak through timing.
        if !combined_nonce.starts_with(&self.client_nonce) {
            return Err(PgError::ScramFailed(
                "the server's nonce does not begin with the client nonce, so the exchange may be \
                 a replay",
            ));
        }
        if combined_nonce.len() == self.client_nonce.len() {
            return Err(PgError::ScramFailed(
                "the server contributed no nonce of its own",
            ));
        }

        let iterations: u32 = iterations_text
            .parse()
            .map_err(|_| PgError::ScramFailed("the iteration count is not a number"))?;
        if iterations < MIN_ITERATIONS {
            return Err(PgError::ScramFailed(
                "the server asked for fewer PBKDF2 iterations than RFC 7677 permits",
            ));
        }

        let salt = b64_decode(salt_b64)
            .ok_or(PgError::ScramFailed("the salt is not valid base64"))?;

        // RFC 5802 §3, with SHA-256 and a 32-byte output per RFC 7677.
        let salted_password = pbkdf2_hmac_sha256(password.as_bytes(), &salt, iterations);
        let client_key = hmac_sha256(&salted_password, b"Client Key");
        let stored_key = sha256(&client_key);

        let client_final_without_proof =
            format!("c={},r={combined_nonce}", b64_encode(GS2_HEADER.as_bytes()));
        let auth_message =
            format!("{},{server_first},{client_final_without_proof}", self.client_first_bare);

        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let mut client_proof = client_key;
        for i in 0..32 {
            client_proof[i] ^= client_signature[i];
        }

        // Computed now, while we still have SaltedPassword, and checked after
        // the server replies.
        let server_key = hmac_sha256(&salted_password, b"Server Key");
        self.expected_server_signature = Some(hmac_sha256(&server_key, auth_message.as_bytes()));

        Ok(format!("{client_final_without_proof},p={}", b64_encode(&client_proof)))
    }

    /// Check the server's `v=` signature against the one we derived.
    ///
    /// Mandatory. Without it the exchange authenticates us to the server but
    /// never the server to us, which is precisely the case SCRAM exists to
    /// cover.
    pub fn verify_server_final(&self, server_final: &[u8]) -> Result<(), PgError> {
        let expected = self
            .expected_server_signature
            .ok_or(PgError::ScramFailed("the server sent SASLFinal before SASLContinue"))?;
        let text = std::str::from_utf8(server_final)
            .map_err(|_| PgError::ScramFailed("the server-final message was not valid UTF-8"))?;

        let attrs = Attributes::parse(text)?;
        if let Some(err) = attrs.get('e') {
            return Err(PgError::Protocol(format!("the SCRAM exchange failed: {err}")));
        }
        let signature_b64 = attrs
            .get('v')
            .ok_or(PgError::ScramFailed("the server-final message has no signature"))?;
        let signature = b64_decode(signature_b64)
            .ok_or(PgError::ScramFailed("the server signature is not valid base64"))?;

        if !constant_time_eq(&signature, &expected) {
            return Err(PgError::ScramFailed(
                "the server signature does not verify, so the peer does not hold this role's \
                 stored key and is not the database it claims to be",
            ));
        }
        Ok(())
    }
}

/// The `a=b,c=d` attribute lists SCRAM messages are made of.
struct Attributes<'a> {
    pairs: Vec<(char, &'a str)>,
}

impl<'a> Attributes<'a> {
    fn parse(message: &'a str) -> Result<Self, PgError> {
        let mut pairs = Vec::new();
        for (index, part) in message.split(',').enumerate() {
            let mut chars = part.chars();
            let name = chars
                .next()
                .ok_or(PgError::ScramFailed("empty attribute in a SCRAM message"))?;
            if chars.next() != Some('=') {
                return Err(PgError::ScramFailed(
                    "malformed SCRAM attribute: expected <letter>=<value>",
                ));
            }
            // RFC 5802 §5.1: `m` is the mandatory-extension attribute. A client
            // that does not understand the extension MUST fail, and we
            // understand none of them.
            if name == 'm' && index == 0 {
                return Err(PgError::ScramFailed(
                    "the server requires a SCRAM extension the agent does not implement",
                ));
            }
            pairs.push((name, &part[2..]));
        }
        if pairs.is_empty() {
            return Err(PgError::ScramFailed("empty SCRAM message"));
        }
        Ok(Attributes { pairs })
    }

    fn get(&self, name: char) -> Option<&'a str> {
        self.pairs.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The worked example from RFC 7677 section 3. Every value below is quoted
    // from the RFC; if any assertion here fails, the implementation is wrong,
    // not the vector.
    const RFC7677_USER: &str = "user";
    const RFC7677_PASSWORD: &str = "pencil";
    const RFC7677_CLIENT_NONCE: &str = "rOprNGfwEbeRWgbNEkqO";
    const RFC7677_SERVER_FIRST: &str = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                                        s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    const RFC7677_CLIENT_FINAL: &str = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                                        p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    const RFC7677_SERVER_FINAL: &str = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";

    fn rfc_client() -> ScramClient {
        ScramClient::with_parameters(RFC7677_USER, RFC7677_CLIENT_NONCE)
    }

    // ---- RFC 7677 section 3 vectors ---------------------------------------

    #[test]
    fn rfc7677_client_first_is_byte_identical() {
        assert_eq!(rfc_client().client_first(), "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");
    }

    #[test]
    fn rfc7677_client_final_is_byte_identical() {
        let mut c = rfc_client();
        let got = c.client_final(RFC7677_SERVER_FIRST.as_bytes(), RFC7677_PASSWORD).unwrap();
        assert_eq!(got, RFC7677_CLIENT_FINAL);
    }

    #[test]
    fn rfc7677_client_proof_matches_exactly() {
        let mut c = rfc_client();
        let final_message =
            c.client_final(RFC7677_SERVER_FIRST.as_bytes(), RFC7677_PASSWORD).unwrap();
        let proof = final_message.rsplit_once("p=").unwrap().1;
        assert_eq!(proof, "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");
    }

    #[test]
    fn rfc7677_server_signature_verifies() {
        let mut c = rfc_client();
        c.client_final(RFC7677_SERVER_FIRST.as_bytes(), RFC7677_PASSWORD).unwrap();
        c.verify_server_final(RFC7677_SERVER_FINAL.as_bytes()).unwrap();
    }

    #[test]
    fn rfc7677_expected_server_signature_is_byte_identical() {
        let mut c = rfc_client();
        c.client_final(RFC7677_SERVER_FIRST.as_bytes(), RFC7677_PASSWORD).unwrap();
        let sig = c.expected_server_signature.unwrap();
        assert_eq!(b64_encode(&sig), "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=");
    }

    #[test]
    fn rfc7677_salted_password_intermediate_is_correct() {
        // SaltedPassword is not printed in RFC 7677, but ClientKey/StoredKey
        // derive from it, so deriving StoredKey and reproducing the proof by
        // hand cross-checks the PBKDF2 step independently of `client_final`.
        let salt = b64_decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let salted = pbkdf2_hmac_sha256(RFC7677_PASSWORD.as_bytes(), &salt, 4096);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = sha256(&client_key);
        let auth_message = format!(
            "n=user,r={RFC7677_CLIENT_NONCE},{RFC7677_SERVER_FIRST},c=biws,\
             r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
        );
        let client_signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let mut proof = client_key;
        for i in 0..32 {
            proof[i] ^= client_signature[i];
        }
        assert_eq!(b64_encode(&proof), "dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=");
    }

    // ---- the mandatory checks ---------------------------------------------

    #[test]
    fn rejects_a_nonce_that_does_not_extend_ours() {
        let mut c = rfc_client();
        let forged = "r=somethingElseEntirely,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        match c.client_final(forged.as_bytes(), RFC7677_PASSWORD) {
            Err(PgError::ScramFailed(why)) => assert!(why.contains("replay"), "{why}"),
            other => panic!("expected a nonce rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_nonce_echoed_without_server_entropy() {
        let mut c = rfc_client();
        let echoed = format!("r={RFC7677_CLIENT_NONCE},s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096");
        match c.client_final(echoed.as_bytes(), RFC7677_PASSWORD) {
            Err(PgError::ScramFailed(why)) => assert!(why.contains("no nonce of its own"), "{why}"),
            other => panic!("expected a nonce rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_iteration_counts_below_the_rfc_floor() {
        for i in [1u32, 1000, 4095] {
            let mut c = rfc_client();
            let weak = format!(
                "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i={i}"
            );
            match c.client_final(weak.as_bytes(), RFC7677_PASSWORD) {
                Err(PgError::ScramFailed(why)) => assert!(why.contains("iterations"), "{why}"),
                other => panic!("expected an iteration rejection for i={i}, got {other:?}"),
            }
        }
    }

    #[test]
    fn accepts_exactly_the_minimum_iteration_count() {
        let mut c = rfc_client();
        assert!(c.client_final(RFC7677_SERVER_FIRST.as_bytes(), RFC7677_PASSWORD).is_ok());
        assert_eq!(MIN_ITERATIONS, 4096);
    }

    #[test]
    fn rejects_a_server_signature_that_does_not_verify() {
        let mut c = rfc_client();
        c.client_final(RFC7677_SERVER_FIRST.as_bytes(), RFC7677_PASSWORD).unwrap();
        // A well-formed, correctly sized, wrong signature.
        let forged = format!("v={}", b64_encode(&[0x11u8; 32]));
        match c.verify_server_final(forged.as_bytes()) {
            Err(PgError::ScramFailed(why)) => assert!(why.contains("does not verify"), "{why}"),
            other => panic!("expected a signature rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_server_signature_of_the_wrong_length() {
        let mut c = rfc_client();
        c.client_final(RFC7677_SERVER_FIRST.as_bytes(), RFC7677_PASSWORD).unwrap();
        let short = format!("v={}", b64_encode(&[0u8; 16]));
        assert!(c.verify_server_final(short.as_bytes()).is_err());
    }

    #[test]
    fn verify_before_continue_is_an_error_not_a_pass() {
        let c = rfc_client();
        assert!(c.verify_server_final(RFC7677_SERVER_FINAL.as_bytes()).is_err());
    }

    #[test]
    fn wrong_password_produces_a_proof_that_the_vector_rejects() {
        let mut c = rfc_client();
        let out = c.client_final(RFC7677_SERVER_FIRST.as_bytes(), "not-pencil").unwrap();
        assert_ne!(out, RFC7677_CLIENT_FINAL);
        // And the real server's signature no longer matches what we expect.
        assert!(c.verify_server_final(RFC7677_SERVER_FINAL.as_bytes()).is_err());
    }

    // ---- malformed server-first -------------------------------------------

    #[test]
    fn rejects_server_first_without_a_salt() {
        let mut c = rfc_client();
        let bad = "r=rOprNGfwEbeRWgbNEkqOxyz,i=4096";
        assert!(matches!(
            c.client_final(bad.as_bytes(), RFC7677_PASSWORD),
            Err(PgError::ScramFailed(_))
        ));
    }

    #[test]
    fn rejects_server_first_without_an_iteration_count() {
        let mut c = rfc_client();
        let bad = "r=rOprNGfwEbeRWgbNEkqOxyz,s=W22ZaJ0SNY7soEsUEjb6gQ==";
        assert!(matches!(
            c.client_final(bad.as_bytes(), RFC7677_PASSWORD),
            Err(PgError::ScramFailed(_))
        ));
    }

    #[test]
    fn rejects_server_first_without_a_nonce() {
        let mut c = rfc_client();
        let bad = "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        assert!(matches!(
            c.client_final(bad.as_bytes(), RFC7677_PASSWORD),
            Err(PgError::ScramFailed(_))
        ));
    }

    #[test]
    fn rejects_a_non_base64_salt() {
        let mut c = rfc_client();
        let bad = "r=rOprNGfwEbeRWgbNEkqOxyz,s=not!base64!,i=4096";
        assert!(matches!(
            c.client_final(bad.as_bytes(), RFC7677_PASSWORD),
            Err(PgError::ScramFailed(_))
        ));
    }

    #[test]
    fn rejects_a_non_numeric_iteration_count() {
        let mut c = rfc_client();
        let bad = "r=rOprNGfwEbeRWgbNEkqOxyz,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=lots";
        assert!(matches!(
            c.client_final(bad.as_bytes(), RFC7677_PASSWORD),
            Err(PgError::ScramFailed(_))
        ));
    }

    #[test]
    fn rejects_a_structurally_malformed_attribute_list() {
        let mut c = rfc_client();
        for bad in ["garbage", "rr=x,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096", ""] {
            assert!(
                c.client_final(bad.as_bytes(), RFC7677_PASSWORD).is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_a_mandatory_extension_we_do_not_understand() {
        let mut c = rfc_client();
        let bad = format!("m=whatever,{RFC7677_SERVER_FIRST}");
        match c.client_final(bad.as_bytes(), RFC7677_PASSWORD) {
            Err(PgError::ScramFailed(why)) => assert!(why.contains("extension"), "{why}"),
            other => panic!("expected an extension rejection, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_utf8_server_messages() {
        let mut c = rfc_client();
        assert!(c.client_final(&[0xff, 0xfe], RFC7677_PASSWORD).is_err());
    }

    #[test]
    fn surfaces_a_scram_level_server_error() {
        let mut c = rfc_client();
        c.client_final(RFC7677_SERVER_FIRST.as_bytes(), RFC7677_PASSWORD).unwrap();
        match c.verify_server_final(b"e=invalid-proof") {
            Err(PgError::Protocol(m)) => assert!(m.contains("invalid-proof"), "{m}"),
            other => panic!("expected the server error to surface, got {other:?}"),
        }
    }

    // ---- nonce generation --------------------------------------------------

    #[test]
    fn generated_nonces_are_long_random_and_comma_free() {
        let a = ScramClient::new().unwrap();
        let b = ScramClient::new().unwrap();
        assert_ne!(a.client_nonce, b.client_nonce);
        // 18 bytes -> 24 base64 characters, no padding needed.
        assert_eq!(a.client_nonce.len(), 24);
        // RFC 5802 printable excludes ',' (0x2C); base64's alphabet does too.
        assert!(!a.client_nonce.contains(','));
        assert!(a.client_nonce.chars().all(|c| ('!'..='~').contains(&c)));
    }

    #[test]
    fn generated_client_first_sends_a_star_username() {
        let c = ScramClient::new().unwrap();
        assert!(c.client_first().starts_with("n,,n=*,r="));
    }

    #[test]
    fn gs2_header_base64s_to_biws() {
        assert_eq!(b64_encode(GS2_HEADER.as_bytes()), "biws");
    }

    // ---- mechanism selection ----------------------------------------------

    #[test]
    fn prefers_plain_scram_when_both_are_offered() {
        let offered = vec![SCRAM_SHA_256_PLUS.to_string(), SCRAM_SHA_256.to_string()];
        assert_eq!(select_mechanism(&offered).unwrap(), SCRAM_SHA_256);
    }

    #[test]
    fn plus_only_reports_channel_binding_required() {
        let offered = vec![SCRAM_SHA_256_PLUS.to_string()];
        assert!(matches!(
            select_mechanism(&offered),
            Err(PgError::ChannelBindingRequired)
        ));
    }

    #[test]
    fn an_unknown_mechanism_list_is_reported_verbatim() {
        let offered = vec!["GS2-KRB5".to_string()];
        match select_mechanism(&offered) {
            Err(PgError::Protocol(m)) => assert!(m.contains("GS2-KRB5"), "{m}"),
            other => panic!("expected a protocol error, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_mechanism_list_is_an_error() {
        assert!(select_mechanism(&[]).is_err());
    }

    // ---- SASLprep ----------------------------------------------------------

    #[test]
    fn saslprep_passes_ascii_through_unchanged() {
        for pw in ["pencil", "hunter2", "a b c", "~!@#$%^&*()_+-=[]{}|;:'\",.<>/?"] {
            assert_eq!(saslprep(pw).unwrap(), pw);
        }
    }

    #[test]
    fn saslprep_passes_non_ascii_through_unchanged_rather_than_mangling() {
        // Documented behaviour: we do not normalise, we do not strip.
        for pw in ["pässwörd", "パスワード", "naïve"] {
            assert_eq!(saslprep(pw).unwrap(), pw);
        }
    }

    #[test]
    fn saslprep_rejects_ascii_control_characters() {
        for pw in ["pen\0cil", "pen\tcil", "pen\ncil", "pen\rcil", "pen\x7fcil"] {
            assert!(matches!(saslprep(pw), Err(PgError::UnsupportedPassword(_))), "{pw:?}");
        }
    }

    #[test]
    fn saslprep_rejects_non_ascii_formatting_characters() {
        for pw in ["pen\u{200c}cil", "pen\u{feff}cil", "pen\u{2028}cil", "pen\u{0085}cil"] {
            assert!(matches!(saslprep(pw), Err(PgError::UnsupportedPassword(_))), "{pw:?}");
        }
    }

    #[test]
    fn saslprep_rejection_never_echoes_the_password() {
        let e = saslprep("hunter2\0").unwrap_err();
        let rendered = format!("{e} {e:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }

    #[test]
    fn a_prohibited_password_fails_before_any_key_derivation() {
        let mut c = rfc_client();
        assert!(matches!(
            c.client_final(RFC7677_SERVER_FIRST.as_bytes(), "pen\0cil"),
            Err(PgError::UnsupportedPassword(_))
        ));
        assert!(c.expected_server_signature.is_none());
    }

    // ---- md5 ---------------------------------------------------------------

    #[test]
    fn md5_inner_digest_matches_what_postgresql_stores() {
        // `SET password_encryption='md5'; CREATE ROLE md5user PASSWORD 'md5pw'`
        // stores exactly md5(password || username) in pg_authid.rolpassword.
        // This value was read back off the live PostgreSQL 16 test cluster.
        let inner = md5(b"md5pwmd5user");
        assert_eq!(format!("md5{}", hex_encode(&inner)), "md5704ac3bc41dadc414b9aa9dbf5e63cdd");
    }

    #[test]
    fn md5_password_response_is_exact() {
        // Independently computed:
        //   inner = md5("md5pwmd5user")          = 704ac3bc41dadc414b9aa9dbf5e63cdd
        //   outer = md5(hex(inner) || 0xDEADBEEF)
        let got = md5_password("md5pw", "md5user", [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(got, "md5cac2d5bf70e5114000bbd172dcb4dd96");
    }

    #[test]
    fn md5_response_is_always_the_expected_shape() {
        let got = md5_password("secret", "alice", [0, 1, 2, 3]);
        assert!(got.starts_with("md5"));
        assert_eq!(got.len(), 35); // "md5" + 32 hex characters
        assert!(got[3..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn md5_response_depends_on_the_salt() {
        let a = md5_password("secret", "alice", [0, 0, 0, 0]);
        let b = md5_password("secret", "alice", [0, 0, 0, 1]);
        assert_ne!(a, b);
    }

    #[test]
    fn md5_response_depends_on_the_username() {
        let a = md5_password("secret", "alice", [1, 2, 3, 4]);
        let b = md5_password("secret", "bob", [1, 2, 3, 4]);
        assert_ne!(a, b);
    }
}
