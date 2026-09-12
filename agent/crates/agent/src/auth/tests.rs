//! Authorisation is the agent's front door. These tests are adversarial on
//! purpose: every one of them is a way in that must stay shut.

use super::*;

const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";
const NOW: i64 = 1_757_635_200;

fn auth() -> Authenticator {
    Authenticator::new(SECRET.to_vec())
}

fn token_at(scopes: &[Scope], lifetime: i64, now: i64) -> String {
    mint_token(SECRET, "test-mac", scopes, lifetime, now)
}

fn valid_token() -> String {
    token_at(&[Scope::Read, Scope::Write], 120, NOW)
}

// ---------------------------------------------------------- happy path -----

#[test]
fn accepts_a_freshly_minted_token() {
    let a = auth();
    let p = a.verify_at(&valid_token(), NOW).expect("should verify");
    assert_eq!(p.subject, "test-mac");
    assert!(p.has(Scope::Read));
    assert!(p.has(Scope::Write));
    assert!(!p.has(Scope::Admin));
}

#[test]
fn scopes_are_hierarchical() {
    let a = auth();
    let p = a.verify_at(&token_at(&[Scope::Admin], 120, NOW), NOW).unwrap();
    assert!(p.has(Scope::Read), "admin implies read");
    assert!(p.has(Scope::Write), "admin implies write");
    assert!(p.has(Scope::Admin));

    let a2 = auth();
    let p2 = a2.verify_at(&token_at(&[Scope::Read], 120, NOW), NOW).unwrap();
    assert!(p2.has(Scope::Read));
    assert!(!p2.has(Scope::Write), "read must not imply write");
}

#[test]
fn tokens_are_unique_even_when_minted_in_the_same_second() {
    // Without a random jti, two tokens minted in one second would collide and
    // the second request would look like a replay.
    let a = token_at(&[Scope::Read], 120, NOW);
    let b = token_at(&[Scope::Read], 120, NOW);
    assert_ne!(a, b);
    let auth = auth();
    assert!(auth.verify_at(&a, NOW).is_ok());
    assert!(auth.verify_at(&b, NOW).is_ok(), "distinct tokens must both verify");
}

// ------------------------------------------------------------ forgery ------

#[test]
fn rejects_a_token_signed_with_a_different_key() {
    let forged = mint_token(b"a different 32 byte secret......", "attacker", &[Scope::Admin], 120, NOW);
    assert_eq!(auth().verify_at(&forged, NOW), Err(AuthError::BadSignature));
}

#[test]
fn rejects_a_tampered_payload() {
    // Escalate read -> admin by editing the payload and keeping the signature.
    let token = token_at(&[Scope::Read], 120, NOW);
    let parts: Vec<&str> = token.split('.').collect();
    let payload = String::from_utf8(b64url_decode(parts[1]).unwrap()).unwrap();
    let escalated = payload.replace(r#""scp":"read""#, r#""scp":"admin""#);
    assert_ne!(escalated, payload, "test setup: payload should have changed");
    let forged = format!("{}.{}.{}", parts[0], b64url_encode(escalated.as_bytes()), parts[2]);
    assert_eq!(auth().verify_at(&forged, NOW), Err(AuthError::BadSignature));
}

#[test]
fn rejects_a_stripped_signature() {
    let token = token_at(&[Scope::Read], 120, NOW);
    let parts: Vec<&str> = token.split('.').collect();
    for bad in [
        format!("{}.{}.", parts[0], parts[1]),
        format!("{}.{}", parts[0], parts[1]),
        format!("{}.{}.{}", parts[0], parts[1], b64url_encode(&[0u8; 32])),
    ] {
        assert!(auth().verify_at(&bad, NOW).is_err(), "accepted {bad}");
    }
}

#[test]
fn rejects_structurally_broken_tokens() {
    let a = auth();
    let cases = [
        "",
        "serveros",
        "serveros.",
        "notserveros.abc.def",
        "serveros.!!!.abc",
        "serveros.abc.!!!",
        "serveros.a.b.c",
        "Bearer serveros.a.b",
    ];
    for case in cases {
        assert!(a.verify_at(case, NOW).is_err(), "accepted {case:?}");
    }
}

#[test]
fn signature_is_checked_before_the_payload_is_parsed() {
    // An unauthenticated payload must never reach the JSON parser. Feed a
    // payload that would be rejected by the parser and confirm the error is a
    // signature failure, not a parse failure — proving the order.
    let bogus_payload = b64url_encode(b"{not json at all");
    let token = format!("serveros.{bogus_payload}.{}", b64url_encode(&[0u8; 32]));
    assert_eq!(auth().verify_at(&token, NOW), Err(AuthError::BadSignature));
}

// ------------------------------------------------------------ lifetime -----

#[test]
fn rejects_an_expired_token() {
    let a = auth();
    let token = token_at(&[Scope::Read], 120, NOW);
    // Inside the skew allowance it still passes.
    assert!(a.verify_at(&token, NOW + 120 + 30).is_ok());
    // Well past it, it does not.
    assert_eq!(a.verify_at(&token, NOW + 120 + 120), Err(AuthError::Expired));
}

#[test]
fn rejects_a_token_from_the_future() {
    let a = auth();
    let token = token_at(&[Scope::Read], 120, NOW + 3600);
    assert_eq!(a.verify_at(&token, NOW), Err(AuthError::NotYetValid));
}

#[test]
fn tolerates_modest_clock_skew_in_both_directions() {
    let a = auth();
    let token = token_at(&[Scope::Read], 120, NOW + 30);
    assert!(a.verify_at(&token, NOW).is_ok(), "30s of client-ahead skew is normal");
}

#[test]
fn refuses_a_token_that_grants_itself_a_long_life() {
    // A client cannot opt out of short credentials.
    let a = auth();
    let token = token_at(&[Scope::Admin], 60 * 60 * 24 * 365, NOW);
    assert_eq!(a.verify_at(&token, NOW), Err(AuthError::LifetimeTooLong));

    let ok = token_at(&[Scope::Admin], MAX_TOKEN_LIFETIME_SECS, NOW);
    assert!(a.verify_at(&ok, NOW).is_ok(), "exactly the maximum must be allowed");
}

// -------------------------------------------------------------- replay -----

#[test]
fn refuses_to_accept_the_same_token_twice() {
    let a = auth();
    let token = valid_token();
    assert!(a.verify_at(&token, NOW).is_ok());
    assert_eq!(a.verify_at(&token, NOW), Err(AuthError::Replayed), "captured token was reusable");
}

#[test]
fn replay_cache_is_bounded_and_expires_old_entries() {
    let mut cache = ReplayCache::new(4);
    assert!(cache.insert("a".into(), NOW + 100));
    assert!(!cache.insert("a".into(), NOW + 100), "duplicate must be rejected");
    assert!(cache.insert("b".into(), NOW + 100));
    assert!(cache.insert("c".into(), NOW + 100));
    assert!(cache.insert("d".into(), NOW + 100));
    // Capacity reached: the oldest is evicted, so "a" becomes insertable again.
    assert!(cache.insert("e".into(), NOW + 100));
    assert_eq!(cache.len(), 4);

    let mut cache2 = ReplayCache::new(10);
    cache2.insert("old".into(), NOW - 1000);
    cache2.insert("new".into(), NOW + 1000);
    cache2.expire(NOW);
    assert_eq!(cache2.len(), 1, "expired entries should be dropped");
}

#[test]
fn a_rejected_token_does_not_consume_a_replay_slot() {
    // Otherwise flooding expired tokens would evict live entries and turn the
    // replay defence off.
    let a = auth();
    for _ in 0..100 {
        let stale = token_at(&[Scope::Read], 60, NOW - 100_000);
        assert!(a.verify_at(&stale, NOW).is_err());
    }
    let good = valid_token();
    assert!(a.verify_at(&good, NOW).is_ok());
    assert_eq!(a.verify_at(&good, NOW), Err(AuthError::Replayed), "cache was flushed by junk");
}

// --------------------------------------------------------------- scope -----

#[test]
fn authorise_enforces_the_required_scope() {
    let a = auth();
    let read_only = token_at(&[Scope::Read], 120, NOW);
    assert!(a.authorise_at(Some(&read_only), "peer", Scope::Read, NOW).is_ok());

    let read_only2 = token_at(&[Scope::Read], 120, NOW);
    assert_eq!(
        a.authorise_at(Some(&read_only2), "peer", Scope::Write, NOW),
        Err(AuthError::InsufficientScope { required: Scope::Write })
    );
}

#[test]
fn a_token_with_no_recognisable_scope_is_rejected() {
    let payload = Object::new()
        .set("sub", "x")
        .set("iat", NOW)
        .set("exp", NOW + 60)
        .set("jti", "abc")
        .set("scp", "superuser wheel");
    let payload_b64 = b64url_encode(serveros_json::Value::Object(payload).to_string().as_bytes());
    let signing_input = format!("serveros.{payload_b64}");
    let mac = hmac_sha256(SECRET, signing_input.as_bytes());
    let token = format!("{signing_input}.{}", b64url_encode(&mac));
    assert!(matches!(auth().verify_at(&token, NOW), Err(AuthError::Malformed(_))));
}

#[test]
fn a_missing_credential_is_distinguished_from_a_bad_one() {
    let a = auth();
    assert_eq!(a.authorise_at(None, "peer", Scope::Read, NOW), Err(AuthError::Missing));
    assert_eq!(AuthError::Missing.status(), 401);
    assert_eq!(AuthError::InsufficientScope { required: Scope::Admin }.status(), 403);
}

// -------------------------------------------------------- rate limiting ----

#[test]
fn repeated_failures_lock_a_peer_out() {
    let a = auth();
    for i in 0..FAILURE_THRESHOLD {
        let err =
            a.authorise_at(Some("serveros.bad.token"), "attacker", Scope::Read, NOW).unwrap_err();
        assert!(!matches!(err, AuthError::RateLimited { .. }), "locked out too early at {i}");
    }
    match a.authorise_at(Some("serveros.bad.token"), "attacker", Scope::Read, NOW) {
        Err(AuthError::RateLimited { retry_after_secs }) => {
            assert!(retry_after_secs > 0 && retry_after_secs <= LOCKOUT_SECS as u64);
        }
        other => panic!("expected rate limiting, got {other:?}"),
    }
}

#[test]
fn one_peer_locking_itself_out_does_not_affect_another() {
    let a = auth();
    for _ in 0..FAILURE_THRESHOLD + 1 {
        let _ = a.authorise_at(Some("serveros.bad.token"), "attacker", Scope::Read, NOW);
    }
    assert!(matches!(
        a.authorise_at(Some("serveros.bad.token"), "attacker", Scope::Read, NOW),
        Err(AuthError::RateLimited { .. })
    ));
    // A different peer with a good token is unaffected.
    assert!(a.authorise_at(Some(&valid_token()), "innocent", Scope::Read, NOW).is_ok());
}

#[test]
fn a_successful_authentication_clears_the_failure_count() {
    let a = auth();
    for _ in 0..FAILURE_THRESHOLD - 1 {
        let _ = a.authorise_at(Some("serveros.bad.token"), "peer", Scope::Read, NOW);
    }
    assert!(a.authorise_at(Some(&valid_token()), "peer", Scope::Read, NOW).is_ok());
    // The counter reset, so there is room to fail again without lockout.
    let err =
        a.authorise_at(Some("serveros.bad.token"), "peer", Scope::Read, NOW).unwrap_err();
    assert!(!matches!(err, AuthError::RateLimited { .. }));
}

#[test]
fn an_insufficient_scope_does_not_count_toward_the_rate_limit() {
    // Otherwise a legitimate client hitting a route it lacks scope for would
    // lock itself out of the routes it does have.
    let a = auth();
    for _ in 0..FAILURE_THRESHOLD + 5 {
        let t = token_at(&[Scope::Read], 120, NOW);
        assert_eq!(
            a.authorise_at(Some(&t), "peer", Scope::Admin, NOW),
            Err(AuthError::InsufficientScope { required: Scope::Admin })
        );
    }
    assert!(a.authorise_at(Some(&valid_token()), "peer", Scope::Read, NOW).is_ok());
}

// ------------------------------------------------------------ messages -----

#[test]
fn error_messages_never_reveal_which_check_failed() {
    // Expired is deliberately specific so the app can silently re-mint; the
    // rest must be indistinguishable to a prober.
    let generic = AuthError::BadSignature.message();
    assert_eq!(AuthError::Malformed("x").message(), generic);
    assert_eq!(AuthError::Replayed.message(), generic);
    assert_eq!(AuthError::NotYetValid.message(), generic);
    assert_ne!(AuthError::Expired.message(), generic);

    // Codes stay distinct for the app's own logic and for support.
    assert_ne!(AuthError::BadSignature.code(), AuthError::Replayed.code());
}

#[test]
fn error_messages_are_human_sentences() {
    for e in [
        AuthError::Missing,
        AuthError::Expired,
        AuthError::BadSignature,
        AuthError::NotEnrolled,
        AuthError::InsufficientScope { required: Scope::Write },
        AuthError::RateLimited { retry_after_secs: 30 },
    ] {
        let m = e.message();
        assert!(m.ends_with('.'), "not a sentence: {m}");
        assert!(m.chars().next().unwrap().is_uppercase(), "not capitalised: {m}");
        assert!(!m.contains('_'), "leaks an identifier: {m}");
    }
}

// ------------------------------------------------------------- key file ----

#[test]
fn load_secret_refuses_a_world_readable_key() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("serveros-auth-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("agent.key");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(b64url_encode(&[7u8; 32]).as_bytes()).unwrap();
    drop(f);

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = load_secret(&path).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(err.to_string().contains("chmod 600"), "error should say how to fix it");

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let secret = load_secret(&path).unwrap();
    assert_eq!(secret, vec![7u8; 32]);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn load_secret_rejects_a_short_or_malformed_key() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("serveros-auth2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for (name, contents) in [("short.key", b64url_encode(&[1u8; 8])), ("junk.key", "!!!!".into())] {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_secret(&path).is_err(), "{name} should be rejected");
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn minted_tokens_are_url_and_header_safe() {
    // The token travels in an Authorization header and sometimes a query
    // string; anything needing escaping would be a source of subtle bugs.
    let t = valid_token();
    assert!(
        t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'),
        "token contains characters needing escaping: {t}"
    );
}
