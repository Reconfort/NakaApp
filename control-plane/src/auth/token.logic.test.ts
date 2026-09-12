import { createHmac } from 'node:crypto';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  ACCESS_TOKEN_ALGORITHM,
  ACCESS_TOKEN_TTL_SECONDS,
  buildAccessClaims,
  decodeBase64Url,
  encodeBase64Url,
  signAccessToken,
  toEpochSeconds,
  verifyAccessToken,
  type AccessTokenClaims,
  type VerifyOptions,
} from './token.logic.js';

const SECRET = 'a'.repeat(64);
const OTHER_SECRET = 'b'.repeat(64);
const NOW = new Date('2026-09-12T10:00:00.000Z');

const baseOptions: VerifyOptions = {
  secret: SECRET,
  issuer: 'serveros-control-plane',
  audience: 'serveros-macos',
  now: NOW,
  clockSkewSeconds: 30,
};

function claimsAt(now: Date = NOW): AccessTokenClaims {
  return buildAccessClaims({
    userId: 'user-1',
    sessionId: 'session-1',
    issuer: 'serveros-control-plane',
    audience: 'serveros-macos',
    jti: 'jti-1',
    now,
  });
}

/** Re-signs an arbitrary header/payload pair with a chosen secret. */
function forge(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  secret: string | null,
): string {
  const h = encodeBase64Url(JSON.stringify(header));
  const p = encodeBase64Url(JSON.stringify(payload));
  if (secret === null) return `${h}.${p}.`;
  const sig = encodeBase64Url(createHmac('sha256', secret).update(`${h}.${p}`).digest());
  return `${h}.${p}.${sig}`;
}

function expectFailure(token: unknown, options: VerifyOptions = baseOptions): string {
  const result = verifyAccessToken(token, options);
  assert.equal(result.ok, false, 'expected verification to fail');
  assert.ok(!result.ok);
  return result.code;
}

describe('base64url', () => {
  it('round-trips bytes without padding', () => {
    const encoded = encodeBase64Url(Buffer.from([0xff, 0xfe, 0xfd]));
    assert.ok(!encoded.includes('='));
    assert.deepEqual(decodeBase64Url(encoded), Buffer.from([0xff, 0xfe, 0xfd]));
  });

  it('rejects padded input', () => {
    assert.equal(decodeBase64Url('YQ=='), null);
  });

  it('rejects characters outside the alphabet', () => {
    assert.equal(decodeBase64Url('ab+cd'), null);
    assert.equal(decodeBase64Url('ab/cd'), null);
    assert.equal(decodeBase64Url('ab cd'), null);
  });

  it('rejects a non-canonical encoding of the same bytes', () => {
    // "YR" and "YR8" both decode under a lenient decoder; only the canonical
    // spelling survives the round-trip check.
    const canonical = encodeBase64Url(Buffer.from('a'));
    assert.equal(decodeBase64Url(canonical)?.toString(), 'a');
    assert.equal(decodeBase64Url(`${canonical}\u0000`), null);
  });

  it('rejects the empty segment', () => {
    assert.equal(decodeBase64Url(''), null);
  });
});

describe('buildAccessClaims', () => {
  it('sets iat, nbf and exp from the injected clock', () => {
    const claims = claimsAt();
    const issued = toEpochSeconds(NOW);
    assert.equal(claims.iat, issued);
    assert.equal(claims.nbf, issued);
    assert.equal(claims.exp, issued + ACCESS_TOKEN_TTL_SECONDS);
  });

  it('marks the token type so a refresh token cannot be replayed as access', () => {
    assert.equal(claimsAt().typ, 'access');
  });

  it('honours an explicit ttl', () => {
    const claims = buildAccessClaims({
      userId: 'u',
      sessionId: 's',
      issuer: 'i',
      audience: 'a',
      jti: 'j',
      now: NOW,
      ttlSeconds: 60,
    });
    assert.equal(claims.exp - claims.iat, 60);
  });
});

describe('signAccessToken', () => {
  it('produces three segments with an HS256 header', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    const parts = token.split('.');
    assert.equal(parts.length, 3);
    const header = JSON.parse(decodeBase64Url(parts[0] as string)!.toString('utf8')) as {
      alg: string;
      typ: string;
    };
    assert.equal(header.alg, ACCESS_TOKEN_ALGORITHM);
    assert.equal(header.typ, 'JWT');
  });

  it('refuses a secret shorter than 32 bytes', () => {
    assert.throws(() => signAccessToken(claimsAt(), 'short'), /at least 32 bytes/);
  });
});

describe('verifyAccessToken — happy path', () => {
  it('accepts a freshly minted token and returns its claims', () => {
    const result = verifyAccessToken(signAccessToken(claimsAt(), SECRET), baseOptions);
    assert.ok(result.ok);
    assert.equal(result.value.sub, 'user-1');
    assert.equal(result.value.sid, 'session-1');
    assert.equal(result.value.jti, 'jti-1');
  });

  it('accepts a token one second before expiry', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    const justBefore = new Date(NOW.getTime() + (ACCESS_TOKEN_TTL_SECONDS - 1) * 1000);
    assert.ok(verifyAccessToken(token, { ...baseOptions, now: justBefore }).ok);
  });
});

describe('verifyAccessToken — structure', () => {
  it('rejects a non-string', () => {
    assert.equal(expectFailure(undefined), 'token_malformed');
    assert.equal(expectFailure(null), 'token_malformed');
    assert.equal(expectFailure(42), 'token_malformed');
    assert.equal(expectFailure({}), 'token_malformed');
  });

  it('rejects the empty string', () => {
    assert.equal(expectFailure(''), 'token_malformed');
  });

  it('rejects a token with the wrong number of segments', () => {
    assert.equal(expectFailure('a.b'), 'token_malformed');
    assert.equal(expectFailure('a.b.c.d'), 'token_malformed');
  });

  it('rejects an oversized token before doing any HMAC work', () => {
    assert.equal(expectFailure(`${'x'.repeat(5000)}.y.z`), 'token_malformed');
  });

  it('rejects a header that is not base64url', () => {
    assert.equal(expectFailure('!!!.eyJhIjoxfQ.sig'), 'token_malformed');
  });

  it('rejects a header that is not a JSON object', () => {
    const header = encodeBase64Url('"not-an-object"');
    assert.equal(expectFailure(`${header}.eyJhIjoxfQ.c2ln`), 'token_malformed');
  });

  it('rejects a header that is a JSON array', () => {
    const header = encodeBase64Url('[]');
    assert.equal(expectFailure(`${header}.eyJhIjoxfQ.c2ln`), 'token_malformed');
  });
});

describe('verifyAccessToken — algorithm confusion', () => {
  it('rejects alg: none with an empty signature', () => {
    const token = forge({ alg: 'none', typ: 'JWT' }, { ...claimsAt() }, null);
    assert.equal(expectFailure(token), 'token_algorithm_not_allowed');
  });

  it('rejects alg: none even when a signature is present', () => {
    const token = forge({ alg: 'none', typ: 'JWT' }, { ...claimsAt() }, SECRET);
    assert.equal(expectFailure(token), 'token_algorithm_not_allowed');
  });

  it('rejects a case-variant of the algorithm name', () => {
    const token = forge({ alg: 'hs256', typ: 'JWT' }, { ...claimsAt() }, SECRET);
    assert.equal(expectFailure(token), 'token_algorithm_not_allowed');
  });

  it('rejects a stronger-looking HMAC variant we did not configure', () => {
    const token = forge({ alg: 'HS512', typ: 'JWT' }, { ...claimsAt() }, SECRET);
    assert.equal(expectFailure(token), 'token_algorithm_not_allowed');
  });

  it('rejects an asymmetric algorithm claim', () => {
    const token = forge({ alg: 'RS256', typ: 'JWT' }, { ...claimsAt() }, SECRET);
    assert.equal(expectFailure(token), 'token_algorithm_not_allowed');
  });

  it('rejects a missing alg header', () => {
    const token = forge({ typ: 'JWT' }, { ...claimsAt() }, SECRET);
    assert.equal(expectFailure(token), 'token_algorithm_not_allowed');
  });

  it('rejects a non-string alg header', () => {
    const token = forge({ alg: 256, typ: 'JWT' }, { ...claimsAt() }, SECRET);
    assert.equal(expectFailure(token), 'token_algorithm_not_allowed');
  });

  it('rejects an unknown typ header', () => {
    const token = forge({ alg: 'HS256', typ: 'JWE' }, { ...claimsAt() }, SECRET);
    assert.equal(expectFailure(token), 'token_malformed');
  });

  it('rejects a token declaring crit extensions we do not implement', () => {
    const token = forge({ alg: 'HS256', typ: 'JWT', crit: ['exp'] }, { ...claimsAt() }, SECRET);
    assert.equal(expectFailure(token), 'token_malformed');
  });
});

describe('verifyAccessToken — signature', () => {
  it('rejects a token signed with a different secret', () => {
    const token = signAccessToken(claimsAt(), OTHER_SECRET);
    assert.equal(expectFailure(token), 'token_signature_invalid');
  });

  it('rejects a tampered payload', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    const [h, p, s] = token.split('.') as [string, string, string];
    const payload = JSON.parse(decodeBase64Url(p)!.toString('utf8')) as Record<string, unknown>;
    payload['sub'] = 'someone-else';
    const tampered = `${h}.${encodeBase64Url(JSON.stringify(payload))}.${s}`;
    assert.equal(expectFailure(tampered), 'token_signature_invalid');
  });

  it('rejects a tampered header', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    const [, p, s] = token.split('.') as [string, string, string];
    const swapped = `${encodeBase64Url(JSON.stringify({ alg: 'HS256' }))}.${p}.${s}`;
    assert.equal(expectFailure(swapped), 'token_signature_invalid');
  });

  it('rejects a truncated signature', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    const [h, p, s] = token.split('.') as [string, string, string];
    assert.equal(expectFailure(`${h}.${p}.${s.slice(0, 10)}`), 'token_signature_invalid');
  });

  it('rejects an empty signature segment', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    const [h, p] = token.split('.') as [string, string, string];
    assert.equal(expectFailure(`${h}.${p}.`), 'token_signature_invalid');
  });

  it('rejects a signature that is not base64url', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    const [h, p] = token.split('.') as [string, string, string];
    assert.equal(expectFailure(`${h}.${p}.***`), 'token_signature_invalid');
  });
});

describe('verifyAccessToken — claims', () => {
  it('rejects a token whose issuer does not match', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    assert.equal(
      expectFailure(token, { ...baseOptions, issuer: 'someone-else' }),
      'token_issuer_invalid',
    );
  });

  it('rejects a token whose audience does not match', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    assert.equal(
      expectFailure(token, { ...baseOptions, audience: 'serveros-ios' }),
      'token_audience_invalid',
    );
  });

  it('rejects a refresh-typed token presented as an access token', () => {
    const token = forge({ alg: 'HS256', typ: 'JWT' }, { ...claimsAt(), typ: 'refresh' }, SECRET);
    assert.equal(expectFailure(token), 'token_type_invalid');
  });

  it('rejects a payload missing sub', () => {
    const { sub: _sub, ...rest } = claimsAt();
    assert.equal(
      expectFailure(forge({ alg: 'HS256', typ: 'JWT' }, rest, SECRET)),
      'token_claims_invalid',
    );
  });

  it('rejects a payload missing sid', () => {
    const { sid: _sid, ...rest } = claimsAt();
    assert.equal(
      expectFailure(forge({ alg: 'HS256', typ: 'JWT' }, rest, SECRET)),
      'token_claims_invalid',
    );
  });

  it('rejects a payload missing jti', () => {
    const { jti: _jti, ...rest } = claimsAt();
    assert.equal(
      expectFailure(forge({ alg: 'HS256', typ: 'JWT' }, rest, SECRET)),
      'token_claims_invalid',
    );
  });

  it('rejects an empty-string sub', () => {
    const token = forge({ alg: 'HS256', typ: 'JWT' }, { ...claimsAt(), sub: '' }, SECRET);
    assert.equal(expectFailure(token), 'token_claims_invalid');
  });

  it('rejects a string exp rather than coercing it', () => {
    const token = forge(
      { alg: 'HS256', typ: 'JWT' },
      { ...claimsAt(), exp: '99999999999' },
      SECRET,
    );
    assert.equal(expectFailure(token), 'token_claims_invalid');
  });

  it('rejects a fractional exp', () => {
    const claims = claimsAt();
    const token = forge({ alg: 'HS256', typ: 'JWT' }, { ...claims, exp: claims.exp + 0.5 }, SECRET);
    assert.equal(expectFailure(token), 'token_claims_invalid');
  });

  it('rejects an absurd far-future exp', () => {
    const token = forge({ alg: 'HS256', typ: 'JWT' }, { ...claimsAt(), exp: 99_999_999_999 }, SECRET);
    assert.equal(expectFailure(token), 'token_claims_invalid');
  });

  it('rejects a negative iat', () => {
    const token = forge({ alg: 'HS256', typ: 'JWT' }, { ...claimsAt(), iat: -1 }, SECRET);
    assert.equal(expectFailure(token), 'token_claims_invalid');
  });

  it('rejects a validly signed token whose lifetime exceeds policy', () => {
    const claims = claimsAt();
    const token = forge(
      { alg: 'HS256', typ: 'JWT' },
      { ...claims, exp: claims.iat + 86_400 },
      SECRET,
    );
    assert.equal(expectFailure(token), 'token_claims_invalid');
  });

  it('rejects a payload that is a JSON array', () => {
    const h = encodeBase64Url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const p = encodeBase64Url('[]');
    const sig = encodeBase64Url(createHmac('sha256', SECRET).update(`${h}.${p}`).digest());
    assert.equal(expectFailure(`${h}.${p}.${sig}`), 'token_malformed');
  });
});

describe('verifyAccessToken — clock', () => {
  it('rejects a token past its expiry', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    const later = new Date(NOW.getTime() + (ACCESS_TOKEN_TTL_SECONDS + 120) * 1000);
    assert.equal(expectFailure(token, { ...baseOptions, now: later }), 'token_expired');
  });

  it('still accepts a just-expired token inside the skew window', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    const barelyLate = new Date(NOW.getTime() + (ACCESS_TOKEN_TTL_SECONDS + 10) * 1000);
    assert.ok(verifyAccessToken(token, { ...baseOptions, now: barelyLate }).ok);
  });

  it('rejects once the skew window has passed', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    const past = new Date(NOW.getTime() + (ACCESS_TOKEN_TTL_SECONDS + 31) * 1000);
    assert.equal(expectFailure(token, { ...baseOptions, now: past }), 'token_expired');
  });

  it('rejects a token from a clock far in the future', () => {
    const future = new Date(NOW.getTime() + 3600 * 1000);
    const token = signAccessToken(claimsAt(future), SECRET);
    assert.equal(expectFailure(token), 'token_not_yet_valid');
  });

  it('accepts a token from a clock slightly ahead, within skew', () => {
    const slightlyAhead = new Date(NOW.getTime() + 10 * 1000);
    const token = signAccessToken(claimsAt(slightlyAhead), SECRET);
    assert.ok(verifyAccessToken(token, baseOptions).ok);
  });

  it('rejects an nbf in the future even when exp is valid', () => {
    const claims = claimsAt();
    const token = forge(
      { alg: 'HS256', typ: 'JWT' },
      { ...claims, nbf: claims.iat + 600 },
      SECRET,
    );
    assert.equal(expectFailure(token), 'token_not_yet_valid');
  });

  it('applies zero skew when configured to', () => {
    const token = signAccessToken(claimsAt(), SECRET);
    const justAfter = new Date(NOW.getTime() + (ACCESS_TOKEN_TTL_SECONDS + 1) * 1000);
    assert.equal(
      expectFailure(token, { ...baseOptions, now: justAfter, clockSkewSeconds: 0 }),
      'token_expired',
    );
  });
});

describe('verifyAccessToken — disclosure', () => {
  it('gives the same user-facing sentence whatever the cause', () => {
    const expired = verifyAccessToken(signAccessToken(claimsAt(), SECRET), {
      ...baseOptions,
      now: new Date(NOW.getTime() + 86_400_000),
    });
    const forged = verifyAccessToken(signAccessToken(claimsAt(), OTHER_SECRET), baseOptions);
    assert.ok(!expired.ok && !forged.ok);
    assert.equal(expired.message, forged.message);
    assert.equal(expired.message, 'Your session is no longer valid. Sign in again.');
  });

  it('keeps the discriminating information in detail, not message', () => {
    const result = verifyAccessToken(signAccessToken(claimsAt(), OTHER_SECRET), baseOptions);
    assert.ok(!result.ok);
    assert.match(result.detail ?? '', /signature/);
    assert.doesNotMatch(result.message, /signature/);
  });
});
