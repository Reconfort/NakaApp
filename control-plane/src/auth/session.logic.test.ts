import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  REFRESH_TOKEN_TTL_SECONDS,
  buildRotationGuard,
  decideRefresh,
  generateRefreshToken,
  hashRefreshToken,
  hashesMatch,
  interpretRotationResult,
  looksLikeRefreshToken,
  parsePresentedRefreshToken,
  type SessionRecord,
} from './session.logic.js';

const NOW = new Date('2026-09-12T10:00:00.000Z');

function session(overrides: Partial<SessionRecord> = {}): SessionRecord {
  return {
    id: 'session-1',
    userId: 'user-1',
    familyId: 'family-1',
    expiresAt: new Date(NOW.getTime() + 86_400_000),
    rotatedAt: null,
    revokedAt: null,
    ...overrides,
  };
}

describe('generateRefreshToken', () => {
  it('produces a 43-character base64url token from 32 random bytes', () => {
    const { token } = generateRefreshToken(() => Buffer.alloc(32, 7));
    assert.equal(token.length, 43);
    assert.match(token, /^[A-Za-z0-9_-]+$/);
  });

  it('returns the hash of the token it returns', () => {
    const { token, tokenHash } = generateRefreshToken(() => Buffer.alloc(32, 3));
    assert.equal(tokenHash, hashRefreshToken(token));
  });

  it('is unique across calls with real randomness', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i += 1) seen.add(generateRefreshToken().token);
    assert.equal(seen.size, 200);
  });

  it('does not embed the plaintext in the hash', () => {
    const { token, tokenHash } = generateRefreshToken();
    assert.ok(!tokenHash.includes(token));
    assert.equal(tokenHash.length, 64);
  });
});

describe('hashesMatch', () => {
  it('matches identical hashes', () => {
    assert.ok(hashesMatch(hashRefreshToken('a'), hashRefreshToken('a')));
  });

  it('rejects different hashes', () => {
    assert.ok(!hashesMatch(hashRefreshToken('a'), hashRefreshToken('b')));
  });

  it('rejects different lengths without throwing', () => {
    assert.ok(!hashesMatch('abc', 'abcd'));
  });
});

describe('looksLikeRefreshToken', () => {
  it('accepts a generated token', () => {
    assert.ok(looksLikeRefreshToken(generateRefreshToken().token));
  });

  it('rejects the wrong length', () => {
    assert.ok(!looksLikeRefreshToken('short'));
    assert.ok(!looksLikeRefreshToken('a'.repeat(44)));
  });

  it('rejects characters outside base64url', () => {
    assert.ok(!looksLikeRefreshToken(`${'a'.repeat(42)}+`));
    assert.ok(!looksLikeRefreshToken(`${'a'.repeat(42)}=`));
  });

  it('rejects non-strings', () => {
    assert.ok(!looksLikeRefreshToken(null));
    assert.ok(!looksLikeRefreshToken(undefined));
    assert.ok(!looksLikeRefreshToken(12345));
  });
});

describe('parsePresentedRefreshToken', () => {
  it('accepts a well-formed token', () => {
    const { token } = generateRefreshToken();
    const result = parsePresentedRefreshToken(token);
    assert.ok(result.ok);
    assert.equal(result.value, token);
  });

  it('rejects junk with a uniform message', () => {
    const result = parsePresentedRefreshToken('nope');
    assert.ok(!result.ok);
    assert.equal(result.code, 'refresh_token_malformed');
    assert.equal(result.message, 'Your session has ended. Sign in again.');
  });
});

describe('decideRefresh', () => {
  it('rotates a live, unused token', () => {
    const decision = decideRefresh({ record: session(), now: NOW });
    assert.equal(decision.action, 'rotate');
    assert.ok(decision.action === 'rotate');
    assert.equal(decision.userId, 'user-1');
    assert.equal(decision.familyId, 'family-1');
    assert.equal(decision.previousSessionId, 'session-1');
  });

  it('gives the successor the full policy lifetime', () => {
    const decision = decideRefresh({ record: session(), now: NOW });
    assert.ok(decision.action === 'rotate');
    assert.equal(
      decision.expiresAt.getTime(),
      NOW.getTime() + REFRESH_TOKEN_TTL_SECONDS * 1000,
    );
  });

  it('honours an explicit ttl', () => {
    const decision = decideRefresh({ record: session(), now: NOW, ttlSeconds: 60 });
    assert.ok(decision.action === 'rotate');
    assert.equal(decision.expiresAt.getTime(), NOW.getTime() + 60_000);
  });

  it('rejects an unknown token', () => {
    const decision = decideRefresh({ record: null, now: NOW });
    assert.equal(decision.action, 'reject');
    assert.ok(decision.action === 'reject');
    assert.equal(decision.code, 'refresh_token_unknown');
  });

  it('revokes the family when an already-rotated token is presented', () => {
    const decision = decideRefresh({
      record: session({ rotatedAt: new Date(NOW.getTime() - 1000) }),
      now: NOW,
    });
    assert.equal(decision.action, 'revoke_family');
    assert.ok(decision.action === 'revoke_family');
    assert.equal(decision.familyId, 'family-1');
    assert.equal(decision.reason, 'reuse_detected');
    assert.equal(decision.code, 'refresh_token_reused');
  });

  it('revokes the family when an explicitly revoked token is presented', () => {
    const decision = decideRefresh({
      record: session({ revokedAt: new Date(NOW.getTime() - 1000) }),
      now: NOW,
    });
    assert.ok(decision.action === 'revoke_family');
    assert.equal(decision.code, 'refresh_token_revoked');
  });

  it('treats reuse of an expired token as theft, not as expiry', () => {
    // A replayed token that also happens to be expired is still evidence that
    // two parties held it; the family must die.
    const decision = decideRefresh({
      record: session({
        rotatedAt: new Date(NOW.getTime() - 10_000),
        expiresAt: new Date(NOW.getTime() - 1000),
      }),
      now: NOW,
    });
    assert.equal(decision.action, 'revoke_family');
  });

  it('rejects an expired but never-used token without revoking the family', () => {
    const decision = decideRefresh({
      record: session({ expiresAt: new Date(NOW.getTime() - 1) }),
      now: NOW,
    });
    assert.equal(decision.action, 'reject');
    assert.ok(decision.action === 'reject');
    assert.equal(decision.code, 'refresh_token_expired');
  });

  it('treats expiry as inclusive at the exact instant', () => {
    const decision = decideRefresh({ record: session({ expiresAt: NOW }), now: NOW });
    assert.ok(decision.action === 'reject');
    assert.equal(decision.code, 'refresh_token_expired');
  });

  it('still rotates one millisecond before expiry', () => {
    const decision = decideRefresh({
      record: session({ expiresAt: new Date(NOW.getTime() + 1) }),
      now: NOW,
    });
    assert.equal(decision.action, 'rotate');
  });

  it('uses one sentence for every failure mode', () => {
    const decisions = [
      decideRefresh({ record: null, now: NOW }),
      decideRefresh({ record: session({ rotatedAt: NOW }), now: NOW }),
      decideRefresh({ record: session({ revokedAt: NOW }), now: NOW }),
      decideRefresh({ record: session({ expiresAt: new Date(0) }), now: NOW }),
    ];
    const messages = new Set<string>();
    for (const decision of decisions) {
      assert.notEqual(decision.action, 'rotate');
      if (decision.action !== 'rotate') messages.add(decision.message);
    }
    assert.equal(messages.size, 1);
  });
});

describe('concurrent rotation', () => {
  it('guards the update on the row still being unused', () => {
    assert.deepEqual(buildRotationGuard('session-9'), {
      id: 'session-9',
      rotatedAt: null,
      revokedAt: null,
    });
  });

  it('accepts the winner of a race', () => {
    const result = interpretRotationResult(1, session());
    assert.ok('ok' in result && result.ok);
  });

  it('converts the loser of a race into a family revocation', () => {
    const result = interpretRotationResult(0, session());
    assert.ok(!('ok' in result));
    assert.equal(result.action, 'revoke_family');
    assert.equal(result.reason, 'reuse_detected');
    assert.equal(result.familyId, 'family-1');
  });

  it('treats a multi-row update as a race loss rather than success', () => {
    const result = interpretRotationResult(2, session());
    assert.ok(!('ok' in result));
  });
});
