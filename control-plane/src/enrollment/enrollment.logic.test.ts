import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  CODE_ENTROPY_BITS,
  ENROLLMENT_TTL_SECONDS,
  buildConsumeGuard,
  canonicaliseCode,
  codeHashesMatch,
  decideConsume,
  enrollmentExpiry,
  generateEnrollmentCode,
  groupCode,
  hashEnrollmentCode,
  interpretConsumeResult,
  type EnrollmentRecord,
} from './enrollment.logic.js';

const NOW = new Date('2026-09-12T10:00:00.000Z');

function enrollment(overrides: Partial<EnrollmentRecord> = {}): EnrollmentRecord {
  const canonical = 'ABCD'.repeat(7);
  return {
    id: 'enrollment-1',
    serverId: 'server-1',
    codeHash: hashEnrollmentCode(canonical),
    expiresAt: new Date(NOW.getTime() + 600_000),
    consumedAt: null,
    ...overrides,
  };
}

const VALID_CANONICAL = 'ABCD'.repeat(7);

describe('generateEnrollmentCode', () => {
  it('carries at least the required 128 bits of entropy', () => {
    assert.ok(CODE_ENTROPY_BITS >= 128);
    assert.equal(CODE_ENTROPY_BITS, 140);
  });

  it('produces 28 characters grouped in fours', () => {
    const { display, canonical } = generateEnrollmentCode();
    assert.equal(canonical.length, 28);
    assert.equal(display, groupCode(canonical));
    assert.equal(display.split('-').length, 7);
    assert.ok(display.split('-').every((group) => group.length === 4));
  });

  it('never emits the ambiguous characters I, L, O or U', () => {
    for (let i = 0; i < 200; i += 1) {
      assert.doesNotMatch(generateEnrollmentCode().canonical, /[ILOU]/);
    }
  });

  it('uses the whole alphabet uniformly from masked bytes', () => {
    // Bytes 0..255 masked to 5 bits must walk the alphabet exactly 8 times.
    const bytes = Buffer.from(Array.from({ length: 28 }, (_, i) => i));
    const { canonical } = generateEnrollmentCode(() => bytes);
    assert.equal(canonical.slice(0, 10), '0123456789');
  });

  it('returns the hash of the canonical form it returns', () => {
    const generated = generateEnrollmentCode();
    assert.equal(generated.codeHash, hashEnrollmentCode(generated.canonical));
  });

  it('does not leak the code into its own hash', () => {
    const { canonical, codeHash } = generateEnrollmentCode();
    assert.ok(!codeHash.includes(canonical));
    assert.equal(codeHash.length, 64);
  });

  it('is unique across many draws', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 500; i += 1) seen.add(generateEnrollmentCode().canonical);
    assert.equal(seen.size, 500);
  });

  it('refuses to build a code from a short random source', () => {
    assert.throws(() => generateEnrollmentCode(() => Buffer.alloc(4)), /need 28/);
  });
});

describe('canonicaliseCode', () => {
  it('accepts the display form', () => {
    const { display, canonical } = generateEnrollmentCode();
    assert.equal(canonicaliseCode(display), canonical);
  });

  it('accepts the canonical form unchanged', () => {
    assert.equal(canonicaliseCode(VALID_CANONICAL), VALID_CANONICAL);
  });

  it('accepts lower case', () => {
    assert.equal(canonicaliseCode(VALID_CANONICAL.toLowerCase()), VALID_CANONICAL);
  });

  it('tolerates spaces instead of dashes', () => {
    assert.equal(canonicaliseCode(groupCode(VALID_CANONICAL).replace(/-/g, ' ')), VALID_CANONICAL);
  });

  it('tolerates a code pasted with surrounding whitespace', () => {
    assert.equal(canonicaliseCode(`  ${VALID_CANONICAL}\n`), VALID_CANONICAL);
  });

  it("maps the letter O onto zero, because that is what people type", () => {
    const typed = `O${VALID_CANONICAL.slice(1)}`;
    assert.equal(canonicaliseCode(typed), `0${VALID_CANONICAL.slice(1)}`);
  });

  it('maps I and l onto one', () => {
    assert.equal(canonicaliseCode(`I${VALID_CANONICAL.slice(1)}`), `1${VALID_CANONICAL.slice(1)}`);
    assert.equal(canonicaliseCode(`l${VALID_CANONICAL.slice(1)}`), `1${VALID_CANONICAL.slice(1)}`);
  });

  it('rejects a code of the wrong length', () => {
    assert.equal(canonicaliseCode('ABCD'), null);
    assert.equal(canonicaliseCode(`${VALID_CANONICAL}A`), null);
  });

  it('rejects characters outside the alphabet', () => {
    assert.equal(canonicaliseCode(`$${VALID_CANONICAL.slice(1)}`), null);
    assert.equal(canonicaliseCode(`U${VALID_CANONICAL.slice(1)}`), null);
  });

  it('rejects a non-string', () => {
    assert.equal(canonicaliseCode(null), null);
    assert.equal(canonicaliseCode(undefined), null);
    assert.equal(canonicaliseCode(12345), null);
  });

  it('bounds the work before doing it', () => {
    assert.equal(canonicaliseCode('-'.repeat(10_000)), null);
  });
});

describe('codeHashesMatch', () => {
  it('matches a hash with itself', () => {
    const hash = hashEnrollmentCode(VALID_CANONICAL);
    assert.ok(codeHashesMatch(hash, hash));
  });

  it('rejects a different hash', () => {
    assert.ok(!codeHashesMatch(hashEnrollmentCode('A'.repeat(28)), hashEnrollmentCode('B'.repeat(28))));
  });

  it('rejects a length mismatch without throwing', () => {
    assert.ok(!codeHashesMatch('abc', 'abcdef'));
  });
});

describe('decideConsume', () => {
  it('accepts a live, unused code', () => {
    const result = decideConsume({
      record: enrollment(),
      presentedCanonical: VALID_CANONICAL,
      now: NOW,
    });
    assert.ok(result.ok);
    assert.equal(result.value.enrollmentId, 'enrollment-1');
    assert.equal(result.value.serverId, 'server-1');
  });

  it('rejects an unknown code', () => {
    const result = decideConsume({ record: null, presentedCanonical: VALID_CANONICAL, now: NOW });
    assert.ok(!result.ok);
    assert.equal(result.code, 'enrollment_code_invalid');
  });

  it('rejects a code whose hash does not match the row', () => {
    const result = decideConsume({
      record: enrollment({ codeHash: hashEnrollmentCode('Z'.repeat(28)) }),
      presentedCanonical: VALID_CANONICAL,
      now: NOW,
    });
    assert.ok(!result.ok);
    assert.equal(result.code, 'enrollment_code_invalid');
  });

  it('rejects an already-consumed code', () => {
    const result = decideConsume({
      record: enrollment({ consumedAt: new Date(NOW.getTime() - 1000) }),
      presentedCanonical: VALID_CANONICAL,
      now: NOW,
    });
    assert.ok(!result.ok);
    assert.equal(result.code, 'enrollment_code_already_used');
  });

  it('rejects an expired code', () => {
    const result = decideConsume({
      record: enrollment({ expiresAt: new Date(NOW.getTime() - 1) }),
      presentedCanonical: VALID_CANONICAL,
      now: NOW,
    });
    assert.ok(!result.ok);
    assert.equal(result.code, 'enrollment_code_expired');
  });

  it('treats expiry as inclusive at the exact instant', () => {
    const result = decideConsume({
      record: enrollment({ expiresAt: NOW }),
      presentedCanonical: VALID_CANONICAL,
      now: NOW,
    });
    assert.ok(!result.ok);
    assert.equal(result.code, 'enrollment_code_expired');
  });

  it('still accepts one millisecond before expiry', () => {
    const result = decideConsume({
      record: enrollment({ expiresAt: new Date(NOW.getTime() + 1) }),
      presentedCanonical: VALID_CANONICAL,
      now: NOW,
    });
    assert.ok(result.ok);
  });

  it('reports "already used" ahead of "expired" for a code that is both', () => {
    // A redeemed code that later expired was still redeemed; saying so is more
    // useful than blaming the clock.
    const result = decideConsume({
      record: enrollment({
        consumedAt: new Date(NOW.getTime() - 10_000),
        expiresAt: new Date(NOW.getTime() - 1000),
      }),
      presentedCanonical: VALID_CANONICAL,
      now: NOW,
    });
    assert.ok(!result.ok);
    assert.equal(result.code, 'enrollment_code_already_used');
  });

  it('gives one sentence for every failure so the endpoint is not an oracle', () => {
    const failures = [
      decideConsume({ record: null, presentedCanonical: VALID_CANONICAL, now: NOW }),
      decideConsume({
        record: enrollment({ consumedAt: NOW }),
        presentedCanonical: VALID_CANONICAL,
        now: NOW,
      }),
      decideConsume({
        record: enrollment({ expiresAt: new Date(0) }),
        presentedCanonical: VALID_CANONICAL,
        now: NOW,
      }),
      decideConsume({
        record: enrollment({ codeHash: hashEnrollmentCode('Z'.repeat(28)) }),
        presentedCanonical: VALID_CANONICAL,
        now: NOW,
      }),
    ];
    const messages = new Set(failures.map((f) => (f.ok ? '' : f.message)));
    assert.equal(messages.size, 1);
    assert.equal([...messages][0], "That enrollment code isn't valid. Generate a new one from ServerOS.");
  });

  it('never echoes the presented code back to the caller', () => {
    const result = decideConsume({
      record: enrollment({ consumedAt: NOW }),
      presentedCanonical: VALID_CANONICAL,
      now: NOW,
    });
    assert.ok(!JSON.stringify(result).includes(VALID_CANONICAL));
  });
});

describe('concurrent consume', () => {
  it('guards the update on the row still being unconsumed', () => {
    assert.deepEqual(buildConsumeGuard('e-9'), { id: 'e-9', consumedAt: null });
  });

  it('accepts the winner of a race', () => {
    const result = interpretConsumeResult(1, { enrollmentId: 'e-1', serverId: 's-1' });
    assert.ok(result.ok);
    assert.equal(result.value.serverId, 's-1');
  });

  it('turns the loser of a race into "already used"', () => {
    const result = interpretConsumeResult(0, { enrollmentId: 'e-1', serverId: 's-1' });
    assert.ok(!result.ok);
    assert.equal(result.code, 'enrollment_code_already_used');
  });

  it('does not treat a multi-row update as success', () => {
    assert.ok(!interpretConsumeResult(2, { enrollmentId: 'e-1', serverId: 's-1' }).ok);
  });
});

describe('enrollmentExpiry', () => {
  it('defaults to fifteen minutes', () => {
    assert.equal(ENROLLMENT_TTL_SECONDS, 900);
    assert.equal(enrollmentExpiry(NOW).getTime(), NOW.getTime() + 900_000);
  });

  it('honours an explicit ttl', () => {
    assert.equal(enrollmentExpiry(NOW, 60).getTime(), NOW.getTime() + 60_000);
  });
});
