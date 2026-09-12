import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  DUMMY_ARGON2ID_HASH,
  MIN_PASSWORD_LENGTH,
  authenticate,
  isArgon2idHash,
  validatePasswordStrength,
  type CredentialRecord,
  type PasswordHasher,
} from './password.logic.js';

/** Records every call so the anti-enumeration invariant can be asserted. */
class FakeHasher implements PasswordHasher {
  readonly verifyCalls: Array<{ storedHash: string; plaintext: string }> = [];
  readonly hashCalls: string[] = [];
  constructor(private readonly pairs: ReadonlyMap<string, string> = new Map()) {}

  async hash(plaintext: string): Promise<string> {
    this.hashCalls.push(plaintext);
    return `$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$${Buffer.from(plaintext).toString('base64url')}`;
  }

  async verify(storedHash: string, plaintext: string): Promise<boolean> {
    this.verifyCalls.push({ storedHash, plaintext });
    return this.pairs.get(storedHash) === plaintext;
  }
}

const GOOD_HASH = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$c29tZWhhc2g';

function record(overrides: Partial<CredentialRecord> = {}): CredentialRecord {
  return { userId: 'user-1', passwordHash: GOOD_HASH, isActive: true, ...overrides };
}

describe('validatePasswordStrength', () => {
  it('accepts a reasonable passphrase', () => {
    assert.ok(validatePasswordStrength('correct horse battery').ok);
  });

  it('rejects a non-string', () => {
    const result = validatePasswordStrength(12345678901234);
    assert.ok(!result.ok);
    assert.equal(result.code, 'password_invalid');
  });

  it(`rejects fewer than ${MIN_PASSWORD_LENGTH} characters`, () => {
    const result = validatePasswordStrength('short1234');
    assert.ok(!result.ok);
    assert.equal(result.code, 'password_too_short');
  });

  it('accepts exactly the minimum length', () => {
    assert.ok(validatePasswordStrength('abcdefghijkm').ok);
  });

  it('rejects an over-long password to bound hashing cost', () => {
    const result = validatePasswordStrength('a1b2'.repeat(500));
    assert.ok(!result.ok);
    assert.equal(result.code, 'password_too_long');
  });

  it('counts bytes, not code points, for the upper bound', () => {
    // 400 four-byte emoji is 1600 bytes but only 400 characters.
    const result = validatePasswordStrength('🔐'.repeat(400));
    assert.ok(!result.ok);
    assert.equal(result.code, 'password_too_long');
  });

  it('rejects whitespace-only input', () => {
    const result = validatePasswordStrength(' '.repeat(20));
    assert.ok(!result.ok);
    assert.equal(result.code, 'password_invalid');
    assert.equal(result.message, 'A password cannot be only spaces.');
  });

  it('rejects a repeated single character', () => {
    const result = validatePasswordStrength('aaaaaaaaaaaaaaa');
    assert.ok(!result.ok);
    assert.equal(result.code, 'password_too_simple');
  });

  it('rejects a well-known password', () => {
    const result = validatePasswordStrength('password123');
    assert.ok(!result.ok);
    // Length check fires first for this one; the point is that it is refused.
    assert.ok(result.code.startsWith('password_'));
  });

  it('rejects a banned password that is long enough to pass the length check', () => {
    const result = validatePasswordStrength('administrator');
    assert.ok(!result.ok);
    assert.equal(result.code, 'password_too_common');
  });

  it('rejects a password containing the email local part', () => {
    const result = validatePasswordStrength('alexandra-rules', 'alexandra@example.com');
    assert.ok(!result.ok);
    assert.equal(result.code, 'password_too_similar');
  });

  it('ignores a very short local part rather than banning common substrings', () => {
    assert.ok(validatePasswordStrength('a fine long passphrase', 'a@example.com').ok);
  });

  it('does not impose composition rules', () => {
    assert.ok(validatePasswordStrength('all lowercase words here').ok);
  });
});

describe('isArgon2idHash', () => {
  it('accepts a well-formed encoding', () => {
    assert.ok(isArgon2idHash(GOOD_HASH));
  });

  it('rejects a bcrypt hash', () => {
    assert.ok(!isArgon2idHash('$2b$12$abcdefghijklmnopqrstuv'));
  });

  it('rejects argon2i and argon2d', () => {
    assert.ok(!isArgon2idHash('$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA'));
    assert.ok(!isArgon2idHash('$argon2d$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA'));
  });

  it('rejects plaintext that was stored by mistake', () => {
    assert.ok(!isArgon2idHash('hunter2hunter2'));
  });

  it('rejects a non-string', () => {
    assert.ok(!isArgon2idHash(null));
    assert.ok(!isArgon2idHash(undefined));
  });

  it('recognises the dummy hash used for constant-time denial', () => {
    assert.ok(isArgon2idHash(DUMMY_ARGON2ID_HASH));
  });
});

describe('authenticate', () => {
  it('succeeds with the right password', async () => {
    const hasher = new FakeHasher(new Map([[GOOD_HASH, 'right-password']]));
    const result = await authenticate(hasher, record(), 'right-password');
    assert.ok(result.ok);
    assert.equal(result.value.userId, 'user-1');
  });

  it('fails with the wrong password', async () => {
    const hasher = new FakeHasher(new Map([[GOOD_HASH, 'right-password']]));
    const result = await authenticate(hasher, record(), 'wrong-password');
    assert.ok(!result.ok);
    assert.equal(result.code, 'invalid_credentials');
  });

  it('fails for an unknown address', async () => {
    const hasher = new FakeHasher();
    const result = await authenticate(hasher, null, 'anything-at-all');
    assert.ok(!result.ok);
    assert.equal(result.code, 'invalid_credentials');
  });

  it('still runs one hash verification when the user does not exist', async () => {
    const hasher = new FakeHasher();
    await authenticate(hasher, null, 'anything-at-all');
    assert.equal(hasher.verifyCalls.length, 1);
    assert.equal(hasher.verifyCalls[0]?.storedHash, DUMMY_ARGON2ID_HASH);
  });

  it('runs exactly one hash verification on every path', async () => {
    const pairs = new Map([[GOOD_HASH, 'right-password']]);
    for (const [rec, pwd] of [
      [record(), 'right-password'],
      [record(), 'wrong-password'],
      [record({ isActive: false }), 'right-password'],
      [null, 'anything'],
    ] as const) {
      const hasher = new FakeHasher(pairs);
      await authenticate(hasher, rec, pwd);
      assert.equal(hasher.verifyCalls.length, 1);
    }
  });

  it('denies a deactivated account', async () => {
    const hasher = new FakeHasher(new Map([[GOOD_HASH, 'right-password']]));
    const result = await authenticate(hasher, record({ isActive: false }), 'right-password');
    assert.ok(!result.ok);
    assert.equal(result.code, 'invalid_credentials');
  });

  it('gives an identical code and sentence for unknown, wrong and deactivated', async () => {
    const pairs = new Map([[GOOD_HASH, 'right-password']]);
    const unknown = await authenticate(new FakeHasher(pairs), null, 'x'.repeat(12));
    const wrong = await authenticate(new FakeHasher(pairs), record(), 'nope-nope-nope');
    const inactive = await authenticate(
      new FakeHasher(pairs),
      record({ isActive: false }),
      'right-password',
    );
    assert.ok(!unknown.ok && !wrong.ok && !inactive.ok);
    assert.equal(unknown.code, wrong.code);
    assert.equal(wrong.code, inactive.code);
    assert.equal(unknown.message, wrong.message);
    assert.equal(wrong.message, inactive.message);
  });

  it('never puts the password or the hash in the failure', async () => {
    const hasher = new FakeHasher();
    const result = await authenticate(hasher, record(), 'super-secret-value');
    assert.ok(!result.ok);
    const serialised = JSON.stringify(result);
    assert.ok(!serialised.includes('super-secret-value'));
    assert.ok(!serialised.includes(GOOD_HASH));
  });

  it('throws rather than denying when the stored hash is not Argon2id', async () => {
    const hasher = new FakeHasher();
    await assert.rejects(
      () => authenticate(hasher, record({ passwordHash: '$2b$12$legacybcrypt' }), 'whatever'),
      /not an Argon2id hash/,
    );
  });

  it('does not consult the hasher when the stored hash is unusable', async () => {
    const hasher = new FakeHasher();
    await authenticate(hasher, record({ passwordHash: 'plaintext!' }), 'whatever').catch(
      () => undefined,
    );
    assert.equal(hasher.verifyCalls.length, 0);
  });
});
