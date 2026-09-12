import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { REDACTED, isSensitiveKey, redactMetadata, redactString } from './redaction.logic.js';

/** Asserts that no part of the serialised output contains the needle. */
function assertAbsent(value: unknown, needle: string): void {
  assert.ok(
    !JSON.stringify(value).includes(needle),
    `expected ${needle} to be absent from ${JSON.stringify(value)}`,
  );
}

describe('isSensitiveKey', () => {
  const sensitive = [
    'password',
    'passwd',
    'passphrase',
    'Password',
    'user_password',
    'apiKey',
    'api_key',
    'API-KEY',
    'secret',
    'clientSecret',
    'token',
    'accessToken',
    'refreshToken',
    'authorization',
    'Authorization',
    'cookie',
    'privateKey',
    'private_key',
    'sessionId',
    'signature',
    'otp',
    'totp',
    'pin',
    'connectionString',
    'DSN',
    'env',
  ];
  for (const key of sensitive) {
    it(`treats ${key} as sensitive`, () => {
      assert.ok(isSensitiveKey(key));
    });
  }

  const safe = ['name', 'containerId', 'imageTag', 'tokenCount', 'sessionCount', 'authMethod', 'environment'];
  for (const key of safe) {
    it(`leaves ${key} alone`, () => {
      assert.ok(!isSensitiveKey(key));
    });
  }
});

describe('redactString', () => {
  it('removes a PEM private key block', () => {
    const value = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB\n-----END RSA PRIVATE KEY-----';
    assert.equal(redactString(value), REDACTED);
  });

  it('removes an OpenSSH private key block', () => {
    assert.equal(redactString('-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb\n'), REDACTED);
  });

  it('removes a JWT found in free text', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJlX2hlcmU';
    assert.equal(redactString(`token is ${jwt}`), REDACTED);
  });

  it('removes an Authorization header value', () => {
    assert.equal(redactString('Bearer abcdefghijklmnopqrst'), REDACTED);
    assert.equal(redactString('Basic dXNlcjpwYXNzd29yZA=='), REDACTED);
  });

  it('removes an AWS access key id', () => {
    assert.equal(redactString('AKIAIOSFODNN7EXAMPLE'), REDACTED);
  });

  it('removes a GitHub token', () => {
    assert.equal(redactString('ghp_16C7e42F292c6912E7710c838347Ae178B4a'), REDACTED);
  });

  it('removes an OpenAI-style key', () => {
    assert.equal(redactString('sk-abcdefghijklmnopqrstuvwx'), REDACTED);
  });

  it('removes a Slack token', () => {
    assert.equal(redactString('xoxb-1234567890-abcdefghij'), REDACTED);
  });

  it('rewrites a database URL, keeping the useful part', () => {
    assert.equal(
      redactString('postgres://app:hunter2@db.internal:5432/serveros'),
      `postgres://app:${REDACTED}@db.internal:5432/serveros`,
    );
  });

  it('rewrites an https URL with inline credentials', () => {
    assert.equal(
      redactString('https://deploy:s3cr3t@registry.example.com/v2/'),
      `https://deploy:${REDACTED}@registry.example.com/v2/`,
    );
  });

  it('leaves an ordinary URL untouched', () => {
    assert.equal(redactString('https://example.com/a/b?c=1'), 'https://example.com/a/b?c=1');
  });

  it('leaves ordinary prose untouched', () => {
    assert.equal(redactString('Restarted nginx in 240ms'), 'Restarted nginx in 240ms');
  });

  it('truncates an enormous string', () => {
    const result = redactString('a'.repeat(10_000));
    assert.ok(result.length <= 2049);
    assert.ok(result.endsWith('…'));
  });
});

describe('redactMetadata — key pass', () => {
  it('removes a password', () => {
    const result = redactMetadata({ user: 'alex', password: 'hunter2' });
    assert.equal(result['password'], REDACTED);
    assert.equal(result['user'], 'alex');
    assertAbsent(result, 'hunter2');
  });

  it('removes a nested token', () => {
    const result = redactMetadata({ request: { headers: { authorization: 'Bearer xyz' } } });
    assertAbsent(result, 'Bearer xyz');
  });

  it('removes a key regardless of separator style', () => {
    const result = redactMetadata({ api_key: 'k1', 'API-KEY': 'k2', apiKey: 'k3' });
    assertAbsent(result, 'k1');
    assertAbsent(result, 'k2');
    assertAbsent(result, 'k3');
  });

  it('removes secrets inside arrays of objects', () => {
    const result = redactMetadata({ users: [{ name: 'a', password: 'p1' }, { name: 'b', password: 'p2' }] });
    assertAbsent(result, 'p1');
    assertAbsent(result, 'p2');
  });

  it('keeps a metric whose name merely resembles a secret', () => {
    const result = redactMetadata({ tokenCount: 42, sessionCount: 3 });
    assert.equal(result['tokenCount'], 42);
    assert.equal(result['sessionCount'], 3);
  });

  it('removes an env map wholesale', () => {
    const result = redactMetadata({ env: { DATABASE_URL: 'postgres://a:b@c/d', PORT: '3000' } });
    assert.equal(result['env'], REDACTED);
  });
});

describe('redactMetadata — value pass', () => {
  it('removes an SSH private key hiding under an innocent key', () => {
    const result = redactMetadata({ note: '-----BEGIN OPENSSH PRIVATE KEY-----\nabc' });
    assert.equal(result['note'], REDACTED);
  });

  it('removes a JWT hiding under an innocent key', () => {
    const result = redactMetadata({
      description: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlZGF0YQ',
    });
    assert.equal(result['description'], REDACTED);
  });

  it('rewrites a connection string hiding under an innocent key', () => {
    const result = redactMetadata({ target: 'mysql://root:toor@10.0.0.5:3306/app' });
    assertAbsent(result, 'toor');
    assert.ok(String(result['target']).includes('10.0.0.5'));
  });
});

describe('redactMetadata — totality', () => {
  it('does not mutate its input', () => {
    const input = { password: 'hunter2', nested: { token: 'abc' } };
    const snapshot = JSON.stringify(input);
    redactMetadata(input);
    assert.equal(JSON.stringify(input), snapshot);
  });

  it('survives a cyclic structure', () => {
    const input: Record<string, unknown> = { name: 'loop' };
    input['self'] = input;
    const result = redactMetadata(input);
    assert.equal(result['self'], '[circular]');
  });

  it('truncates runaway nesting', () => {
    let deep: Record<string, unknown> = { leaf: true };
    for (let i = 0; i < 50; i += 1) deep = { child: deep };
    const result = redactMetadata(deep);
    assert.ok(JSON.stringify(result).includes('[truncated]'));
  });

  it('caps the number of object entries', () => {
    const wide: Record<string, number> = {};
    for (let i = 0; i < 500; i += 1) wide[`k${i}`] = i;
    const result = redactMetadata(wide);
    assert.ok(Object.keys(result).length <= 65);
  });

  it('caps array length and says how much was dropped', () => {
    const result = redactMetadata({ items: Array.from({ length: 500 }, (_, i) => i) });
    const items = result['items'];
    assert.ok(Array.isArray(items));
    assert.ok(items.length <= 65);
    assert.equal(items[items.length - 1], '…436 more');
  });

  it('wraps a non-object input so the JSON column stays an object', () => {
    assert.deepEqual(redactMetadata('just a string'), { value: 'just a string' });
    assert.deepEqual(redactMetadata(42), { value: 42 });
    assert.deepEqual(redactMetadata(null), { value: null });
  });

  it('wraps a top-level array', () => {
    assert.deepEqual(redactMetadata([1, 2]), { value: [1, 2] });
  });

  it('converts a Date to ISO-8601', () => {
    const result = redactMetadata({ at: new Date('2026-09-12T10:00:00.000Z') });
    assert.equal(result['at'], '2026-09-12T10:00:00.000Z');
  });

  it('handles an invalid Date', () => {
    assert.equal(redactMetadata({ at: new Date('nope') })['at'], null);
  });

  it('keeps only the message of an Error, never the stack', () => {
    const result = redactMetadata({ cause: new Error('container exited') });
    assert.equal(result['cause'], 'container exited');
    assertAbsent(result, 'redaction.logic.test');
  });

  it('replaces a Buffer with its size rather than its bytes', () => {
    const result = redactMetadata({ blob: Buffer.from('secret key material') });
    assert.equal(result['blob'], '[19 bytes]');
    assertAbsent(result, 'secret key material');
  });

  it('drops non-JSON numbers', () => {
    const result = redactMetadata({ a: Number.NaN, b: Number.POSITIVE_INFINITY, c: 1 });
    assert.equal(result['a'], null);
    assert.equal(result['b'], null);
    assert.equal(result['c'], 1);
  });

  it('drops functions and symbols', () => {
    const result = redactMetadata({ fn: () => 1, sym: Symbol('s'), ok: true });
    assert.equal(result['fn'], null);
    assert.equal(result['sym'], null);
    assert.equal(result['ok'], true);
  });

  it('stringifies a bigint, which JSON cannot carry', () => {
    assert.equal(redactMetadata({ n: 10n })['n'], '10');
  });

  it('normalises undefined to null', () => {
    assert.equal(redactMetadata({ maybe: undefined })['maybe'], null);
  });

  it('always produces JSON-serialisable output', () => {
    const hostile: Record<string, unknown> = {
      fn: () => 1,
      sym: Symbol('x'),
      big: 1n,
      date: new Date(),
      buf: Buffer.from('x'),
      nan: Number.NaN,
      nested: { deep: { deeper: { password: 'p' } } },
    };
    hostile['cycle'] = hostile;
    assert.doesNotThrow(() => JSON.stringify(redactMetadata(hostile)));
  });
});
