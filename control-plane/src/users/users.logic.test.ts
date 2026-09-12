import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { normaliseEmail, normaliseName, toPublicUser, type UserRow } from './users.logic.js';

describe('normaliseEmail', () => {
  it('lower-cases and trims', () => {
    const result = normaliseEmail('  Alex@Example.COM ');
    assert.ok(result.ok);
    assert.equal(result.value, 'alex@example.com');
  });

  it('maps every casing of one address to one value', () => {
    const spellings = ['alex@example.com', 'ALEX@EXAMPLE.COM', 'Alex@Example.Com'];
    const normalised = new Set(
      spellings.map((s) => {
        const r = normaliseEmail(s);
        return r.ok ? r.value : 'failed';
      }),
    );
    assert.equal(normalised.size, 1);
  });

  it('preserves dots and plus tags rather than merging distinct addresses', () => {
    const dotted = normaliseEmail('a.b@example.com');
    const plain = normaliseEmail('ab@example.com');
    const tagged = normaliseEmail('a+serveros@example.com');
    assert.ok(dotted.ok && plain.ok && tagged.ok);
    assert.notEqual(dotted.value, plain.value);
    assert.equal(tagged.value, 'a+serveros@example.com');
  });

  it('accepts addresses with hyphens and subdomains', () => {
    assert.ok(normaliseEmail('first-last@mail.example.co.uk').ok);
  });

  it('rejects a non-string', () => {
    assert.ok(!normaliseEmail(undefined).ok);
    assert.ok(!normaliseEmail(null).ok);
    assert.ok(!normaliseEmail(42).ok);
  });

  it('rejects an empty address', () => {
    assert.ok(!normaliseEmail('   ').ok);
  });

  it('rejects an address with no @ or with two', () => {
    assert.ok(!normaliseEmail('nobody').ok);
    assert.ok(!normaliseEmail('a@b@c.com').ok);
  });

  it('rejects a missing local part or domain', () => {
    assert.ok(!normaliseEmail('@example.com').ok);
    assert.ok(!normaliseEmail('alex@').ok);
  });

  it('rejects a domain with no TLD', () => {
    assert.ok(!normaliseEmail('alex@localhost').ok);
  });

  it('rejects whitespace inside the address', () => {
    assert.ok(!normaliseEmail('a b@example.com').ok);
    assert.ok(!normaliseEmail('a@exa mple.com').ok);
  });

  it('rejects an over-long address', () => {
    assert.ok(!normaliseEmail(`${'a'.repeat(250)}@example.com`).ok);
  });

  it('rejects an over-long local part', () => {
    assert.ok(!normaliseEmail(`${'a'.repeat(70)}@example.com`).ok);
  });

  it('uses one sentence for every rejection, so it cannot be probed', () => {
    const messages = new Set(
      ['nobody', 'a@b@c.com', '@example.com', `${'a'.repeat(300)}@x.com`]
        .map((s) => normaliseEmail(s))
        .map((r) => (r.ok ? '' : r.message)),
    );
    assert.equal(messages.size, 1);
  });
});

describe('normaliseName', () => {
  it('collapses whitespace', () => {
    const result = normaliseName('  Alex   Rivera ');
    assert.ok(result.ok);
    assert.equal(result.value, 'Alex Rivera');
  });

  it('strips control characters rather than rejecting the name', () => {
    const result = normaliseName('Alex\u0000\u001FRivera');
    assert.ok(result.ok);
    assert.equal(result.value, 'AlexRivera');
  });

  it('keeps non-ASCII names intact', () => {
    const result = normaliseName('Zoë Müller-Škoda');
    assert.ok(result.ok);
    assert.equal(result.value, 'Zoë Müller-Škoda');
  });

  it('rejects an empty name', () => {
    assert.ok(!normaliseName('   ').ok);
    assert.ok(!normaliseName('\u0000').ok);
  });

  it('rejects a non-string', () => {
    assert.ok(!normaliseName(null).ok);
  });

  it('rejects an over-long name', () => {
    const result = normaliseName('a'.repeat(200));
    assert.ok(!result.ok);
    assert.equal(result.code, 'name_too_long');
  });
});

describe('toPublicUser', () => {
  const row: UserRow = {
    id: 'user-1',
    email: 'alex@example.com',
    name: 'Alex',
    passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA',
    isActive: true,
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    lastLoginAt: new Date('2026-09-12T10:00:00.000Z'),
  };

  it('never includes the password hash', () => {
    const result = toPublicUser(row);
    assert.ok(!('passwordHash' in result));
    assert.ok(!JSON.stringify(result).includes('argon2id'));
  });

  it('renders dates as ISO-8601 strings', () => {
    const result = toPublicUser(row);
    assert.equal(result.createdAt, '2026-01-01T00:00:00.000Z');
    assert.equal(result.lastLoginAt, '2026-09-12T10:00:00.000Z');
  });

  it('carries a null last login through', () => {
    assert.equal(toPublicUser({ ...row, lastLoginAt: null }).lastLoginAt, null);
  });

  it('exposes exactly the expected keys', () => {
    assert.deepEqual(Object.keys(toPublicUser(row)).sort(), [
      'createdAt',
      'email',
      'id',
      'isActive',
      'lastLoginAt',
      'name',
    ]);
  });
});
