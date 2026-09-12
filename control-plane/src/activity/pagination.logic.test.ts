import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  DEFAULT_PAGE_SIZE,
  MAX_PAGE_SIZE,
  buildKeysetFilter,
  buildPage,
  decodeCursor,
  encodeCursor,
  normalisePageSize,
} from './pagination.logic.js';

const SECRET = 'cursor-signing-secret-at-least-32-bytes';
const OTHER_SECRET = 'a-completely-different-signing-secret!!';
const AT = new Date('2026-09-12T10:00:00.000Z');

function row(id: string, offsetMs = 0): { id: string; createdAt: Date } {
  return { id, createdAt: new Date(AT.getTime() - offsetMs) };
}

describe('normalisePageSize', () => {
  it('defaults when absent', () => {
    assert.equal(normalisePageSize(undefined), DEFAULT_PAGE_SIZE);
    assert.equal(normalisePageSize(null), DEFAULT_PAGE_SIZE);
  });

  it('accepts a number', () => {
    assert.equal(normalisePageSize(25), 25);
  });

  it('accepts a numeric string, which is what a query parameter is', () => {
    assert.equal(normalisePageSize('25'), 25);
  });

  it('caps at the maximum', () => {
    assert.equal(normalisePageSize(10_000), MAX_PAGE_SIZE);
    assert.equal(normalisePageSize('99999'), MAX_PAGE_SIZE);
  });

  it('defaults on nonsense rather than erroring', () => {
    assert.equal(normalisePageSize('abc'), DEFAULT_PAGE_SIZE);
    assert.equal(normalisePageSize(-5), DEFAULT_PAGE_SIZE);
    assert.equal(normalisePageSize(0), DEFAULT_PAGE_SIZE);
    assert.equal(normalisePageSize(Number.NaN), DEFAULT_PAGE_SIZE);
    assert.equal(normalisePageSize({}), DEFAULT_PAGE_SIZE);
  });

  it('floors a fractional request', () => {
    assert.equal(normalisePageSize(10.9), 10);
  });
});

describe('cursor round trip', () => {
  it('decodes what it encoded', () => {
    const cursor = encodeCursor({ createdAt: AT, id: 'row-1' }, SECRET);
    const result = decodeCursor(cursor, SECRET);
    assert.ok(result.ok);
    assert.equal(result.value.id, 'row-1');
    assert.equal(result.value.createdAt.getTime(), AT.getTime());
  });

  it('is opaque — the id is not readable in the cursor', () => {
    const cursor = encodeCursor({ createdAt: AT, id: 'row-1' }, SECRET);
    assert.ok(!cursor.includes('row-1'));
  });

  it('is url-safe', () => {
    for (let i = 0; i < 50; i += 1) {
      const cursor = encodeCursor({ createdAt: new Date(AT.getTime() + i), id: `r${i}` }, SECRET);
      assert.match(cursor, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    }
  });
});

describe('decodeCursor — rejection', () => {
  const expectInvalid = (cursor: unknown, secret = SECRET): void => {
    const result = decodeCursor(cursor, secret);
    assert.ok(!result.ok, `expected rejection for ${String(cursor)}`);
    assert.equal(result.code, 'cursor_invalid');
  };

  it('rejects a non-string', () => {
    expectInvalid(undefined);
    expectInvalid(null);
    expectInvalid(42);
  });

  it('rejects the empty string', () => {
    expectInvalid('');
  });

  it('rejects an oversized cursor before verifying it', () => {
    expectInvalid('a'.repeat(1000));
  });

  it('rejects a cursor with no signature', () => {
    expectInvalid('eyJ0IjoxfQ');
  });

  it('rejects a cursor with an empty signature', () => {
    expectInvalid('eyJ0IjoxfQ.');
  });

  it('rejects a cursor signed with a different secret', () => {
    expectInvalid(encodeCursor({ createdAt: AT, id: 'row-1' }, OTHER_SECRET));
  });

  it('rejects a tampered body', () => {
    const cursor = encodeCursor({ createdAt: AT, id: 'row-1' }, SECRET);
    const [body, signature] = cursor.split('.') as [string, string];
    const forgedBody = Buffer.from(JSON.stringify({ t: 0, i: 'other' }), 'utf8').toString(
      'base64url',
    );
    expectInvalid(`${forgedBody}.${signature}`);
    assert.notEqual(forgedBody, body);
  });

  it('rejects a tampered signature', () => {
    const cursor = encodeCursor({ createdAt: AT, id: 'row-1' }, SECRET);
    const [body, signature] = cursor.split('.') as [string, string];
    expectInvalid(`${body}.${signature.slice(0, -1)}X`);
  });

  it('rejects a truncated signature without throwing on length mismatch', () => {
    const cursor = encodeCursor({ createdAt: AT, id: 'row-1' }, SECRET);
    const [body] = cursor.split('.') as [string, string];
    expectInvalid(`${body}.abc`);
  });

  it('rejects non-base64url characters', () => {
    expectInvalid('not+valid/base64.signature');
  });

  it('rejects a validly signed body that is not a JSON object', () => {
    // Signed with our own secret, so only the payload check can catch it.
    const body = Buffer.from('"a string"', 'utf8').toString('base64url');
    const cursor = `${body}.${encodeCursor({ createdAt: AT, id: 'x' }, SECRET).split('.')[1]}`;
    expectInvalid(cursor);
  });

  it('gives the same sentence for every rejection', () => {
    const results = ['', 'abc', 'a'.repeat(1000), encodeCursor({ createdAt: AT, id: 'x' }, OTHER_SECRET)]
      .map((c) => decodeCursor(c, SECRET))
      .filter((r) => !r.ok);
    const messages = new Set(results.map((r) => (r.ok ? '' : r.message)));
    assert.equal(messages.size, 1);
  });

  it('keeps the diagnostic in detail, not in the sentence', () => {
    const result = decodeCursor(encodeCursor({ createdAt: AT, id: 'x' }, OTHER_SECRET), SECRET);
    assert.ok(!result.ok);
    assert.match(result.detail ?? '', /signature/);
    assert.doesNotMatch(result.message, /signature/);
  });
});

describe('buildPage', () => {
  it('returns everything and no cursor when the page is not full', () => {
    const rows = [row('a'), row('b', 1)];
    const page = buildPage(rows, 10, SECRET);
    assert.equal(page.items.length, 2);
    assert.equal(page.nextCursor, null);
  });

  it('returns no cursor when the result exactly fills the page', () => {
    const rows = [row('a'), row('b', 1)];
    const page = buildPage(rows, 2, SECRET);
    assert.equal(page.items.length, 2);
    assert.equal(page.nextCursor, null);
  });

  it('drops the over-fetched row and mints a cursor', () => {
    const rows = [row('a'), row('b', 1), row('c', 2)];
    const page = buildPage(rows, 2, SECRET);
    assert.equal(page.items.length, 2);
    assert.equal(page.items[1]?.id, 'b');
    assert.ok(page.nextCursor !== null);
  });

  it('points the cursor at the last returned row, not the over-fetched one', () => {
    const rows = [row('a'), row('b', 1), row('c', 2)];
    const page = buildPage(rows, 2, SECRET);
    const decoded = decodeCursor(page.nextCursor, SECRET);
    assert.ok(decoded.ok);
    assert.equal(decoded.value.id, 'b');
  });

  it('handles an empty result set', () => {
    const page = buildPage([], 10, SECRET);
    assert.equal(page.items.length, 0);
    assert.equal(page.nextCursor, null);
  });
});

describe('buildKeysetFilter', () => {
  it('includes both an older-than clause and a same-millisecond tiebreak', () => {
    const filter = buildKeysetFilter({ createdAt: AT, id: 'row-5' });
    assert.equal(filter.OR.length, 2);
    assert.deepEqual(filter.OR[0], { createdAt: { lt: AT } });
    assert.deepEqual(filter.OR[1], { createdAt: AT, id: { lt: 'row-5' } });
  });

  it('would not lose rows that share a millisecond', () => {
    // Three rows in the same millisecond, page size 2: the tiebreak clause is
    // what makes the third row reachable at all.
    const same = [row('c3'), row('c2'), row('c1')];
    const page = buildPage(same, 2, SECRET);
    const decoded = decodeCursor(page.nextCursor, SECRET);
    assert.ok(decoded.ok);
    const filter = buildKeysetFilter(decoded.value);
    assert.equal(filter.OR[1].createdAt.getTime(), AT.getTime());
    assert.equal(filter.OR[1].id.lt, 'c2');
  });
});
