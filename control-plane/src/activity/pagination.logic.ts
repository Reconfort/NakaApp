/**
 * Opaque, tamper-evident cursors for the activity feed.
 *
 * Offset pagination is wrong for an append-only feed: rows arrive at the head
 * while the user is scrolling, so page 2 of an offset query re-shows rows the
 * user already read. A keyset cursor (`createdAt`, then `id` as a tiebreak)
 * is stable under insertion and is one index scan on
 * `Activity(serverId, createdAt)`.
 *
 * The cursor is signed. Not because `createdAt`/`id` are secret — they are in
 * the response body — but because an unsigned cursor is an input the client can
 * craft, and the moment it is decoded straight into a `where` clause it becomes
 * a way to probe for rows the query was supposed to scope. Signing means the
 * server only ever honours a position it issued itself.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

import { fail, ok, type Result } from '../common/result.logic.js';

/** Default rows per page when the client does not ask. */
export const DEFAULT_PAGE_SIZE = 50;

/** Hard ceiling. A client asking for 10,000 rows gets 100. */
export const MAX_PAGE_SIZE = 100;

/** Bound on an inbound cursor string, so a huge one is cheap to reject. */
const MAX_CURSOR_LENGTH = 512;

/** A position in the feed. */
export interface CursorPosition {
  /** Sort key: the `createdAt` of the last row on the previous page. */
  readonly createdAt: Date;
  /** Tiebreak for rows sharing a millisecond. */
  readonly id: string;
}

/** The serialised body of a cursor, before signing. */
interface CursorPayload {
  readonly t: number;
  readonly i: string;
}

/**
 * Clamps a requested page size into policy.
 *
 * Accepts the raw query value — which is a string, or absent, or nonsense —
 * and always returns a usable number, because "page size was silly" is not
 * worth a 400 when a sensible default exists.
 */
export function normalisePageSize(requested: unknown): number {
  const value =
    typeof requested === 'number'
      ? requested
      : typeof requested === 'string' && /^\d+$/.test(requested)
        ? Number.parseInt(requested, 10)
        : Number.NaN;
  if (!Number.isFinite(value) || value < 1) return DEFAULT_PAGE_SIZE;
  return Math.min(Math.floor(value), MAX_PAGE_SIZE);
}

/** Computes the signature over a cursor body. */
function sign(body: string, secret: string): string {
  return createHmac('sha256', secret).update(body, 'utf8').digest('base64url');
}

/**
 * Encodes a feed position into an opaque cursor.
 *
 * The format is `base64url(json).base64url(hmac)`. It is deliberately not a
 * readable `id` — clients that can read a cursor start depending on its
 * contents, and then the pagination strategy can never change.
 */
export function encodeCursor(position: CursorPosition, secret: string): string {
  const payload: CursorPayload = { t: position.createdAt.getTime(), i: position.id };
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `${body}.${sign(body, secret)}`;
}

/**
 * Decodes and authenticates a cursor.
 *
 * Every rejection returns the same code and sentence: a client holding a stale
 * or corrupt cursor should restart the feed, and the distinction between
 * "malformed" and "forged" is only useful to someone probing.
 */
export function decodeCursor(cursor: unknown, secret: string): Result<CursorPosition> {
  const invalid = (detail: string): ReturnType<typeof fail> =>
    fail('cursor_invalid', 'That page is no longer available. Reload the list.', detail);

  if (typeof cursor !== 'string' || cursor.length === 0) return invalid('not a string');
  if (cursor.length > MAX_CURSOR_LENGTH) return invalid('cursor too long');

  const separator = cursor.lastIndexOf('.');
  if (separator <= 0 || separator === cursor.length - 1) return invalid('missing signature');

  const body = cursor.slice(0, separator);
  const signature = cursor.slice(separator + 1);
  if (!/^[A-Za-z0-9_-]+$/.test(body) || !/^[A-Za-z0-9_-]+$/.test(signature)) {
    return invalid('not base64url');
  }

  const expected = Buffer.from(sign(body, secret), 'utf8');
  const provided = Buffer.from(signature, 'utf8');
  if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
    return invalid('signature mismatch');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return invalid('body is not JSON');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return invalid('body is not an object');
  }

  const { t, i } = parsed as Record<string, unknown>;
  if (typeof t !== 'number' || !Number.isFinite(t) || t < 0) return invalid('bad timestamp');
  if (typeof i !== 'string' || i.length === 0 || i.length > 64) return invalid('bad id');

  return ok({ createdAt: new Date(t), id: i });
}

/** One page of results, as returned to the client. */
export interface Page<T> {
  readonly items: readonly T[];
  /** Cursor for the next page, or null when this is the last one. */
  readonly nextCursor: string | null;
}

/** The minimum a row must expose to be paginated. */
export interface Paginable {
  readonly id: string;
  readonly createdAt: Date;
}

/**
 * Trims an over-fetched result set into a page and mints the next cursor.
 *
 * The caller queries `pageSize + 1` rows: the extra row is how we know whether
 * a further page exists without a second `count(*)` over an append-only table
 * that only ever grows.
 */
export function buildPage<T extends Paginable>(
  rows: readonly T[],
  pageSize: number,
  secret: string,
): Page<T> {
  if (rows.length <= pageSize) return { items: rows, nextCursor: null };
  const items = rows.slice(0, pageSize);
  const last = items[items.length - 1];
  if (last === undefined) return { items, nextCursor: null };
  return { items, nextCursor: encodeCursor({ createdAt: last.createdAt, id: last.id }, secret) };
}

/**
 * Builds the keyset predicate for "everything strictly older than this point".
 *
 * Expressed as an OR of two clauses rather than a tuple comparison because
 * Prisma has no tuple operator: rows in an earlier millisecond, plus rows in
 * the same millisecond with a smaller id. Both halves are needed — without the
 * tiebreak, a burst of rows sharing one millisecond straddles a page boundary
 * and some of them are never returned.
 */
export function buildKeysetFilter(position: CursorPosition): {
  OR: [{ createdAt: { lt: Date } }, { createdAt: Date; id: { lt: string } }];
} {
  return {
    OR: [
      { createdAt: { lt: position.createdAt } },
      { createdAt: position.createdAt, id: { lt: position.id } },
    ],
  };
}
