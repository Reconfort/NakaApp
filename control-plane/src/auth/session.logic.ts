/**
 * Refresh-token lifecycle: minting, hashing, rotation and reuse detection.
 *
 * Refresh tokens are opaque random strings, not JWTs. That is the whole point:
 * a JWT is valid until it expires and cannot be withdrawn, whereas an opaque
 * token is only as valid as the row backing it, so "sign out everywhere" and
 * "this token was stolen" are both one UPDATE.
 *
 * The model is a *token family*. A login starts a family; every refresh marks
 * the presented row rotated and writes a successor with the same `familyId`.
 * Presenting a row that has already been rotated therefore means two parties
 * hold the same token — the legitimate client and a thief — and there is no way
 * to tell which one is asking. The response is to revoke the entire family,
 * which logs the thief out and forces the real user to sign in again. This is
 * the OAuth 2.1 / BCP 212 recommendation for public clients, and it is why
 * `rotatedAt` is a column rather than a delete.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import { fail, ok, type Result } from '../common/result.logic.js';

/** Refresh tokens live 30 days; the Mac app refreshes long before that. */
export const REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

/** 256 bits of entropy. */
const REFRESH_TOKEN_BYTES = 32;

/** Length of the base64url encoding of {@link REFRESH_TOKEN_BYTES}. */
const REFRESH_TOKEN_LENGTH = 43;

/** Injectable randomness, so token generation is testable and deterministic. */
export type RandomBytes = (size: number) => Buffer;

/**
 * Mints a refresh token.
 *
 * Returns the plaintext (handed to the client exactly once) and the hash (the
 * only form persisted). Callers must never log or return `token` beyond the
 * single response that carries it.
 */
export function generateRefreshToken(random: RandomBytes = randomBytes): {
  token: string;
  tokenHash: string;
} {
  const token = random(REFRESH_TOKEN_BYTES).toString('base64url');
  return { token, tokenHash: hashRefreshToken(token) };
}

/**
 * Hashes a refresh token for storage and lookup.
 *
 * SHA-256, not Argon2id. A refresh token is 256 uniform random bits, so there
 * is nothing to brute-force and a memory-hard KDF would only add tens of
 * milliseconds to every refresh. Argon2id is for *user-chosen* secrets.
 */
export function hashRefreshToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/**
 * Compares two token hashes without leaking where they diverge.
 *
 * The database lookup is by hash and therefore already constant-ish, but the
 * comparison after a lookup by some other key (family, user) must not be `===`.
 */
export function hashesMatch(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Rejects a presented refresh token that cannot possibly be one of ours.
 *
 * Cheap pre-filter so a garbage value does not reach the database at all.
 */
export function looksLikeRefreshToken(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length === REFRESH_TOKEN_LENGTH &&
    /^[A-Za-z0-9_-]+$/.test(value)
  );
}

/** The `Session` row as the rotation decision needs to see it. */
export interface SessionRecord {
  readonly id: string;
  readonly userId: string;
  readonly familyId: string;
  readonly expiresAt: Date;
  readonly rotatedAt: Date | null;
  readonly revokedAt: Date | null;
}

/** Rotate: issue a successor and mark the presented row used. */
export interface RotateDecision {
  readonly action: 'rotate';
  readonly userId: string;
  readonly familyId: string;
  /** The row to mark rotated. */
  readonly previousSessionId: string;
  /** Expiry for the successor row. */
  readonly expiresAt: Date;
}

/** Revoke the family: the presented token had already been used or withdrawn. */
export interface RevokeFamilyDecision {
  readonly action: 'revoke_family';
  readonly userId: string;
  readonly familyId: string;
  readonly reason: 'reuse_detected';
  readonly code: string;
  readonly message: string;
}

/** Reject: nothing to revoke, the token is simply not usable. */
export interface RejectDecision {
  readonly action: 'reject';
  readonly code: string;
  readonly message: string;
}

export type RefreshDecision = RotateDecision | RevokeFamilyDecision | RejectDecision;

/** Inputs to the rotation decision. */
export interface RefreshInput {
  /** The row matching the presented token hash, or null if there is none. */
  readonly record: SessionRecord | null;
  readonly now: Date;
  /** How long the successor should live. Defaults to the 30-day policy. */
  readonly ttlSeconds?: number;
}

/**
 * Sentence shown for every refresh failure.
 *
 * Uniform on purpose: "your token was replayed by an attacker" and "your token
 * expired last week" both mean "sign in again" to the user, and distinguishing
 * them tells an attacker whether their stolen token was ever valid.
 */
const REFRESH_FAILED_MESSAGE = 'Your session has ended. Sign in again.';

/**
 * Decides what to do with a presented refresh token.
 *
 * Pure: it reads a row and returns an instruction. The service performs the
 * writes inside one transaction, which is what makes the concurrent case safe
 * — see `buildRotationGuard`.
 *
 * Order of checks is deliberate. Reuse is tested *before* expiry, because a
 * replayed token that has also expired is still evidence of theft and should
 * still kill the family.
 */
export function decideRefresh(input: RefreshInput): RefreshDecision {
  const { record, now } = input;

  if (record === null) {
    return {
      action: 'reject',
      code: 'refresh_token_unknown',
      message: REFRESH_FAILED_MESSAGE,
    };
  }

  // Already rotated: two holders of one token. Whoever is asking now, the
  // family is compromised.
  if (record.rotatedAt !== null) {
    return {
      action: 'revoke_family',
      userId: record.userId,
      familyId: record.familyId,
      reason: 'reuse_detected',
      code: 'refresh_token_reused',
      message: REFRESH_FAILED_MESSAGE,
    };
  }

  // Explicitly revoked (logout, admin action, or an earlier reuse event) and
  // presented anyway.
  if (record.revokedAt !== null) {
    return {
      action: 'revoke_family',
      userId: record.userId,
      familyId: record.familyId,
      reason: 'reuse_detected',
      code: 'refresh_token_revoked',
      message: REFRESH_FAILED_MESSAGE,
    };
  }

  if (record.expiresAt.getTime() <= now.getTime()) {
    return {
      action: 'reject',
      code: 'refresh_token_expired',
      message: REFRESH_FAILED_MESSAGE,
    };
  }

  const ttl = input.ttlSeconds ?? REFRESH_TOKEN_TTL_SECONDS;
  return {
    action: 'rotate',
    userId: record.userId,
    familyId: record.familyId,
    previousSessionId: record.id,
    expiresAt: new Date(now.getTime() + ttl * 1000),
  };
}

/**
 * The conditional `where` clause that makes rotation safe under concurrency.
 *
 * Two refreshes racing on the same row would both read `rotatedAt: null` and
 * both decide to rotate. Applying the update with `rotatedAt: null` in the
 * WHERE clause means the database picks a winner: exactly one UPDATE matches a
 * row, the loser matches zero and is converted to a reuse event by
 * {@link interpretRotationResult}. This is the reason the decision above is
 * advisory and the database is authoritative.
 */
export function buildRotationGuard(sessionId: string): {
  id: string;
  rotatedAt: null;
  revokedAt: null;
} {
  return { id: sessionId, rotatedAt: null, revokedAt: null };
}

/**
 * Turns "how many rows did the guarded UPDATE touch" into a decision.
 *
 * Zero rows means another request rotated the same token first, which is the
 * concurrent form of reuse and is treated identically.
 */
export function interpretRotationResult(
  updatedCount: number,
  record: SessionRecord,
): Result<{ rotated: true }> | RevokeFamilyDecision {
  if (updatedCount === 1) return ok({ rotated: true });
  return {
    action: 'revoke_family',
    userId: record.userId,
    familyId: record.familyId,
    reason: 'reuse_detected',
    code: 'refresh_token_reused',
    message: REFRESH_FAILED_MESSAGE,
  };
}

/**
 * Validates a presented refresh token before any database work.
 *
 * Separate from {@link decideRefresh} so the service can reject obvious junk
 * without a query, and so the shape check is tested independently.
 */
export function parsePresentedRefreshToken(value: unknown): Result<string> {
  if (!looksLikeRefreshToken(value)) {
    return fail('refresh_token_malformed', REFRESH_FAILED_MESSAGE);
  }
  return ok(value);
}
