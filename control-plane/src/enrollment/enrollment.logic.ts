/**
 * Enrollment codes: the one-time secret that lets an agent claim its `Server`
 * row.
 *
 * The flow is: the Mac app asks the control plane to mint a code, the person
 * pastes it into the installer on the Linux box, the agent redeems it once and
 * is thereafter identified by its own key material. The code is therefore a
 * bearer credential with a very short life, and the three properties that
 * matter are that it is unguessable, that it is not recoverable from the
 * database, and that it can be redeemed exactly once even if two requests
 * arrive at the same instant.
 *
 * A person has to read this code off one screen and type it into another, so
 * it is also a piece of interface: Crockford's base32 alphabet drops I, L, O
 * and U, and {@link canonicaliseCode} maps the characters people substitute
 * anyway (`O`→`0`, `I`/`l`→`1`) so a correctly-read code never fails because of
 * a font.
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import { fail, ok, type Result } from '../common/result.logic.js';

/**
 * Crockford base32: the digits and upper-case letters minus I, L, O and U.
 *
 * U is excluded by Crockford to avoid accidental obscenities; I, L and O
 * because they are indistinguishable from 1 and 0 in most typefaces.
 */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** Characters per code. */
const CODE_LENGTH = 28;

/** Characters per display group. */
const GROUP_SIZE = 4;

/**
 * Entropy per code, in bits.
 *
 * Each character is drawn uniformly from a 32-symbol alphabet, so 5 bits each:
 * 28 × 5 = 140 bits. The requirement is 128; 28 was chosen over the 26
 * characters that 128 bits needs because 28 divides evenly into groups of four
 * and a code a human has to read aloud should not end in a ragged group.
 */
export const CODE_ENTROPY_BITS = CODE_LENGTH * 5;

/** Enrollment codes live 15 minutes. Long enough to paste, short enough to matter. */
export const ENROLLMENT_TTL_SECONDS = 15 * 60;

/** Injectable randomness so generation is deterministic under test. */
export type RandomBytes = (size: number) => Buffer;

/** A freshly minted code in both the form the user sees and the form we store. */
export interface GeneratedCode {
  /** Grouped for reading: `XXXX-XXXX-…`. Shown once, never stored. */
  readonly display: string;
  /** Ungrouped upper-case form. What gets hashed. Never stored either. */
  readonly canonical: string;
  /** SHA-256 of the canonical form. The only part that reaches the database. */
  readonly codeHash: string;
}

/**
 * Mints an enrollment code.
 *
 * Each character consumes one random byte masked to five bits. That is uniform
 * with no rejection sampling because 32 divides 256 exactly — worth stating,
 * since the same trick with a 62-character alphabet would be biased.
 */
export function generateEnrollmentCode(random: RandomBytes = randomBytes): GeneratedCode {
  const bytes = random(CODE_LENGTH);
  if (bytes.length < CODE_LENGTH) {
    throw new Error(`Random source returned ${bytes.length} bytes, need ${CODE_LENGTH}.`);
  }
  let canonical = '';
  for (let i = 0; i < CODE_LENGTH; i += 1) {
    // Non-null: the length was checked above.
    canonical += ALPHABET[(bytes[i] as number) & 0x1f];
  }
  return { display: groupCode(canonical), canonical, codeHash: hashEnrollmentCode(canonical) };
}

/** Inserts a dash every {@link GROUP_SIZE} characters. */
export function groupCode(canonical: string): string {
  const groups: string[] = [];
  for (let i = 0; i < canonical.length; i += GROUP_SIZE) {
    groups.push(canonical.slice(i, i + GROUP_SIZE));
  }
  return groups.join('-');
}

/**
 * Normalises whatever the user typed into the canonical form.
 *
 * Accepts dashes, spaces and lower case, and applies Crockford's substitutions
 * for the characters the alphabet omits. Returns null when the result is not a
 * possible code, so a malformed submission never reaches the database.
 */
export function canonicaliseCode(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  // Bound the work before doing any of it.
  if (input.length > 128) return null;

  const stripped = input.replace(/[\s-]/g, '').toUpperCase();
  if (stripped.length !== CODE_LENGTH) return null;

  let canonical = '';
  for (const character of stripped) {
    const mapped = character === 'O' ? '0' : character === 'I' || character === 'L' ? '1' : character;
    if (!ALPHABET.includes(mapped)) return null;
    canonical += mapped;
  }
  return canonical;
}

/**
 * Hashes a canonical code for storage.
 *
 * SHA-256 rather than Argon2id: the code carries 140 bits of uniform entropy,
 * so there is no dictionary to run and a memory-hard KDF would only slow down
 * the redemption path. The same reasoning as refresh tokens — see
 * auth/session.logic.ts.
 */
export function hashEnrollmentCode(canonical: string): string {
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Compares two code hashes in constant time.
 *
 * The primary lookup is by hash, so this guards the second comparison — the one
 * that happens after a row has been fetched by id — where `===` would leak the
 * matching prefix length to an attacker who can time it.
 */
export function codeHashesMatch(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/** The `ServerEnrollment` row as the consume decision needs to see it. */
export interface EnrollmentRecord {
  readonly id: string;
  readonly serverId: string;
  readonly codeHash: string;
  readonly expiresAt: Date;
  readonly consumedAt: Date | null;
}

/** What a successful redemption yields. */
export interface ConsumedEnrollment {
  readonly enrollmentId: string;
  readonly serverId: string;
}

/** Inputs to the consume decision. */
export interface ConsumeInput {
  /** The row found by code hash, or null when there is none. */
  readonly record: EnrollmentRecord | null;
  /** The canonical code the agent presented. */
  readonly presentedCanonical: string;
  readonly now: Date;
}

/**
 * Sentence shown for every redemption failure.
 *
 * Uniform because the alternative is an oracle: distinguishing "no such code"
 * from "expired" from "already used" tells someone spraying codes which of
 * their guesses previously existed.
 */
const CONSUME_FAILED_MESSAGE =
  "That enrollment code isn't valid. Generate a new one from ServerOS.";

/**
 * Decides whether an enrollment code may be redeemed.
 *
 * Pure. The caller performs the write under the guard from
 * {@link buildConsumeGuard}, which is what actually makes redemption
 * single-use; this function is the readable statement of the policy and the
 * thing the tests pin down.
 */
export function decideConsume(input: ConsumeInput): Result<ConsumedEnrollment> {
  const { record, presentedCanonical, now } = input;

  const denied = fail('enrollment_code_invalid', CONSUME_FAILED_MESSAGE);

  if (record === null) return denied;

  // The lookup was by hash, so this can only fail if the caller passed a
  // mismatched pair — but it is checked, in constant time, rather than assumed.
  if (!codeHashesMatch(record.codeHash, hashEnrollmentCode(presentedCanonical))) {
    return fail('enrollment_code_invalid', CONSUME_FAILED_MESSAGE, 'presented hash mismatch');
  }

  if (record.consumedAt !== null) {
    return fail('enrollment_code_already_used', CONSUME_FAILED_MESSAGE, 'already consumed');
  }

  if (record.expiresAt.getTime() <= now.getTime()) {
    return fail('enrollment_code_expired', CONSUME_FAILED_MESSAGE, 'expired');
  }

  return ok({ enrollmentId: record.id, serverId: record.serverId });
}

/**
 * The conditional `where` clause that makes redemption single-use.
 *
 * Two agents redeeming the same code simultaneously would both read
 * `consumedAt: null` and both decide to proceed. Including `consumedAt: null`
 * in the WHERE clause hands the tie-break to the database: one UPDATE matches,
 * the other matches zero rows and is converted to a failure by
 * {@link interpretConsumeResult}.
 */
export function buildConsumeGuard(enrollmentId: string): { id: string; consumedAt: null } {
  return { id: enrollmentId, consumedAt: null };
}

/**
 * Turns "how many rows did the guarded UPDATE touch" into a result.
 *
 * Zero rows means another request redeemed the code first — the concurrent
 * form of "already used", and reported identically.
 */
export function interpretConsumeResult(
  updatedCount: number,
  consumed: ConsumedEnrollment,
): Result<ConsumedEnrollment> {
  if (updatedCount === 1) return ok(consumed);
  return fail('enrollment_code_already_used', CONSUME_FAILED_MESSAGE, 'lost the consume race');
}

/** Expiry timestamp for a code minted now. */
export function enrollmentExpiry(now: Date, ttlSeconds: number = ENROLLMENT_TTL_SECONDS): Date {
  return new Date(now.getTime() + ttlSeconds * 1000);
}
