/**
 * Email normalisation and the public shape of a user.
 *
 * `User.email` is a plain unique column rather than `citext`, so case-folding
 * has to happen in code — consistently, on every write *and* every lookup, or
 * `Alex@Example.com` becomes a second account. Doing it here rather than in the
 * database is deliberate: a `citext` column needs an extension the database
 * owner may not be able to create, and an invariant enforced in a function with
 * tests around it is more visible to the next reader than one hidden in a
 * column type.
 */

import { fail, ok, type Result } from '../common/result.logic.js';

/** RFC 5321 caps the whole address at 254 octets. */
const MAX_EMAIL_LENGTH = 254;

/** And the local part at 64. */
const MAX_LOCAL_PART_LENGTH = 64;

/**
 * Deliberately conservative address shape.
 *
 * Not an attempt at RFC 5322 — that grammar admits quoted strings and comments
 * that no mail provider accepts anyway, and a regex claiming to implement it is
 * a liability. This accepts what real addresses look like and rejects the rest;
 * deliverability is proven by sending mail, not by a pattern.
 */
const EMAIL_PATTERN = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}$/;

/**
 * Normalises an email address for storage and lookup.
 *
 * Lower-cases and trims. Explicitly does *not* strip dots or `+tags` from the
 * local part: `a.b@gmail.com` and `ab@gmail.com` are the same Gmail inbox but
 * different addresses everywhere else, and silently merging them would let one
 * user take over another's sign-in at a provider that treats them separately.
 */
export function normaliseEmail(input: unknown): Result<string> {
  if (typeof input !== 'string') {
    return fail('email_invalid', 'Enter an email address.');
  }
  const normalised = input.trim().toLowerCase();
  if (normalised.length === 0) {
    return fail('email_invalid', 'Enter an email address.');
  }
  if (normalised.length > MAX_EMAIL_LENGTH) {
    return fail('email_invalid', "That email address doesn't look right.");
  }
  const atIndex = normalised.indexOf('@');
  if (atIndex === -1 || atIndex !== normalised.lastIndexOf('@')) {
    return fail('email_invalid', "That email address doesn't look right.");
  }
  if (atIndex > MAX_LOCAL_PART_LENGTH) {
    return fail('email_invalid', "That email address doesn't look right.");
  }
  if (!EMAIL_PATTERN.test(normalised)) {
    return fail('email_invalid', "That email address doesn't look right.");
  }
  return ok(normalised);
}

/** Longest display name we store. */
const MAX_NAME_LENGTH = 120;

/**
 * Validates and tidies a display name.
 *
 * Control characters are stripped rather than rejected: they arrive from paste
 * accidents far more often than from attacks, and a name that renders as a
 * broken glyph in the sidebar is a bug the user cannot diagnose.
 */
export function normaliseName(input: unknown): Result<string> {
  if (typeof input !== 'string') {
    return fail('name_invalid', 'Enter your name.');
  }
  // C0 control characters and DEL, written as escapes so the intent survives
  // a copy-paste and so the source file itself stays printable.
  const cleaned = input
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (cleaned.length === 0) {
    return fail('name_invalid', 'Enter your name.');
  }
  if (cleaned.length > MAX_NAME_LENGTH) {
    return fail('name_too_long', `Use ${MAX_NAME_LENGTH} characters or fewer.`);
  }
  return ok(cleaned);
}

/** A user row as it exists in the database. */
export interface UserRow {
  readonly id: string;
  readonly email: string;
  readonly name: string;
  readonly passwordHash: string;
  readonly isActive: boolean;
  readonly createdAt: Date;
  readonly lastLoginAt: Date | null;
}

/** A user as the API returns it. */
export interface PublicUser {
  readonly id: string;
  readonly email: string;
  readonly name: string;
  readonly isActive: boolean;
  readonly createdAt: string;
  readonly lastLoginAt: string | null;
}

/**
 * Projects a user row onto its public shape.
 *
 * Written as an explicit field list rather than a spread-and-delete, because
 * spread-and-delete silently starts leaking any column added later — and the
 * column that gets added later is exactly the kind that should not leak. The
 * test asserts that `passwordHash` is absent for precisely this reason.
 */
export function toPublicUser(row: UserRow): PublicUser {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    isActive: row.isActive,
    createdAt: row.createdAt.toISOString(),
    lastLoginAt: row.lastLoginAt === null ? null : row.lastLoginAt.toISOString(),
  };
}
