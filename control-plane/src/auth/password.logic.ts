/**
 * Password policy and the credential-check decision.
 *
 * The actual Argon2id computation is not here. It sits behind the
 * {@link PasswordHasher} port, implemented in `password.hasher.ts` by the
 * `argon2` native module. That split exists for two reasons: the decision that
 * matters — *whether* a login succeeds, and whether the attempt leaked
 * information — is pure and can be tested exhaustively with a fake hasher, and
 * the choice of KDF becomes swappable without touching the authentication flow.
 *
 * Argon2id rather than bcrypt: bcrypt truncates at 72 bytes (so a long
 * passphrase is silently weakened) and has no memory hardness. See
 * docs/reference/backend-stack.md §1.3.
 */

import { fail, ok, type Result } from '../common/result.logic.js';

/**
 * The KDF seam.
 *
 * `verify` returns `false` for a wrong password and *throws* only when the hash
 * itself is unusable, so a corrupt row surfaces as a 500 rather than silently
 * denying a legitimate user forever.
 */
export interface PasswordHasher {
  hash(plaintext: string): Promise<string>;
  verify(storedHash: string, plaintext: string): Promise<boolean>;
}

/**
 * Minimum length.
 *
 * 12 rather than 8: with a memory-hard KDF the cost of a longer minimum is
 * zero, and NIST SP 800-63B's guidance is to lean on length rather than
 * composition rules (which is why there is no "must contain a symbol" check
 * below — those push users toward `Password1!` and nothing else).
 */
export const MIN_PASSWORD_LENGTH = 12;

/**
 * Maximum length, in bytes.
 *
 * Not a security limit — Argon2id has no truncation problem — but a denial-of-
 * service one: hashing a 10 MB "password" is free for the attacker and
 * expensive for us.
 */
export const MAX_PASSWORD_BYTES = 1024;

/** Passwords rejected outright regardless of length. */
const BANNED = new Set([
  'password',
  'passw0rd',
  'password123',
  'administrator',
  'changeme',
  'letmein12345',
  'qwertyuiop12',
  '123456789012',
  'serveros1234',
]);

/**
 * Checks a candidate password against policy.
 *
 * Runs at registration and password change, never at login — an existing
 * password that no longer meets policy must still authenticate, otherwise a
 * policy change locks users out.
 */
export function validatePasswordStrength(password: unknown, email?: string): Result<string> {
  if (typeof password !== 'string') {
    return fail('password_invalid', 'Enter a password.');
  }
  const byteLength = Buffer.byteLength(password, 'utf8');
  if (password.length < MIN_PASSWORD_LENGTH) {
    return fail(
      'password_too_short',
      `Use at least ${MIN_PASSWORD_LENGTH} characters. A short phrase works well.`,
    );
  }
  if (byteLength > MAX_PASSWORD_BYTES) {
    return fail('password_too_long', 'That password is too long.');
  }
  if (password.trim().length === 0) {
    return fail('password_invalid', 'A password cannot be only spaces.');
  }
  // A single repeated character passes a naive length check but carries almost
  // no entropy.
  if (new Set(password).size <= 3) {
    return fail('password_too_simple', 'That password repeats too few characters.');
  }
  if (BANNED.has(password.toLowerCase())) {
    return fail('password_too_common', 'That password is too common. Choose another.');
  }
  if (email !== undefined && email.length > 0) {
    const localPart = email.split('@')[0] ?? '';
    if (localPart.length >= 4 && password.toLowerCase().includes(localPart.toLowerCase())) {
      return fail('password_too_similar', "Don't use your email address in your password.");
    }
  }
  return ok(password);
}

/**
 * Recognises an Argon2id encoded hash.
 *
 * Used to detect rows written by a different algorithm — an imported bcrypt
 * hash, or a bug that stored the plaintext. The login path treats an
 * unrecognised hash as a server fault rather than a wrong password, so the
 * problem is visible instead of looking like a user typo.
 */
export function isArgon2idHash(value: unknown): boolean {
  return typeof value === 'string' && /^\$argon2id\$v=19\$m=\d+,t=\d+,p=\d+\$[^$]+\$[^$]+$/.test(value);
}

/** The stored credential of a user, as the login path needs to see it. */
export interface CredentialRecord {
  readonly userId: string;
  readonly passwordHash: string;
  readonly isActive: boolean;
}

/** What a successful authentication yields. */
export interface AuthenticatedUser {
  readonly userId: string;
}

/**
 * A hash to verify against when no user exists.
 *
 * Argon2id encoding of a random value, present so that a login attempt for an
 * unknown address performs the *same* work as one for a known address. Without
 * this, "no such user" returns in microseconds and "wrong password" in ~50 ms,
 * which is a usable account-enumeration oracle. The value is not a secret and
 * cannot authenticate anything: no plaintext produces it.
 */
export const DUMMY_ARGON2ID_HASH =
  '$argon2id$v=19$m=65536,t=3,p=4$c2VydmVyb3NkdW1teXNhbHQ$Zm9yY29uc3RhbnR0aW1lY29tcGFyaXNvbg';

/**
 * Decides whether a set of credentials authenticates.
 *
 * Takes the record (or `null` for an unknown address) rather than looking it up
 * itself, which is what makes the whole decision — including the anti-
 * enumeration behaviour — testable without a database.
 *
 * Invariants this enforces, each covered by a test:
 *   * exactly one hash verification runs on every path, including "no such
 *     user" and "deactivated user";
 *   * every failure returns the same code and the same sentence, so the
 *     response cannot distinguish the three cases;
 *   * a hash that is not Argon2id throws rather than denying quietly.
 */
export async function authenticate(
  hasher: PasswordHasher,
  record: CredentialRecord | null,
  password: string,
): Promise<Result<AuthenticatedUser>> {
  const storedHash = record === null ? DUMMY_ARGON2ID_HASH : record.passwordHash;

  if (record !== null && !isArgon2idHash(storedHash)) {
    throw new Error(`Stored credential for user ${record.userId} is not an Argon2id hash.`);
  }

  const matches = await hasher.verify(storedHash, password);

  // The uniform failure. Deliberately identical for "unknown address", "wrong
  // password" and "deactivated account": the sign-in screen must not be a
  // directory of who has an account here.
  const denied = fail(
    'invalid_credentials',
    "That email and password don't match an account.",
  );

  if (record === null) return denied;
  if (!matches) return denied;
  if (!record.isActive) return denied;

  return ok({ userId: record.userId });
}
