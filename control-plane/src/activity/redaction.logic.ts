/**
 * Strips secrets out of activity and audit metadata before it is persisted.
 *
 * This is a security control, not a tidiness pass. `metadata` is the one field
 * in the system that accepts arbitrary JSON from a caller, and the callers are
 * an agent reporting what it did and a service recording what a user asked
 * for — both of which routinely have a token, an environment variable or a
 * connection string in hand. Anything written here is durable, is read back
 * into the activity feed, and will end up in a support export, so the rule is
 * that it never enters the database in the first place. Redacting at read time
 * would be too late.
 *
 * Two independent passes, because either alone is insufficient:
 *   * **by key** — `password`, `token`, `secret`, `apiKey`, `authorization`…
 *     catches values that look ordinary (`{"password": "hunter2"}`).
 *   * **by value shape** — PEM blocks, JWTs, `Bearer …`, SSH keys, URLs with
 *     inline credentials. Catches secrets under an innocent key
 *     (`{"note": "ssh-rsa AAAAB3..."}`), which the key pass cannot see.
 *
 * The function is total: it never throws, never mutates its input, terminates
 * on cyclic structures, and bounds its own output size. A redactor that throws
 * on a hostile input would take down the write path it is protecting.
 */

/** The marker written in place of a redacted value. */
export const REDACTED = '[redacted]';

/** Maximum nesting depth retained. Deeper structures are truncated. */
const MAX_DEPTH = 8;

/** Maximum keys kept per object, and items per array. */
const MAX_ENTRIES = 64;

/** Maximum length of any retained string. */
const MAX_STRING_LENGTH = 2048;

/** JSON that is safe to persist. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/**
 * Key names whose value is always removed.
 *
 * Matched case-insensitively against the key with separators stripped, so
 * `api_key`, `apiKey`, `API-KEY` and `apikey` are one rule.
 */
const SENSITIVE_KEY_PATTERN =
  /(pass(word|wd|phrase)?|secret|token|apikey|privatekey|credential|authorization|auth|cookie|session(id)?|signature|otp|mfa|totp|pin|salt|nonce|bearer|clientsecret|refresh|accesskey|connectionstring|dsn|env)/i;

/**
 * Key names that survive the pattern above despite matching it.
 *
 * `tokenCount`, `sessionCount` and friends are metrics, not secrets, and the
 * activity feed is much less useful without them. Listed explicitly so that
 * widening the allowance is a deliberate, reviewable act.
 */
const SAFE_KEY_EXACT = new Set([
  'tokencount',
  'tokens',
  'sessioncount',
  'sessionstarted',
  'authmethod',
  'authtype',
  'envname',
  'environment',
  'passed',
  'passing',
]);

/** Normalises a key for matching: lower case, separators removed. */
function normaliseKey(key: string): string {
  return key.toLowerCase().replace(/[\s._-]/g, '');
}

/**
 * Whether a key's value must be removed regardless of what it holds.
 *
 * Exported because the same decision is needed when logging request bodies.
 */
export function isSensitiveKey(key: string): boolean {
  const normalised = normaliseKey(key);
  if (SAFE_KEY_EXACT.has(normalised)) return false;
  return SENSITIVE_KEY_PATTERN.test(normalised);
}

/** Value shapes that are secrets regardless of the key they sit under. */
const SECRET_VALUE_PATTERNS: readonly RegExp[] = [
  // PEM private key blocks of every flavour.
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/,
  // OpenSSH private key.
  /-----BEGIN OPENSSH PRIVATE KEY-----/,
  // A compact JWS/JWT: three base64url segments.
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,
  // Authorization header values.
  /\b(?:Bearer|Basic|Digest)\s+[A-Za-z0-9+/=._-]{12,}/i,
  // Common vendor key prefixes.
  /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
  /\bsk-[A-Za-z0-9]{16,}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  // An SSH private key blob pasted inline.
  /\bPRIVATE KEY\b/,
];

/** A URL carrying inline credentials, e.g. postgres://user:pass@host/db. */
const URL_CREDENTIAL_PATTERN = /([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^/\s@]+)@/gi;

/**
 * Redacts a single string value.
 *
 * URLs are rewritten rather than dropped — `postgres://app:[redacted]@db:5432/x`
 * is still a useful thing to see in an activity row, and the useful part is
 * exactly the part that is not the password.
 */
export function redactString(value: string): string {
  const withoutUrlCredentials = value.replace(
    URL_CREDENTIAL_PATTERN,
    (_match, scheme: string, user: string) => `${scheme}${user}:${REDACTED}@`,
  );
  for (const pattern of SECRET_VALUE_PATTERNS) {
    if (pattern.test(withoutUrlCredentials)) return REDACTED;
  }
  return withoutUrlCredentials.length > MAX_STRING_LENGTH
    ? `${withoutUrlCredentials.slice(0, MAX_STRING_LENGTH)}…`
    : withoutUrlCredentials;
}

/**
 * Produces a persistable copy of arbitrary metadata with secrets removed.
 *
 * Always returns a plain object: `metadata` is a JSON column with a `{}`
 * default, and a scalar or array there would break every reader. A non-object
 * input is wrapped under a `value` key rather than discarded.
 */
export function redactMetadata(input: unknown): Record<string, JsonValue> {
  const seen = new WeakSet<object>();
  const redacted = walk(input, 0, seen);
  if (redacted !== null && typeof redacted === 'object' && !Array.isArray(redacted)) {
    return redacted;
  }
  return { value: redacted };
}

/** Recursive worker. `seen` breaks cycles; `depth` bounds runaway nesting. */
function walk(value: unknown, depth: number, seen: WeakSet<object>): JsonValue {
  if (value === null || value === undefined) return null;

  switch (typeof value) {
    case 'string':
      return redactString(value);
    case 'number':
      // NaN and Infinity are not representable in JSON.
      return Number.isFinite(value) ? value : null;
    case 'boolean':
      return value;
    case 'bigint':
      return value.toString();
    case 'function':
    case 'symbol':
      return null;
    default:
      break;
  }

  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString();
  }
  if (value instanceof Error) {
    // The message only; a stack is internal detail and belongs in the log.
    return redactString(value.message);
  }
  if (Buffer.isBuffer(value)) {
    // Never persist raw bytes — they are as likely to be key material as not.
    return `[${value.byteLength} bytes]`;
  }

  if (typeof value !== 'object') return null;
  if (seen.has(value)) return '[circular]';
  if (depth >= MAX_DEPTH) return '[truncated]';
  seen.add(value);

  if (Array.isArray(value)) {
    const items = value.slice(0, MAX_ENTRIES).map((item) => walk(item, depth + 1, seen));
    if (value.length > MAX_ENTRIES) items.push(`…${value.length - MAX_ENTRIES} more`);
    return items;
  }

  const output: Record<string, JsonValue> = {};
  let count = 0;
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (count >= MAX_ENTRIES) {
      output['…'] = 'truncated';
      break;
    }
    count += 1;
    output[key] = isSensitiveKey(key) ? REDACTED : walk(entry, depth + 1, seen);
  }
  return output;
}
