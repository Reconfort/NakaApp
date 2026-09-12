/**
 * Access-token minting and verification.
 *
 * Why this is hand-rolled rather than `@nestjs/jwt`/`jsonwebtoken`:
 * verification is the single control standing between an attacker and every
 * server in the registry, and the failures that matter here — accepting
 * `alg: none`, accepting HS256 when RS256 was configured, accepting a token
 * whose `aud` belongs to a different service, comparing signatures with `===`
 * — are all *omissions*, which a library cannot be relied upon to prevent and
 * which are trivially testable only if the decision code is ours. Keeping it in
 * the pure layer means the whole matrix below is exercised on every run with no
 * database, no network and no installed dependency.
 *
 * The token is a compact JWS: `base64url(header).base64url(payload).base64url(sig)`
 * with HMAC-SHA-256. Refresh tokens are *not* JWTs — see session.logic.ts;
 * they are opaque random strings so that revocation is a database fact rather
 * than an expiry we have to wait out.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

import { fail, ok, type Result } from '../common/result.logic.js';

/**
 * The only algorithm this service will accept.
 *
 * Declared as a constant and compared by equality so that widening it is a
 * deliberate edit with a test to update, never an accident.
 */
export const ACCESS_TOKEN_ALGORITHM = 'HS256' as const;

/** Access tokens are short by design; revocation happens at refresh time. */
export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;

/** Upper bound on an inbound token, so a huge body cannot become CPU work. */
const MAX_TOKEN_LENGTH = 4096;

/** Minimum secret length. 32 bytes of entropy is the floor for HMAC-SHA-256. */
export const MIN_SECRET_BYTES = 32;

/** The JOSE header we emit and the only one we accept. */
interface TokenHeader {
  readonly alg: string;
  readonly typ?: string;
  readonly crit?: unknown;
}

/** Claims carried by an access token. */
export interface AccessTokenClaims {
  /** Subject — the user id. */
  readonly sub: string;
  /** The `Session` row this token descends from, so refresh can revoke it. */
  readonly sid: string;
  /** Token type, to stop a refresh or enrollment token being replayed here. */
  readonly typ: 'access';
  readonly iss: string;
  readonly aud: string;
  /** Issued-at, seconds since the epoch. */
  readonly iat: number;
  /** Not-before, seconds since the epoch. */
  readonly nbf: number;
  /** Expiry, seconds since the epoch. */
  readonly exp: number;
  /** Unique token id, for audit correlation and future denylisting. */
  readonly jti: string;
}

/** Inputs needed to mint a token. */
export interface BuildClaimsInput {
  readonly userId: string;
  readonly sessionId: string;
  readonly issuer: string;
  readonly audience: string;
  readonly jti: string;
  /** Current time. Injected so tests are not wall-clock dependent. */
  readonly now: Date;
  readonly ttlSeconds?: number;
}

/** Verification parameters. */
export interface VerifyOptions {
  readonly secret: string;
  readonly issuer: string;
  readonly audience: string;
  readonly now: Date;
  /**
   * Tolerance applied to `exp`, `nbf` and `iat`, in seconds.
   *
   * Non-zero because the Mac and the control plane are different clocks; a
   * token must not be rejected because the client is a second ahead. Kept
   * small — skew tolerance is extra lifetime granted to a stolen token.
   */
  readonly clockSkewSeconds?: number;
}

/** Default clock tolerance in seconds. */
export const DEFAULT_CLOCK_SKEW_SECONDS = 30;

/** Converts a Date to integer epoch seconds. */
export function toEpochSeconds(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}

/**
 * Encodes bytes or text as unpadded base64url.
 *
 * Unpadded because RFC 7515 requires it; a token carrying `=` is malformed and
 * `decodeBase64Url` rejects it rather than tolerating it.
 */
export function encodeBase64Url(input: Buffer | string): string {
  const buffer = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
  return buffer.toString('base64url');
}

/**
 * Decodes unpadded base64url, rejecting anything non-canonical.
 *
 * `Buffer.from(s, 'base64url')` silently ignores characters outside the
 * alphabet, which would let `eyJhbGci!!!` decode to something plausible. The
 * charset check and the re-encode round-trip together guarantee that the only
 * strings accepted are the exact encodings of the bytes returned — which is
 * what stops a signature being replayed under a mutated but equivalent
 * encoding.
 */
export function decodeBase64Url(segment: string): Buffer | null {
  if (segment.length === 0) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) return null;
  const decoded = Buffer.from(segment, 'base64url');
  if (decoded.toString('base64url') !== segment) return null;
  return decoded;
}

/** Parses a JSON segment into a plain object, or null if it is not one. */
function parseJsonObject(buffer: Buffer): Record<string, unknown> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(buffer.toString('utf8'));
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
  return parsed as Record<string, unknown>;
}

/**
 * Builds the claim set for a new access token.
 *
 * Separate from signing so a test can assert on the claims themselves, and so
 * the TTL and the not-before policy live in one readable place.
 */
export function buildAccessClaims(input: BuildClaimsInput): AccessTokenClaims {
  const issuedAt = toEpochSeconds(input.now);
  const ttl = input.ttlSeconds ?? ACCESS_TOKEN_TTL_SECONDS;
  return {
    sub: input.userId,
    sid: input.sessionId,
    typ: 'access',
    iss: input.issuer,
    aud: input.audience,
    iat: issuedAt,
    // nbf equals iat: the token is valid immediately. Stated explicitly so a
    // verifier that requires nbf has one, rather than treating it as optional.
    nbf: issuedAt,
    exp: issuedAt + ttl,
    jti: input.jti,
  };
}

/** Computes the HMAC over `header.payload`. */
function signingInput(headerSegment: string, payloadSegment: string): string {
  return `${headerSegment}.${payloadSegment}`;
}

function hmac(secret: string, data: string): Buffer {
  return createHmac('sha256', secret).update(data, 'utf8').digest();
}

/**
 * Signs a claim set into a compact JWS.
 *
 * Throws rather than returning a `Result` on a weak secret: a short signing key
 * is a deployment fault that must stop the process, not a request that returns
 * 400.
 */
export function signAccessToken(claims: AccessTokenClaims, secret: string): string {
  assertUsableSecret(secret);
  const header: TokenHeader = { alg: ACCESS_TOKEN_ALGORITHM, typ: 'JWT' };
  const headerSegment = encodeBase64Url(JSON.stringify(header));
  const payloadSegment = encodeBase64Url(JSON.stringify(claims));
  const signature = encodeBase64Url(hmac(secret, signingInput(headerSegment, payloadSegment)));
  return `${headerSegment}.${payloadSegment}.${signature}`;
}

/**
 * Rejects a signing secret that is too short to be safe.
 *
 * Exported so the config loader can fail at boot rather than at first login.
 */
export function assertUsableSecret(secret: string): void {
  if (Buffer.byteLength(secret, 'utf8') < MIN_SECRET_BYTES) {
    throw new Error(
      `Signing secret must be at least ${MIN_SECRET_BYTES} bytes; refusing to sign with a weaker key.`,
    );
  }
}

/** Constant-time comparison of two signatures. */
function signaturesMatch(expected: Buffer, provided: Buffer): boolean {
  // timingSafeEqual throws on length mismatch, which would itself be a timing
  // signal; the length check is cheap and the lengths are not secret.
  if (expected.length !== provided.length) return false;
  return timingSafeEqual(expected, provided);
}

/**
 * Verifies a token and returns its claims.
 *
 * Order is deliberate: structure, then algorithm, then signature, then claims.
 * Nothing inside the payload is trusted — not even read — until the signature
 * over it has been verified, so a forged payload can never influence a
 * decision. Every failure returns a distinct `code` for logging but a
 * deliberately uniform `message`, so the endpoint cannot be used to distinguish
 * "expired" from "forged".
 */
export function verifyAccessToken(
  token: unknown,
  options: VerifyOptions,
): Result<AccessTokenClaims> {
  const invalid = (code: string, detail: string): ReturnType<typeof fail> =>
    fail(code, 'Your session is no longer valid. Sign in again.', detail);

  if (typeof token !== 'string' || token.length === 0) {
    return invalid('token_malformed', 'token is not a non-empty string');
  }
  if (token.length > MAX_TOKEN_LENGTH) {
    return invalid('token_malformed', `token exceeds ${MAX_TOKEN_LENGTH} characters`);
  }

  const segments = token.split('.');
  if (segments.length !== 3) {
    return invalid('token_malformed', `expected 3 segments, got ${segments.length}`);
  }
  const [headerSegment, payloadSegment, signatureSegment] = segments as [string, string, string];

  const headerBytes = decodeBase64Url(headerSegment);
  if (headerBytes === null) return invalid('token_malformed', 'header is not valid base64url');
  const header = parseJsonObject(headerBytes);
  if (header === null) return invalid('token_malformed', 'header is not a JSON object');

  // Algorithm confusion. `alg: none` is caught by this same equality check, but
  // is called out because it is the classic bypass and must stay covered.
  if (header['alg'] !== ACCESS_TOKEN_ALGORITHM) {
    return invalid(
      'token_algorithm_not_allowed',
      `header alg is ${JSON.stringify(header['alg'])}, expected ${ACCESS_TOKEN_ALGORITHM}`,
    );
  }
  if (header['typ'] !== undefined && header['typ'] !== 'JWT') {
    return invalid('token_malformed', `header typ is ${JSON.stringify(header['typ'])}`);
  }
  // RFC 7515 §4.1.11: a `crit` header names extensions the verifier MUST
  // understand. We understand none, so any `crit` is a refusal, not a shrug.
  if (header['crit'] !== undefined) {
    return invalid('token_malformed', 'header declares unsupported crit extensions');
  }

  const providedSignature = decodeBase64Url(signatureSegment);
  if (providedSignature === null) {
    return invalid('token_signature_invalid', 'signature is not valid base64url');
  }
  const expectedSignature = hmac(options.secret, signingInput(headerSegment, payloadSegment));
  if (!signaturesMatch(expectedSignature, providedSignature)) {
    return invalid('token_signature_invalid', 'signature does not match');
  }

  // Signature verified — only now is the payload trustworthy enough to read.
  const payloadBytes = decodeBase64Url(payloadSegment);
  if (payloadBytes === null) return invalid('token_malformed', 'payload is not valid base64url');
  const payload = parseJsonObject(payloadBytes);
  if (payload === null) return invalid('token_malformed', 'payload is not a JSON object');

  const claims = readClaims(payload);
  if (claims === null) return invalid('token_claims_invalid', 'payload is missing required claims');

  if (claims.typ !== 'access') {
    return invalid('token_type_invalid', `typ is ${JSON.stringify(claims.typ)}, expected access`);
  }
  if (claims.iss !== options.issuer) {
    return invalid('token_issuer_invalid', `iss is ${JSON.stringify(claims.iss)}`);
  }
  if (claims.aud !== options.audience) {
    return invalid('token_audience_invalid', `aud is ${JSON.stringify(claims.aud)}`);
  }

  const now = toEpochSeconds(options.now);
  const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;

  if (claims.exp <= now - skew) {
    return invalid('token_expired', `exp ${claims.exp} is before ${now - skew}`);
  }
  if (claims.nbf > now + skew) {
    return invalid('token_not_yet_valid', `nbf ${claims.nbf} is after ${now + skew}`);
  }
  if (claims.iat > now + skew) {
    return invalid('token_not_yet_valid', `iat ${claims.iat} is after ${now + skew}`);
  }
  // A token claiming to outlive its own policy was minted by something else,
  // even if it carries a valid signature (for example, a leaked secret used to
  // mint a year-long token). Rejecting it caps the blast radius.
  if (claims.exp - claims.iat > ACCESS_TOKEN_TTL_SECONDS + skew) {
    return invalid('token_claims_invalid', `lifetime ${claims.exp - claims.iat}s exceeds policy`);
  }

  return ok({ ...claims, typ: 'access' });
}

/** A verified payload before the `typ` value has been checked. */
interface RawClaims {
  readonly sub: string;
  readonly sid: string;
  readonly typ: string;
  readonly iss: string;
  readonly aud: string;
  readonly iat: number;
  readonly nbf: number;
  readonly exp: number;
  readonly jti: string;
}

/** A non-empty string. */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/**
 * An integer epoch-second claim within a sane range.
 *
 * The upper bound rejects the "expires in the year 275760" token that a
 * `new Date(exp * 1000)` elsewhere would turn into `Invalid Date`; the lower
 * bound rejects negatives.
 */
function isEpochSecond(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 0 &&
    value <= 4_102_444_800 // 2100-01-01
  );
}

/**
 * Type-checks a decoded payload into `RawClaims`.
 *
 * Every claim is checked for exact type; a numeric claim arriving as a string
 * ("exp": "99999999999") is a rejection, not a coercion, because coercion is
 * how expiry checks get bypassed.
 */
function readClaims(payload: Record<string, unknown>): RawClaims | null {
  const { sub, sid, typ, iss, aud, iat, nbf, exp, jti } = payload;

  if (!isNonEmptyString(sub)) return null;
  if (!isNonEmptyString(sid)) return null;
  if (typeof typ !== 'string') return null;
  if (typeof iss !== 'string') return null;
  if (typeof aud !== 'string') return null;
  if (!isNonEmptyString(jti)) return null;
  if (!isEpochSecond(iat) || !isEpochSecond(nbf) || !isEpochSecond(exp)) return null;

  return { sub, sid, typ, iss, aud, iat, nbf, exp, jti };
}
