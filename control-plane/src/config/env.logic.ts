/**
 * Configuration parsing and validation.
 *
 * Kept pure so that "the process refuses to start with a weak JWT secret" is a
 * tested property rather than an aspiration. Every value the application needs
 * is read once, here, and a missing or unusable one is a startup failure — not
 * a runtime surprise at the first login, and never a silent fallback to a
 * development default. A control plane that boots with `JWT_SECRET=secret`
 * because the variable was misspelled is worse than one that refuses to boot.
 */

import { fail, ok, type Result } from '../common/result.logic.js';
import { MIN_SECRET_BYTES } from '../auth/token.logic.js';

/** The fully resolved configuration. */
export interface AppConfig {
  readonly nodeEnv: 'development' | 'test' | 'production';
  readonly port: number;
  readonly databaseUrl: string;
  readonly redisUrl: string;
  readonly jwtSecret: string;
  readonly jwtIssuer: string;
  readonly jwtAudience: string;
  readonly cursorSecret: string;
  /** Origins allowed to call the API. Empty means same-origin only. */
  readonly corsOrigins: readonly string[];
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error';
  /** Trust `X-Forwarded-For` — only true behind a proxy you control. */
  readonly trustProxy: boolean;
}

/** The raw environment, as `process.env`. */
export type RawEnv = Record<string, string | undefined>;

function readString(env: RawEnv, key: string): string | null {
  const value = env[key];
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
}

/**
 * Validates a secret used for signing.
 *
 * The byte-length floor is the same one `token.logic.ts` enforces at sign time;
 * checking it here means the failure happens at boot, where an operator sees
 * it, rather than at the first request.
 */
function readSecret(env: RawEnv, key: string): Result<string> {
  const value = readString(env, key);
  if (value === null) {
    return fail('config_missing', `${key} is not set.`);
  }
  if (Buffer.byteLength(value, 'utf8') < MIN_SECRET_BYTES) {
    return fail(
      'config_weak_secret',
      `${key} must be at least ${MIN_SECRET_BYTES} bytes. Generate one with: openssl rand -base64 48`,
    );
  }
  // Catches the copy-pasted example value surviving into a real deployment.
  if (/^(change[-_]?me|secret|password|example|placeholder)/i.test(value)) {
    return fail('config_weak_secret', `${key} still looks like a placeholder value.`);
  }
  return ok(value);
}

/** Parses a port, rejecting anything outside the valid range. */
function readPort(env: RawEnv, key: string, fallback: number): Result<number> {
  const raw = readString(env, key);
  if (raw === null) return ok(fallback);
  if (!/^\d+$/.test(raw)) return fail('config_invalid', `${key} must be a number.`);
  const value = Number.parseInt(raw, 10);
  if (value < 1 || value > 65535) {
    return fail('config_invalid', `${key} must be between 1 and 65535.`);
  }
  return ok(value);
}

/** Parses a `postgres://` or `postgresql://` connection string. */
function readDatabaseUrl(env: RawEnv): Result<string> {
  const value = readString(env, 'DATABASE_URL');
  if (value === null) return fail('config_missing', 'DATABASE_URL is not set.');
  if (!/^postgres(ql)?:\/\//.test(value)) {
    return fail('config_invalid', 'DATABASE_URL must be a postgres:// connection string.');
  }
  return ok(value);
}

/** Parses a `redis://` or `rediss://` connection string. */
function readRedisUrl(env: RawEnv): Result<string> {
  const value = readString(env, 'REDIS_URL');
  if (value === null) return fail('config_missing', 'REDIS_URL is not set.');
  if (!/^rediss?:\/\//.test(value)) {
    return fail('config_invalid', 'REDIS_URL must be a redis:// connection string.');
  }
  return ok(value);
}

/** Splits a comma-separated origin list, dropping empties. */
function readOrigins(env: RawEnv): readonly string[] {
  const raw = readString(env, 'CORS_ORIGINS');
  if (raw === null) return [];
  return raw
    .split(',')
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);
}

/**
 * Resolves the whole configuration from an environment.
 *
 * Takes the environment as an argument rather than reading `process.env`
 * directly — that is what makes the whole surface testable, including the
 * refusals.
 */
export function loadConfig(env: RawEnv): Result<AppConfig> {
  const nodeEnvRaw = readString(env, 'NODE_ENV') ?? 'development';
  if (nodeEnvRaw !== 'development' && nodeEnvRaw !== 'test' && nodeEnvRaw !== 'production') {
    return fail('config_invalid', 'NODE_ENV must be development, test or production.');
  }

  const port = readPort(env, 'PORT', 3000);
  if (!port.ok) return port;

  const databaseUrl = readDatabaseUrl(env);
  if (!databaseUrl.ok) return databaseUrl;

  const redisUrl = readRedisUrl(env);
  if (!redisUrl.ok) return redisUrl;

  const jwtSecret = readSecret(env, 'JWT_SECRET');
  if (!jwtSecret.ok) return jwtSecret;

  const cursorSecret = readSecret(env, 'CURSOR_SECRET');
  if (!cursorSecret.ok) return cursorSecret;

  // Separate keys for separate jobs: a cursor signature and a session token
  // have different lifetimes and different blast radii, and reusing one key for
  // both means rotating either one invalidates the other.
  if (jwtSecret.value === cursorSecret.value) {
    return fail('config_invalid', 'JWT_SECRET and CURSOR_SECRET must be different values.');
  }

  const logLevelRaw = readString(env, 'LOG_LEVEL') ?? 'info';
  if (
    logLevelRaw !== 'debug' &&
    logLevelRaw !== 'info' &&
    logLevelRaw !== 'warn' &&
    logLevelRaw !== 'error'
  ) {
    return fail('config_invalid', 'LOG_LEVEL must be debug, info, warn or error.');
  }

  return ok({
    nodeEnv: nodeEnvRaw,
    port: port.value,
    databaseUrl: databaseUrl.value,
    redisUrl: redisUrl.value,
    jwtSecret: jwtSecret.value,
    jwtIssuer: readString(env, 'JWT_ISSUER') ?? 'serveros-control-plane',
    jwtAudience: readString(env, 'JWT_AUDIENCE') ?? 'serveros-app',
    cursorSecret: cursorSecret.value,
    corsOrigins: readOrigins(env),
    logLevel: logLevelRaw,
    trustProxy: readString(env, 'TRUST_PROXY') === 'true',
  });
}

/**
 * Loads the configuration or throws with the operator-facing sentence.
 *
 * Used by `main.ts`. Throwing is right here and only here: there is no request
 * to return a status to, and a control plane that starts up misconfigured is a
 * worse outcome than one that does not start.
 */
export function loadConfigOrThrow(env: RawEnv): AppConfig {
  const result = loadConfig(env);
  if (!result.ok) {
    throw new Error(`Configuration error: ${result.message}`);
  }
  return result.value;
}
