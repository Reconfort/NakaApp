/**
 * Maps every error the control plane can produce onto one wire envelope.
 *
 * The envelope is fixed and shared with the Rust agent
 * (`agent/crates/http/src/response.rs#Response::error`):
 *
 *   {"error":{"code":"snake_case_code","message":"Human sentence.","detail":"..."}}
 *
 * The macOS app therefore renders an error from the control plane and an error
 * from an agent through exactly the same code path: `code` selects the copy and
 * the recovery affordance, `message` is the safe fallback sentence, `detail` is
 * what the "View technical details" disclosure shows. `detail` is *omitted*
 * when absent — never `null` — which is what the agent does.
 *
 * Security rule enforced here, not in the filter: a stack trace, a SQL
 * fragment, a Prisma message or a connection string must never reach a client.
 * `mapErrorToEnvelope` returns the client envelope *and* a separate
 * `logDetail`; anything sensitive goes in the latter and is written to the
 * server log by the exception filter.
 *
 * This module imports nothing. Prisma and Nest errors are recognised
 * structurally, which is also what keeps the layer testable with no
 * dependencies installed.
 */

/** The `error` object carried by every non-2xx response body. */
export interface ErrorBody {
  readonly code: string;
  readonly message: string;
  readonly detail?: string;
}

/** A complete response body. */
export interface ErrorEnvelope {
  readonly error: ErrorBody;
}

/** The mapping result: what the client gets, and what the server logs. */
export interface MappedError {
  readonly status: number;
  readonly body: ErrorEnvelope;
  /** `error` for 5xx and unrecognised throwables, `warn` for 4xx. */
  readonly logLevel: 'warn' | 'error';
  /**
   * The technical string for the server log. Holds the original message and
   * any Prisma metadata — precisely the material that must not go to a client.
   */
  readonly logDetail: string;
}

/**
 * An expected, user-facing failure raised by a service.
 *
 * Services throw this instead of a Nest `HttpException` so the service layer
 * stays free of framework imports and so the `code` is chosen at the point the
 * failure is understood, not guessed from a status code later.
 */
export class AppError extends Error {
  readonly code: string;
  readonly status: number;
  readonly detail: string | undefined;

  constructor(code: string, message: string, status = 400, detail?: string) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}

/** Generic sentence used whenever the real cause must not be disclosed. */
const GENERIC_500 = 'Something went wrong on our side.';

/** Default human sentence per HTTP status, used when no better one exists. */
const STATUS_MESSAGES: ReadonlyMap<number, string> = new Map([
  [400, 'That request was not valid.'],
  [401, 'You need to sign in to do that.'],
  [403, "You don't have access to that."],
  [404, "We couldn't find that."],
  [405, 'That action is not allowed here.'],
  [409, 'That conflicts with something that already exists.'],
  [413, 'That request was too large.'],
  [415, 'That content type is not supported.'],
  [422, 'That request was understood but could not be processed.'],
  [429, 'Too many requests. Try again in a moment.'],
  [500, GENERIC_500],
  [502, 'An upstream service did not respond correctly.'],
  [503, 'The service is temporarily unavailable.'],
  [504, 'An upstream service took too long to respond.'],
]);

/** Default `code` per HTTP status. */
const STATUS_CODES: ReadonlyMap<number, string> = new Map([
  [400, 'bad_request'],
  [401, 'unauthorized'],
  [403, 'forbidden'],
  [404, 'not_found'],
  [405, 'method_not_allowed'],
  [409, 'conflict'],
  [413, 'payload_too_large'],
  [415, 'unsupported_media_type'],
  [422, 'unprocessable_entity'],
  [429, 'rate_limited'],
  [500, 'internal_error'],
  [502, 'bad_gateway'],
  [503, 'service_unavailable'],
  [504, 'gateway_timeout'],
]);

/**
 * Prisma error codes we translate deliberately.
 *
 * Everything not listed collapses to a 500 with a generic message: an
 * unrecognised Prisma code usually means schema drift or a bug, and its
 * message routinely contains column names and query fragments.
 */
const PRISMA_MAP: ReadonlyMap<number, { status: number; code: string; message: string }> =
  new Map([
    [2002, { status: 409, code: 'already_exists', message: 'That already exists.' }],
    [2025, { status: 404, code: 'not_found', message: "We couldn't find that." }],
    [
      2003,
      {
        status: 409,
        code: 'related_record_missing',
        message: 'Something this depends on is missing or still in use.',
      },
    ],
    [2000, { status: 400, code: 'value_too_long', message: 'One of those values is too long.' }],
    [
      2001,
      { status: 404, code: 'not_found', message: "We couldn't find the record to update." },
    ],
    [
      2014,
      {
        status: 409,
        code: 'relation_violation',
        message: 'That change would break a link between records.',
      },
    ],
  ]);

/** Structural shape of a Prisma known-request error. */
interface PrismaLikeError {
  readonly code: string;
  readonly message?: unknown;
  readonly meta?: unknown;
}

/** Structural shape of a Nest `HttpException`. */
interface HttpExceptionLike {
  getStatus(): number;
  getResponse(): unknown;
  readonly message?: unknown;
}

/** Structural shape of a zod (or any Standard Schema) validation failure. */
interface SchemaIssue {
  readonly path?: unknown;
  readonly code?: unknown;
  readonly message?: unknown;
}
interface SchemaErrorLike {
  readonly issues: readonly SchemaIssue[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * Recognises a Prisma known-request error without importing Prisma.
 *
 * Prisma's codes are the letter `P` followed by four digits. Matching the shape
 * rather than `instanceof` keeps this module dependency-free, and also survives
 * the duplicate-class problem you get when two copies of the client are
 * installed.
 */
export function isPrismaKnownError(error: unknown): error is PrismaLikeError {
  return isRecord(error) && typeof error['code'] === 'string' && /^P\d{4}$/.test(error['code']);
}

/** Recognises a Nest `HttpException` structurally. */
export function isHttpExceptionLike(error: unknown): error is HttpExceptionLike {
  return (
    isRecord(error) &&
    typeof error['getStatus'] === 'function' &&
    typeof error['getResponse'] === 'function'
  );
}

/** Recognises a zod/Standard Schema error structurally. */
export function isSchemaErrorLike(error: unknown): error is SchemaErrorLike {
  return isRecord(error) && Array.isArray(error['issues']);
}

/**
 * Renders the field paths of a validation failure as an engineer-facing string.
 *
 * Only paths and issue codes are included — never the offending *values*, which
 * are frequently the password or token that failed length validation.
 */
export function summariseSchemaIssues(error: SchemaErrorLike): string {
  const parts: string[] = [];
  for (const issue of error.issues.slice(0, 12)) {
    const path = Array.isArray(issue.path)
      ? issue.path.map((segment) => String(segment)).join('.')
      : '';
    const code = typeof issue.code === 'string' ? issue.code : 'invalid';
    parts.push(path === '' ? code : `${path}: ${code}`);
  }
  if (error.issues.length > 12) parts.push(`…and ${error.issues.length - 12} more`);
  return parts.join(', ');
}

/** Builds an envelope, omitting `detail` when there is none. */
function envelope(code: string, message: string, detail?: string): ErrorEnvelope {
  return { error: detail === undefined ? { code, message } : { code, message, detail } };
}

/**
 * Extracts the technical text of a throwable for the server log.
 *
 * Includes the stack when there is one, since this string never leaves the
 * process.
 */
function technicalText(error: unknown): string {
  if (error instanceof Error) {
    return error.stack ?? `${error.name}: ${error.message}`;
  }
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error) ?? String(error);
  } catch {
    return String(error);
  }
}

/**
 * Pulls the `constraint`/`target` out of Prisma's `meta` for a P2002.
 *
 * Column names are schema information, not user data, and knowing *which*
 * uniqueness failed is the difference between a usable error and a shrug — so
 * this goes in `detail`, which the app shows only behind a disclosure.
 */
function uniqueTargetDetail(error: PrismaLikeError): string | undefined {
  if (!isRecord(error.meta)) return undefined;
  const target = error.meta['target'];
  if (typeof target === 'string') return `unique constraint: ${target}`;
  if (Array.isArray(target)) return `unique constraint: ${target.map(String).join(', ')}`;
  return undefined;
}

/**
 * Maps any throwable to the wire envelope plus a log line.
 *
 * This is the single decision point for "what does the client see when
 * something fails", which is why it is pure and exhaustively tested rather than
 * living inside the Nest exception filter.
 */
export function mapErrorToEnvelope(error: unknown): MappedError {
  const logDetail = technicalText(error);

  // 1. Our own errors: the code and sentence were chosen where the failure was
  //    understood, so pass them through untouched.
  if (error instanceof AppError) {
    return {
      status: error.status,
      body: envelope(error.code, error.message, error.detail),
      logLevel: error.status >= 500 ? 'error' : 'warn',
      logDetail,
    };
  }

  // 2. Schema validation. The sentence is generic on purpose; the field paths
  //    go to `detail`, and no submitted value appears anywhere.
  if (isSchemaErrorLike(error)) {
    const detail = summariseSchemaIssues(error);
    return {
      status: 400,
      body: envelope(
        'validation_failed',
        'Some of those details were not valid.',
        detail === '' ? undefined : detail,
      ),
      logLevel: 'warn',
      logDetail,
    };
  }

  // 3. Prisma. Anything not explicitly mapped becomes a generic 500 — Prisma
  //    messages embed column names and query text.
  if (isPrismaKnownError(error)) {
    const numeric = Number(error.code.slice(1));
    const mapped = PRISMA_MAP.get(numeric);
    if (mapped === undefined) {
      return {
        status: 500,
        body: envelope('internal_error', GENERIC_500),
        logLevel: 'error',
        logDetail: `prisma ${error.code}: ${logDetail}`,
      };
    }
    const detail = numeric === 2002 ? uniqueTargetDetail(error) : undefined;
    return {
      status: mapped.status,
      body: envelope(mapped.code, mapped.message, detail),
      logLevel: 'warn',
      logDetail: `prisma ${error.code}: ${logDetail}`,
    };
  }

  // 4. Nest HttpExceptions raised by guards, pipes and the framework itself.
  if (isHttpExceptionLike(error)) {
    const status = normaliseStatus(error.getStatus());
    const response = error.getResponse();
    const fromResponse = readNestResponse(response);
    const code = fromResponse.code ?? STATUS_CODES.get(status) ?? 'internal_error';
    const fallback = STATUS_MESSAGES.get(status) ?? GENERIC_500;
    // A 5xx sentence is always the generic one: framework 5xx messages leak
    // handler names and internal paths.
    const message = status >= 500 ? GENERIC_500 : (fromResponse.message ?? fallback);
    return {
      status,
      body: envelope(code, message),
      logLevel: status >= 500 ? 'error' : 'warn',
      logDetail,
    };
  }

  // 5. Anything else is a bug. The client learns nothing beyond "we failed".
  return {
    status: 500,
    body: envelope('internal_error', GENERIC_500),
    logLevel: 'error',
    logDetail,
  };
}

/** Clamps an arbitrary status to a plausible HTTP status. */
function normaliseStatus(status: unknown): number {
  if (typeof status !== 'number' || !Number.isInteger(status) || status < 100 || status > 599) {
    return 500;
  }
  return status;
}

/**
 * Reads a `code`/`message` out of a Nest exception response, if it already
 * carries our envelope.
 *
 * Nest exceptions built by our own code may already contain
 * `{error:{code,message}}` (a guard that wants a specific code); the framework's
 * own carry `{statusCode, message, error}`. A `message` is only adopted when it
 * is a single safe-looking sentence — never an array of class-validator strings
 * and never something that looks like a stack or a query.
 */
function readNestResponse(response: unknown): { code?: string; message?: string } {
  if (typeof response === 'string') {
    return looksSafeSentence(response) ? { message: response } : {};
  }
  if (!isRecord(response)) return {};

  const nested = response['error'];
  if (isRecord(nested) && typeof nested['code'] === 'string') {
    const message = typeof nested['message'] === 'string' ? nested['message'] : undefined;
    return message === undefined
      ? { code: nested['code'] }
      : { code: nested['code'], message };
  }

  const message = response['message'];
  if (typeof message === 'string' && looksSafeSentence(message)) return { message };
  return {};
}

/**
 * Guards against adopting a framework string as user-facing copy.
 *
 * Two jobs. It rejects anything long, multi-line, or carrying the tell-tale
 * marks of a stack trace, a SQL statement, a file path or a connection string —
 * the leak protection. And it requires terminal punctuation, which is what
 * filters out HTTP reason phrases: Nest throws `ForbiddenException()` with the
 * response `"Forbidden"`, and `"Forbidden"` is a status name, not something a
 * person should read. Falling through to our own sentence for those is the
 * whole point of the STATUS_MESSAGES table.
 */
export function looksSafeSentence(text: string): boolean {
  if (text.length === 0 || text.length > 200) return false;
  if (!/[.!?]$/.test(text)) return false;
  if (/[\n\r]/.test(text)) return false;
  if (/\bat\s+\S+\s+\(/.test(text)) return false; // stack frame
  if (/\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)\b/.test(text)) return false;
  if (/(?:\w+:\/\/|\/(?:home|usr|var|etc|root|proc)\/|[A-Za-z]:\\)/.test(text)) return false;
  if (/\b(prisma|postgres|postgresql|ECONNREFUSED|ENOTFOUND|ETIMEDOUT|EACCES)\b/i.test(text)) {
    return false;
  }
  return true;
}
