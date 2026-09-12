/**
 * The result type every pure-logic module returns.
 *
 * Why not exceptions: the logic layer has no framework to catch for it, and a
 * failure here is nearly always an expected outcome (a wrong password, an
 * expired code) rather than a bug. Making failure part of the return type means
 * the compiler forces each caller to decide what the user should see, and means
 * every failure already carries the `code`/`message` pair the HTTP envelope and
 * the macOS app need.
 */

/** A failed operation, already shaped for the wire envelope. */
export interface Failure {
  readonly ok: false;
  /** Stable snake_case identifier. The macOS app keys its copy off this. */
  readonly code: string;
  /** One human sentence, safe to show a user. Never technical. */
  readonly message: string;
  /** Engineer-facing text, shown behind "View technical details". */
  readonly detail?: string;
}

/** A successful operation carrying its value. */
export interface Success<T> {
  readonly ok: true;
  readonly value: T;
}

/** Either outcome of an operation that can fail in an expected way. */
export type Result<T> = Success<T> | Failure;

/**
 * Wraps a value as a success.
 *
 * Exists so call sites read as `return ok(claims)` rather than repeating the
 * object literal, and so the discriminant can never be typo'd.
 */
export function ok<T>(value: T): Success<T> {
  return { ok: true, value };
}

/**
 * Builds a failure.
 *
 * `detail` is omitted from the object entirely when not supplied rather than
 * set to `undefined`, because the wire envelope omits absent details (matching
 * the Rust agent, which writes no `"detail"` key at all) and because
 * `exactOptionalPropertyTypes` makes the distinction real to the compiler.
 */
export function fail(code: string, message: string, detail?: string): Failure {
  return detail === undefined
    ? { ok: false, code, message }
    : { ok: false, code, message, detail };
}

/**
 * Narrows a `Result` to its failure branch.
 *
 * A type predicate rather than `!result.ok` so it can be passed to `filter`
 * and used in expressions where the discriminant check would not narrow.
 */
export function isFailure<T>(result: Result<T>): result is Failure {
  return result.ok === false;
}
