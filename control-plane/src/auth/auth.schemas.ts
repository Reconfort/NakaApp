import { z } from 'zod';

/**
 * Request schemas for the auth endpoints.
 *
 * zod 4 API (docs/reference/backend-stack.md §4.5): `z.email()` is top-level
 * rather than `z.string().email()`, and error customisation uses `error:`
 * rather than `message:`. A v3 snippet pasted here will not typecheck.
 *
 * These schemas intentionally validate *shape only* — length bounds and format.
 * The rules that carry meaning (is this password strong enough, is this address
 * one we have already normalised) live in the logic layer, because they need to
 * be tested and reused by paths that never see an HTTP request.
 */

/** Registration payload. */
export const registerSchema = z.object({
  email: z.email({ error: 'Enter a valid email address.' }).max(254),
  // No `.min(12)` here: the policy sentence comes from
  // `validatePasswordStrength`, so that the user gets one consistent message
  // rather than a zod one at the edge and ours in the service.
  password: z.string().min(1).max(1024),
  name: z.string().min(1).max(120),
});
export type RegisterDto = z.infer<typeof registerSchema>;

/** Login payload. */
export const loginSchema = z.object({
  email: z.string().min(1).max(254),
  password: z.string().min(1).max(1024),
});
export type LoginDto = z.infer<typeof loginSchema>;

/** Refresh payload. */
export const refreshSchema = z.object({
  refreshToken: z.string().min(1).max(256),
});
export type RefreshDto = z.infer<typeof refreshSchema>;
