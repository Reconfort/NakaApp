import { z } from 'zod';

/**
 * Request schemas for `/v1/servers`.
 *
 * Shape only — the meaning-bearing rules (is this a valid hostname, is this a
 * POSIX username, is this a SHA256 fingerprint) live in `servers.logic.ts`, so
 * that they are tested once and produce one consistent sentence whether the
 * input arrived over HTTP or from the enrollment path.
 */

export const createServerSchema = z.object({
  name: z.string().min(1).max(64),
  hostname: z.string().min(1).max(253),
  sshPort: z.union([z.number().int(), z.string()]).optional(),
  sshUsername: z.string().min(1).max(32),
  agentPort: z.union([z.number().int(), z.string()]).optional(),
  tags: z.array(z.string().max(32)).max(16).optional(),
  hostKeyFingerprint: z.string().max(128).nullish(),
});
export type CreateServerDto = z.infer<typeof createServerSchema>;

/** Update takes the same shape — a server is small enough to send whole. */
export const updateServerSchema = createServerSchema;
export type UpdateServerDto = z.infer<typeof updateServerSchema>;

/** Telemetry an agent posts on its heartbeat. */
export const heartbeatSchema = z.object({
  cpuPercent: z.number().nullable(),
  memoryPercent: z.number().nullable(),
  diskPercent: z.number().nullable(),
  containersStopped: z.number().int().min(0).default(0),
  servicesFailed: z.number().int().min(0).default(0),
  agentVersion: z.string().max(32).nullish(),
  os: z.string().max(64).nullish(),
  arch: z.string().max(32).nullish(),
  hostKeyFingerprint: z.string().max(128).nullish(),
});
export type HeartbeatDto = z.infer<typeof heartbeatSchema>;
