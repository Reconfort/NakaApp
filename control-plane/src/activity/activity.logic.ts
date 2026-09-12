/**
 * Shaping for the two append-only record types.
 *
 * `Activity` is a product surface — the "Recent Activity" list the user reads
 * on the dashboard — so its rows are validated for *presentation*: a finished
 * summary sentence, a known event kind, bounded lengths. `AuditLog` is
 * evidence, so its rows are validated for *retention*: an actor that will still
 * mean something after the user is deleted, and no foreign keys that could
 * cascade the record away.
 *
 * Both pass their metadata through `redaction.logic.ts` here rather than at the
 * call sites, so there is exactly one route into either table and it cannot be
 * bypassed by forgetting.
 */

import { fail, ok, type Result } from '../common/result.logic.js';
import { redactMetadata, type JsonValue } from './redaction.logic.js';

/** Outcome of the operation an activity row describes. */
export type ActivityResultValue = 'SUCCEEDED' | 'FAILED';

/** Outcome recorded on an audit row. */
export type AuditOutcomeValue = 'SUCCEEDED' | 'FAILED' | 'DENIED';

/** Longest summary retained. Beyond this it is not a feed entry, it is a log. */
const MAX_SUMMARY_LENGTH = 280;

/** Longest user-agent retained. */
const MAX_USER_AGENT_LENGTH = 512;

/** Dotted lower-case event name, e.g. `docker.container.restart`. */
const KIND_PATTERN = /^[a-z][a-z0-9]*(?:\.[a-z0-9]+){1,3}$/;

/** Resource type, e.g. `container`, `service`, `server`. */
const RESOURCE_TYPE_PATTERN = /^[a-z][a-z0-9_]{1,31}$/;

/** What a caller supplies to record an activity. */
export interface ActivityInput {
  readonly serverId?: string | null;
  readonly userId?: string | null;
  readonly kind: string;
  readonly resourceType: string;
  readonly resourceId?: string | null;
  readonly summary: string;
  readonly metadata?: unknown;
  readonly result?: ActivityResultValue;
}

/** A row ready to be written to `Activity`. */
export interface ActivityRecord {
  readonly serverId: string | null;
  readonly userId: string | null;
  readonly kind: string;
  readonly resourceType: string;
  readonly resourceId: string | null;
  readonly summary: string;
  readonly metadata: Record<string, JsonValue>;
  readonly result: ActivityResultValue;
}

/**
 * Collapses whitespace and trims a user-visible string.
 *
 * Activity summaries are rendered in a single-line list row, so an embedded
 * newline would either be swallowed silently or break the layout depending on
 * the view. Normalising here means the UI never has to defend against it.
 */
function normaliseSentence(value: string, maxLength: number): string {
  const collapsed = value.replace(/\s+/g, ' ').trim();
  return collapsed.length > maxLength ? `${collapsed.slice(0, maxLength - 1)}…` : collapsed;
}

/** Null-safe identifier read: empty strings become null rather than ''. */
function optionalId(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
}

/**
 * Validates and shapes an activity row.
 *
 * Returns a `Result` rather than throwing because a malformed activity must
 * never fail the operation it describes — restarting a container succeeded even
 * if the feed entry for it was rejected. The caller logs the failure and moves
 * on.
 */
export function buildActivityRecord(input: ActivityInput): Result<ActivityRecord> {
  if (!KIND_PATTERN.test(input.kind)) {
    return fail(
      'activity_kind_invalid',
      "That activity couldn't be recorded.",
      `kind ${JSON.stringify(input.kind)} is not a dotted lower-case name`,
    );
  }
  if (!RESOURCE_TYPE_PATTERN.test(input.resourceType)) {
    return fail(
      'activity_resource_type_invalid',
      "That activity couldn't be recorded.",
      `resourceType ${JSON.stringify(input.resourceType)} is not a known shape`,
    );
  }
  const summary = normaliseSentence(input.summary, MAX_SUMMARY_LENGTH);
  if (summary.length === 0) {
    return fail(
      'activity_summary_empty',
      "That activity couldn't be recorded.",
      'summary is empty after normalisation',
    );
  }

  return ok({
    serverId: optionalId(input.serverId),
    userId: optionalId(input.userId),
    kind: input.kind,
    resourceType: input.resourceType,
    resourceId: optionalId(input.resourceId),
    summary,
    metadata: redactMetadata(input.metadata ?? {}),
    result: input.result ?? 'SUCCEEDED',
  });
}

/** What a caller supplies to record an audit event. */
export interface AuditInput {
  readonly actor: string;
  readonly actorType?: 'user' | 'api_key' | 'agent' | 'system';
  readonly action: string;
  readonly targetType?: string | null;
  readonly targetId?: string | null;
  readonly ip?: string | null;
  readonly userAgent?: string | null;
  readonly outcome: AuditOutcomeValue;
  readonly metadata?: unknown;
}

/** A row ready to be written to `AuditLog`. */
export interface AuditRecord {
  readonly actor: string;
  readonly actorType: string;
  readonly action: string;
  readonly targetType: string | null;
  readonly targetId: string | null;
  readonly ip: string | null;
  readonly userAgent: string | null;
  readonly outcome: AuditOutcomeValue;
  readonly metadata: Record<string, JsonValue>;
}

/**
 * Normalises a client IP for the audit trail.
 *
 * Strips an IPv6 zone index and the `::ffff:` prefix Node puts on
 * IPv4-mapped addresses, so the same client is not recorded under two
 * spellings — which would quietly defeat "show me everything from this
 * address". Anything that does not look like an address at all is dropped
 * rather than stored, since a forged `X-Forwarded-For` is worse than no value.
 */
export function normaliseIp(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  let address = value.trim();
  if (address.length === 0 || address.length > 45) return null;
  const zone = address.indexOf('%');
  if (zone !== -1) address = address.slice(0, zone);
  if (address.toLowerCase().startsWith('::ffff:')) address = address.slice(7);

  const isIpv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(address);
  if (isIpv4 !== null) {
    return isIpv4.slice(1).every((octet) => Number(octet) <= 255) ? address : null;
  }
  // Deliberately permissive on IPv6: the goal is to reject junk, not to
  // reimplement inet_pton.
  if (/^[0-9a-fA-F:]{2,45}$/.test(address) && address.includes(':')) return address.toLowerCase();
  return null;
}

/**
 * Validates and shapes an audit row.
 *
 * Unlike activity, a rejected audit record is a problem: it means a
 * security-relevant event went unrecorded. The caller is expected to treat the
 * failure as an error rather than swallowing it.
 */
export function buildAuditRecord(input: AuditInput): Result<AuditRecord> {
  const actor = input.actor.trim();
  if (actor.length === 0 || actor.length > 128) {
    return fail('audit_actor_invalid', 'That action could not be recorded.', 'actor is empty or too long');
  }
  if (!KIND_PATTERN.test(input.action)) {
    return fail(
      'audit_action_invalid',
      'That action could not be recorded.',
      `action ${JSON.stringify(input.action)} is not a dotted lower-case name`,
    );
  }

  const targetType = optionalId(input.targetType);
  if (targetType !== null && !RESOURCE_TYPE_PATTERN.test(targetType)) {
    return fail(
      'audit_target_invalid',
      'That action could not be recorded.',
      `targetType ${JSON.stringify(targetType)} is not a known shape`,
    );
  }

  const userAgent = optionalId(input.userAgent);

  return ok({
    actor,
    actorType: input.actorType ?? 'user',
    action: input.action,
    targetType,
    targetId: optionalId(input.targetId),
    ip: normaliseIp(input.ip),
    userAgent: userAgent === null ? null : normaliseSentence(userAgent, MAX_USER_AGENT_LENGTH),
    outcome: input.outcome,
    metadata: redactMetadata(input.metadata ?? {}),
  });
}
