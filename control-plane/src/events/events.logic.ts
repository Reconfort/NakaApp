/**
 * WebSocket authorisation, room naming and event envelopes.
 *
 * The gateway itself is a thin shell (`events.gateway.ts`); everything that
 * decides *whether* a socket may do something lives here. That matters more for
 * sockets than for HTTP: an HTTP request is authorised once per request by a
 * guard, whereas a socket authenticates once at connect and then issues many
 * subscriptions, so the per-subscription check is easy to forget and impossible
 * to retrofit. Keeping it pure means it is checked on every test run.
 *
 * Rooms are per-server, not per-user, so that one status change is broadcast
 * once rather than fanned out per subscriber — but membership is granted per
 * user, after an ownership check, so a room name alone grants nothing.
 */

import { fail, ok, type Result } from '../common/result.logic.js';

/** Namespace the gateway listens on. */
export const EVENTS_NAMESPACE = '/v1/events';

/** UUID v4-ish shape. Ids come from Prisma's `uuid()`. */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Types of event the gateway emits. */
export type EventType = 'server.status' | 'server.metrics' | 'activity.created';

/** Everything the gateway broadcasts shares this envelope. */
export interface EventEnvelope<T> {
  readonly type: EventType;
  /** The server the event is about, or null for account-level events. */
  readonly serverId: string | null;
  /** ISO-8601 emission time, so a client can order and de-duplicate. */
  readonly at: string;
  readonly payload: T;
}

/**
 * The room a server's events are published to.
 *
 * Prefixed and validated so a caller cannot pass `*` or a crafted string and
 * join something it should not — socket.io room names are just strings, and an
 * unvalidated one joined straight from client input is the socket equivalent of
 * string-concatenated SQL.
 */
export function roomForServer(serverId: string): string {
  if (!UUID_PATTERN.test(serverId)) {
    throw new Error('Refusing to build a room name from a non-UUID server id.');
  }
  return `server:${serverId.toLowerCase()}`;
}

/** The room an account's own events are published to. */
export function roomForUser(userId: string): string {
  if (!UUID_PATTERN.test(userId)) {
    throw new Error('Refusing to build a room name from a non-UUID user id.');
  }
  return `user:${userId.toLowerCase()}`;
}

/**
 * The handshake a socket.io client presents.
 *
 * Modelled structurally so this module needs no socket.io import.
 */
export interface Handshake {
  readonly auth?: Record<string, unknown> | undefined;
  readonly headers?: Record<string, unknown> | undefined;
  readonly query?: Record<string, unknown> | undefined;
}

/**
 * Extracts a bearer token from a handshake.
 *
 * Three places are checked, in descending order of safety:
 *   1. `auth.token` — the socket.io idiom, and the only one that is not
 *      logged by an intermediary.
 *   2. the `Authorization` header — works for non-browser clients.
 *   3. `query.token` — accepted last and reluctantly, because query strings end
 *      up in proxy access logs. Supported only because some WebSocket clients
 *      cannot set headers at all.
 */
export function extractToken(handshake: Handshake): string | null {
  const fromAuth = handshake.auth?.['token'];
  if (typeof fromAuth === 'string' && fromAuth.length > 0) return fromAuth;

  const header = handshake.headers?.['authorization'] ?? handshake.headers?.['Authorization'];
  if (typeof header === 'string') {
    const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
    if (match?.[1] !== undefined) return match[1];
  }

  const fromQuery = handshake.query?.['token'];
  if (typeof fromQuery === 'string' && fromQuery.length > 0) return fromQuery;

  return null;
}

/** Who a connected socket belongs to. */
export interface SocketIdentity {
  readonly userId: string;
  readonly sessionId: string;
}

/** Verifier seam: the gateway passes in `verifyAccessToken` bound to config. */
export type TokenVerifier = (token: string) => Result<{ sub: string; sid: string }>;

/**
 * Decides whether a connecting socket is authenticated.
 *
 * Returning a `Result` rather than throwing matters here: a socket rejected
 * with an exception disconnects with a generic transport error, whereas a
 * `code` can be sent to the client so the Mac app knows to refresh its token
 * and reconnect rather than to show "connection failed" and give up.
 */
export function authoriseConnection(
  handshake: Handshake,
  verify: TokenVerifier,
): Result<SocketIdentity> {
  const token = extractToken(handshake);
  if (token === null) {
    return fail('unauthorized', 'Sign in to receive live updates.', 'no token in handshake');
  }
  const verified = verify(token);
  if (!verified.ok) return verified;
  return ok({ userId: verified.value.sub, sessionId: verified.value.sid });
}

/** A subscription request from an authenticated socket. */
export interface SubscriptionRequest {
  readonly identity: SocketIdentity;
  readonly serverId: unknown;
  /** Server ids this user owns, as loaded by the gateway. */
  readonly ownedServerIds: readonly string[];
}

/**
 * Decides whether a socket may join a server's room.
 *
 * A non-existent server and someone else's server produce the same refusal, for
 * the same reason as `authoriseServerAccess` in servers.logic.ts: distinguishing
 * them turns the socket into an id oracle, and a socket is a much cheaper thing
 * to spray than an HTTP endpoint behind a rate limiter.
 */
export function decideSubscription(request: SubscriptionRequest): Result<string> {
  const { serverId, ownedServerIds } = request;

  if (typeof serverId !== 'string' || !UUID_PATTERN.test(serverId)) {
    return fail('subscription_invalid', "That server isn't available.", 'serverId is not a uuid');
  }
  const normalised = serverId.toLowerCase();
  const owned = ownedServerIds.some((id) => id.toLowerCase() === normalised);
  if (!owned) {
    return fail('subscription_denied', "That server isn't available.", 'not owned by this user');
  }
  return ok(roomForServer(normalised));
}

/**
 * Rooms a socket should join the moment it connects.
 *
 * The account room is joined unconditionally so that account-level events —
 * a server added on another Mac, a session revoked — reach the client without
 * it having to ask. Server rooms are not auto-joined: a user with forty servers
 * should not receive forty metric streams to render one dashboard.
 */
export function initialRooms(identity: SocketIdentity): string[] {
  return [roomForUser(identity.userId)];
}

/** Payload of a `server.status` event. */
export interface ServerStatusPayload {
  readonly status: string;
  readonly health: { state: string; reason: string | null; primaryAction: string | null };
  readonly lastSeenAt: string | null;
}

/**
 * Builds a status-change event.
 *
 * `at` is supplied rather than read from the clock so that a batch of events
 * emitted from one tick share a timestamp, which is what lets the client order
 * them deterministically.
 */
export function buildStatusEvent(
  serverId: string,
  payload: ServerStatusPayload,
  at: Date,
): EventEnvelope<ServerStatusPayload> {
  return { type: 'server.status', serverId, at: at.toISOString(), payload };
}

/** Payload of an `activity.created` event. */
export interface ActivityPayload {
  readonly id: string;
  readonly kind: string;
  readonly summary: string;
  readonly result: string;
}

/** Builds an activity event for the live feed. */
export function buildActivityEvent(
  serverId: string | null,
  payload: ActivityPayload,
  at: Date,
): EventEnvelope<ActivityPayload> {
  return { type: 'activity.created', serverId, at: at.toISOString(), payload };
}

/**
 * Where an event should be delivered.
 *
 * An event about a server goes to that server's room; an account-level event
 * goes to the account room. Returning the room from a function rather than
 * computing it at each emit site means an event can never be published to a
 * room nobody is authorised to be in.
 */
export function routeFor(event: EventEnvelope<unknown>, userId: string): string {
  return event.serverId === null ? roomForUser(userId) : roomForServer(event.serverId);
}
