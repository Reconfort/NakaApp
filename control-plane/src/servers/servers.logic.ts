/**
 * Validation and access control for the server registry.
 *
 * The registry holds no credentials (see the comment on `model Server` in
 * prisma/schema.prisma), so the sensitive decisions here are about *access* —
 * who may see and change a row — and about *shape*, because a hostname or
 * username stored here is later interpolated into an SSH invocation by the Mac
 * app. A hostname containing a space or a shell metacharacter is rejected at
 * the door rather than trusted to be quoted correctly three layers later.
 */

import { fail, ok, type Result } from '../common/result.logic.js';

/** Longest display name for a server. */
const MAX_NAME_LENGTH = 64;

/** Longest hostname, per RFC 1035. */
const MAX_HOSTNAME_LENGTH = 253;

/** Most tags a server may carry, and the longest a tag may be. */
const MAX_TAGS = 16;
const MAX_TAG_LENGTH = 32;

/** A DNS name: labels of letters, digits and hyphens, separated by dots. */
const HOSTNAME_PATTERN = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** Dotted-quad IPv4. */
const IPV4_PATTERN = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Permissive IPv6 — enough to reject junk without reimplementing inet_pton. */
const IPV6_PATTERN = /^[0-9a-f:]{2,45}$/;

/** POSIX portable username: starts with a letter or underscore. */
const USERNAME_PATTERN = /^[a-z_][a-z0-9_-]{0,31}$/;

/** Lower-case slug, for tags. */
const TAG_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;

/** `SHA256:` followed by the unpadded base64 of a 32-byte digest. */
const FINGERPRINT_PATTERN = /^SHA256:[A-Za-z0-9+/]{43}$/;

/** What a client may submit when creating or updating a server. */
export interface ServerInput {
  readonly name: unknown;
  readonly hostname: unknown;
  readonly sshPort?: unknown;
  readonly sshUsername: unknown;
  readonly agentPort?: unknown;
  readonly tags?: unknown;
  readonly hostKeyFingerprint?: unknown;
}

/** A validated server, ready to persist. */
export interface NormalisedServer {
  readonly name: string;
  readonly hostname: string;
  readonly sshPort: number;
  readonly sshUsername: string;
  readonly agentPort: number;
  readonly tags: string[];
  readonly hostKeyFingerprint: string | null;
}

/** Default SSH port. */
export const DEFAULT_SSH_PORT = 22;

/** Default port the agent listens on behind the SSH tunnel. */
export const DEFAULT_AGENT_PORT = 9443;

/**
 * Validates a hostname or IP address.
 *
 * Accepts either form because both are legitimate ways to reach a server, and
 * rejecting IPs would break every user whose box has no DNS name. Trailing dots
 * are trimmed so `example.com.` and `example.com` are one server, not two.
 */
export function normaliseHostname(input: unknown): Result<string> {
  if (typeof input !== 'string') {
    return fail('hostname_invalid', 'Enter a hostname or IP address.');
  }
  let value = input.trim().toLowerCase();
  if (value.endsWith('.')) value = value.slice(0, -1);
  if (value.length === 0 || value.length > MAX_HOSTNAME_LENGTH) {
    return fail('hostname_invalid', "That hostname doesn't look right.");
  }

  const ipv4 = IPV4_PATTERN.exec(value);
  if (ipv4 !== null) {
    return ipv4.slice(1).every((octet) => Number(octet) <= 255)
      ? ok(value)
      : fail('hostname_invalid', "That IP address doesn't look right.");
  }
  if (value.includes(':')) {
    return IPV6_PATTERN.test(value)
      ? ok(value)
      : fail('hostname_invalid', "That IP address doesn't look right.");
  }
  if (!HOSTNAME_PATTERN.test(value)) {
    return fail('hostname_invalid', "That hostname doesn't look right.");
  }
  return ok(value);
}

/**
 * Validates a TCP port.
 *
 * Accepts the string form too, because a port arrives from a text field and
 * from a query parameter far more often than it arrives as a number.
 */
export function normalisePort(input: unknown, fallback: number): Result<number> {
  if (input === undefined || input === null || input === '') return ok(fallback);
  const value =
    typeof input === 'number'
      ? input
      : typeof input === 'string' && /^\d+$/.test(input)
        ? Number.parseInt(input, 10)
        : Number.NaN;
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    return fail('port_invalid', 'Enter a port between 1 and 65535.');
  }
  return ok(value);
}

/** Validates a Linux username. */
export function normaliseUsername(input: unknown): Result<string> {
  if (typeof input !== 'string') {
    return fail('username_invalid', 'Enter the username to connect with.');
  }
  const value = input.trim();
  if (!USERNAME_PATTERN.test(value)) {
    return fail('username_invalid', "That username isn't a valid Linux username.");
  }
  return ok(value);
}

/**
 * Validates the tag list.
 *
 * Deduplicates rather than rejecting duplicates: a user who typed "prod" twice
 * meant it once, and an error there is friction with no security value.
 */
export function normaliseTags(input: unknown): Result<string[]> {
  if (input === undefined || input === null) return ok([]);
  if (!Array.isArray(input)) {
    return fail('tags_invalid', 'Tags must be a list.');
  }
  if (input.length > MAX_TAGS) {
    return fail('tags_invalid', `Use ${MAX_TAGS} tags or fewer.`);
  }
  const seen = new Set<string>();
  for (const entry of input) {
    if (typeof entry !== 'string') {
      return fail('tags_invalid', 'Tags must be text.');
    }
    const tag = entry.trim().toLowerCase();
    if (tag.length === 0) continue;
    if (tag.length > MAX_TAG_LENGTH || !TAG_PATTERN.test(tag)) {
      return fail('tags_invalid', 'Use letters, numbers and hyphens in tags.');
    }
    seen.add(tag);
  }
  return ok([...seen].sort());
}

/**
 * Validates an SSH host key fingerprint.
 *
 * Only the modern `SHA256:` form is accepted. The legacy MD5 hex fingerprint is
 * refused outright rather than stored and compared, because accepting it would
 * mean the "has this server's host key changed?" check is only as strong as
 * MD5.
 */
export function normaliseFingerprint(input: unknown): Result<string | null> {
  if (input === undefined || input === null || input === '') return ok(null);
  if (typeof input !== 'string') {
    return fail('fingerprint_invalid', "That host key fingerprint doesn't look right.");
  }
  const value = input.trim();
  if (!FINGERPRINT_PATTERN.test(value)) {
    return fail(
      'fingerprint_invalid',
      'ServerOS expects a SHA256 host key fingerprint.',
      'expected SHA256:<43 base64 characters>',
    );
  }
  return ok(value);
}

/** Validates a server display name. */
export function normaliseServerName(input: unknown): Result<string> {
  if (typeof input !== 'string') {
    return fail('name_invalid', 'Give this server a name.');
  }
  const value = input.replace(/\s+/g, ' ').trim();
  if (value.length === 0) {
    return fail('name_invalid', 'Give this server a name.');
  }
  if (value.length > MAX_NAME_LENGTH) {
    return fail('name_too_long', `Use ${MAX_NAME_LENGTH} characters or fewer.`);
  }
  return ok(value);
}

/**
 * Validates a whole server submission.
 *
 * Short-circuits on the first failure so the user fixes one thing at a time.
 * The alternative — returning every error at once — reads as a wall of red on a
 * five-field form and is worse, not better.
 */
export function normaliseServerInput(input: ServerInput): Result<NormalisedServer> {
  const name = normaliseServerName(input.name);
  if (!name.ok) return name;

  const hostname = normaliseHostname(input.hostname);
  if (!hostname.ok) return hostname;

  const sshPort = normalisePort(input.sshPort, DEFAULT_SSH_PORT);
  if (!sshPort.ok) return sshPort;

  const sshUsername = normaliseUsername(input.sshUsername);
  if (!sshUsername.ok) return sshUsername;

  const agentPort = normalisePort(input.agentPort, DEFAULT_AGENT_PORT);
  if (!agentPort.ok) return agentPort;

  const tags = normaliseTags(input.tags);
  if (!tags.ok) return tags;

  const hostKeyFingerprint = normaliseFingerprint(input.hostKeyFingerprint);
  if (!hostKeyFingerprint.ok) return hostKeyFingerprint;

  return ok({
    name: name.value,
    hostname: hostname.value,
    sshPort: sshPort.value,
    sshUsername: sshUsername.value,
    agentPort: agentPort.value,
    tags: tags.value,
    hostKeyFingerprint: hostKeyFingerprint.value,
  });
}

/** The minimum of a server row needed for an access decision. */
export interface OwnedResource {
  readonly id: string;
  readonly ownerId: string;
}

/**
 * Decides whether a user may act on a server.
 *
 * Returns 404, not 403, for a server owned by someone else. A 403 confirms the
 * id exists, which turns the endpoint into a way to enumerate other people's
 * server ids; the caller of a resource they cannot see should be told the same
 * thing as the caller of a resource that does not exist.
 *
 * `resource` is `null` when the row was not found, so the two cases converge
 * here rather than at four different call sites.
 */
export function authoriseServerAccess(
  resource: OwnedResource | null,
  userId: string,
): Result<OwnedResource> {
  if (resource === null || resource.ownerId !== userId) {
    return fail('not_found', "We couldn't find that server.");
  }
  return ok(resource);
}

/**
 * Whether a host key fingerprint change should be surfaced as a warning.
 *
 * A first-time fingerprint is simply recorded — that is trust on first use. A
 * *changed* fingerprint on a server we have already seen is either a rebuilt
 * machine or a machine-in-the-middle, and the user has to be the one to decide
 * which. The control plane never silently overwrites the stored value.
 */
export function isHostKeyChanged(stored: string | null, observed: string | null): boolean {
  if (stored === null || observed === null) return false;
  return stored !== observed;
}
