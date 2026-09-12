/**
 * Turns raw server telemetry into the one thing the product is built around:
 * a state, a sentence, and something to do about it.
 *
 * This function drives the most visible surface in ServerOS — the dot and the
 * line of copy on every server card and at the top of every server detail page.
 * It is deliberately the most heavily tested code in the control plane, because
 * a wrong verdict here is either a false alarm at 3am or a real outage the user
 * was never told about.
 *
 * Design rules:
 *   * `reason` is a finished human sentence. The UI renders it verbatim — it
 *     does not template, pluralise or capitalise. That keeps the copy in one
 *     reviewable place instead of spread across SwiftUI views.
 *   * `primaryAction` is a route hint, not a label. The app maps it to a
 *     destination and supplies its own button copy.
 *   * a healthy server has `reason: null` and `primaryAction: null`. There is
 *     nothing to say and nothing to do, and the UI shows the calm state.
 *   * exactly one reason is returned, the most severe. A card that lists four
 *     problems is the "wall of numbers" the product exists to avoid.
 */

/** The four states a server can be in, in ascending severity. */
export type HealthState = 'healthy' | 'warning' | 'critical' | 'offline';

/** The verdict rendered on a server card. */
export interface HealthVerdict {
  readonly state: HealthState;
  /** A finished sentence, or null when everything is fine. */
  readonly reason: string | null;
  /** A UI route hint such as `server.storage`, or null when there is nothing to do. */
  readonly primaryAction: string | null;
}

/** Telemetry as reported by the agent, plus the freshness of that report. */
export interface HealthInput {
  /** Sustained CPU utilisation, 0-100. Null when not yet reported. */
  readonly cpuPercent: number | null;
  /** Memory in use, 0-100. Null when not yet reported. */
  readonly memoryPercent: number | null;
  /** Fullest filesystem, 0-100. Null when not yet reported. */
  readonly diskPercent: number | null;
  /** When the agent last checked in. Null means it never has. */
  readonly agentLastSeenAt: Date | null;
  /** Containers in a non-running state. */
  readonly containersStopped: number;
  /** systemd units in a failed state. */
  readonly servicesFailed: number;
}

/**
 * How stale a report may be before the server is considered offline.
 *
 * The agent heartbeats every 30s, so 90s is three missed beats: long enough to
 * ride out a dropped packet or a brief network blip, short enough that a real
 * outage is on screen inside two minutes.
 */
export const OFFLINE_AFTER_SECONDS = 90;

/** Disk at or above this is an outage in progress. */
export const DISK_CRITICAL_PERCENT = 95;
/** Disk at or above this needs attention this week. */
export const DISK_WARNING_PERCENT = 80;
/** Sustained CPU at or above this means something is wrong or undersized. */
export const CPU_WARNING_PERCENT = 90;
/** Memory at or above this means the OOM killer is close. */
export const MEMORY_WARNING_PERCENT = 90;

/** Route hints the macOS app understands. */
export const ACTIONS = {
  reconnect: 'server.reconnect',
  storage: 'server.storage',
  services: 'server.services',
  docker: 'server.docker',
  processes: 'server.processes',
  memory: 'server.processes',
} as const;

/**
 * Reads a percentage that may be missing or nonsense.
 *
 * Non-finite values, negatives and values above 100 are treated as *unknown*
 * rather than clamped. Clamping a `NaN` to 0 would report a full disk as
 * healthy; treating it as unknown means the metric simply does not contribute
 * to the verdict, which is the safe failure.
 */
function readPercent(value: number | null): number | null {
  if (value === null) return null;
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  if (value < 0 || value > 100) return null;
  return value;
}

/** Reads a count that may be missing or nonsense, defaulting to zero. */
function readCount(value: number): number {
  if (!Number.isFinite(value) || value < 0) return 0;
  return Math.floor(value);
}

/** Rounds a percentage for display — nobody needs "82.4183% full". */
function displayPercent(value: number): number {
  return Math.round(value);
}

/**
 * Renders "4 minutes"-style copy for how long the agent has been silent.
 *
 * Written out rather than pulled from a library because this string goes on
 * screen and the phrasing is part of the product.
 */
export function describeSilence(seconds: number): string {
  if (seconds < 120) return 'the last minute or so';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minutes`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return hours === 1 ? 'an hour' : `${hours} hours`;
  return `${Math.floor(hours / 24)} days`;
}

/** Pluralises a noun against a count. */
function plural(count: number, singular: string, pluralForm: string): string {
  return count === 1 ? singular : pluralForm;
}

/**
 * Computes the health verdict for a server.
 *
 * Precedence, highest first — the ordering is a product decision, not an
 * accident of the `if` chain, so it is stated here and asserted in the tests:
 *
 *  1. **offline** — we have not heard from the agent. Nothing else can be
 *     trusted, because every other figure in the input is a stale reading from
 *     before the silence began.
 *  2. **critical / failed services** — something is already down. A failed unit
 *     is a user-visible outage right now.
 *  3. **critical / disk ≥ 95%** — an outage arriving within hours, and the one
 *     that takes a database with it.
 *  4. **warning / disk ≥ 80%** — needs a decision this week.
 *  5. **warning / CPU ≥ 90%** sustained.
 *  6. **warning / memory ≥ 90%**.
 *  7. **warning / any stopped container** — possibly deliberate, which is why
 *     it ranks below the resource pressure that is never deliberate.
 *  8. **healthy**.
 *
 * `now` is a parameter rather than a call to `Date.now()` so the offline
 * boundary is testable to the second.
 */
export function computeHealth(input: HealthInput, now: Date = new Date()): HealthVerdict {
  // 1. Offline.
  if (input.agentLastSeenAt === null) {
    return {
      state: 'offline',
      reason: "ServerOS hasn't connected to this server yet.",
      primaryAction: ACTIONS.reconnect,
    };
  }
  const lastSeen = input.agentLastSeenAt.getTime();
  if (!Number.isFinite(lastSeen)) {
    return {
      state: 'offline',
      reason: "ServerOS can't tell when this server was last seen.",
      primaryAction: ACTIONS.reconnect,
    };
  }
  const silentForSeconds = Math.floor((now.getTime() - lastSeen) / 1000);
  if (silentForSeconds > OFFLINE_AFTER_SECONDS) {
    return {
      state: 'offline',
      reason: `ServerOS hasn't heard from this server in ${describeSilence(silentForSeconds)}.`,
      primaryAction: ACTIONS.reconnect,
    };
  }

  const disk = readPercent(input.diskPercent);
  const cpu = readPercent(input.cpuPercent);
  const memory = readPercent(input.memoryPercent);
  const stopped = readCount(input.containersStopped);
  const failed = readCount(input.servicesFailed);

  // 2. Failed services — already broken.
  if (failed > 0) {
    return {
      state: 'critical',
      reason:
        failed === 1
          ? 'A service has failed and is not running.'
          : `${failed} services have failed and are not running.`,
      primaryAction: ACTIONS.services,
    };
  }

  // 3. Disk about to run out.
  if (disk !== null && disk >= DISK_CRITICAL_PERCENT) {
    return {
      state: 'critical',
      reason: `Storage is ${displayPercent(disk)}% full and about to run out.`,
      primaryAction: ACTIONS.storage,
    };
  }

  // 4-7. Warnings, in the order a person would want to hear them.
  if (disk !== null && disk >= DISK_WARNING_PERCENT) {
    return {
      state: 'warning',
      reason: `Storage is ${displayPercent(disk)}% full.`,
      primaryAction: ACTIONS.storage,
    };
  }
  if (cpu !== null && cpu >= CPU_WARNING_PERCENT) {
    return {
      state: 'warning',
      reason: `CPU has been at ${displayPercent(cpu)}% for a sustained period.`,
      primaryAction: ACTIONS.processes,
    };
  }
  if (memory !== null && memory >= MEMORY_WARNING_PERCENT) {
    return {
      state: 'warning',
      reason: `Memory is ${displayPercent(memory)}% used.`,
      primaryAction: ACTIONS.memory,
    };
  }
  if (stopped > 0) {
    return {
      state: 'warning',
      reason: `${stopped} ${plural(stopped, 'container is', 'containers are')} stopped.`,
      primaryAction: ACTIONS.docker,
    };
  }

  // 8. Nothing to report.
  return { state: 'healthy', reason: null, primaryAction: null };
}

/** The `ServerStatus` enum values, mirrored so this module stays Prisma-free. */
export type ServerStatusValue = 'PENDING' | 'CONNECTED' | 'DEGRADED' | 'OFFLINE' | 'UNREACHABLE';

/**
 * Maps a health verdict onto the persisted `Server.status`.
 *
 * Two vocabularies exist on purpose. `HealthState` is what the user reads and
 * changes as often as telemetry does; `ServerStatus` is the connection fact
 * stored on the row and used for filtering and for the sidebar count. A server
 * that has never enrolled stays `PENDING` no matter what stale metrics say —
 * "pending" is about the relationship, not about the load.
 */
export function statusForVerdict(
  verdict: HealthVerdict,
  current: ServerStatusValue,
): ServerStatusValue {
  if (current === 'PENDING') return 'PENDING';
  switch (verdict.state) {
    case 'offline':
      return 'OFFLINE';
    case 'critical':
    case 'warning':
      return 'DEGRADED';
    case 'healthy':
      return 'CONNECTED';
  }
}

/**
 * Whether a status change is worth writing an Activity row for.
 *
 * Only transitions matter. Writing a row for every heartbeat would bury the
 * feed the user actually reads under thousands of "still connected" entries.
 */
export function shouldRecordStatusChange(
  previous: ServerStatusValue,
  next: ServerStatusValue,
): boolean {
  return previous !== next;
}
