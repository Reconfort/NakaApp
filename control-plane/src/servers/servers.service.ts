import { Injectable, Logger } from '@nestjs/common';

import { ActivityService } from '../activity/activity.service.js';
import { AppError } from '../common/error-mapping.logic.js';
import { EventsPublisher } from '../events/events.publisher.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { computeHealth, shouldRecordStatusChange, statusForVerdict, type HealthVerdict } from './health.logic.js';
import {
  authoriseServerAccess,
  isHostKeyChanged,
  normaliseServerInput,
  type ServerInput,
} from './servers.logic.js';

/** A server as the API returns it: the row plus its computed health. */
export interface ServerView {
  readonly id: string;
  readonly name: string;
  readonly hostname: string;
  readonly sshPort: number;
  readonly sshUsername: string;
  readonly os: string | null;
  readonly arch: string | null;
  readonly status: string;
  readonly agentVersion: string | null;
  readonly agentPort: number;
  readonly lastSeenAt: string | null;
  readonly hostKeyFingerprint: string | null;
  readonly tags: readonly string[];
  readonly createdAt: string;
  readonly health: HealthVerdict;
}

/** Telemetry an agent reports on its heartbeat. */
export interface HeartbeatInput {
  readonly cpuPercent: number | null;
  readonly memoryPercent: number | null;
  readonly diskPercent: number | null;
  readonly containersStopped: number;
  readonly servicesFailed: number;
  readonly agentVersion?: string | null;
  readonly os?: string | null;
  readonly arch?: string | null;
  readonly hostKeyFingerprint?: string | null;
}

/**
 * The server registry.
 *
 * Note what this service does *not* do: it never connects to a server, never
 * runs a command on one, and never holds a credential for one. The Mac app
 * talks to the agent directly over an SSH-forwarded channel; the control plane
 * owns the list, the identity and the history. Adding a "restart this service"
 * method here would be the architectural mistake the whole design exists to
 * avoid.
 */
@Injectable()
export class ServersService {
  private readonly logger = new Logger(ServersService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly activity: ActivityService,
    private readonly events: EventsPublisher,
  ) {}

  /** Lists a user's servers, newest first. */
  async list(userId: string): Promise<ServerView[]> {
    const rows = await this.prisma.server.findMany({
      where: { ownerId: userId },
      orderBy: { createdAt: 'desc' },
    });
    const now = new Date();
    return rows.map((row) => this.toView(row, now));
  }

  /**
   * Loads one server, or fails as if it did not exist.
   *
   * The `row === null` check is repeated after `authoriseServerAccess` rather
   * than asserted away: the two conditions are the same in practice, but a
   * non-null assertion here would silently become wrong the day the
   * authorisation rule grows a case that does not imply existence.
   */
  async findOne(userId: string, serverId: string): Promise<ServerView> {
    const row = await this.prisma.server.findUnique({ where: { id: serverId } });
    const access = authoriseServerAccess(
      row === null ? null : { id: row.id, ownerId: row.ownerId },
      userId,
    );
    if (!access.ok || row === null) {
      throw new AppError('not_found', "We couldn't find that server.", 404);
    }
    return this.toView(row, new Date());
  }

  /** Registers a new server. It starts PENDING until an agent enrolls. */
  async create(userId: string, input: ServerInput): Promise<ServerView> {
    const normalised = normaliseServerInput(input);
    if (!normalised.ok) {
      throw new AppError(normalised.code, normalised.message, 400, normalised.detail);
    }

    const row = await this.prisma.server.create({
      data: { ...normalised.value, ownerId: userId },
    });

    await this.activity.record({
      serverId: row.id,
      userId,
      kind: 'server.create',
      resourceType: 'server',
      resourceId: row.id,
      summary: `Added ${row.name}`,
    });

    return this.toView(row, new Date());
  }

  /** Updates a server's registration details. */
  async update(userId: string, serverId: string, input: ServerInput): Promise<ServerView> {
    await this.findOne(userId, serverId);

    const normalised = normaliseServerInput(input);
    if (!normalised.ok) {
      throw new AppError(normalised.code, normalised.message, 400, normalised.detail);
    }

    const row = await this.prisma.server.update({
      where: { id: serverId },
      data: normalised.value,
    });

    await this.activity.record({
      serverId: row.id,
      userId,
      kind: 'server.update',
      resourceType: 'server',
      resourceId: row.id,
      summary: `Updated ${row.name}`,
    });

    return this.toView(row, new Date());
  }

  /** Removes a server from the registry. */
  async remove(userId: string, serverId: string): Promise<void> {
    const server = await this.findOne(userId, serverId);
    await this.prisma.server.delete({ where: { id: serverId } });
    await this.activity.record({
      serverId: null,
      userId,
      kind: 'server.delete',
      resourceType: 'server',
      resourceId: serverId,
      summary: `Removed ${server.name}`,
    });
  }

  /**
   * Records a heartbeat and recomputes health.
   *
   * Posted by the macOS app, not by the agent. That follows from the
   * architecture rather than from convenience: the app is already connected to
   * the agent over its SSH-forwarded channel and already has this telemetry on
   * screen, whereas the agent has no credential for the control plane and the
   * control plane cannot reach the agent. Relaying through the authenticated
   * client means the fleet stays reachable without opening an inbound path to
   * every server.
   *
   * The status column is only written when the verdict actually changes, and an
   * activity row only on a transition. A heartbeat every 30 seconds across a
   * fleet would otherwise be a write per server per 30s and a feed nobody can
   * read.
   */
  async recordHeartbeat(
    userId: string,
    serverId: string,
    telemetry: HeartbeatInput,
  ): Promise<ServerView> {
    const row = await this.prisma.server.findUnique({ where: { id: serverId } });
    const access = authoriseServerAccess(
      row === null ? null : { id: row.id, ownerId: row.ownerId },
      userId,
    );
    if (!access.ok || row === null) {
      throw new AppError('not_found', "We couldn't find that server.", 404);
    }

    const now = new Date();
    const verdict = computeHealth(
      {
        cpuPercent: telemetry.cpuPercent,
        memoryPercent: telemetry.memoryPercent,
        diskPercent: telemetry.diskPercent,
        agentLastSeenAt: now,
        containersStopped: telemetry.containersStopped,
        servicesFailed: telemetry.servicesFailed,
      },
      now,
    );

    const nextStatus = statusForVerdict(verdict, row.status === 'PENDING' ? 'CONNECTED' : row.status);
    const changed = shouldRecordStatusChange(row.status, nextStatus);

    // A changed host key is never overwritten silently — the user decides
    // whether the machine was rebuilt or is being impersonated.
    const observedFingerprint = telemetry.hostKeyFingerprint ?? null;
    if (isHostKeyChanged(row.hostKeyFingerprint, observedFingerprint)) {
      this.logger.warn(`Host key changed for server ${serverId}; leaving the stored value in place.`);
      await this.activity.record({
        serverId,
        userId: null,
        kind: 'server.hostkey.changed',
        resourceType: 'server',
        resourceId: serverId,
        summary: `The SSH host key for ${row.name} has changed`,
        result: 'FAILED',
      });
    }

    const updated = await this.prisma.server.update({
      where: { id: serverId },
      data: {
        status: nextStatus,
        lastSeenAt: now,
        agentVersion: telemetry.agentVersion ?? row.agentVersion,
        os: telemetry.os ?? row.os,
        arch: telemetry.arch ?? row.arch,
        hostKeyFingerprint: row.hostKeyFingerprint ?? observedFingerprint,
      },
    });

    const view = this.toView(updated, now);

    if (changed) {
      await this.activity.record({
        serverId,
        userId: null,
        kind: 'server.status.changed',
        resourceType: 'server',
        resourceId: serverId,
        summary: `${updated.name} is now ${verdict.state}`,
        metadata: { from: row.status, to: nextStatus },
        result: verdict.state === 'healthy' ? 'SUCCEEDED' : 'FAILED',
      });
    }

    this.events.publishServerStatus(serverId, {
      status: view.status,
      health: view.health,
      lastSeenAt: view.lastSeenAt,
    });

    return view;
  }

  /**
   * Projects a row plus its computed health into the API shape.
   *
   * Health is computed on read rather than stored. A stored verdict goes stale
   * the moment the agent stops reporting — which is precisely the case where it
   * matters most — so the one value that must never lie is derived every time.
   */
  private toView(
    row: {
      id: string;
      name: string;
      hostname: string;
      sshPort: number;
      sshUsername: string;
      os: string | null;
      arch: string | null;
      status: string;
      agentVersion: string | null;
      agentPort: number;
      lastSeenAt: Date | null;
      hostKeyFingerprint: string | null;
      tags: string[];
      createdAt: Date;
    },
    now: Date,
  ): ServerView {
    const health = computeHealth(
      {
        // Live metrics arrive over the event stream from the agent, not from
        // this table; on a plain read the only thing the control plane knows is
        // how long it has been since the agent last checked in. That alone is
        // enough to distinguish "offline" from "we have no reason to worry",
        // which is what a list row needs to show.
        cpuPercent: null,
        memoryPercent: null,
        diskPercent: null,
        agentLastSeenAt: row.lastSeenAt,
        containersStopped: 0,
        servicesFailed: 0,
      },
      now,
    );

    return {
      id: row.id,
      name: row.name,
      hostname: row.hostname,
      sshPort: row.sshPort,
      sshUsername: row.sshUsername,
      os: row.os,
      arch: row.arch,
      status: row.status,
      agentVersion: row.agentVersion,
      agentPort: row.agentPort,
      lastSeenAt: row.lastSeenAt === null ? null : row.lastSeenAt.toISOString(),
      hostKeyFingerprint: row.hostKeyFingerprint,
      tags: row.tags,
      createdAt: row.createdAt.toISOString(),
      health: row.status === 'PENDING'
        ? { state: 'offline', reason: 'Waiting for the agent to connect.', primaryAction: 'server.enroll' }
        : health,
    };
  }
}
