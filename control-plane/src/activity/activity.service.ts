import { Injectable, Logger } from '@nestjs/common';

import { AppConfigService } from '../config/config.service.js';
import { AppError } from '../common/error-mapping.logic.js';
import { EventsPublisher } from '../events/events.publisher.js';
import { PrismaService } from '../prisma/prisma.service.js';
import {
  buildActivityRecord,
  buildAuditRecord,
  type ActivityInput,
  type AuditInput,
} from './activity.logic.js';
import {
  buildKeysetFilter,
  buildPage,
  decodeCursor,
  normalisePageSize,
  type Page,
} from './pagination.logic.js';

/** An activity row as the API returns it. */
export interface ActivityView {
  readonly id: string;
  readonly serverId: string | null;
  readonly userId: string | null;
  readonly kind: string;
  readonly resourceType: string;
  readonly resourceId: string | null;
  readonly summary: string;
  readonly result: string;
  readonly createdAt: string;
}

/** Query parameters for the feed. */
export interface FeedQuery {
  readonly serverId?: string | undefined;
  readonly cursor?: string | undefined;
  readonly limit?: string | number | undefined;
}

/**
 * The append-only activity feed and audit trail.
 *
 * Reads are keyset-paginated; writes go through the shaping and redaction in
 * `activity.logic.ts`. There is no update or delete method here, and
 * `PrismaService`'s append-only extension refuses them at the client level too,
 * so the absence is enforced rather than merely observed.
 */
@Injectable()
export class ActivityService {
  private readonly logger = new Logger(ActivityService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: AppConfigService,
    private readonly events: EventsPublisher,
  ) {}

  /**
   * Appends an activity row and announces it on the event stream.
   *
   * Never throws. An activity entry describes something that already happened;
   * refusing to write the note must not undo the deed or turn a successful
   * operation into a 500 for the user. Failures are logged loudly instead.
   *
   * Writing and announcing are one call so that the dashboard's live feed
   * cannot fall out of step with the table behind it — every row that lands is
   * broadcast, without each call site having to remember.
   */
  async record(input: ActivityInput): Promise<void> {
    const shaped = buildActivityRecord(input);
    if (!shaped.ok) {
      this.logger.error(`Rejected activity (${input.kind}): ${shaped.detail ?? shaped.message}`);
      return;
    }
    try {
      const row = await this.prisma.activity.create({ data: shaped.value });
      const payload = {
        id: row.id,
        kind: row.kind,
        summary: row.summary,
        result: row.result,
      };
      // Account-scoped rows (a server was added or removed) have no server room
      // to go to, so they reach the owner's own room instead.
      if (row.serverId !== null) {
        this.events.publishActivity(row.serverId, payload);
      } else if (row.userId !== null) {
        this.events.publishAccountActivity(row.userId, payload);
      }
    } catch (error) {
      this.logger.error(`Activity write failed for ${input.kind}`, error as Error);
    }
  }

  /**
   * Appends an audit row.
   *
   * Unlike `record`, this throws. A security event that goes unrecorded is a
   * failure of the control, and the caller has to know.
   */
  async audit(input: AuditInput): Promise<void> {
    const shaped = buildAuditRecord(input);
    if (!shaped.ok) {
      throw new AppError(shaped.code, shaped.message, 500, shaped.detail);
    }
    await this.prisma.auditLog.create({ data: shaped.value });
  }

  /**
   * Reads a page of the feed, newest first.
   *
   * Scoped to servers the caller owns. The `ownerId` filter is applied through
   * the relation rather than trusted from the caller's `serverId` parameter, so
   * passing someone else's server id returns an empty page rather than their
   * history.
   */
  async list(userId: string, query: FeedQuery): Promise<Page<ActivityView>> {
    const pageSize = normalisePageSize(query.limit);

    const scope =
      query.serverId === undefined
        ? { server: { ownerId: userId } }
        : { serverId: query.serverId, server: { ownerId: userId } };

    let keyset: ReturnType<typeof buildKeysetFilter> | undefined;
    if (query.cursor !== undefined) {
      const position = decodeCursor(query.cursor, this.config.cursorSecret);
      if (!position.ok) {
        throw new AppError(position.code, position.message, 400, position.detail);
      }
      keyset = buildKeysetFilter(position.value);
    }

    // Over-fetch by one: that extra row is how `buildPage` knows whether a
    // further page exists, without a count(*) over a table that only grows.
    const rows = await this.prisma.activity.findMany({
      where: keyset === undefined ? scope : { AND: [scope, keyset] },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: pageSize + 1,
    });

    const page = buildPage(rows, pageSize, this.config.cursorSecret);
    return {
      items: page.items.map((row) => ({
        id: row.id,
        serverId: row.serverId,
        userId: row.userId,
        kind: row.kind,
        resourceType: row.resourceType,
        resourceId: row.resourceId,
        summary: row.summary,
        result: row.result,
        createdAt: row.createdAt.toISOString(),
      })),
      nextCursor: page.nextCursor,
    };
  }
}
