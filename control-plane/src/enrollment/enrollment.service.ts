import { Injectable, Logger } from '@nestjs/common';

import { ActivityService } from '../activity/activity.service.js';
import { AppError } from '../common/error-mapping.logic.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { authoriseServerAccess } from '../servers/servers.logic.js';
import {
  ENROLLMENT_TTL_SECONDS,
  buildConsumeGuard,
  canonicaliseCode,
  decideConsume,
  enrollmentExpiry,
  generateEnrollmentCode,
  hashEnrollmentCode,
  interpretConsumeResult,
} from './enrollment.logic.js';

/** A freshly minted code, returned exactly once. */
export interface MintedEnrollment {
  /** The grouped, human-readable code. Not recoverable after this response. */
  readonly code: string;
  readonly expiresAt: string;
  readonly expiresInSeconds: number;
}

/** What an agent receives when it successfully enrolls. */
export interface EnrollmentResult {
  readonly serverId: string;
  readonly serverName: string;
}

/**
 * Minting and redeeming enrollment codes.
 *
 * The plaintext code exists in exactly two places: the response body of
 * `mint`, and the request body of `consume`. It is never logged, never stored,
 * and never returned again — `ServerEnrollment` holds only its SHA-256.
 */
@Injectable()
export class EnrollmentService {
  private readonly logger = new Logger(EnrollmentService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly activity: ActivityService,
  ) {}

  /**
   * Mints a one-time code for a server the caller owns.
   *
   * Any outstanding unconsumed codes for the same server are expired first.
   * Otherwise asking for a new code because the first one was mislaid would
   * leave the mislaid one valid — and "I generated a new code" reads to a user
   * as "the old one is dead".
   */
  async mint(userId: string, serverId: string, ip: string | null): Promise<MintedEnrollment> {
    const server = await this.prisma.server.findUnique({ where: { id: serverId } });
    const access = authoriseServerAccess(
      server === null ? null : { id: server.id, ownerId: server.ownerId },
      userId,
    );
    if (!access.ok) throw new AppError(access.code, access.message, 404);

    const now = new Date();
    const generated = generateEnrollmentCode();
    const expiresAt = enrollmentExpiry(now);

    await this.prisma.$transaction([
      this.prisma.serverEnrollment.updateMany({
        where: { serverId, consumedAt: null, expiresAt: { gt: now } },
        data: { expiresAt: now },
      }),
      this.prisma.serverEnrollment.create({
        data: { serverId, codeHash: generated.codeHash, expiresAt, createdByIp: ip },
      }),
    ]);

    await this.activity.record({
      serverId,
      userId,
      kind: 'server.enrollment.minted',
      resourceType: 'server',
      resourceId: serverId,
      // Deliberately no code, not even a prefix, in the feed.
      summary: 'Generated an enrollment code',
    });

    return {
      code: generated.display,
      expiresAt: expiresAt.toISOString(),
      expiresInSeconds: ENROLLMENT_TTL_SECONDS,
    };
  }

  /**
   * Redeems a code presented by an agent.
   *
   * Unauthenticated by necessity — the agent has no credential yet; the code
   * *is* the credential. Single-use is enforced by the guarded UPDATE rather
   * than by the read, so two agents racing on one code cannot both win.
   */
  async consume(presented: string, ip: string | null): Promise<EnrollmentResult> {
    const canonical = canonicaliseCode(presented);
    if (canonical === null) {
      throw new AppError(
        'enrollment_code_invalid',
        "That enrollment code isn't valid. Generate a new one from ServerOS.",
        400,
      );
    }

    const now = new Date();
    const record = await this.prisma.serverEnrollment.findUnique({
      where: { codeHash: hashEnrollmentCode(canonical) },
    });

    const decision = decideConsume({
      record:
        record === null
          ? null
          : {
              id: record.id,
              serverId: record.serverId,
              codeHash: record.codeHash,
              expiresAt: record.expiresAt,
              consumedAt: record.consumedAt,
            },
      presentedCanonical: canonical,
      now,
    });
    if (!decision.ok) {
      throw new AppError(decision.code, decision.message, 400, decision.detail);
    }

    const marked = await this.prisma.serverEnrollment.updateMany({
      where: buildConsumeGuard(decision.value.enrollmentId),
      data: { consumedAt: now, consumedByIp: ip },
    });
    const settled = interpretConsumeResult(marked.count, decision.value);
    if (!settled.ok) {
      throw new AppError(settled.code, settled.message, 409, settled.detail);
    }

    const server = await this.prisma.server.update({
      where: { id: settled.value.serverId },
      data: { status: 'CONNECTED', lastSeenAt: now },
    });

    await this.activity.record({
      serverId: server.id,
      userId: null,
      kind: 'server.enrollment.consumed',
      resourceType: 'server',
      resourceId: server.id,
      summary: `${server.name} connected`,
    });

    this.logger.log(`Server ${server.id} enrolled.`);
    return { serverId: server.id, serverName: server.name };
  }
}
