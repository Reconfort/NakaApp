import { Controller, Get } from '@nestjs/common';

import { Public } from '../common/guards/jwt-auth.guard.js';
import { PrismaService } from '../prisma/prisma.service.js';

/** Liveness response. */
interface LivenessResult {
  readonly status: 'ok';
}

/** Readiness response. */
interface ReadinessResult {
  readonly status: 'ok' | 'degraded';
  readonly checks: { readonly database: 'ok' | 'unreachable' };
}

/**
 * Process health, for the orchestrator rather than for a user.
 *
 * Two endpoints, because they answer different questions and a load balancer
 * that conflates them will restart a healthy process during a database blip:
 *
 *   * `/healthz` — is the process alive? Never touches a dependency. A failing
 *     liveness probe means "restart me".
 *   * `/readyz` — can it serve traffic? Checks the database. A failing
 *     readiness probe means "stop sending me requests", not "restart me".
 *
 * Neither reveals anything about the deployment: no version, no hostname, no
 * connection detail. These are the two most-scanned paths on any public host.
 */
@Controller()
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  @Public()
  @Get('healthz')
  live(): LivenessResult {
    return { status: 'ok' };
  }

  @Public()
  @Get('readyz')
  async ready(): Promise<ReadinessResult> {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      return { status: 'ok', checks: { database: 'ok' } };
    } catch {
      // The exception is swallowed on purpose: a readiness probe returning a
      // Postgres error message would publish the connection detail to anyone
      // who can reach the port. The exception filter logs it.
      return { status: 'degraded', checks: { database: 'unreachable' } };
    }
  }
}
