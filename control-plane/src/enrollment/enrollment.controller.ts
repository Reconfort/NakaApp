import { Body, Controller, HttpCode, Param, Post, Req } from '@nestjs/common';
import type { Request } from 'express';
import { z } from 'zod';

import { CurrentUser } from '../common/decorators/current-user.decorator.js';
import { Public } from '../common/guards/jwt-auth.guard.js';
import { normaliseIp } from '../activity/activity.logic.js';
import type { AccessTokenClaims } from '../auth/token.logic.js';
import {
  EnrollmentService,
  type EnrollmentResult,
  type MintedEnrollment,
} from './enrollment.service.js';

/** An agent presenting its code. Generous on length; canonicalised in logic. */
const consumeSchema = z.object({ code: z.string().min(1).max(128) });
type ConsumeDto = z.infer<typeof consumeSchema>;

/**
 * Enrollment: minting (authenticated, by the owner) and redeeming
 * (unauthenticated, by the agent).
 *
 * The two halves live on different paths on purpose. `POST /v1/servers/:id/enrollment`
 * is an act by a signed-in person against a server they own;
 * `POST /v1/enrollment/consume` is an act by a machine that has no identity yet
 * and whose only credential is the code in the body.
 */
@Controller('v1')
export class EnrollmentController {
  constructor(private readonly enrollment: EnrollmentService) {}

  @Post('servers/:id/enrollment')
  mint(
    @CurrentUser() user: AccessTokenClaims,
    @Param('id') serverId: string,
    @Req() request: Request,
  ): Promise<MintedEnrollment> {
    return this.enrollment.mint(user.sub, serverId, normaliseIp(request.ip));
  }

  @Public()
  @Post('enrollment/consume')
  @HttpCode(200)
  consume(
    @Body({ schema: consumeSchema }) body: ConsumeDto,
    @Req() request: Request,
  ): Promise<EnrollmentResult> {
    return this.enrollment.consume(body.code, normaliseIp(request.ip));
  }
}
