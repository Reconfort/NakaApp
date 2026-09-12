import { Controller, Get, Query } from '@nestjs/common';

import { CurrentUser } from '../common/decorators/current-user.decorator.js';
import type { AccessTokenClaims } from '../auth/token.logic.js';
import { ActivityService, type ActivityView } from './activity.service.js';
import type { Page } from './pagination.logic.js';

/**
 * `/v1/activity` — the feed.
 *
 * Read-only by design. There is no POST: activity is written by the services
 * that perform the work, never by a client, because a client-writable feed is a
 * feed that can be forged.
 */
@Controller('v1/activity')
export class ActivityController {
  constructor(private readonly activity: ActivityService) {}

  @Get()
  list(
    @CurrentUser() user: AccessTokenClaims,
    @Query('serverId') serverId?: string,
    @Query('cursor') cursor?: string,
    @Query('limit') limit?: string,
  ): Promise<Page<ActivityView>> {
    return this.activity.list(user.sub, { serverId, cursor, limit });
  }
}
