import { Body, Controller, Delete, Get, HttpCode, Param, Post, Put } from '@nestjs/common';

import { CurrentUser } from '../common/decorators/current-user.decorator.js';
import type { AccessTokenClaims } from '../auth/token.logic.js';
import { ServersService, type ServerView } from './servers.service.js';
import {
  createServerSchema,
  heartbeatSchema,
  updateServerSchema,
  type CreateServerDto,
  type HeartbeatDto,
  type UpdateServerDto,
} from './servers.schemas.js';

/**
 * `/v1/servers` — the registry.
 *
 * Every route is authenticated by the global `JwtAuthGuard`; ownership is then
 * checked inside the service, because "is this my server" is a data question
 * and a guard would have to load the row to answer it anyway.
 */
@Controller('v1/servers')
export class ServersController {
  constructor(private readonly servers: ServersService) {}

  @Get()
  list(@CurrentUser() user: AccessTokenClaims): Promise<ServerView[]> {
    return this.servers.list(user.sub);
  }

  @Get(':id')
  findOne(
    @CurrentUser() user: AccessTokenClaims,
    @Param('id') id: string,
  ): Promise<ServerView> {
    return this.servers.findOne(user.sub, id);
  }

  @Post()
  create(
    @CurrentUser() user: AccessTokenClaims,
    @Body({ schema: createServerSchema }) body: CreateServerDto,
  ): Promise<ServerView> {
    return this.servers.create(user.sub, body);
  }

  @Put(':id')
  update(
    @CurrentUser() user: AccessTokenClaims,
    @Param('id') id: string,
    @Body({ schema: updateServerSchema }) body: UpdateServerDto,
  ): Promise<ServerView> {
    return this.servers.update(user.sub, id, body);
  }

  @Delete(':id')
  @HttpCode(204)
  remove(@CurrentUser() user: AccessTokenClaims, @Param('id') id: string): Promise<void> {
    return this.servers.remove(user.sub, id);
  }

  /**
   * Telemetry relay.
   *
   * The macOS app posts what it has already read from the agent. 200 rather
   * than 201 — nothing is created, an existing server's status is refreshed —
   * and the refreshed view comes back so the client can reconcile its own state
   * against the server's verdict rather than computing health twice.
   */
  @Post(':id/heartbeat')
  @HttpCode(200)
  heartbeat(
    @CurrentUser() user: AccessTokenClaims,
    @Param('id') id: string,
    @Body({ schema: heartbeatSchema }) body: HeartbeatDto,
  ): Promise<ServerView> {
    return this.servers.recordHeartbeat(user.sub, id, body);
  }
}
