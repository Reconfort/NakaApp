import { Body, Controller, Delete, Get, HttpCode, Param, Post, Put } from '@nestjs/common';
import { z } from 'zod';

import { CurrentUser } from '../common/decorators/current-user.decorator.js';
import type { AccessTokenClaims } from '../auth/token.logic.js';
import { ProjectsService, type ProjectView } from './projects.service.js';

/** Shape only; the meaning-bearing rules live in `projects.logic.ts`. */
const projectSchema = z.object({
  name: z.string().min(1).max(64),
  composeProject: z.string().max(63).nullish(),
  workingDir: z.string().max(4096).nullish(),
  description: z.string().max(500).nullish(),
});
type ProjectDto = z.infer<typeof projectSchema>;

/**
 * Projects, nested under their server for the collection routes and addressed
 * directly for the item routes.
 *
 * Both shapes are on one controller because they are one resource; splitting
 * them across two files would put the ownership rule in two places.
 */
@Controller('v1')
export class ProjectsController {
  constructor(private readonly projects: ProjectsService) {}

  @Get('servers/:serverId/projects')
  list(
    @CurrentUser() user: AccessTokenClaims,
    @Param('serverId') serverId: string,
  ): Promise<ProjectView[]> {
    return this.projects.list(user.sub, serverId);
  }

  @Post('servers/:serverId/projects')
  create(
    @CurrentUser() user: AccessTokenClaims,
    @Param('serverId') serverId: string,
    @Body({ schema: projectSchema }) body: ProjectDto,
  ): Promise<ProjectView> {
    return this.projects.create(user.sub, serverId, body);
  }

  @Put('projects/:id')
  update(
    @CurrentUser() user: AccessTokenClaims,
    @Param('id') id: string,
    @Body({ schema: projectSchema }) body: ProjectDto,
  ): Promise<ProjectView> {
    return this.projects.update(user.sub, id, body);
  }

  @Delete('projects/:id')
  @HttpCode(204)
  remove(@CurrentUser() user: AccessTokenClaims, @Param('id') id: string): Promise<void> {
    return this.projects.remove(user.sub, id);
  }
}
