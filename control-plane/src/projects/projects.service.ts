import { Injectable } from '@nestjs/common';

import { ActivityService } from '../activity/activity.service.js';
import { AppError } from '../common/error-mapping.logic.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { authoriseServerAccess } from '../servers/servers.logic.js';
import { normaliseProjectInput, type ProjectInput } from './projects.logic.js';

/** A project as the API returns it. */
export interface ProjectView {
  readonly id: string;
  readonly serverId: string;
  readonly name: string;
  readonly composeProject: string | null;
  readonly workingDir: string | null;
  readonly description: string | null;
  readonly createdAt: string;
}

/**
 * Projects — the applications deployed on a server.
 *
 * Every method starts by proving the caller owns the parent server, because a
 * project id on its own carries no ownership information and checking the
 * project row alone would let anyone who guessed an id read someone else's
 * deployment layout.
 */
@Injectable()
export class ProjectsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly activity: ActivityService,
  ) {}

  /** Lists the projects on a server the caller owns. */
  async list(userId: string, serverId: string): Promise<ProjectView[]> {
    await this.assertOwnsServer(userId, serverId);
    const rows = await this.prisma.project.findMany({
      where: { serverId },
      orderBy: { name: 'asc' },
    });
    return rows.map(toView);
  }

  /** Creates a project on a server the caller owns. */
  async create(userId: string, serverId: string, input: ProjectInput): Promise<ProjectView> {
    await this.assertOwnsServer(userId, serverId);

    const normalised = normaliseProjectInput(input);
    if (!normalised.ok) {
      throw new AppError(normalised.code, normalised.message, 400, normalised.detail);
    }

    const row = await this.prisma.project.create({
      data: { ...normalised.value, serverId },
    });

    await this.activity.record({
      serverId,
      userId,
      kind: 'project.create',
      resourceType: 'project',
      resourceId: row.id,
      summary: `Added project ${row.name}`,
    });

    return toView(row);
  }

  /** Updates a project. */
  async update(userId: string, projectId: string, input: ProjectInput): Promise<ProjectView> {
    const existing = await this.loadOwned(userId, projectId);

    const normalised = normaliseProjectInput(input);
    if (!normalised.ok) {
      throw new AppError(normalised.code, normalised.message, 400, normalised.detail);
    }

    const row = await this.prisma.project.update({
      where: { id: projectId },
      data: normalised.value,
    });

    await this.activity.record({
      serverId: existing.serverId,
      userId,
      kind: 'project.update',
      resourceType: 'project',
      resourceId: row.id,
      summary: `Updated project ${row.name}`,
    });

    return toView(row);
  }

  /** Deletes a project. */
  async remove(userId: string, projectId: string): Promise<void> {
    const existing = await this.loadOwned(userId, projectId);
    await this.prisma.project.delete({ where: { id: projectId } });
    await this.activity.record({
      serverId: existing.serverId,
      userId,
      kind: 'project.delete',
      resourceType: 'project',
      resourceId: projectId,
      summary: `Removed project ${existing.name}`,
    });
  }

  /** Loads a project only if the caller owns the server it belongs to. */
  private async loadOwned(
    userId: string,
    projectId: string,
  ): Promise<{ id: string; serverId: string; name: string }> {
    const row = await this.prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true, serverId: true, name: true, server: { select: { ownerId: true } } },
    });
    const access = authoriseServerAccess(
      row === null ? null : { id: row.serverId, ownerId: row.server.ownerId },
      userId,
    );
    if (!access.ok || row === null) {
      throw new AppError('not_found', "We couldn't find that project.", 404);
    }
    return { id: row.id, serverId: row.serverId, name: row.name };
  }

  /** Fails as if the server did not exist unless the caller owns it. */
  private async assertOwnsServer(userId: string, serverId: string): Promise<void> {
    const server = await this.prisma.server.findUnique({
      where: { id: serverId },
      select: { id: true, ownerId: true },
    });
    const access = authoriseServerAccess(server, userId);
    if (!access.ok) throw new AppError(access.code, access.message, 404);
  }
}

/** Projects a row into the API shape. */
function toView(row: {
  id: string;
  serverId: string;
  name: string;
  composeProject: string | null;
  workingDir: string | null;
  description: string | null;
  createdAt: Date;
}): ProjectView {
  return {
    id: row.id,
    serverId: row.serverId,
    name: row.name,
    composeProject: row.composeProject,
    workingDir: row.workingDir,
    description: row.description,
    createdAt: row.createdAt.toISOString(),
  };
}
