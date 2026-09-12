import { Injectable } from '@nestjs/common';

import { AppError } from '../common/error-mapping.logic.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { toPublicUser, type PublicUser } from './users.logic.js';

/**
 * User lookup.
 *
 * Every method returns `PublicUser`, never a raw row. That is the single reason
 * this service exists rather than controllers querying Prisma directly: the
 * projection through `toPublicUser` is the thing standing between
 * `passwordHash` and a JSON response, and it should be impossible to skip by
 * accident.
 */
@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  /** Loads a user by id. */
  async findById(userId: string): Promise<PublicUser> {
    const row = await this.prisma.user.findUnique({ where: { id: userId } });
    if (row === null) {
      // A valid token for a deleted user. Rare, but it happens between a
      // deletion and the expiry of an access token already in flight.
      throw new AppError('not_found', "We couldn't find that account.", 404);
    }
    return toPublicUser(row);
  }
}
