import { Controller, Get } from '@nestjs/common';

import { CurrentUser } from '../common/decorators/current-user.decorator.js';
import type { AccessTokenClaims } from '../auth/token.logic.js';
import { UsersService } from './users.service.js';
import type { PublicUser } from './users.logic.js';

/**
 * `/v1/users` — currently just "who am I".
 *
 * There is deliberately no route that takes a user id. This is a single-tenant
 * account model today; adding `GET /v1/users/:id` before there is a team
 * concept would create an endpoint whose only correct answer is always the
 * caller's own row.
 */
@Controller('v1/users')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get('me')
  me(@CurrentUser() user: AccessTokenClaims): Promise<PublicUser> {
    return this.users.findById(user.sub);
  }
}
