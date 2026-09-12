import { createParamDecorator, type ExecutionContext } from '@nestjs/common';

import type { AccessTokenClaims } from '../../auth/token.logic.js';
import type { AuthenticatedRequest } from '../guards/jwt-auth.guard.js';

/**
 * Injects the verified token claims into a handler parameter.
 *
 * Throws rather than returning `undefined` when the request is unauthenticated:
 * reaching this decorator without a user means the route is `@Public()` but the
 * handler expects a caller, which is a programming error that should surface
 * immediately rather than become a `userId: undefined` in a `where` clause.
 */
export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext): AccessTokenClaims => {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    if (request.user === undefined) {
      throw new Error('CurrentUser used on a route that is not authenticated.');
    }
    return request.user;
  },
);
