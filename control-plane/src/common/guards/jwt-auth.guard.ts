import {
  CanActivate,
  ExecutionContext,
  Injectable,
  SetMetadata,
  UnauthorizedException,
  type CustomDecorator,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';

import { AppError } from '../error-mapping.logic.js';
import { verifyAccessToken, type AccessTokenClaims } from '../../auth/token.logic.js';
import { AppConfigService } from '../../config/config.service.js';

/** Metadata key marking a route as reachable without a token. */
const IS_PUBLIC_KEY = 'serveros:isPublic';

/**
 * Marks a route as reachable without authentication.
 *
 * The guard is registered globally and denies by default, so a new controller
 * is protected the moment it is written. Opening a route is therefore an
 * explicit, greppable act — the opposite of the default-open arrangement where
 * forgetting `@UseGuards` silently publishes an endpoint.
 */
export const Public = (): CustomDecorator<string> => SetMetadata(IS_PUBLIC_KEY, true);

/** The authenticated caller, attached to the request by the guard. */
export interface AuthenticatedRequest extends Request {
  user?: AccessTokenClaims;
}

/**
 * Verifies the bearer token on every request that is not marked `@Public()`.
 *
 * The verification itself is `token.logic.ts`; this class only finds the token
 * and translates a refusal into an HTTP exception carrying the same
 * `code`/`message` pair the rest of the API uses.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly config: AppConfigService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const isPublic = this.reflector.getAllAndOverride<boolean | undefined>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic === true) return true;

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const header = request.headers.authorization;
    const match = typeof header === 'string' ? /^Bearer\s+(\S+)$/i.exec(header.trim()) : null;
    const token = match?.[1];

    if (token === undefined) {
      throw new UnauthorizedException({
        error: { code: 'unauthorized', message: 'Sign in to continue.' },
      });
    }

    const verified = verifyAccessToken(token, {
      secret: this.config.jwtSecret,
      issuer: this.config.jwtIssuer,
      audience: this.config.jwtAudience,
      now: new Date(),
    });

    if (!verified.ok) {
      // The `detail` from the verifier says *why* (expired vs forged) and is
      // deliberately dropped here rather than returned: it is a diagnostic for
      // us, not information a caller should be able to enumerate. The exception
      // filter logs the AppError, which carries it.
      throw new UnauthorizedException({
        error: { code: verified.code, message: verified.message },
        cause: new AppError(verified.code, verified.message, 401, verified.detail),
      });
    }

    request.user = verified.value;
    return true;
  }
}
