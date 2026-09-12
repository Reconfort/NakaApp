import { Body, Controller, HttpCode, Post, Req } from '@nestjs/common';
import type { Request } from 'express';

import { Public } from '../common/guards/jwt-auth.guard.js';
import { normaliseIp } from '../activity/activity.logic.js';
import { AuthService, type AuthTokens, type RequestContext } from './auth.service.js';
import {
  loginSchema,
  refreshSchema,
  registerSchema,
  type LoginDto,
  type RefreshDto,
  type RegisterDto,
} from './auth.schemas.js';

/**
 * `/v1/auth` — the only unauthenticated surface in the API.
 *
 * Every route is `@Public()`, which is the explicit opt-out from the globally
 * registered `JwtAuthGuard`. Schemas are attached per-parameter via
 * `@Body({ schema })`, which is the Nest 12 `StandardSchemaValidationPipe`
 * convention (docs/reference/backend-stack.md §3.2) — not the class-validator
 * DTO style, and the two are not mixed.
 */
@Controller('v1/auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @Post('register')
  register(
    @Body({ schema: registerSchema }) body: RegisterDto,
    @Req() request: Request,
  ): Promise<AuthTokens> {
    return this.auth.register(body, contextFrom(request));
  }

  @Public()
  @Post('login')
  // 200 rather than 201: a login creates a session, but the resource the caller
  // asked for is the token pair in the body, and a Location header would be a
  // lie.
  @HttpCode(200)
  login(
    @Body({ schema: loginSchema }) body: LoginDto,
    @Req() request: Request,
  ): Promise<AuthTokens> {
    return this.auth.login(body, contextFrom(request));
  }

  @Public()
  @Post('refresh')
  @HttpCode(200)
  refresh(
    @Body({ schema: refreshSchema }) body: RefreshDto,
    @Req() request: Request,
  ): Promise<AuthTokens> {
    return this.auth.refresh(body, contextFrom(request));
  }

  @Public()
  @Post('logout')
  @HttpCode(204)
  logout(
    @Body({ schema: refreshSchema }) body: RefreshDto,
    @Req() request: Request,
  ): Promise<void> {
    return this.auth.logout(body, contextFrom(request));
  }
}

/**
 * Extracts the audit context from a request.
 *
 * `request.ip` is Express's resolved client address, which respects the app's
 * `trust proxy` setting — set from `TRUST_PROXY` in `main.ts`. Reading
 * `X-Forwarded-For` directly here would honour a header any client can forge.
 */
function contextFrom(request: Request): RequestContext {
  const userAgent = request.headers['user-agent'];
  return {
    ip: normaliseIp(request.ip),
    userAgent: typeof userAgent === 'string' ? userAgent : null,
  };
}
