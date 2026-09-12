import { randomUUID } from 'node:crypto';

import { Inject, Injectable, Logger } from '@nestjs/common';

import { AppError } from '../common/error-mapping.logic.js';
import { AppConfigService } from '../config/config.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { buildAuditRecord } from '../activity/activity.logic.js';
import { normaliseEmail, normaliseName, toPublicUser, type PublicUser } from '../users/users.logic.js';
import { PASSWORD_HASHER } from './password.hasher.js';
import {
  authenticate,
  validatePasswordStrength,
  type PasswordHasher,
} from './password.logic.js';
import {
  REFRESH_TOKEN_TTL_SECONDS,
  buildRotationGuard,
  decideRefresh,
  generateRefreshToken,
  hashRefreshToken,
  parsePresentedRefreshToken,
} from './session.logic.js';
import { buildAccessClaims, signAccessToken } from './token.logic.js';
import type { LoginDto, RefreshDto, RegisterDto } from './auth.schemas.js';

/** What the client receives after a successful sign-in or refresh. */
export interface AuthTokens {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly expiresIn: number;
  readonly user: PublicUser;
}

/** Request context recorded on the audit trail. */
export interface RequestContext {
  readonly ip: string | null;
  readonly userAgent: string | null;
}

/**
 * Registration, sign-in, refresh and sign-out.
 *
 * Every decision this service makes is delegated to the pure layer —
 * `password.logic.ts` decides whether credentials authenticate,
 * `session.logic.ts` decides what to do with a presented refresh token,
 * `token.logic.ts` mints the access token. What is left here is orchestration:
 * loading rows, writing rows, and making sure the writes that must be atomic
 * happen in one transaction.
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: AppConfigService,
    @Inject(PASSWORD_HASHER) private readonly hasher: PasswordHasher,
  ) {}

  /** Creates an account and signs the new user in. */
  async register(dto: RegisterDto, context: RequestContext): Promise<AuthTokens> {
    const email = normaliseEmail(dto.email);
    if (!email.ok) throw new AppError(email.code, email.message, 400, email.detail);

    const name = normaliseName(dto.name);
    if (!name.ok) throw new AppError(name.code, name.message, 400, name.detail);

    const password = validatePasswordStrength(dto.password, email.value);
    if (!password.ok) throw new AppError(password.code, password.message, 400, password.detail);

    const passwordHash = await this.hasher.hash(password.value);

    // A duplicate address surfaces as Prisma P2002, which the exception filter
    // maps to 409 `already_exists`. Checking first and then inserting would be
    // a race; letting the unique index decide is both correct and one query.
    const user = await this.prisma.user.create({
      data: { email: email.value, name: name.value, passwordHash },
    });

    await this.recordAudit({
      actor: user.id,
      action: 'auth.register',
      targetType: 'user',
      targetId: user.id,
      outcome: 'SUCCEEDED',
      context,
    });

    return this.issueTokens(user.id, context);
  }

  /** Verifies credentials and starts a new token family. */
  async login(dto: LoginDto, context: RequestContext): Promise<AuthTokens> {
    const email = normaliseEmail(dto.email);
    // A malformed address is still a failed sign-in, not a validation error:
    // telling the caller "that isn't an email" and "that isn't an account"
    // differently is the enumeration oracle `authenticate` exists to avoid.
    const record = email.ok
      ? await this.prisma.user.findUnique({ where: { email: email.value } })
      : null;

    const result = await authenticate(
      this.hasher,
      record === null
        ? null
        : { userId: record.id, passwordHash: record.passwordHash, isActive: record.isActive },
      dto.password,
    );

    if (!result.ok) {
      // The actor is the user id when we have one and the literal "unknown"
      // otherwise — deliberately not the submitted address. Writing attacker-
      // controlled text into a durable audit column turns a login form into a
      // way to inject content into an operator's own console.
      await this.recordAudit({
        actor: record?.id ?? 'unknown',
        action: 'auth.login',
        targetType: 'user',
        targetId: record?.id ?? null,
        outcome: 'FAILED',
        context,
      });
      throw new AppError(result.code, result.message, 401, result.detail);
    }

    await this.prisma.user.update({
      where: { id: result.value.userId },
      data: { lastLoginAt: new Date() },
    });

    await this.recordAudit({
      actor: result.value.userId,
      action: 'auth.login',
      targetType: 'user',
      targetId: result.value.userId,
      outcome: 'SUCCEEDED',
      context,
    });

    return this.issueTokens(result.value.userId, context);
  }

  /**
   * Rotates a refresh token.
   *
   * The guarded update and the successor insert happen in one transaction so
   * that a crash between them cannot leave a family with no live token — and so
   * that two concurrent refreshes cannot both succeed. `buildRotationGuard`
   * puts `rotatedAt: null` in the WHERE clause, which is what makes the
   * database, not this code, pick the winner.
   */
  async refresh(dto: RefreshDto, context: RequestContext): Promise<AuthTokens> {
    const presented = parsePresentedRefreshToken(dto.refreshToken);
    if (!presented.ok) {
      throw new AppError(presented.code, presented.message, 401, presented.detail);
    }

    const tokenHash = hashRefreshToken(presented.value);
    const record = await this.prisma.session.findUnique({ where: { refreshTokenHash: tokenHash } });
    const now = new Date();

    const decision = decideRefresh({
      record:
        record === null
          ? null
          : {
              id: record.id,
              userId: record.userId,
              familyId: record.familyId,
              expiresAt: record.expiresAt,
              rotatedAt: record.rotatedAt,
              revokedAt: record.revokedAt,
            },
      now,
    });

    if (decision.action === 'revoke_family') {
      // Theft. Everything descended from that login dies, including whatever
      // the legitimate client is holding — it will sign in again, and the
      // attacker cannot.
      await this.prisma.session.updateMany({
        where: { familyId: decision.familyId, revokedAt: null },
        data: { revokedAt: now, revokedReason: decision.reason },
      });
      this.logger.warn(
        `Refresh token reuse detected for family ${decision.familyId}; revoked the family.`,
      );
      await this.recordAudit({
        actor: decision.userId,
        action: 'auth.refresh',
        targetType: 'session',
        targetId: decision.familyId,
        outcome: 'DENIED',
        context,
        metadata: { reason: decision.reason },
      });
      throw new AppError(decision.code, decision.message, 401);
    }

    if (decision.action === 'reject') {
      throw new AppError(decision.code, decision.message, 401);
    }

    const successor = generateRefreshToken();
    const rotated = await this.prisma.$transaction(async (tx) => {
      const marked = await tx.session.updateMany({
        where: buildRotationGuard(decision.previousSessionId),
        data: { rotatedAt: now, revokedAt: now, revokedReason: 'rotated' },
      });
      if (marked.count !== 1) return null;

      return tx.session.create({
        data: {
          userId: decision.userId,
          familyId: decision.familyId,
          refreshTokenHash: successor.tokenHash,
          expiresAt: decision.expiresAt,
          ip: context.ip,
          userAgent: context.userAgent,
        },
      });
    });

    if (rotated === null) {
      // Lost the race: another request rotated this row first, which is the
      // concurrent form of reuse. Same treatment.
      await this.prisma.session.updateMany({
        where: { familyId: decision.familyId, revokedAt: null },
        data: { revokedAt: now, revokedReason: 'reuse_detected' },
      });
      throw new AppError(
        'refresh_token_reused',
        'Your session has ended. Sign in again.',
        401,
      );
    }

    const user = await this.prisma.user.findUniqueOrThrow({ where: { id: decision.userId } });
    return {
      ...this.mintAccessToken(rotated.userId, rotated.id),
      refreshToken: successor.token,
      user: toPublicUser(user),
    };
  }

  /**
   * Signs out by revoking the whole family.
   *
   * Revoking only the presented token would leave every earlier rotation in the
   * family technically unused, so "sign out" has to mean the family or it means
   * very little.
   */
  async logout(dto: RefreshDto, context: RequestContext): Promise<void> {
    const presented = parsePresentedRefreshToken(dto.refreshToken);
    if (!presented.ok) return; // Signing out with junk is still signed out.

    const record = await this.prisma.session.findUnique({
      where: { refreshTokenHash: hashRefreshToken(presented.value) },
    });
    if (record === null) return;

    await this.prisma.session.updateMany({
      where: { familyId: record.familyId, revokedAt: null },
      data: { revokedAt: new Date(), revokedReason: 'logout' },
    });

    await this.recordAudit({
      actor: record.userId,
      action: 'auth.logout',
      targetType: 'session',
      targetId: record.familyId,
      outcome: 'SUCCEEDED',
      context,
    });
  }

  /** Starts a brand-new token family for a user who has just authenticated. */
  private async issueTokens(userId: string, context: RequestContext): Promise<AuthTokens> {
    const refresh = generateRefreshToken();
    const familyId = randomUUID();

    const session = await this.prisma.session.create({
      data: {
        userId,
        familyId,
        refreshTokenHash: refresh.tokenHash,
        expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000),
        ip: context.ip,
        userAgent: context.userAgent,
      },
    });

    const user = await this.prisma.user.findUniqueOrThrow({ where: { id: userId } });
    return {
      ...this.mintAccessToken(userId, session.id),
      refreshToken: refresh.token,
      user: toPublicUser(user),
    };
  }

  /** Mints a signed access token for a user and session. */
  private mintAccessToken(userId: string, sessionId: string): { accessToken: string; expiresIn: number } {
    const now = new Date();
    const claims = buildAccessClaims({
      userId,
      sessionId,
      issuer: this.config.jwtIssuer,
      audience: this.config.jwtAudience,
      jti: randomUUID(),
      now,
    });
    return {
      accessToken: signAccessToken(claims, this.config.jwtSecret),
      expiresIn: claims.exp - claims.iat,
    };
  }

  /**
   * Writes an audit row.
   *
   * Failures are logged, not thrown: an audit write that fails must not turn a
   * successful sign-in into a 500 for the user. The log line is the compensating
   * control, and it is loud on purpose.
   */
  private async recordAudit(input: {
    actor: string;
    action: string;
    targetType: string | null;
    targetId: string | null;
    outcome: 'SUCCEEDED' | 'FAILED' | 'DENIED';
    context: RequestContext;
    metadata?: unknown;
  }): Promise<void> {
    const record = buildAuditRecord({
      actor: input.actor,
      action: input.action,
      targetType: input.targetType,
      targetId: input.targetId,
      ip: input.context.ip,
      userAgent: input.context.userAgent,
      outcome: input.outcome,
      metadata: input.metadata,
    });
    if (!record.ok) {
      this.logger.error(`Could not build audit record for ${input.action}: ${record.detail ?? ''}`);
      return;
    }
    try {
      await this.prisma.auditLog.create({ data: record.value });
    } catch (error) {
      this.logger.error(`Audit write failed for ${input.action}`, error as Error);
    }
  }
}
