import { Injectable } from '@nestjs/common';

import { loadConfigOrThrow, type AppConfig } from './env.logic.js';

/**
 * The validated configuration, as an injectable.
 *
 * A thin wrapper over `env.logic.ts` — deliberately thin, because every rule
 * about what a valid configuration *is* belongs in the pure module where it can
 * be tested. This class exists only so services can depend on typed fields
 * (`config.jwtSecret`) rather than on `ConfigService.get<string>('JWT_SECRET')`,
 * which is untyped, returns `undefined` for a typo, and has no idea the value
 * has to be 32 bytes long.
 */
@Injectable()
export class AppConfigService {
  private readonly config: AppConfig;

  constructor() {
    // Validated once, at construction. A bad value fails module init, which
    // fails startup — the failure an operator can see and fix.
    this.config = loadConfigOrThrow(process.env);
  }

  get nodeEnv(): AppConfig['nodeEnv'] {
    return this.config.nodeEnv;
  }
  get isProduction(): boolean {
    return this.config.nodeEnv === 'production';
  }
  get port(): number {
    return this.config.port;
  }
  get redisUrl(): string {
    return this.config.redisUrl;
  }
  get jwtSecret(): string {
    return this.config.jwtSecret;
  }
  get jwtIssuer(): string {
    return this.config.jwtIssuer;
  }
  get jwtAudience(): string {
    return this.config.jwtAudience;
  }
  get cursorSecret(): string {
    return this.config.cursorSecret;
  }
  get corsOrigins(): readonly string[] {
    return this.config.corsOrigins;
  }
  get logLevel(): AppConfig['logLevel'] {
    return this.config.logLevel;
  }
  get trustProxy(): boolean {
    return this.config.trustProxy;
  }

  // `databaseUrl` is deliberately not exposed. PrismaService reads it from the
  // environment directly, and nothing else in the application has any business
  // holding a connection string.
}
