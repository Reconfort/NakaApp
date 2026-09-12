import 'reflect-metadata';

import { Logger, StandardSchemaValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';

import { AppModule } from './app.module.js';
import { AllExceptionsFilter } from './common/all-exceptions.filter.js';
import { loadConfigOrThrow } from './config/env.logic.js';

/**
 * Process entry point.
 *
 * ESM-era shape, per docs/reference/backend-stack.md §3.1 — do not "fix" these
 * back to the CommonJS idiom:
 *   * every relative import carries a `.js` extension, even though the sources
 *     are `.ts`;
 *   * `bootstrap()` is awaited at the top level rather than called bare;
 *   * `__dirname` and `__filename` do not exist here — use `import.meta.dirname`.
 */
async function bootstrap(): Promise<void> {
  // Read and validate configuration *before* creating the app, so a bad
  // environment fails in one line rather than halfway through module init.
  const config = loadConfigOrThrow(process.env);

  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    // Nest's own bootstrap logging is noisy in production and lists every
    // mapped route, which is a free map of the API for anyone reading logs.
    logger: config.nodeEnv === 'production' ? ['error', 'warn', 'log'] : ['error', 'warn', 'log', 'debug'],
  });

  // Standard Schema validation, the Nest 12 path (§3.2). Schemas are attached
  // per parameter — `@Body({ schema })` — rather than through class-validator
  // decorators. The two approaches are not mixed anywhere in this codebase.
  app.useGlobalPipes(new StandardSchemaValidationPipe({ transform: true }));

  // One envelope for every failure, matching the Rust agent's.
  app.useGlobalFilters(new AllExceptionsFilter());

  // Express 5 note (§4.1), for whoever adds a catch-all route next: wildcards
  // must be *named*. `@Get('*')` throws at startup; write `@Get('*splat')`.
  // No route in this codebase uses one today.

  // Only trust X-Forwarded-For when TRUST_PROXY says a proxy is in front of us.
  // Trusting it unconditionally would let any client dictate the address that
  // lands in the audit log and in rate-limit buckets.
  if (config.trustProxy) {
    app.set('trust proxy', 1);
  }

  if (config.corsOrigins.length > 0) {
    app.enableCors({ origin: [...config.corsOrigins], credentials: true });
  }
  // No `enableCors()` fallback: the macOS client is not a browser and needs no
  // CORS headers, so the safe default is to send none.

  // Graceful shutdown, so in-flight requests finish and Prisma disconnects
  // cleanly. Note the Nest 11 change (§4.1): termination hooks now run in the
  // opposite order from Nest 10.
  app.enableShutdownHooks();

  await app.listen(config.port);
  new Logger('Bootstrap').log(`Control plane listening on port ${config.port}.`);
}

await bootstrap();
