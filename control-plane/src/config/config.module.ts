import { Global, Module } from '@nestjs/common';

import { AppConfigService } from './config.service.js';

/**
 * Configuration, available application-wide.
 *
 * `@nestjs/config`'s `ConfigModule` is deliberately not used. Its 12.x release
 * moved `validationSchema` to Standard Schema (see
 * docs/reference/backend-stack.md §4.2), which would work — but the validation
 * we need is more than a shape check: "JWT_SECRET and CURSOR_SECRET must
 * differ", "a secret must be at least 32 bytes", "this still looks like the
 * placeholder". Those are decisions, they live in `env.logic.ts`, and they are
 * tested without a framework. Adding ConfigModule on top would put the same
 * rules in two places.
 */
@Global()
@Module({
  providers: [AppConfigService],
  exports: [AppConfigService],
})
export class AppConfigModule {}
