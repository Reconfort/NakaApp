import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';

import { ActivityModule } from './activity/activity.module.js';
import { AuthModule } from './auth/auth.module.js';
import { AppConfigModule } from './config/config.module.js';
import { JwtAuthGuard } from './common/guards/jwt-auth.guard.js';
import { EnrollmentModule } from './enrollment/enrollment.module.js';
import { EventsModule } from './events/events.module.js';
import { HealthModule } from './health/health.module.js';
import { PrismaModule } from './prisma/prisma.module.js';
import { ProjectsModule } from './projects/projects.module.js';
import { ServersModule } from './servers/servers.module.js';
import { UsersModule } from './users/users.module.js';

/**
 * The application root.
 *
 * One decision worth calling out: `JwtAuthGuard` is registered as a global
 * `APP_GUARD`, so **every** route is authenticated unless it opts out with
 * `@Public()`. Deny-by-default means a controller added next month is protected
 * before anyone remembers to protect it, and every exception is a decorator
 * somebody has to type — which is greppable in a way that a missing
 * `@UseGuards` is not.
 */
@Module({
  imports: [
    AppConfigModule,
    PrismaModule,
    AuthModule,
    UsersModule,
    ServersModule,
    EnrollmentModule,
    ProjectsModule,
    ActivityModule,
    EventsModule,
    HealthModule,
  ],
  providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }],
})
export class AppModule {}
