import { Global, Module } from '@nestjs/common';

import { PrismaService } from './prisma.service.js';

/**
 * Makes the database handle available everywhere without each feature module
 * re-importing it.
 *
 * `@Global` is used sparingly in this codebase — this is the only one. A
 * database connection is genuinely cross-cutting; business services are not,
 * and should be imported explicitly so the dependency graph stays readable.
 */
@Global()
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
