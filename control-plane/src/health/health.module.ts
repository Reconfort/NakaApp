import { Module } from '@nestjs/common';

import { HealthController } from './health.controller.js';

/** Liveness and readiness probes. */
@Module({
  controllers: [HealthController],
})
export class HealthModule {}
