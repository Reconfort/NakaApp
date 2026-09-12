import { Module } from '@nestjs/common';

import { ActivityModule } from '../activity/activity.module.js';
import { EnrollmentController } from './enrollment.controller.js';
import { EnrollmentService } from './enrollment.service.js';

/** Minting and redeeming server enrollment codes. */
@Module({
  imports: [ActivityModule],
  controllers: [EnrollmentController],
  providers: [EnrollmentService],
  exports: [EnrollmentService],
})
export class EnrollmentModule {}
