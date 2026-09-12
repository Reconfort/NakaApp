import { Module } from '@nestjs/common';

import { EventsModule } from '../events/events.module.js';
import { ActivityController } from './activity.controller.js';
import { ActivityService } from './activity.service.js';

/**
 * The activity feed and audit trail.
 *
 * Imports EventsModule so that writing a row and announcing it are one act.
 * Leaving the announcement to each caller would mean the dashboard's live feed
 * silently stops updating for whichever call site forgot.
 */
@Module({
  imports: [EventsModule],
  controllers: [ActivityController],
  providers: [ActivityService],
  exports: [ActivityService],
})
export class ActivityModule {}
