import { Module } from '@nestjs/common';

import { ActivityModule } from '../activity/activity.module.js';
import { EventsModule } from '../events/events.module.js';
import { ServersController } from './servers.controller.js';
import { ServersService } from './servers.service.js';

/** The server registry. */
@Module({
  imports: [ActivityModule, EventsModule],
  controllers: [ServersController],
  providers: [ServersService],
  exports: [ServersService],
})
export class ServersModule {}
