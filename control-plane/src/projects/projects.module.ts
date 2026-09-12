import { Module } from '@nestjs/common';

import { ActivityModule } from '../activity/activity.module.js';
import { ProjectsController } from './projects.controller.js';
import { ProjectsService } from './projects.service.js';

/** Applications deployed on a server. */
@Module({
  imports: [ActivityModule],
  controllers: [ProjectsController],
  providers: [ProjectsService],
  exports: [ProjectsService],
})
export class ProjectsModule {}
