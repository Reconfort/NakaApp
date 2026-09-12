import { Module } from '@nestjs/common';

import { EventsGateway } from './events.gateway.js';
import { EventsPublisher } from './events.publisher.js';

/**
 * The live event stream.
 *
 * Depends on nothing but the two global modules (config and Prisma), which is
 * what keeps the dependency graph acyclic: `Activity → Events` and
 * `Servers → Events` are both one-way edges. An earlier draft injected
 * `ServersService` into the gateway for its ownership check and needed
 * `forwardRef` in both directions; the gateway now issues that one SELECT
 * itself instead.
 *
 * Exports only `EventsPublisher`, never the gateway. A service that could
 * inject the gateway could emit into an arbitrary room; going through the
 * publisher means every broadcast passes through validated room naming.
 */
@Module({
  providers: [EventsGateway, EventsPublisher],
  exports: [EventsPublisher],
})
export class EventsModule {}
