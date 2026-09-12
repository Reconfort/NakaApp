import { Injectable } from '@nestjs/common';

import { EventsGateway } from './events.gateway.js';
import {
  buildActivityEvent,
  buildStatusEvent,
  roomForServer,
  roomForUser,
  type ActivityPayload,
  type ServerStatusPayload,
} from './events.logic.js';

/**
 * The only way a service publishes to the event stream.
 *
 * Services depend on this rather than on `EventsGateway` directly, so that a
 * business service never touches socket.io and never constructs a room name by
 * hand. Room names come from `events.logic.ts`, which validates them — which is
 * what makes it structurally impossible to broadcast a server's metrics into a
 * room nobody had to be authorised to join.
 */
@Injectable()
export class EventsPublisher {
  constructor(private readonly gateway: EventsGateway) {}

  /** Broadcasts a server's new status to everyone watching that server. */
  publishServerStatus(serverId: string, payload: ServerStatusPayload): void {
    const event = buildStatusEvent(serverId, payload, new Date());
    this.gateway.emitToRoom(roomForServer(serverId), event.type, event);
  }

  /** Broadcasts a new activity row to the server's watchers. */
  publishActivity(serverId: string, payload: ActivityPayload): void {
    const event = buildActivityEvent(serverId, payload, new Date());
    this.gateway.emitToRoom(roomForServer(serverId), event.type, event);
  }

  /** Broadcasts an account-level activity row to the owner's own room. */
  publishAccountActivity(userId: string, payload: ActivityPayload): void {
    const event = buildActivityEvent(null, payload, new Date());
    this.gateway.emitToRoom(roomForUser(userId), event.type, event);
  }
}
