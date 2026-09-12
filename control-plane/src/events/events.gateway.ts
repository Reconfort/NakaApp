import { Logger } from '@nestjs/common';
import {
  ConnectedSocket,
  MessageBody,
  SubscribeMessage,
  WebSocketGateway,
  WebSocketServer,
  type OnGatewayConnection,
  type OnGatewayDisconnect,
} from '@nestjs/websockets';
import type { Server, Socket } from 'socket.io';

import { AppConfigService } from '../config/config.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { verifyAccessToken } from '../auth/token.logic.js';
import {
  EVENTS_NAMESPACE,
  authoriseConnection,
  decideSubscription,
  initialRooms,
  type SocketIdentity,
} from './events.logic.js';

/** Acknowledgement returned to a subscribe request. */
interface SubscribeAck {
  readonly ok: boolean;
  readonly room?: string;
  readonly error?: { code: string; message: string };
}

/**
 * The live event stream: `/v1/events`.
 *
 * A shell. Authentication, room naming and the subscription decision all live
 * in `events.logic.ts`; this class connects those decisions to socket.io.
 *
 * Authentication happens once per connection, in `handleConnection`, and the
 * resulting identity is stashed on the socket. A subscription is then checked
 * *again* against what the user actually owns, because the set of servers a
 * user owns can change during a long-lived connection and a token minted an
 * hour ago is not evidence of current ownership.
 */
@WebSocketGateway({
  namespace: EVENTS_NAMESPACE,
  // `origin: false` disables the CORS headers entirely: the macOS client is not
  // a browser and sends no Origin, so permitting one would only widen the
  // surface for a page that is not our client.
  cors: { origin: false },
})
export class EventsGateway implements OnGatewayConnection, OnGatewayDisconnect {
  private readonly logger = new Logger(EventsGateway.name);

  /** socket.id -> identity, for sockets that authenticated successfully. */
  private readonly identities = new Map<string, SocketIdentity>();

  @WebSocketServer() server!: Server;

  constructor(
    private readonly config: AppConfigService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * Server ids the user owns.
   *
   * Queried here rather than through `ServersService` on purpose: this is an
   * authorisation lookup, not business logic, and injecting the server service
   * would make EventsModule and ServersModule mutually dependent — a cycle that
   * only exists to reach a two-column SELECT.
   */
  private async ownedServerIds(userId: string): Promise<string[]> {
    const rows = await this.prisma.server.findMany({
      where: { ownerId: userId },
      select: { id: true },
    });
    return rows.map((row) => row.id);
  }

  handleConnection(client: Socket): void {
    const decision = authoriseConnection(
      {
        auth: client.handshake.auth as Record<string, unknown> | undefined,
        headers: client.handshake.headers as unknown as Record<string, unknown>,
        query: client.handshake.query as unknown as Record<string, unknown>,
      },
      (token) =>
        verifyAccessToken(token, {
          secret: this.config.jwtSecret,
          issuer: this.config.jwtIssuer,
          audience: this.config.jwtAudience,
          now: new Date(),
        }),
    );

    if (!decision.ok) {
      // Emit the reason before disconnecting so the client knows whether to
      // refresh its token or to stop trying. A bare transport close cannot
      // distinguish the two and produces a reconnect loop.
      client.emit('error', { error: { code: decision.code, message: decision.message } });
      client.disconnect(true);
      return;
    }

    this.identities.set(client.id, decision.value);
    for (const room of initialRooms(decision.value)) {
      void client.join(room);
    }
  }

  handleDisconnect(client: Socket): void {
    this.identities.delete(client.id);
  }

  /**
   * Joins a server's room after re-checking ownership.
   *
   * Ownership is loaded per subscribe rather than cached on the socket:
   * caching it would mean a server removed from the account keeps streaming to
   * a connection that is still open.
   */
  @SubscribeMessage('subscribe:server')
  async onSubscribeServer(
    @MessageBody() serverId: unknown,
    @ConnectedSocket() client: Socket,
  ): Promise<SubscribeAck> {
    const identity = this.identities.get(client.id);
    if (identity === undefined) {
      return { ok: false, error: { code: 'unauthorized', message: 'Sign in to receive live updates.' } };
    }

    const owned = await this.ownedServerIds(identity.userId);
    const decision = decideSubscription({ identity, serverId, ownedServerIds: owned });
    if (!decision.ok) {
      return { ok: false, error: { code: decision.code, message: decision.message } };
    }

    await client.join(decision.value);
    return { ok: true, room: decision.value };
  }

  /** Leaves a server's room. */
  @SubscribeMessage('unsubscribe:server')
  async onUnsubscribeServer(
    @MessageBody() serverId: unknown,
    @ConnectedSocket() client: Socket,
  ): Promise<SubscribeAck> {
    const identity = this.identities.get(client.id);
    if (identity === undefined) {
      return { ok: false, error: { code: 'unauthorized', message: 'Sign in to receive live updates.' } };
    }
    // Leaving is checked the same way as joining, so an arbitrary string can
    // never be passed to socket.io's room machinery.
    const decision = decideSubscription({
      identity,
      serverId,
      ownedServerIds: await this.ownedServerIds(identity.userId),
    });
    if (!decision.ok) {
      return { ok: false, error: { code: decision.code, message: decision.message } };
    }
    await client.leave(decision.value);
    return { ok: true, room: decision.value };
  }

  /** Emits an event into a room. Called by `EventsPublisher`, not by clients. */
  emitToRoom(room: string, event: string, payload: unknown): void {
    if (this.server === undefined) {
      this.logger.warn(`Dropped ${event}: the gateway is not initialised yet.`);
      return;
    }
    this.server.to(room).emit(event, payload);
  }
}
