import { Catch, Logger, type ArgumentsHost, type ExceptionFilter } from '@nestjs/common';
import type { Request, Response } from 'express';

import { mapErrorToEnvelope } from './error-mapping.logic.js';

/**
 * The single exit point for every error the HTTP layer produces.
 *
 * Registered globally in `main.ts`. All it does is call
 * `mapErrorToEnvelope` — the decision of what a client may see lives in that
 * pure module, exhaustively tested, and this class only moves the result onto
 * the wire and writes the other half to the log.
 *
 * The split is the point: `body` goes to the client and contains no stack, no
 * SQL and no Prisma text; `logDetail` stays on the server and contains all of
 * it.
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger('Http');

  catch(exception: unknown, host: ArgumentsHost): void {
    const context = host.switchToHttp();
    const response = context.getResponse<Response>();
    const request = context.getRequest<Request>();

    const mapped = mapErrorToEnvelope(exception);

    // `${method} ${path}` rather than the full URL: a query string can carry a
    // token (see events.logic.ts on why that fallback exists at all), and the
    // log is the one place it must not be duplicated.
    const where = `${request.method} ${request.path}`;
    const line = `${where} -> ${mapped.status} ${mapped.body.error.code}: ${mapped.logDetail}`;

    if (mapped.logLevel === 'error') {
      this.logger.error(line);
    } else {
      this.logger.warn(line);
    }

    response.status(mapped.status).json(mapped.body);
  }
}
