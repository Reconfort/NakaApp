import { Module } from '@nestjs/common';

import { AuthController } from './auth.controller.js';
import { AuthService } from './auth.service.js';
import { Argon2PasswordHasher, PASSWORD_HASHER } from './password.hasher.js';

/**
 * Identity: registration, sign-in, refresh, sign-out.
 *
 * The hasher is bound to its port here rather than injected as a concrete
 * class, which is what lets `password.logic.ts` be tested against a fake and
 * what would let Argon2id be replaced without touching `AuthService`.
 *
 * `@nestjs/jwt` is intentionally absent: token signing and verification are
 * implemented in `token.logic.ts` so that algorithm-confusion rejection, clock
 * skew and claim validation are our own tested code rather than a library's
 * defaults. See the header comment in that file.
 */
@Module({
  controllers: [AuthController],
  providers: [AuthService, { provide: PASSWORD_HASHER, useClass: Argon2PasswordHasher }],
  exports: [AuthService],
})
export class AuthModule {}
