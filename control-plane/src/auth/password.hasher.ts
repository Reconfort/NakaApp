import { Injectable } from '@nestjs/common';
import argon2 from 'argon2';

import type { PasswordHasher } from './password.logic.js';

/**
 * The Argon2id implementation of the {@link PasswordHasher} port.
 *
 * Parameters are stated explicitly rather than left to the library's defaults.
 * They happen to match `argon2@0.45.1`'s defaults today, but a password hash
 * outlives the dependency that produced it, and a silent default change between
 * versions would mean new hashes and old hashes no longer share a cost — which
 * is exactly the kind of drift nobody notices until an audit.
 *
 * The values are OWASP's current Argon2id recommendation: 64 MiB of memory,
 * three iterations, four lanes. See docs/reference/backend-stack.md §1.3.
 */
@Injectable()
export class Argon2PasswordHasher implements PasswordHasher {
  private static readonly OPTIONS = {
    type: argon2.argon2id,
    memoryCost: 65_536,
    timeCost: 3,
    parallelism: 4,
  } as const;

  async hash(plaintext: string): Promise<string> {
    return argon2.hash(plaintext, Argon2PasswordHasher.OPTIONS);
  }

  /**
   * Verifies a password against a stored hash.
   *
   * `argon2.verify` throws on a malformed hash and returns false on a mismatch.
   * That distinction is preserved rather than collapsed: a corrupt row is a
   * server fault worth a 500 and an alert, whereas returning false for it would
   * lock a user out permanently while looking exactly like a typo.
   */
  async verify(storedHash: string, plaintext: string): Promise<boolean> {
    return argon2.verify(storedHash, plaintext);
  }
}

/** DI token for the port, so a test module can substitute a fake. */
export const PASSWORD_HASHER = Symbol('PASSWORD_HASHER');
