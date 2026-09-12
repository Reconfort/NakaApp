/**
 * Validation for projects — the applications deployed on a server.
 *
 * A project is usually a docker compose stack, so `composeProject` has to match
 * what Docker will actually label the containers with, and `workingDir` has to
 * be an absolute path the agent can `cd` into. Both are checked here rather
 * than trusted, because both end up in an agent request where a `..` or a shell
 * metacharacter would be a path-traversal or an injection.
 */

import { fail, ok, type Result } from '../common/result.logic.js';

/** Longest project name. */
const MAX_NAME_LENGTH = 64;

/** Longest description. */
const MAX_DESCRIPTION_LENGTH = 500;

/** Longest path. */
const MAX_PATH_LENGTH = 4096;

/**
 * Docker's own compose project name rule: lower-case letters, digits, dashes
 * and underscores, starting with a letter or digit.
 */
const COMPOSE_PROJECT_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/;

/** What a client submits. */
export interface ProjectInput {
  readonly name: unknown;
  readonly composeProject?: unknown;
  readonly workingDir?: unknown;
  readonly description?: unknown;
}

/** A validated project, ready to persist. */
export interface NormalisedProject {
  readonly name: string;
  readonly composeProject: string | null;
  readonly workingDir: string | null;
  readonly description: string | null;
}

/**
 * Validates an absolute POSIX path.
 *
 * Rejects `..` anywhere in the path, and rejects NUL bytes and newlines. A
 * relative path is refused rather than resolved: the control plane has no idea
 * what the agent's working directory is, so "resolving" it here would be a
 * guess, and a wrong guess would point an operation at the wrong directory.
 */
export function normaliseAbsolutePath(input: unknown): Result<string | null> {
  if (input === undefined || input === null || input === '') return ok(null);
  if (typeof input !== 'string') {
    return fail('path_invalid', 'Enter a directory path.');
  }
  const value = input.trim();
  if (value.length === 0) return ok(null);
  if (value.length > MAX_PATH_LENGTH) {
    return fail('path_invalid', 'That path is too long.');
  }
  if (!value.startsWith('/')) {
    return fail('path_invalid', 'Use an absolute path, starting with /.');
  }
  if (/[\u0000-\u001F]/.test(value)) {
    return fail('path_invalid', "That path contains characters we can't use.");
  }
  if (value.split('/').includes('..')) {
    return fail('path_invalid', "That path can't contain '..'.");
  }
  // Collapse repeated slashes and drop a trailing one, so /srv/app and
  // /srv//app/ are one directory rather than two rows.
  const collapsed = value.replace(/\/+/g, '/').replace(/(.)\/$/, '$1');
  return ok(collapsed);
}

/** Validates a docker compose project label. */
export function normaliseComposeProject(input: unknown): Result<string | null> {
  if (input === undefined || input === null || input === '') return ok(null);
  if (typeof input !== 'string') {
    return fail('compose_project_invalid', "That compose project name isn't valid.");
  }
  const value = input.trim().toLowerCase();
  if (value.length === 0) return ok(null);
  if (!COMPOSE_PROJECT_PATTERN.test(value)) {
    return fail(
      'compose_project_invalid',
      'Use lower-case letters, numbers, dashes and underscores.',
    );
  }
  return ok(value);
}

/** Validates a whole project submission. */
export function normaliseProjectInput(input: ProjectInput): Result<NormalisedProject> {
  if (typeof input.name !== 'string') {
    return fail('name_invalid', 'Give this project a name.');
  }
  const name = input.name.replace(/\s+/g, ' ').trim();
  if (name.length === 0) {
    return fail('name_invalid', 'Give this project a name.');
  }
  if (name.length > MAX_NAME_LENGTH) {
    return fail('name_too_long', `Use ${MAX_NAME_LENGTH} characters or fewer.`);
  }

  const composeProject = normaliseComposeProject(input.composeProject);
  if (!composeProject.ok) return composeProject;

  const workingDir = normaliseAbsolutePath(input.workingDir);
  if (!workingDir.ok) return workingDir;

  let description: string | null = null;
  if (typeof input.description === 'string') {
    const trimmed = input.description.trim();
    if (trimmed.length > MAX_DESCRIPTION_LENGTH) {
      return fail('description_too_long', `Use ${MAX_DESCRIPTION_LENGTH} characters or fewer.`);
    }
    description = trimmed.length === 0 ? null : trimmed;
  }

  return ok({
    name,
    composeProject: composeProject.value,
    workingDir: workingDir.value,
    description,
  });
}
