import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  normaliseAbsolutePath,
  normaliseComposeProject,
  normaliseProjectInput,
} from './projects.logic.js';

describe('normaliseAbsolutePath', () => {
  it('accepts an absolute path', () => {
    const result = normaliseAbsolutePath('/srv/estatify');
    assert.ok(result.ok);
    assert.equal(result.value, '/srv/estatify');
  });

  it('treats absent as null', () => {
    for (const value of [undefined, null, '', '   ']) {
      const result = normaliseAbsolutePath(value);
      assert.ok(result.ok);
      assert.equal(result.value, null);
    }
  });

  it('rejects a relative path rather than guessing at a base directory', () => {
    const result = normaliseAbsolutePath('srv/estatify');
    assert.ok(!result.ok);
    assert.equal(result.code, 'path_invalid');
  });

  it('rejects traversal segments', () => {
    for (const value of ['/srv/../etc/shadow', '/../etc', '/srv/app/..']) {
      const result = normaliseAbsolutePath(value);
      assert.ok(!result.ok, `expected ${value} to be rejected`);
    }
  });

  it('allows a filename that merely contains dots', () => {
    assert.ok(normaliseAbsolutePath('/srv/app..name').ok);
    assert.ok(normaliseAbsolutePath('/srv/.env.d').ok);
  });

  it('rejects control characters and newlines', () => {
    assert.ok(!normaliseAbsolutePath('/srv/app\u0000/etc').ok);
    assert.ok(!normaliseAbsolutePath('/srv/app\nrm -rf /').ok);
  });

  it('collapses repeated slashes and a trailing slash', () => {
    const result = normaliseAbsolutePath('/srv//app///web/');
    assert.ok(result.ok);
    assert.equal(result.value, '/srv/app/web');
  });

  it('keeps the root path as a single slash', () => {
    const result = normaliseAbsolutePath('/');
    assert.ok(result.ok);
    assert.equal(result.value, '/');
  });

  it('rejects an over-long path', () => {
    assert.ok(!normaliseAbsolutePath(`/${'a'.repeat(5000)}`).ok);
  });
});

describe('normaliseComposeProject', () => {
  it('accepts a docker-legal project name', () => {
    const result = normaliseComposeProject('estatify-api');
    assert.ok(result.ok);
    assert.equal(result.value, 'estatify-api');
  });

  it('lower-cases, as docker does', () => {
    const result = normaliseComposeProject('Estatify');
    assert.ok(result.ok);
    assert.equal(result.value, 'estatify');
  });

  it('treats absent as null', () => {
    const result = normaliseComposeProject(undefined);
    assert.ok(result.ok);
    assert.equal(result.value, null);
  });

  it('rejects a name starting with a dash or underscore', () => {
    assert.ok(!normaliseComposeProject('-api').ok);
    assert.ok(!normaliseComposeProject('_api').ok);
  });

  it('rejects spaces and punctuation', () => {
    for (const value of ['my api', 'api!', 'api/web', 'api.web']) {
      assert.ok(!normaliseComposeProject(value).ok, `expected ${value} to be rejected`);
    }
  });
});

describe('normaliseProjectInput', () => {
  it('accepts a minimal project', () => {
    const result = normaliseProjectInput({ name: 'Estatify' });
    assert.ok(result.ok);
    assert.equal(result.value.name, 'Estatify');
    assert.equal(result.value.composeProject, null);
    assert.equal(result.value.workingDir, null);
    assert.equal(result.value.description, null);
  });

  it('carries every field through', () => {
    const result = normaliseProjectInput({
      name: '  Estatify   API ',
      composeProject: 'Estatify-API',
      workingDir: '/srv/estatify/',
      description: '  The public API.  ',
    });
    assert.ok(result.ok);
    assert.equal(result.value.name, 'Estatify API');
    assert.equal(result.value.composeProject, 'estatify-api');
    assert.equal(result.value.workingDir, '/srv/estatify');
    assert.equal(result.value.description, 'The public API.');
  });

  it('rejects a missing or empty name', () => {
    assert.ok(!normaliseProjectInput({ name: undefined }).ok);
    assert.ok(!normaliseProjectInput({ name: '   ' }).ok);
  });

  it('rejects an over-long name', () => {
    const result = normaliseProjectInput({ name: 'x'.repeat(100) });
    assert.ok(!result.ok);
    assert.equal(result.code, 'name_too_long');
  });

  it('rejects an over-long description', () => {
    const result = normaliseProjectInput({ name: 'a', description: 'd'.repeat(600) });
    assert.ok(!result.ok);
    assert.equal(result.code, 'description_too_long');
  });

  it('surfaces a bad working directory', () => {
    const result = normaliseProjectInput({ name: 'a', workingDir: '../etc' });
    assert.ok(!result.ok);
    assert.equal(result.code, 'path_invalid');
  });
});
