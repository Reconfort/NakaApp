import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  DEFAULT_AGENT_PORT,
  DEFAULT_SSH_PORT,
  authoriseServerAccess,
  isHostKeyChanged,
  normaliseFingerprint,
  normaliseHostname,
  normalisePort,
  normaliseServerInput,
  normaliseServerName,
  normaliseTags,
  normaliseUsername,
} from './servers.logic.js';

const GOOD_FINGERPRINT = `SHA256:${'A'.repeat(43)}`;

describe('normaliseHostname', () => {
  it('accepts a DNS name and lower-cases it', () => {
    const result = normaliseHostname('Prod.Example.COM');
    assert.ok(result.ok);
    assert.equal(result.value, 'prod.example.com');
  });

  it('trims a trailing root dot so one host is one row', () => {
    const result = normaliseHostname('example.com.');
    assert.ok(result.ok);
    assert.equal(result.value, 'example.com');
  });

  it('accepts an IPv4 address', () => {
    assert.ok(normaliseHostname('185.12.33.7').ok);
  });

  it('rejects an IPv4 address with an out-of-range octet', () => {
    assert.ok(!normaliseHostname('256.1.1.1').ok);
  });

  it('accepts an IPv6 address', () => {
    assert.ok(normaliseHostname('2001:db8::1').ok);
  });

  it('rejects a hostname with a space', () => {
    assert.ok(!normaliseHostname('my server').ok);
  });

  it('rejects shell metacharacters', () => {
    for (const value of ['host;rm -rf /', 'host$(id)', 'host`id`', 'host|nc', "host'x"]) {
      const result = normaliseHostname(value);
      assert.ok(!result.ok, `expected ${value} to be rejected`);
      assert.equal(result.code, 'hostname_invalid');
    }
  });

  it('rejects a hostname starting or ending with a hyphen', () => {
    assert.ok(!normaliseHostname('-bad.example.com').ok);
    assert.ok(!normaliseHostname('bad-.example.com').ok);
  });

  it('rejects an over-long hostname', () => {
    assert.ok(!normaliseHostname(`${'a'.repeat(300)}.com`).ok);
  });

  it('rejects a non-string and the empty string', () => {
    assert.ok(!normaliseHostname(null).ok);
    assert.ok(!normaliseHostname(1234).ok);
    assert.ok(!normaliseHostname('   ').ok);
  });
});

describe('normalisePort', () => {
  it('falls back when absent', () => {
    const result = normalisePort(undefined, 22);
    assert.ok(result.ok);
    assert.equal(result.value, 22);
  });

  it('accepts a number and a numeric string', () => {
    const asNumber = normalisePort(2222, 22);
    assert.ok(asNumber.ok);
    assert.equal(asNumber.value, 2222);

    const asString = normalisePort('2222', 22);
    assert.ok(asString.ok);
    assert.equal(asString.value, 2222);
  });

  it('accepts the boundaries', () => {
    assert.ok(normalisePort(1, 22).ok);
    assert.ok(normalisePort(65535, 22).ok);
  });

  it('rejects out-of-range and non-integer ports', () => {
    for (const value of [0, -1, 65536, 22.5, 'abc', {}, true]) {
      assert.ok(!normalisePort(value, 22).ok, `expected ${String(value)} to be rejected`);
    }
  });
});

describe('normaliseUsername', () => {
  it('accepts ordinary Linux usernames', () => {
    for (const value of ['root', 'deploy', 'ubuntu', '_svc', 'app-runner']) {
      assert.ok(normaliseUsername(value).ok, `expected ${value} to be accepted`);
    }
  });

  it('rejects a username starting with a digit or hyphen', () => {
    assert.ok(!normaliseUsername('1root').ok);
    assert.ok(!normaliseUsername('-root').ok);
  });

  it('rejects shell metacharacters and spaces', () => {
    for (const value of ['ro ot', 'root;id', 'root$(id)', '../root', 'root@host']) {
      assert.ok(!normaliseUsername(value).ok, `expected ${value} to be rejected`);
    }
  });

  it('rejects an over-long username', () => {
    assert.ok(!normaliseUsername('a'.repeat(40)).ok);
  });
});

describe('normaliseTags', () => {
  it('defaults to an empty list', () => {
    const result = normaliseTags(undefined);
    assert.ok(result.ok);
    assert.deepEqual(result.value, []);
  });

  it('lower-cases, sorts and deduplicates', () => {
    const result = normaliseTags(['Prod', 'eu-west', 'prod']);
    assert.ok(result.ok);
    assert.deepEqual(result.value, ['eu-west', 'prod']);
  });

  it('drops empty entries rather than failing', () => {
    const result = normaliseTags(['prod', '  ']);
    assert.ok(result.ok);
    assert.deepEqual(result.value, ['prod']);
  });

  it('rejects too many tags', () => {
    assert.ok(!normaliseTags(Array.from({ length: 20 }, (_, i) => `t${i}`)).ok);
  });

  it('rejects a non-array and non-string entries', () => {
    assert.ok(!normaliseTags('prod').ok);
    assert.ok(!normaliseTags([1, 2]).ok);
  });

  it('rejects a tag with punctuation', () => {
    assert.ok(!normaliseTags(['prod!']).ok);
    assert.ok(!normaliseTags(['-prod']).ok);
  });
});

describe('normaliseFingerprint', () => {
  it('accepts the SHA256 form', () => {
    const result = normaliseFingerprint(GOOD_FINGERPRINT);
    assert.ok(result.ok);
    assert.equal(result.value, GOOD_FINGERPRINT);
  });

  it('treats absent as null rather than an error', () => {
    for (const value of [undefined, null, '']) {
      const result = normaliseFingerprint(value);
      assert.ok(result.ok);
      assert.equal(result.value, null);
    }
  });

  it('refuses a legacy MD5 fingerprint outright', () => {
    const md5 = 'MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48';
    const result = normaliseFingerprint(md5);
    assert.ok(!result.ok);
    assert.equal(result.code, 'fingerprint_invalid');
  });

  it('rejects a SHA256 fingerprint of the wrong length', () => {
    assert.ok(!normaliseFingerprint('SHA256:tooshort').ok);
  });
});

describe('normaliseServerName', () => {
  it('collapses whitespace', () => {
    const result = normaliseServerName('  Production   API  ');
    assert.ok(result.ok);
    assert.equal(result.value, 'Production API');
  });

  it('rejects an empty name', () => {
    assert.ok(!normaliseServerName('   ').ok);
  });

  it('rejects an over-long name', () => {
    const result = normaliseServerName('x'.repeat(100));
    assert.ok(!result.ok);
    assert.equal(result.code, 'name_too_long');
  });
});

describe('normaliseServerInput', () => {
  const valid = {
    name: 'Production',
    hostname: 'prod.example.com',
    sshUsername: 'deploy',
  };

  it('accepts a minimal submission and fills the defaults', () => {
    const result = normaliseServerInput(valid);
    assert.ok(result.ok);
    assert.equal(result.value.sshPort, DEFAULT_SSH_PORT);
    assert.equal(result.value.agentPort, DEFAULT_AGENT_PORT);
    assert.deepEqual(result.value.tags, []);
    assert.equal(result.value.hostKeyFingerprint, null);
  });

  it('carries every supplied field through', () => {
    const result = normaliseServerInput({
      ...valid,
      sshPort: 2222,
      agentPort: '9500',
      tags: ['Prod'],
      hostKeyFingerprint: GOOD_FINGERPRINT,
    });
    assert.ok(result.ok);
    assert.equal(result.value.sshPort, 2222);
    assert.equal(result.value.agentPort, 9500);
    assert.deepEqual(result.value.tags, ['prod']);
    assert.equal(result.value.hostKeyFingerprint, GOOD_FINGERPRINT);
  });

  it('reports the first problem only', () => {
    const result = normaliseServerInput({ name: '', hostname: 'bad host', sshUsername: '!!' });
    assert.ok(!result.ok);
    assert.equal(result.code, 'name_invalid');
  });

  it('surfaces a bad hostname once the name is fine', () => {
    const result = normaliseServerInput({ ...valid, hostname: 'bad host' });
    assert.ok(!result.ok);
    assert.equal(result.code, 'hostname_invalid');
  });

  it('never returns a technical sentence to the user', () => {
    const result = normaliseServerInput({ ...valid, hostname: 'bad host' });
    assert.ok(!result.ok);
    assert.doesNotMatch(result.message, /regex|pattern|RFC|undefined|null/i);
  });
});

describe('authoriseServerAccess', () => {
  const server = { id: 'server-1', ownerId: 'user-1' };

  it('allows the owner', () => {
    const result = authoriseServerAccess(server, 'user-1');
    assert.ok(result.ok);
    assert.equal(result.value.id, 'server-1');
  });

  it("denies another user's server", () => {
    const result = authoriseServerAccess(server, 'user-2');
    assert.ok(!result.ok);
    assert.equal(result.code, 'not_found');
  });

  it('denies a missing server', () => {
    const result = authoriseServerAccess(null, 'user-1');
    assert.ok(!result.ok);
    assert.equal(result.code, 'not_found');
  });

  it("reports a foreign server identically to a missing one, so ids can't be probed", () => {
    const foreign = authoriseServerAccess(server, 'user-2');
    const missing = authoriseServerAccess(null, 'user-1');
    assert.ok(!foreign.ok && !missing.ok);
    assert.equal(foreign.code, missing.code);
    assert.equal(foreign.message, missing.message);
  });
});

describe('isHostKeyChanged', () => {
  it('is quiet on first sight — trust on first use', () => {
    assert.ok(!isHostKeyChanged(null, GOOD_FINGERPRINT));
  });

  it('is quiet when nothing was observed', () => {
    assert.ok(!isHostKeyChanged(GOOD_FINGERPRINT, null));
  });

  it('is quiet when the key is unchanged', () => {
    assert.ok(!isHostKeyChanged(GOOD_FINGERPRINT, GOOD_FINGERPRINT));
  });

  it('flags a changed key', () => {
    assert.ok(isHostKeyChanged(GOOD_FINGERPRINT, `SHA256:${'B'.repeat(43)}`));
  });
});
