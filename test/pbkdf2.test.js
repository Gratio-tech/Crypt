'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const Crypt = require('..');
const { clientCrypt } = Crypt;
const { ByteBuffer } = Crypt.cypher;

test('pbkdf2-sha256 matches Node crypto.pbkdf2Sync', () => {
  const cases = [
    ['password', 'salt', 1, 16],
    ['password', 'salt', 2, 32],
    ['pässwörd', 'соль', 1000, 16],
    ['', '', 10, 20]
  ];

  for (const [password, salt, iterations, keyLength] of cases) {
    const ours = clientCrypt.pbkdf2(password, salt, iterations, keyLength);
    const node = crypto.pbkdf2Sync(password, salt, iterations, keyLength, 'sha256');

    assert.equal(new ByteBuffer(ours).toHex(), node.toString('hex'));
  }
});

test('pbkdf2 returns the requested key length', () => {
  assert.equal(clientCrypt.pbkdf2('p', 's', 2, 16).length, 16);
  assert.equal(clientCrypt.pbkdf2('p', 's', 2, 32).length, 32);
});
