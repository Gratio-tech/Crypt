'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const Crypt = require('..');

// base64("0123456789abcdef") — 16 bytes
const PASS = 'MDEyMzQ1Njc4OWFiY2RlZg==';
const { serverCrypt, clientCrypt } = Crypt;

test('server -> client object round-trip', () => {
  const encrypted = serverCrypt.encryptMsg({
    message: { hello: 'world', list: [1, 2, 3] },
    pass: PASS
  });

  assert.deepEqual(
    JSON.parse(clientCrypt.decryptMsg({ message: encrypted, pass: PASS })),
    { hello: 'world', list: [1, 2, 3] }
  );
});

test('client -> server long string round-trip (multi-block)', () => {
  const message = 'The quick brown fox jumps over the lazy dog. '.repeat(10);
  const encrypted = clientCrypt.encryptMsg({ message, pass: PASS });

  assert.equal(serverCrypt.decryptMsg({ message: encrypted, pass: PASS }), message);
});

test('client low-level encrypt/decrypt (unicode)', () => {
  const iv = clientCrypt.generateIV();
  const ciphertext = clientCrypt.encrypt('Привет, мир!', PASS, iv);

  assert.equal(clientCrypt.decrypt(ciphertext, PASS, iv), 'Привет, мир!');
});

test('generated keys and IVs are 16-byte base64', () => {
  assert.equal(Buffer.from(clientCrypt.generateCommonKey(), 'base64').length, 16);
  assert.equal(Buffer.from(clientCrypt.generateIV(), 'base64').length, 16);
});

test('sha256 and hmac-sha256 known answers', () => {
  const sha = clientCrypt.sha256.create().update('hello').digest();
  assert.equal(
    sha.toHex(),
    '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
  );

  const mac = clientCrypt.hmac.create();
  mac.start('sha256', 'key');
  mac.update('The quick brown fox jumps over the lazy dog');
  assert.equal(
    mac.digest().toHex(),
    'f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8'
  );
});

test('empty and falsy messages survive the round-trip', () => {
  for (const message of ['', 0, false, null]) {
    const encrypted = serverCrypt.encryptMsg({ message, pass: PASS });
    const decrypted = clientCrypt.decryptMsg({ message: encrypted, pass: PASS });
    const expected = typeof message === 'string' ? message : JSON.stringify(message);

    assert.equal(decrypted, expected);
  }
});

test('client encryptMsg/decryptMsg accept explicit AES-CTR', () => {
  const encrypted = clientCrypt.encryptMsg({
    message: 'hello', pass: PASS, algorithm: 'AES-CTR'
  });
  assert.equal(
    clientCrypt.decryptMsg({ message: encrypted, pass: PASS, algorithm: 'AES-CTR' }),
    'hello'
  );
});

test('client low-level encrypt/decrypt accept explicit algorithm', () => {
  const iv = clientCrypt.generateIV();
  const ciphertext = clientCrypt.encrypt('hello', PASS, iv, 'AES-CTR');
  assert.equal(clientCrypt.decrypt(ciphertext, PASS, iv, 'AES-CTR'), 'hello');
});

test('client rejects an unsupported algorithm', () => {
  assert.throws(
    () => clientCrypt.encryptMsg({ message: 'hello', pass: PASS, algorithm: 'AES-CBC' }),
    /Unsupported algorithm/
  );
});

test('server encryptMsg accepts explicit AES-CTR and stays interoperable', () => {
  const encrypted = serverCrypt.encryptMsg({
    message: { a: 1 }, pass: PASS, algorithm: 'AES-CTR'
  });
  assert.deepEqual(
    JSON.parse(clientCrypt.decryptMsg({ message: encrypted, pass: PASS, algorithm: 'AES-CTR' })),
    { a: 1 }
  );
});
