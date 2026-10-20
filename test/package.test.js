'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PASS = 'MDEyMzQ1Njc4OWFiY2RlZg==';

test('CJS root entry (index.js) has .default for TS/ESM interop', () => {
  const Crypt = require('../index.js');
  assert.equal(Crypt.default, Crypt);
  assert.ok(Crypt.serverCrypt);
  assert.ok(Crypt.clientCrypt);
  assert.ok(Crypt.frontCrypt);
  assert.ok(Crypt.cypher);
});

test('ESM root entry (index.mjs)', async () => {
  const mod = await import('../index.mjs');
  assert.ok(mod.default);
  assert.ok(mod.serverCrypt);
  assert.ok(mod.clientCrypt);
  assert.ok(mod.frontCrypt);
  assert.ok(mod.cypher);

  const encrypted = mod.serverCrypt.encryptMsg({ message: 'esm-test', pass: PASS });
  const decrypted = mod.clientCrypt.decryptMsg({ message: encrypted, pass: PASS });
  assert.equal(decrypted, 'esm-test');
});

test('Browser ESM entry (index.browser.mjs) exports serverCrypt stub that throws', async () => {
  const mod = await import('../index.browser.mjs');
  assert.ok(mod.default);
  assert.ok(mod.clientCrypt);
  assert.ok(mod.frontCrypt);
  assert.ok(mod.cypher);
  assert.ok(mod.serverCrypt);

  assert.throws(() => {
    mod.serverCrypt.encryptMsg({ message: 'test', pass: PASS });
  }, /@gratio\/crypt: serverCrypt is only available in Node\.js\./);

  const iv = mod.clientCrypt.generateIV();
  const cipher = mod.clientCrypt.encrypt('browser-esm', PASS, iv);
  assert.equal(mod.clientCrypt.decrypt(cipher, PASS, iv), 'browser-esm');
});

test('Browser CJS entry (index.browser.js) has .default and throws on serverCrypt', () => {
  const mod = require('../index.browser.js');
  assert.equal(mod.default, mod);
  assert.ok(mod.clientCrypt);
  assert.ok(mod.frontCrypt);
  assert.ok(mod.cypher);
  assert.ok(mod.serverCrypt);

  assert.throws(() => {
    mod.serverCrypt.encryptMsg({ message: 'test', pass: PASS });
  }, /@gratio\/crypt: serverCrypt is only available in Node\.js\./);

  const iv = mod.clientCrypt.generateIV();
  const cipher = mod.clientCrypt.encrypt('browser-cjs', PASS, iv);
  assert.equal(mod.clientCrypt.decrypt(cipher, PASS, iv), 'browser-cjs');
});

test('Bundled client ESM (dist/gcrypt.esm.mjs)', async (t) => {
  const bundlePath = path.resolve(__dirname, '../dist/gcrypt.esm.mjs');
  if (!fs.existsSync(bundlePath)) {
    t.skip('dist/gcrypt.esm.mjs not found; run npm run build first');
    return;
  }
  const mod = await import('../dist/gcrypt.esm.mjs');
  assert.ok(mod.default);
  assert.equal(typeof mod.encrypt, 'function');
  assert.equal(typeof mod.decrypt, 'function');
  assert.equal(typeof mod.generateIV, 'function');

  const iv = mod.generateIV();
  const cipher = mod.encrypt('bundle-esm', PASS, iv);
  assert.equal(mod.decrypt(cipher, PASS, iv), 'bundle-esm');
});

test('Hash algorithms known answers (md5, sha512, sha384)', () => {
  const Crypt = require('..');
  const { md5, sha512 } = Crypt.clientCrypt;

  // MD5
  const md5Digest = md5.create().update('hello').digest().toHex();
  const nodeMd5 = crypto.createHash('md5').update('hello').digest('hex');
  assert.equal(md5Digest, nodeMd5);

  // SHA-512
  const sha512Digest = sha512.create().update('hello world').digest().toHex();
  const nodeSha512 = crypto.createHash('sha512').update('hello world').digest('hex');
  assert.equal(sha512Digest, nodeSha512);

  // SHA-384
  const sha384Digest = sha512.sha384.create().update('hello world').digest().toHex();
  const nodeSha384 = crypto.createHash('sha384').update('hello world').digest('hex');
  assert.equal(sha384Digest, nodeSha384);
});
