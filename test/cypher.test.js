'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');

const Crypt = require('..');
const { ByteBuffer, util, random, hmac, sha256 } = Crypt.cypher;

test('ByteBuffer read/write round-trips', () => {
  const bb = new ByteBuffer();
  bb.putBytes('ab').putByte(0x63).putInt32(0x01020304).putInt32Le(0x01020304);
  assert.equal(bb.length(), 11);

  const copy = new ByteBuffer(bb.data);
  assert.equal(copy.getBytes(2), 'ab');
  assert.equal(copy.getByte(), 0x63);
  assert.equal(copy.getInt32(), 0x01020304);
  assert.equal(copy.getInt32Le(), 0x01020304);
});

test('ByteBuffer getBytes/compact/clear/toHex', () => {
  const bb = new ByteBuffer('hello world');
  assert.equal(bb.getBytes(5), 'hello');
  assert.equal(bb.getBytes(0), '');
  assert.equal(bb.length(), 6);

  bb.compact();
  assert.equal(bb.data, ' world');
  assert.equal(bb.bytes(), ' world');
  assert.equal(bb.at(0), 0x20);

  bb.clear();
  assert.equal(bb.length(), 0);

  const hex = new ByteBuffer();
  hex.putBytes(String.fromCharCode(0x00, 0x0f, 0x10, 0xff));
  assert.equal(hex.toHex(), '000f10ff');
});

test('util encode/decode round-trips', () => {
  const utf8 = 'Привет, 世界!';
  assert.equal(util.decodeUtf8(util.encodeUtf8(utf8)), utf8);

  const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
  const b64 = util.encode64(util.binary.raw.encode(bytes));
  assert.equal(b64, util.binary.base64.encode(bytes));
  assert.deepEqual(Array.from(util.binary.base64.decode(b64)), Array.from(bytes));
  assert.deepEqual(
    Array.from(util.binary.raw.decode(util.binary.raw.encode(bytes))),
    Array.from(bytes)
  );

  assert.equal(util.fillString('x', 7), 'xxxxxxx');

  const b58 = util.binary.base58.encode(bytes);
  assert.deepEqual(Array.from(util.binary.base58.decode(b58)), Array.from(bytes));
});

test('hmac: string and byte-buffer keys produce the same MAC', () => {
  const a = hmac.create();
  a.start('sha256', 'key');
  a.update('data');

  const b = hmac.create();
  b.start('sha256', new ByteBuffer('key'));
  b.update('data');

  assert.equal(a.digest().toHex(), b.digest().toHex());
});

test('hmac: long key is hashed before use', () => {
  const key = 'k'.repeat(100);

  const mac = hmac.create();
  mac.start('sha256', key);
  mac.update('data');
  const got = mac.digest().toHex();

  const hashedKey = sha256.create().update(key).digest().getBytes();
  const expected = hmac.create();
  expected.start('sha256', hashedKey);
  expected.update('data');

  assert.equal(got, expected.digest().toHex());
});

test('prng returns requested byte counts', () => {
  assert.equal(random.getBytes(0).length, 0);
  assert.equal(random.getBytes(16).length, 16);
  assert.equal(random.getBytes(32).length, 32);
  assert.notEqual(random.getBytes(16), random.getBytes(16));
});

test('util decode64/isArrayBuffer/isArrayBufferView/ByteBuffer', () => {
  const binary = util.binary.raw.encode(
    new Uint8Array([0, 1, 2, 253, 254, 255]));
  assert.equal(util.decode64(util.encode64(binary)), binary);

  assert.equal(util.isArrayBuffer(new ArrayBuffer(8)), true);
  assert.equal(util.isArrayBuffer(new Uint8Array(2)), false);

  assert.equal(util.isArrayBufferView(new Uint8Array(2)), true);
  assert.equal(util.isArrayBufferView([1, 2]), false);

  const bb = new util.ByteBuffer('ab');
  assert.equal(bb.getBytes(2), 'ab');
});

test('ByteBuffer copy/truncate/isEmpty/fillWithByte', () => {
  const src = new ByteBuffer('abc');
  src.getByte(); // read = 1
  const cp = src.copy();
  assert.equal(cp.data, 'abc');
  assert.equal(cp.read, 1);
  cp.putBytes('d');
  assert.equal(cp.data, 'abcd');
  assert.equal(src.data, 'abc');

  assert.equal(new ByteBuffer().isEmpty(), true);
  const bb = new ByteBuffer();
  bb.putBytes('x');
  assert.equal(bb.isEmpty(), false);
  assert.equal(bb.getBytes(), 'x');
  assert.equal(bb.isEmpty(), true);

  const fill = new ByteBuffer();
  fill.fillWithByte(0x41, 3);
  assert.equal(fill.data, 'AAA');

  const cut = new ByteBuffer('hello');
  cut.truncate(2);
  assert.equal(cut.data, 'hel');
  assert.equal(cut.read, 0);
});
