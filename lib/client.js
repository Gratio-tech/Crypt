'use strict';

var cypher = require('./cypher');
var util = cypher.util;
var random = cypher.random;
var cipher = cypher.cipher;
var ByteBuffer = cypher.ByteBuffer;
var baseN = cypher.baseN;
var prng = cypher.prng;
var sha256 = cypher.sha256;
var sha512 = cypher.sha512;
var md5 = cypher.md5;
var hmac = cypher.hmac;

// ArrayBuffer / Uint8Array -> Base64
function packToBase64(buffer) {
  return util.binary.base64.encode(
    buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer));
}

// Base64 -> Uint8Array
function unpackBase64(base64) {
  return util.binary.base64.decode(base64);
}

// Generate a 16-byte IV and return it as a base64 string.
function generateIV() {
  return util.encode64(random.getBytes(16));
}

// Generate a 16-byte common key (same format as the server-side key).
var generateCommonKey = generateIV;

function encrypt(plaintext, key, iv) {
  var cipherObj = cipher.createCipher(
    'AES-CTR', new ByteBuffer(unpackBase64(key)));
  cipherObj.start({ iv: new ByteBuffer(unpackBase64(iv)) });

  var bytes = util.binary.raw.decode(util.encodeUtf8(plaintext));
  cipherObj.update(new ByteBuffer(bytes));
  cipherObj.finish();

  return util.encode64(cipherObj.output.getBytes());
}

function decrypt(ciphertext, key, iv) {
  var decipher = cipher.createDecipher(
    'AES-CTR', new ByteBuffer(unpackBase64(key)));
  decipher.start({ iv: new ByteBuffer(unpackBase64(iv)) });

  decipher.update(new ByteBuffer(unpackBase64(ciphertext)));
  decipher.finish();

  return util.decodeUtf8(decipher.output.getBytes());
}

// Message-level API, compatible with lib/server.js.
function encryptMsg(params) {
  if (!params || params.message === undefined || !params.pass) {
    throw new Error(
      'The function parameter must be an object with fields "message" and "pass": { message: string, pass: string }'
    );
  }

  var message = params.message;
  var pass = params.pass;
  var iv = generateIV();
  var stringToCrypt =
    typeof message === 'string' ? message : JSON.stringify(message);

  if (typeof stringToCrypt !== 'string') {
    throw new Error('The "message" must be JSON-serializable.');
  }

  return { data: encrypt(stringToCrypt, pass, iv), v: iv };
}

function decryptMsg(params) {
  if (!params || !params.message || !params.pass) {
    throw new Error(
      'The function parameter must be an object with fields "message" and "pass": { message: string, pass: string }'
    );
  }

  var message = params.message;
  var pass = params.pass;
  if (typeof message.data !== 'string' || typeof message.v !== 'string') {
    throw new Error(
      'Not looks like an encrypted data (message has not "data" or "v" fields).'
    );
  }

  return decrypt(message.data, pass, message.v);
}

module.exports = {
  generateIV: generateIV,
  generateCommonKey: generateCommonKey,
  encryptMsg: encryptMsg,
  decryptMsg: decryptMsg,
  encrypt: encrypt,
  decrypt: decrypt,
  packToBase64: packToBase64,
  unpackBase64: unpackBase64,
  sha256: sha256,
  sha512: sha512,
  md5: md5,
  hmac: hmac,
  util: util,
  random: random,
  cipher: cipher,
  ByteBuffer: ByteBuffer,
  baseN: baseN,
  prng: prng
};
