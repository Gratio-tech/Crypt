'use strict';

var util = require('./util');
var hmac = require('./hmac');

/**
 * PBKDF2 (RFC 2898) with HMAC-SHA256.
 *
 * @param password the password, a UTF-8 string.
 * @param salt the salt, a UTF-8 string.
 * @param iterations the number of iterations (default: 10000).
 * @param keyLength the desired key length in bytes (default: 16).
 *
 * @return the derived key as a binary string of bytes.
 */
function pbkdf2(password, salt, iterations, keyLength) {
  iterations = iterations || 10000;
  keyLength = keyLength || 16;

  password = util.encodeUtf8(password);
  salt = util.encodeUtf8(salt);

  var hashLength = 32; // SHA-256 output length in bytes
  var blockCount = Math.ceil(keyLength / hashLength);
  var dk = '';

  for(var blockIndex = 1; blockIndex <= blockCount; ++blockIndex) {
    // INT(blockIndex) as a 32-bit big-endian
    var blockBytes = String.fromCharCode(
      (blockIndex >>> 24) & 0xFF,
      (blockIndex >>> 16) & 0xFF,
      (blockIndex >>> 8) & 0xFF,
      blockIndex & 0xFF);

    var mac = hmac.create();
    mac.start('sha256', password);
    mac.update(salt);
    mac.update(blockBytes);
    var u = mac.getMac().getBytes();
    var t = u;

    for(var i = 1; i < iterations; ++i) {
      mac = hmac.create();
      mac.start('sha256', password);
      mac.update(u);
      u = mac.getMac().getBytes();
      t = xorBytes(t, u);
    }

    dk += t;
  }

  return dk.slice(0, keyLength);
}

function xorBytes(a, b) {
  var out = '';
  for(var i = 0; i < a.length; ++i) {
    out += String.fromCharCode(a.charCodeAt(i) ^ b.charCodeAt(i));
  }
  return out;
}

module.exports = pbkdf2;
