'use strict';

var util = require('./util');
var ByteBuffer = require('./byte-buffer');
var modes = require('./cipherModes');
var cipher = require('./cipher');

/**
 * Advanced Encryption Standard (AES) block cipher.
 *
 * AES-128/192/256 encryption core required by AES-CTR.
 * CTR never uses the AES decryption path, so the inverse
 * tables and decryption key schedule have been intentionally dropped.
 */
var aes = module.exports = {};

aes.Algorithm = function(name, mode) {
  if(!init) {
    initialize();
  }
  var self = this;
  self.name = name;
  self.mode = new mode({
    blockSize: 16,
    cipher: {
      encrypt: function(inBlock, outBlock) {
        return _updateBlock(self._w, inBlock, outBlock);
      },
      // AES-CTR never calls this, but the mode API expects a decrypt function.
      decrypt: function(inBlock, outBlock) {
        return _updateBlock(self._w, inBlock, outBlock);
      }
    }
  });
  self._init = false;
};

aes.Algorithm.prototype.initialize = function(options) {
  if(this._init) {
    return;
  }

  var key = options.key;
  var tmp;

  /* Note: The key may be a string of bytes, an array of bytes, or a byte
     buffer. If the key is in bytes, then it must be 16, 24, or 32 bytes in
     length. If it is in 32-bit integers, it must be 4, 6, or 8 integers
     long. */

  if(typeof key === 'string' &&
    (key.length === 16 || key.length === 24 || key.length === 32)) {
    // convert key string into byte buffer
    key = new ByteBuffer(key);
  } else if(util.isArray(key) &&
    (key.length === 16 || key.length === 24 || key.length === 32)) {
    // convert key integer array into byte buffer
    tmp = key;
    key = new ByteBuffer();
    for(var i = 0; i < tmp.length; ++i) {
      key.putByte(tmp[i]);
    }
  }

  // convert key byte buffer into 32-bit integer array
  if(!util.isArray(key)) {
    tmp = key;
    key = [];

    // key lengths of 16, 24, 32 bytes allowed
    var len = tmp.length();
    if(len === 16 || len === 24 || len === 32) {
      len = len >>> 2;
      for(var j = 0; j < len; ++j) {
        key.push(tmp.getInt32());
      }
    }
  }

  // key must be an array of 32-bit integers by now
  if(!util.isArray(key) ||
    !(key.length === 4 || key.length === 6 || key.length === 8)) {
    throw new Error('Invalid key parameter.');
  }

  // AES-CTR always uses the encryption key schedule.
  this._w = _expandKey(key);
  this._init = true;
};

// Register only the algorithm used by this package.
cipher.registerAlgorithm('AES-CTR', function() {
  return new aes.Algorithm('AES-CTR', modes.ctr);
});

/** AES implementation (encryption-only) **/

var init = false; // not yet initialized
var Nb = 4;       // number of words comprising the state (AES = 4)
var sbox;         // non-linear substitution table used in key expansion
var rcon;         // round constant word array
var mix;          // mix-columns table

function initialize() {
  init = true;

  rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

  // compute xtime table which maps i onto GF(i, 0x02)
  var xtime = new Array(256);
  for(var i = 0; i < 128; ++i) {
    xtime[i] = i << 1;
    xtime[i + 128] = (i + 128) << 1 ^ 0x11B;
  }

  // compute sbox and mix-columns tables
  sbox = new Array(256);
  mix = new Array(4);
  for(var m = 0; m < 4; ++m) {
    mix[m] = new Array(256);
  }

  var e = 0;
  var ei = 0;
  var e2, e4, e8, sx, sx2, me;
  for(var t = 0; t < 256; ++t) {
    // apply affine transformation
    sx = ei ^ (ei << 1) ^ (ei << 2) ^ (ei << 3) ^ (ei << 4);
    sx = (sx >> 8) ^ (sx & 255) ^ 0x63;

    // update tables
    sbox[e] = sx;

    // calculate mix table value
    sx2 = xtime[sx];
    e2 = xtime[e];
    e4 = xtime[e2];
    e8 = xtime[e4];
    me =
      (sx2 << 24) ^  // 2
      (sx << 16) ^   // 1
      (sx << 8) ^    // 1
      (sx ^ sx2);    // 3

    // produce each of the mix tables by rotating the 2,1,1,3 value
    for(var n = 0; n < 4; ++n) {
      mix[n][e] = me;
      // cycle the right most byte to the left most position
      me = me << 24 | me >>> 8;
    }

    // get next element and inverse
    if(e === 0) {
      // 1 is the inverse of 1
      e = ei = 1;
    } else {
      // e = 2e + 2*2*2*(10e)) = multiply e by 82 (chosen generator)
      // ei = ei + 2*2*ei = multiply ei by 5 (inverse generator)
      e = e2 ^ xtime[xtime[xtime[e2 ^ e8]]];
      ei ^= xtime[xtime[ei]];
    }
  }
}

// Initialize the tables eagerly: the PRNG calls `_expandKey`/`_updateBlock`
// directly (not via `aes.Algorithm`), so `sbox`/`rcon`/`mix` must already
// exist the first time they are used.
initialize();

function _expandKey(key) {
  // copy the key's words to initialize the key schedule
  var w = key.slice(0);

  var temp;
  var iNk = 1;
  var Nk = w.length;
  var Nr1 = Nk + 6 + 1;
  var end = Nb * Nr1;
  for(var i = Nk; i < end; ++i) {
    temp = w[i - 1];
    if(i % Nk === 0) {
      // temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk]
      temp =
        sbox[temp >>> 16 & 255] << 24 ^
        sbox[temp >>> 8 & 255] << 16 ^
        sbox[temp & 255] << 8 ^
        sbox[temp >>> 24] ^ (rcon[iNk] << 24);
      iNk++;
    } else if(Nk > 6 && (i % Nk === 4)) {
      // temp = SubWord(temp)
      temp =
        sbox[temp >>> 24] << 24 ^
        sbox[temp >>> 16 & 255] << 16 ^
        sbox[temp >>> 8 & 255] << 8 ^
        sbox[temp & 255];
    }
    w[i] = w[i - Nk] ^ temp;
  }

  return w;
}

function _updateBlock(w, input, output) {
  var Nr = w.length / 4 - 1;
  var m0 = mix[0];
  var m1 = mix[1];
  var m2 = mix[2];
  var m3 = mix[3];
  var sub = sbox;

  var a, b, c, d, a2, b2, c2;
  a = input[0] ^ w[0];
  b = input[1] ^ w[1];
  c = input[2] ^ w[2];
  d = input[3] ^ w[3];
  var i = 3;

  for(var round = 1; round < Nr; ++round) {
    a2 =
      m0[a >>> 24] ^
      m1[b >>> 16 & 255] ^
      m2[c >>> 8 & 255] ^
      m3[d & 255] ^ w[++i];
    b2 =
      m0[b >>> 24] ^
      m1[c >>> 16 & 255] ^
      m2[d >>> 8 & 255] ^
      m3[a & 255] ^ w[++i];
    c2 =
      m0[c >>> 24] ^
      m1[d >>> 16 & 255] ^
      m2[a >>> 8 & 255] ^
      m3[b & 255] ^ w[++i];
    d =
      m0[d >>> 24] ^
      m1[a >>> 16 & 255] ^
      m2[b >>> 8 & 255] ^
      m3[c & 255] ^ w[++i];
    a = a2;
    b = b2;
    c = c2;
  }

  output[0] =
    (sub[a >>> 24] << 24) ^
    (sub[b >>> 16 & 255] << 16) ^
    (sub[c >>> 8 & 255] << 8) ^
    (sub[d & 255]) ^ w[++i];
  output[1] =
    (sub[b >>> 24] << 24) ^
    (sub[c >>> 16 & 255] << 16) ^
    (sub[d >>> 8 & 255] << 8) ^
    (sub[a & 255]) ^ w[++i];
  output[2] =
    (sub[c >>> 24] << 24) ^
    (sub[d >>> 16 & 255] << 16) ^
    (sub[a >>> 8 & 255] << 8) ^
    (sub[b & 255]) ^ w[++i];
  output[3] =
    (sub[d >>> 24] << 24) ^
    (sub[a >>> 16 & 255] << 16) ^
    (sub[b >>> 8 & 255] << 8) ^
    (sub[c & 255]) ^ w[++i];
}

// PRNG support.
aes._expandKey = _expandKey;
aes._updateBlock = function(w, input, output) {
  return _updateBlock(w, input, output);
};
