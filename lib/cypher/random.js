/**
 * An API for getting cryptographically-secure random bytes.
 *
 * Uses forge's Fortuna PRNG. On browsers with crypto.getRandomValues, that
 * API is used as the entropy source. If it is unavailable (for example in
 * some local/file or older-browser contexts), the PRNG falls back to
 * collected browser entropy and a Park-Miller weak source.
 */
'use strict';

var util = require('./util');
var ByteBuffer = require('./byte-buffer');
var aes = require('./aes');
var sha256 = require('./sha256');
var prng = require('./prng');

// the default prng plugin, uses AES-128
var prng_aes = {};
var _prng_aes_output = new Array(4);
var _prng_aes_buffer = new ByteBuffer();

prng_aes.formatKey = function(key) {
  // convert the key into 32-bit integers
  var tmp = new ByteBuffer(key);
  key = new Array(4);
  key[0] = tmp.getInt32();
  key[1] = tmp.getInt32();
  key[2] = tmp.getInt32();
  key[3] = tmp.getInt32();

  // return the expanded key
  return aes._expandKey(key);
};

prng_aes.formatSeed = function(seed) {
  // convert seed into 32-bit integers
  var tmp = new ByteBuffer(seed);
  seed = new Array(4);
  seed[0] = tmp.getInt32();
  seed[1] = tmp.getInt32();
  seed[2] = tmp.getInt32();
  seed[3] = tmp.getInt32();
  return seed;
};

prng_aes.cipher = function(key, seed) {
  aes._updateBlock(key, seed, _prng_aes_output);
  _prng_aes_buffer.putInt32(_prng_aes_output[0]);
  _prng_aes_buffer.putInt32(_prng_aes_output[1]);
  _prng_aes_buffer.putInt32(_prng_aes_output[2]);
  _prng_aes_buffer.putInt32(_prng_aes_output[3]);
  return _prng_aes_buffer.getBytes();
};

prng_aes.increment = function(seed) {
  ++seed[3];
  return seed;
};

prng_aes.md = sha256;

/**
 * Creates a new PRNG.
 */
function spawnPrng() {
  var ctx = prng.create(prng_aes);

  /**
   * Gets random bytes. If a callback is given, this method will be called
   * asynchronously.
   *
   * @param count the number of random bytes to get.
   * @param [callback(err, bytes)] called once the operation completes.
   *
   * @return the random bytes in a string.
   */
  ctx.getBytes = function(count, callback) {
    return ctx.generate(count, callback);
  };

  /**
   * Gets random bytes synchronously.
   *
   * @param count the number of random bytes to get.
   *
   * @return the random bytes in a string.
   */
  ctx.getBytesSync = function(count) {
    return ctx.generate(count);
  };

  return ctx;
}

// create default prng context
var _ctx = spawnPrng();

// add other sources of entropy only if window.crypto.getRandomValues is not
// available -- otherwise that source will be used by the prng
var _crypto = util.globalScope.crypto || util.globalScope.msCrypto;
var hasGetRandomValues = !!(_crypto && _crypto.getRandomValues);

if(!util.isNodejs && !hasGetRandomValues) {
  // get load time entropy
  _ctx.collectInt(+new Date(), 32);

  // add some entropy from navigator object
  if(typeof navigator !== 'undefined') {
    var _navBytes = '';
    for(var key in navigator) {
      try {
        if(typeof navigator[key] === 'string') {
          _navBytes += navigator[key];
        }
      } catch(e) {
        /* Some navigator keys might not be accessible. */
      }
    }
    _ctx.collect(_navBytes);
    _navBytes = null;
  }

  // native mousemove/keypress/touchmove entropy collectors, no jQuery.
  _ctx.stopCollectors = prng.collectBrowserEntropy(_ctx);
}

var random = module.exports = _ctx;
random.createInstance = spawnPrng;
