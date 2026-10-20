/**
 * A javascript implementation of a cryptographically-secure
 * Pseudo Random Number Generator (PRNG). The Fortuna algorithm is followed
 * here though the use of SHA-256 is not enforced.
 */
'use strict';

var util = require('./util');
var ByteBuffer = require('./byte-buffer');

var prng = module.exports = {};

/**
 * Creates a new PRNG context.
 *
 * A PRNG plugin must be passed in that will provide:
 *
 * 1. A function that initializes the key and seed of a PRNG context.
 * 2. The cryptographic function used by the generator.
 * 3. A seed increment function.
 * 4. An api to create a message digest.
 *
 * @param plugin the PRNG plugin to use.
 */
prng.create = function(plugin) {
  var ctx = {
    plugin: plugin,
    key: null,
    seed: null,
    time: null,
    // number of reseeds so far
    reseeds: 0,
    // amount of data generated so far
    generated: 0,
    // no initial key bytes
    keyBytes: ''
  };

  // create 32 entropy pools (each is a message digest)
  var md = plugin.md;
  var pools = new Array(32);
  for(var i = 0; i < 32; ++i) {
    pools[i] = md.create();
  }
  ctx.pools = pools;

  // entropy pools are written to cyclically, starting at index 0
  ctx.pool = 0;

  /**
   * Generates random bytes. The bytes may be generated synchronously or
   * asynchronously.
   *
   * @param count the number of random bytes to generate.
   * @param [callback(err, bytes)] called once the operation completes.
   *
   * @return count random bytes as a string.
   */
  ctx.generate = function(count, callback) {
    // do synchronously
    if(!callback) {
      return ctx.generateSync(count);
    }

    // simple generator using counter-based CBC
    var cipher = ctx.plugin.cipher;
    var increment = ctx.plugin.increment;
    var formatKey = ctx.plugin.formatKey;
    var formatSeed = ctx.plugin.formatSeed;
    var b = new ByteBuffer();

    // paranoid deviation from Fortuna:
    // reset key for every request
    ctx.key = null;

    generate();

    function generate(err) {
      if(err) {
        return callback(err);
      }

      // sufficient bytes generated
      if(b.length() >= count) {
        return callback(null, b.getBytes(count));
      }

      // if amount of data generated is greater than 1 MiB, trigger reseed
      if(ctx.generated > 0xfffff) {
        ctx.key = null;
      }

      if(ctx.key === null) {
        // prevent stack overflow
        return util.nextTick(function() {
          _reseed(generate);
        });
      }

      // generate the random bytes
      var bytes = cipher(ctx.key, ctx.seed);
      ctx.generated += bytes.length;
      b.putBytes(bytes);

      // generate bytes for a new key and seed
      ctx.key = formatKey(cipher(ctx.key, increment(ctx.seed)));
      ctx.seed = formatSeed(cipher(ctx.key, ctx.seed));

      util.setImmediate(generate);
    }
  };

  /**
   * Generates random bytes synchronously.
   *
   * @param count the number of random bytes to generate.
   *
   * @return count random bytes as a string.
   */
  ctx.generateSync = function(count) {
    // simple generator using counter-based CBC
    var cipher = ctx.plugin.cipher;
    var increment = ctx.plugin.increment;
    var formatKey = ctx.plugin.formatKey;
    var formatSeed = ctx.plugin.formatSeed;

    // paranoid deviation from Fortuna:
    // reset key for every request
    ctx.key = null;

    var b = new ByteBuffer();
    while(b.length() < count) {
      // if amount of data generated is greater than 1 MiB, trigger reseed
      if(ctx.generated > 0xfffff) {
        ctx.key = null;
      }

      if(ctx.key === null) {
        _reseedSync();
      }

      // generate the random bytes
      var bytes = cipher(ctx.key, ctx.seed);
      ctx.generated += bytes.length;
      b.putBytes(bytes);

      // generate bytes for a new key and seed
      ctx.key = formatKey(cipher(ctx.key, increment(ctx.seed)));
      ctx.seed = formatSeed(cipher(ctx.key, ctx.seed));
    }

    return b.getBytes(count);
  };

  /**
   * Private function that asynchronously reseeds a generator.
   *
   * @param callback(err) called once the operation completes.
   */
  function _reseed(callback) {
    if(ctx.pools[0].messageLength >= 32) {
      _seed();
      return callback();
    }
    // not enough seed data...
    var needed = (32 - ctx.pools[0].messageLength) << 5;
    ctx.seedFile(needed, function(err, bytes) {
      if(err) {
        return callback(err);
      }
      ctx.collect(bytes);
      _seed();
      callback();
    });
  }

  /**
   * Private function that synchronously reseeds a generator.
   */
  function _reseedSync() {
    if(ctx.pools[0].messageLength >= 32) {
      return _seed();
    }
    // not enough seed data...
    var needed = (32 - ctx.pools[0].messageLength) << 5;
    ctx.collect(ctx.seedFileSync(needed));
    _seed();
  }

  /**
   * Private function that seeds a generator once enough bytes are available.
   */
  function _seed() {
    // update reseed count
    ctx.reseeds = (ctx.reseeds === 0xffffffff) ? 0 : ctx.reseeds + 1;

    // create a plugin-based message digest
    var md = ctx.plugin.md.create();

    // consume current key bytes
    md.update(ctx.keyBytes);

    // digest the entropy of selected pools
    var _2powK = 1;
    for(var k = 0; k < 32; ++k) {
      if(ctx.reseeds % _2powK === 0) {
        md.update(ctx.pools[k].digest().getBytes());
        ctx.pools[k].start();
      }
      _2powK = _2powK << 1;
    }

    // get digest for key bytes
    ctx.keyBytes = md.digest().getBytes();

    // update seed via seed = hash(key)
    md.start();
    md.update(ctx.keyBytes);
    var seedBytes = md.digest().getBytes();

    // update state
    ctx.key = ctx.plugin.formatKey(ctx.keyBytes);
    ctx.seed = ctx.plugin.formatSeed(seedBytes);
    ctx.generated = 0;
  }

  /**
   * The built-in default seedFile.
   *
   * @param needed the number of bytes that are needed.
   *
   * @return the random bytes.
   */
  function defaultSeedFile(needed) {
    // use window.crypto.getRandomValues strong source of entropy if available
    var getRandomValues = null;
    var globalScope = util.globalScope;
    var _crypto = globalScope.crypto || globalScope.msCrypto;
    if(_crypto && _crypto.getRandomValues) {
      getRandomValues = function(arr) {
        return _crypto.getRandomValues(arr);
      };
    }

    var b = new ByteBuffer();
    if(getRandomValues) {
      while(b.length() < needed) {
        // max byte length is 65536 before QuotaExceededError is thrown
        var count = Math.max(1, Math.min(needed - b.length(), 65536) / 4);
        var entropy = new Uint32Array(Math.floor(count));
        try {
          getRandomValues(entropy);
          for(var i = 0; i < entropy.length; ++i) {
            b.putInt32(entropy[i]);
          }
        } catch(e) {
          /* only ignore QuotaExceededError */
          if(!(typeof QuotaExceededError !== 'undefined' &&
            e instanceof QuotaExceededError)) {
            throw e;
          }
        }
      }
    }

    // fall back to weak random data if no strong source was available
    if(b.length() < needed) {
      /* Draws from Park-Miller "minimal standard" 31 bit PRNG. */
      var hi, lo, next;
      var seed = Math.floor(Math.random() * 0x010000);
      while(b.length() < needed) {
        lo = 16807 * (seed & 0xFFFF);
        hi = 16807 * (seed >> 16);
        lo += (hi & 0x7FFF) << 16;
        lo += hi >> 15;
        lo = (lo & 0x7FFFFFFF) + (lo >> 31);
        seed = lo & 0xFFFFFFFF;

        // consume lower 3 bytes of seed
        for(var i = 0; i < 3; ++i) {
          next = seed >>> (i << 3);
          next ^= Math.floor(Math.random() * 0x0100);
          b.putByte(next & 0xFF);
        }
      }
    }

    return b.getBytes(needed);
  }

  // initialize seed file APIs
  ctx.seedFile = function(needed, callback) {
    try {
      callback(null, defaultSeedFile(needed));
    } catch(e) {
      callback(e);
    }
  };
  ctx.seedFileSync = defaultSeedFile;

  /**
   * Adds entropy to a prng ctx's accumulator.
   *
   * @param bytes the bytes of entropy as a string.
   */
  ctx.collect = function(bytes) {
    // iterate over pools distributing entropy cyclically
    var count = bytes.length;
    for(var i = 0; i < count; ++i) {
      ctx.pools[ctx.pool].update(bytes.substr(i, 1));
      ctx.pool = (ctx.pool === 31) ? 0 : ctx.pool + 1;
    }
  };

  /**
   * Collects an integer of n bits.
   *
   * @param i the integer entropy.
   * @param n the number of bits in the integer.
   */
  ctx.collectInt = function(i, n) {
    var bytes = '';
    for(var x = 0; x < n; x += 8) {
      bytes += String.fromCharCode((i >> x) & 0xFF);
    }
    ctx.collect(bytes);
  };

  return ctx;
};

/**
 * Browser entropy collectors that do not require jQuery.
 *
 * @param ctx a PRNG context returned by prng.create().
 */
prng.collectBrowserEntropy = function(ctx) {
  var globalScope = util.globalScope;
  var doc = globalScope.document;
  if(!doc) {
    return;
  }

  var listeners = [];
  var collectInt = function(i, n) {
    ctx.collectInt(i, n);
  };

  if(doc.addEventListener) {
    var onMouseMove = function(e) {
      collectInt(e.clientX, 16);
      collectInt(e.clientY, 16);
    };
    var onKeyPress = function(e) {
      collectInt(e.charCode || e.keyCode, 8);
    };
    var onTouchMove = function(e) {
      var touches = e.touches;
      if(!touches || !touches.length) {
        return;
      }
      collectInt(touches[0].clientX, 16);
      collectInt(touches[0].clientY, 16);
      collectInt(+new Date(), 16);
    };

    doc.addEventListener('mousemove', onMouseMove, {passive: true});
    doc.addEventListener('keypress', onKeyPress, {passive: true});
    doc.addEventListener('touchmove', onTouchMove, {passive: true});

    listeners.push({type: 'mousemove', fn: onMouseMove});
    listeners.push({type: 'keypress', fn: onKeyPress});
    listeners.push({type: 'touchmove', fn: onTouchMove});
  }

  // Allow cleanup if an app no longer wants the collectors attached.
  return function stop() {
    if(!doc.removeEventListener) {
      return;
    }
    for(var i = 0; i < listeners.length; ++i) {
      doc.removeEventListener(listeners[i].type, listeners[i].fn);
    }
  };
};
