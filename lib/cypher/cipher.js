'use strict';

var ByteBuffer = require('./byte-buffer');

var algorithms = Object.create(null);

function getAlgorithm(name) {
  name = name.toUpperCase();
  if(name in algorithms) {
    return algorithms[name];
  }
  return null;
}

function resolveAlgorithm(algorithm) {
  if(typeof algorithm === 'string') {
    var factory = getAlgorithm(algorithm);
    if(!factory) {
      throw new Error('Unsupported algorithm: ' + algorithm);
    }
    return factory();
  }
  return algorithm;
}

/**
 * Creates a cipher object for encryption.
 */
function createCipher(algorithm, key) {
  return new BlockCipher({
    algorithm: resolveAlgorithm(algorithm),
    key: key,
    decrypt: false
  });
}

/**
 * Creates a decipher object for decryption.
 */
function createDecipher(algorithm, key) {
  return new BlockCipher({
    algorithm: resolveAlgorithm(algorithm),
    key: key,
    decrypt: true
  });
}

function registerAlgorithm(name, factory) {
  algorithms[name.toUpperCase()] = factory;
}

function BlockCipher(options) {
  this.algorithm = options.algorithm;
  this.mode = this.algorithm.mode;
  this.blockSize = this.mode.blockSize;
  this._finish = false;
  this._input = null;
  this.output = null;
  this._op = options.decrypt ? this.mode.decrypt : this.mode.encrypt;
  this._decrypt = options.decrypt;
  this.algorithm.initialize(options);
}

BlockCipher.prototype.start = function(options) {
  options = options || {};
  var opts = {};
  for(var key in options) {
    opts[key] = options[key];
  }
  opts.decrypt = this._decrypt;
  this._finish = false;
  this._input = new ByteBuffer();
  this.output = options.output || new ByteBuffer();
  this.mode.start(opts);
};

BlockCipher.prototype.update = function(input) {
  if(input) {
    // input given, so empty it into the input buffer
    this._input.putBuffer(input);
  }

  // do cipher operation until it needs more input and not finished
  while(!this._op.call(this.mode, this._input, this.output, this._finish) &&
    !this._finish) {}

  // free consumed memory from input buffer
  this._input.compact();
};

BlockCipher.prototype.finish = function() {
  var options = {};
  options.decrypt = this._decrypt;

  // get # of bytes that won't fill a block
  options.overflow = this._input.length() % this.blockSize;

  // do final update
  this._finish = true;
  this.update();

  return true;
};

module.exports = {
  algorithms: algorithms,
  createCipher: createCipher,
  createDecipher: createDecipher,
  registerAlgorithm: registerAlgorithm,
  getAlgorithm: getAlgorithm,
  BlockCipher: BlockCipher
};
