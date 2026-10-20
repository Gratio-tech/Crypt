'use strict';

var ByteBuffer = require('./byte-buffer');
var util = require('./util');

var modes = module.exports = {};

/**
 * Counter (CTR) mode.
 *
 * CTR always uses the block cipher in encryption mode and XORs the keystream
 * with the input. This is the only mode currently extracted because the client
 * and server use AES-128-CTR.
 */
modes.ctr = function(options) {
  options = options || {};
  this.name = 'CTR';
  this.cipher = options.cipher;
  this.blockSize = options.blockSize || 16;
  this._ints = this.blockSize / 4;
  this._inBlock = null;
  this._outBlock = new Array(this._ints);
  this._partialOutput = new ByteBuffer();
  this._partialBytes = 0;
};

modes.ctr.prototype.start = function(options) {
  if(!('iv' in options)) {
    throw new Error('Invalid IV parameter.');
  }

  // use IV as first input
  this._iv = transformIV(options.iv, this.blockSize);
  this._inBlock = this._iv.slice(0);
  this._partialBytes = 0;
};

modes.ctr.prototype.encrypt = function(input, output, finish) {
  // not enough input to encrypt
  var inputLength = input.length();
  if(inputLength === 0) {
    return true;
  }

  // encrypt block (CTR always uses encryption mode)
  this.cipher.encrypt(this._inBlock, this._outBlock);

  // handle full block
  if(this._partialBytes === 0 && inputLength >= this.blockSize) {
    // XOR input with output
    for(var i = 0; i < this._ints; ++i) {
      output.putInt32(input.getInt32() ^ this._outBlock[i]);
    }
  } else {
    // handle partial block
    var partialBytes = (this.blockSize - inputLength) % this.blockSize;
    if(partialBytes > 0) {
      partialBytes = this.blockSize - partialBytes;
    }

    // XOR input with output
    this._partialOutput.clear();
    for(var j = 0; j < this._ints; ++j) {
      this._partialOutput.putInt32(input.getInt32() ^ this._outBlock[j]);
    }

    if(partialBytes > 0) {
      // block still incomplete, restore input buffer
      input.read -= this.blockSize;
    }

    // skip any previous partial bytes
    if(this._partialBytes > 0) {
      this._partialOutput.getBytes(this._partialBytes);
    }

    if(partialBytes > 0 && !finish) {
      output.putBytes(this._partialOutput.getBytes(
        partialBytes - this._partialBytes));
      this._partialBytes = partialBytes;
      return true;
    }

    output.putBytes(this._partialOutput.getBytes(
      inputLength - this._partialBytes));
    this._partialBytes = 0;
  }

  // block complete, increment counter (input block)
  inc32(this._inBlock);
};

modes.ctr.prototype.decrypt = modes.ctr.prototype.encrypt;

/**
 * Cipher Feedback (CFB) mode.
 *
 * CFB always uses the block cipher in encryption mode for both encrypting and
 * decrypting. The previous ciphertext block (the IV for the first block) is
 * encrypted to produce the keystream, which is XORed with the input.
 */
modes.cfb = function(options) {
  options = options || {};
  this.name = 'CFB';
  this.cipher = options.cipher;
  this.blockSize = options.blockSize || 16;
  this._ints = this.blockSize / 4;
  this._inBlock = null;
  this._outBlock = new Array(this._ints);
  this._partialOutput = new ByteBuffer();
  this._partialBytes = 0;
};

modes.cfb.prototype.start = function(options) {
  if(!('iv' in options)) {
    throw new Error('Invalid IV parameter.');
  }

  // use IV as first input block
  this._iv = transformIV(options.iv, this.blockSize);
  this._inBlock = this._iv.slice(0);
  this._partialBytes = 0;
};

modes.cfb.prototype.encrypt = function(input, output, finish) {
  return this._process(input, output, finish, true);
};

modes.cfb.prototype.decrypt = function(input, output, finish) {
  return this._process(input, output, finish, false);
};

modes.cfb.prototype._process = function(input, output, finish, encrypting) {
  // no input to process
  var inputLength = input.length();
  if(inputLength === 0) {
    return true;
  }

  // encrypt the feedback block (CFB always uses encryption mode)
  this.cipher.encrypt(this._inBlock, this._outBlock);

  // handle full block
  if(this._partialBytes === 0 && inputLength >= this.blockSize) {
    for(var i = 0; i < this._ints; ++i) {
      var inputWord = input.getInt32();
      var cipherWord = inputWord ^ this._outBlock[i];
      output.putInt32(cipherWord);
      // feedback is the ciphertext block (the input block when decrypting)
      this._inBlock[i] = encrypting ? cipherWord : inputWord;
    }
  } else {
    // handle partial block
    var partialBytes = (this.blockSize - inputLength) % this.blockSize;
    if(partialBytes > 0) {
      partialBytes = this.blockSize - partialBytes;
    }

    // XOR input with output
    this._partialOutput.clear();
    for(var j = 0; j < this._ints; ++j) {
      this._partialOutput.putInt32(input.getInt32() ^ this._outBlock[j]);
    }

    if(partialBytes > 0) {
      // block still incomplete, restore input buffer
      input.read -= this.blockSize;
    }

    // skip any previous partial bytes
    if(this._partialBytes > 0) {
      this._partialOutput.getBytes(this._partialBytes);
    }

    if(partialBytes > 0 && !finish) {
      output.putBytes(this._partialOutput.getBytes(
        partialBytes - this._partialBytes));
      this._partialBytes = partialBytes;
      return true;
    }

    output.putBytes(this._partialOutput.getBytes(
      inputLength - this._partialBytes));
    this._partialBytes = 0;
  }
};

function transformIV(iv, blockSize) {
  if(typeof iv === 'string') {
    // convert iv string into byte buffer
    iv = new ByteBuffer(iv);
  }

  if(util.isArray(iv) && iv.length > 4) {
    // convert iv byte array into byte buffer
    var tmp = iv;
    iv = new ByteBuffer();
    for(var i = 0; i < tmp.length; ++i) {
      iv.putByte(tmp[i]);
    }
  }

  if(iv.length() < blockSize) {
    throw new Error(
      'Invalid IV length; got ' + iv.length() +
      ' bytes and expected ' + blockSize + ' bytes.');
  }

  if(!util.isArray(iv)) {
    // convert iv byte buffer into 32-bit integer array
    var ints = [];
    var blocks = blockSize / 4;
    for(var j = 0; j < blocks; ++j) {
      ints.push(iv.getInt32());
    }
    iv = ints;
  }

  return iv;
}

function inc32(block) {
  // increment last 32 bits of block only
  block[block.length - 1] = (block[block.length - 1] + 1) & 0xFFFFFFFF;
}
