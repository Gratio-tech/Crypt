'use strict';

/**
 * Minimal binary-string backed byte buffer.
 *
 * This is a deliberately small replacement for forge's ByteStringBuffer. It
 * keeps only the API surface required by the extracted AES-CTR implementation.
 */

function isArrayBuffer(x) {
  return typeof ArrayBuffer !== 'undefined' && x instanceof ArrayBuffer;
}

function isArrayBufferView(x) {
  return !!x && isArrayBuffer(x.buffer) && x.byteLength !== undefined;
}

function bytesToBinaryString(bytes) {
  var chunkSize = 0x8000;
  var result = '';
  for(var i = 0; i < bytes.length; i += chunkSize) {
    result += String.fromCharCode.apply(
      null, bytes.subarray(i, Math.min(i + chunkSize, bytes.length)));
  }
  return result;
}

function coerceBytes(b) {
  if(isArrayBuffer(b)) {
    return new Uint8Array(b);
  }
  if(isArrayBufferView(b)) {
    return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  }
  return null;
}

function ByteBuffer(b) {
  // the data in this buffer, one byte per character
  this.data = '';
  // the pointer for reading from this buffer
  this.read = 0;

  if(typeof b === 'string') {
    this.data = b;
  } else if(b instanceof ByteBuffer ||
    (typeof b === 'object' && b !== null &&
    typeof b.data === 'string' && typeof b.read === 'number')) {
    // copy existing buffer
    this.data = b.data;
    this.read = b.read;
  } else {
    var bytes = coerceBytes(b);
    if(bytes) {
      this.data = bytesToBinaryString(bytes);
    }
  }

  // used for v8 optimization
  this._constructedStringLength = 0;
}

var _MAX_CONSTRUCTED_STRING_LENGTH = 4096;

ByteBuffer.prototype._optimizeConstructedString = function(x) {
  this._constructedStringLength += x;
  if(this._constructedStringLength > _MAX_CONSTRUCTED_STRING_LENGTH) {
    // this substr() should cause the constructed string to join
    this.data.substr(0, 1);
    this._constructedStringLength = 0;
  }
};

ByteBuffer.prototype.length = function() {
  return this.data.length - this.read;
};

ByteBuffer.prototype.putByte = function(b) {
  return this.putBytes(String.fromCharCode(b));
};

ByteBuffer.prototype.putBytes = function(bytes) {
  this.data += bytes;
  this._optimizeConstructedString(bytes.length);
  return this;
};

ByteBuffer.prototype.putInt32 = function(i) {
  return this.putBytes(
    String.fromCharCode(i >> 24 & 0xFF) +
    String.fromCharCode(i >> 16 & 0xFF) +
    String.fromCharCode(i >> 8 & 0xFF) +
    String.fromCharCode(i & 0xFF));
};

ByteBuffer.prototype.putInt32Le = function(i) {
  return this.putBytes(
    String.fromCharCode(i & 0xFF) +
    String.fromCharCode(i >> 8 & 0xFF) +
    String.fromCharCode(i >> 16 & 0xFF) +
    String.fromCharCode(i >> 24 & 0xFF));
};

ByteBuffer.prototype.putBuffer = function(buffer) {
  return this.putBytes(buffer.getBytes());
};

ByteBuffer.prototype.getByte = function() {
  return this.data.charCodeAt(this.read++);
};

ByteBuffer.prototype.getInt32 = function() {
  var rval = (
    this.data.charCodeAt(this.read) << 24 ^
    this.data.charCodeAt(this.read + 1) << 16 ^
    this.data.charCodeAt(this.read + 2) << 8 ^
    this.data.charCodeAt(this.read + 3));
  this.read += 4;
  return rval;
};

ByteBuffer.prototype.getInt32Le = function() {
  var rval = (
    this.data.charCodeAt(this.read) ^
    this.data.charCodeAt(this.read + 1) << 8 ^
    this.data.charCodeAt(this.read + 2) << 16 ^
    this.data.charCodeAt(this.read + 3) << 24);
  this.read += 4;
  return rval;
};

ByteBuffer.prototype.getBytes = function(count) {
  var rval;
  if(count) {
    // read count bytes
    count = Math.min(this.length(), count);
    rval = this.data.slice(this.read, this.read + count);
    this.read += count;
  } else if(count === 0) {
    rval = '';
  } else {
    // read all bytes, optimize to only copy when needed
    rval = (this.read === 0) ? this.data : this.data.slice(this.read);
    this.clear();
  }
  return rval;
};

ByteBuffer.prototype.bytes = function(count) {
  return (typeof count === 'undefined' ?
    this.data.slice(this.read) :
    this.data.slice(this.read, this.read + count));
};

ByteBuffer.prototype.at = function(i) {
  return this.data.charCodeAt(this.read + i);
};

ByteBuffer.prototype.compact = function() {
  if(this.read > 0) {
    this.data = this.data.slice(this.read);
    this.read = 0;
  }
  return this;
};

ByteBuffer.prototype.clear = function() {
  this.data = '';
  this.read = 0;
  return this;
};

ByteBuffer.prototype.toHex = function() {
  var rval = '';
  for(var i = this.read; i < this.data.length; ++i) {
    var b = this.data.charCodeAt(i);
    if(b < 16) {
      rval += '0';
    }
    rval += b.toString(16);
  }
  return rval;
};

ByteBuffer.prototype.fillWithByte = function(b, n) {
  b = String.fromCharCode(b);
  var d = this.data;
  while(n > 0) {
    if(n & 1) {
      d += b;
    }
    n >>>= 1;
    if(n > 0) {
      b += b;
    }
  }
  this.data = d;
  this._optimizeConstructedString(n);
  return this;
};

ByteBuffer.prototype.isEmpty = function() {
  return this.length() <= 0;
};

ByteBuffer.prototype.truncate = function(count) {
  var len = Math.max(0, this.length() - count);
  this.data = this.data.substr(this.read, len);
  this.read = 0;
  return this;
};

ByteBuffer.prototype.copy = function() {
  var c = new ByteBuffer(this.data);
  c.read = this.read;
  return c;
};

module.exports = ByteBuffer;
