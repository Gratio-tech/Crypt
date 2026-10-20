'use strict';

var ByteBuffer = require('./byte-buffer');
var baseN = require('./baseN');

var util = module.exports = {};

util.isArray = Array.isArray || function(x) {
  return Object.prototype.toString.call(x) === '[object Array]';
};

util.isArrayBuffer = function(x) {
  return typeof ArrayBuffer !== 'undefined' && x instanceof ArrayBuffer;
};

util.isArrayBufferView = function(x) {
  return !!x && util.isArrayBuffer(x.buffer) && x.byteLength !== undefined;
};

util.ByteBuffer = ByteBuffer;

util.isNodejs =
  typeof process !== 'undefined' && process.versions && process.versions.node;

util.globalScope = (function() {
  if(util.isNodejs) {
    return global;
  }
  return typeof self === 'undefined' ? window : self;
})();

if(util.isNodejs && typeof process.nextTick === 'function') {
  util.nextTick = process.nextTick;
  util.setImmediate = typeof setImmediate === 'function' ?
    setImmediate : util.nextTick;
} else {
  util.setImmediate = function(callback) {
    return setTimeout(callback, 0);
  };
  util.nextTick = util.setImmediate;
}

/**
 * Fills a string with a particular value. If you want the string to be a byte
 * string, pass in String.fromCharCode(theByte).
 *
 * @param c the character to fill the string with.
 * @param n the number of characters of value c to fill with.
 *
 * @return the filled string.
 */
util.fillString = function(c, n) {
  var s = '';
  while(n > 0) {
    if(n & 1) {
      s += c;
    }
    n >>>= 1;
    if(n > 0) {
      c += c;
    }
  }
  return s;
};

/**
 * Encodes the given string of characters (a standard JavaScript string) as a
 * binary encoded string where the bytes represent UTF-8.
 */
util.encodeUtf8 = function(str) {
  return unescape(encodeURIComponent(str));
};

/**
 * Decodes a binary encoded string containing UTF-8 bytes into a standard
 * JavaScript string.
 */
util.decodeUtf8 = function(str) {
  return decodeURIComponent(escape(str));
};

// base64 characters, reverse mapping
var _base64 =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
var _base64Idx = [
  /*43 -43 = 0*/
  /*'+',  1,  2,  3,'/' */
  62, -1, -1, -1, 63,

  /*'0','1','2','3','4','5','6','7','8','9' */
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61,

  /*15, 16, 17,'=', 19, 20, 21 */
  -1, -1, -1, 64, -1, -1, -1,

  /*65 - 43 = 22*/
  /*'A','B','C','D','E','F','G','H','I','J','K','L','M', */
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,

  /*'N','O','P','Q','R','S','T','U','V','W','X','Y','Z' */
  13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,

  /*91 - 43 = 48 */
  /*48, 49, 50, 51, 52, 53 */
  -1, -1, -1, -1, -1, -1,

  /*97 - 43 = 54*/
  /*'a','b','c','d','e','f','g','h','i','j','k','l','m' */
  26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38,

  /*'n','o','p','q','r','s','t','u','v','w','x','y','z' */
  39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
];

// base58 characters (Bitcoin alphabet)
var _base58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Base64-encodes a binary encoded string of bytes.
 */
util.encode64 = function(input, maxline) {
  var line = '';
  var output = '';
  var chr1, chr2, chr3;
  var i = 0;
  while(i < input.length) {
    chr1 = input.charCodeAt(i++);
    chr2 = input.charCodeAt(i++);
    chr3 = input.charCodeAt(i++);

    // encode 4 character group
    line += _base64.charAt(chr1 >> 2);
    line += _base64.charAt(((chr1 & 3) << 4) | (chr2 >> 4));
    if(isNaN(chr2)) {
      line += '==';
    } else {
      line += _base64.charAt(((chr2 & 15) << 2) | (chr3 >> 6));
      line += isNaN(chr3) ? '=' : _base64.charAt(chr3 & 63);
    }

    if(maxline && line.length > maxline) {
      output += line.substr(0, maxline) + '\r\n';
      line = line.substr(maxline);
    }
  }
  output += line;
  return output;
};

/**
 * Base64-decodes a string into a binary encoded string of bytes.
 */
util.decode64 = function(input) {
  // remove all non-base64 characters
  input = input.replace(/[^A-Za-z0-9\+\/\=]/g, '');

  var output = '';
  var enc1, enc2, enc3, enc4;
  var i = 0;

  while(i < input.length) {
    enc1 = _base64Idx[input.charCodeAt(i++) - 43];
    enc2 = _base64Idx[input.charCodeAt(i++) - 43];
    enc3 = _base64Idx[input.charCodeAt(i++) - 43];
    enc4 = _base64Idx[input.charCodeAt(i++) - 43];

    output += String.fromCharCode((enc1 << 2) | (enc2 >> 4));
    if(enc3 !== 64) {
      // decoded at least 2 bytes
      output += String.fromCharCode(((enc2 & 15) << 4) | (enc3 >> 2));
      if(enc4 !== 64) {
        // decoded 3 bytes
        output += String.fromCharCode(((enc3 & 3) << 6) | enc4);
      }
    }
  }

  return output;
};

util.binary = {
  raw: {},
  base64: {},
  baseN: {},
  base58: {}
};

/**
 * Encodes a Uint8Array as a binary-encoded string.
 */
util.binary.raw.encode = function(bytes) {
  var chunkSize = 0x8000;
  var result = '';
  for(var i = 0; i < bytes.length; i += chunkSize) {
    result += String.fromCharCode.apply(
      null, bytes.subarray(i, Math.min(i + chunkSize, bytes.length)));
  }
  return result;
};

/**
 * Decodes a binary-encoded string to a Uint8Array.
 */
util.binary.raw.decode = function(str, output, offset) {
  var out = output;
  if(!out) {
    out = new Uint8Array(str.length);
  }
  offset = offset || 0;
  var j = offset;
  for(var i = 0; i < str.length; ++i) {
    out[j++] = str.charCodeAt(i);
  }
  return output ? (j - offset) : out;
};

/**
 * Base64-encodes a Uint8Array.
 */
util.binary.base64.encode = function(input, maxline) {
  var line = '';
  var output = '';
  var chr1, chr2, chr3;
  var i = 0;
  while(i < input.byteLength) {
    chr1 = input[i++];
    chr2 = input[i++];
    chr3 = input[i++];

    // encode 4 character group
    line += _base64.charAt(chr1 >> 2);
    line += _base64.charAt(((chr1 & 3) << 4) | (chr2 >> 4));
    if(isNaN(chr2)) {
      line += '==';
    } else {
      line += _base64.charAt(((chr2 & 15) << 2) | (chr3 >> 6));
      line += isNaN(chr3) ? '=' : _base64.charAt(chr3 & 63);
    }

    if(maxline && line.length > maxline) {
      output += line.substr(0, maxline) + '\r\n';
      line = line.substr(maxline);
    }
  }
  output += line;
  return output;
};

/**
 * Base64-decodes a string to a Uint8Array.
 */
util.binary.base64.decode = function(input, output, offset) {
  var out = output;
  if(!out) {
    out = new Uint8Array(Math.ceil(input.length / 4) * 3);
  }

  // remove all non-base64 characters
  input = input.replace(/[^A-Za-z0-9\+\/\=]/g, '');

  offset = offset || 0;
  var enc1, enc2, enc3, enc4;
  var i = 0;
  var j = offset;

  while(i < input.length) {
    enc1 = _base64Idx[input.charCodeAt(i++) - 43];
    enc2 = _base64Idx[input.charCodeAt(i++) - 43];
    enc3 = _base64Idx[input.charCodeAt(i++) - 43];
    enc4 = _base64Idx[input.charCodeAt(i++) - 43];

    out[j++] = (enc1 << 2) | (enc2 >> 4);
    if(enc3 !== 64) {
      // decoded at least 2 bytes
      out[j++] = ((enc2 & 15) << 4) | (enc3 >> 2);
      if(enc4 !== 64) {
        // decoded 3 bytes
        out[j++] = ((enc3 & 3) << 6) | enc4;
      }
    }
  }

  // make sure result is the exact decoded length
  return output ? (j - offset) : out.subarray(0, j);
};

util.binary.baseN = {
  encode: baseN.encode,
  decode: baseN.decode
};

util.binary.base58.encode = function(input, maxline) {
  return baseN.encode(input, _base58, maxline);
};
util.binary.base58.decode = function(input) {
  return baseN.decode(input, _base58);
};
