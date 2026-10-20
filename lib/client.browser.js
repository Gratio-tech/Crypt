'use strict';

// Entry point for the standalone legacy browser bundle.
//
// Bundled as an IIFE (`npm run build:client`), it assigns the client API to
// both `gCypher` and `GratioCypher` globals.
var clientCrypt = require('./client.js');

var root =
  typeof globalThis !== 'undefined' ? globalThis :
  typeof window !== 'undefined' ? window :
  typeof self !== 'undefined' ? self :
  typeof global !== 'undefined' ? global :
  {};

root.gCypher = clientCrypt;
root.GratioCypher = clientCrypt;
