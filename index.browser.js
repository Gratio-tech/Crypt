'use strict';

const clientCrypt = require('./lib/client.js');
const cypher = require('./lib/cypher');

function unavailable() {
  throw new Error('@gratio/crypt: serverCrypt is only available in Node.js.');
}

const serverCrypt = typeof Proxy !== 'undefined'
  ? new Proxy({}, {
      get() { return unavailable; },
      apply() { unavailable(); }
    })
  : {
      generateCommonKey: unavailable,
      encryptMsg: unavailable,
      decryptMsg: unavailable,
      pack: unavailable,
      unpack: unavailable
    };

const Crypt = {
  serverCrypt,
  clientCrypt,
  frontCrypt: clientCrypt,
  cypher
};

Crypt.default = Crypt;

module.exports = Crypt;
