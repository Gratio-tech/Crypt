'use strict';

const clientCrypt = require('./lib/client.js');

const Crypt = {
  serverCrypt: require('./lib/server.js'),
  clientCrypt,
  frontCrypt: clientCrypt,
  cypher: require('./lib/cypher')
};

Crypt.default = Crypt;

module.exports = Crypt;
