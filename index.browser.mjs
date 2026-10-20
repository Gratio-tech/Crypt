import clientCrypt from './lib/client.js';
import cypher from './lib/cypher/index.js';

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

const frontCrypt = clientCrypt;
const Crypt = { serverCrypt, clientCrypt, frontCrypt, cypher };

export { serverCrypt, clientCrypt, frontCrypt, cypher };
export default Crypt;
