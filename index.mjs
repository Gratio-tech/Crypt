import serverCrypt from './lib/server.js';
import clientCrypt from './lib/client.js';
import cypher from './lib/cypher/index.js';

const frontCrypt = clientCrypt;
const Crypt = { serverCrypt, clientCrypt, frontCrypt, cypher };

export { serverCrypt, clientCrypt, frontCrypt, cypher };
export default Crypt;
