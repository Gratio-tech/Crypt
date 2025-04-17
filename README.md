# Crypt
 A very simple package for encrypting communications between server and client.

## Description
 The library has two modules - for the server and for the client, so that you can use secure encrypted data exchange not only between the API, but also with the frontend.

## Usage on serverside
 First of all install lib:
 ```shell
 npm i @gratio/crypt
 ```

 Usage example:
 ```TS
 import Crypt from '@gratio/crypt';

 const { encryptMsg, decryptMsg } = Crypt.serverCrypt;
 const pass_in_base64 = 'U0VDUkVUX1BBU1M='; // Base64 encrypted pass

 const cipher = encryptMsg({
   message: {}, // Any serializable type (not a function!) e.g. {} | 'string' | []
   pass: pass_in_base64
 }); // Return { data, v } witch you can stringify and send as a body

 // Any encrypted message must has an `data` and `v` fields with base64 encoded strings
 // data is encrypted data, v is an init vector
 const decryptedString = decryptMsg({
   message: { data: 'string', v: 'string' },
   pass: pass_in_base64
 }); // Return correct JSON-string

 const decryptedData = JSON.parse(decryptedString); // return Initial data
 ```

 `pass_in_base64` - preferably a valid base64 string (but not strictly necessarily). \
 You can generate your own pass like this:

 ```TS
 import Crypt from '@gratio/crypt';
 const { pack } = Crypt.serverCrypt;
 const your_pass = 'SECRET_PASS';

 console.log(pack(your_pass)); // 'U0VDUkVUX1BBU1M='
 ```
