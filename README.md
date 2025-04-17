# Crypt
 A very simple package for encrypting communications between server and client.

## Description
 The library has two modules - for the server and for the client, so that you can use secure encrypted data exchange not only between the API, but also with the frontend.

## Usage on serverside
 First of all install lib:
 `npm i @gratio/crypt`

 Import and usage:
 ```TS
 import Crypt from '@gratio/crypt';

 const { encryptMsg } = Crypt.serverCrypt;

 const cipher = encryptMsg({
   message: { some_serializable: {}, or_just: 'string' }, // Any serializable type (not a function!)
   pass: 'SECRET_PASS'
 });
 ```
 `cipher` is an object { data: string, v: string }, witch you can stringify and send as a body
