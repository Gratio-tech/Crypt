# Crypt
 A very simple package for encrypting communications between server and client.

## Description
 The library has two modules - for the server and for the client, so that you can use secure encrypted data exchange not only between the API, but also with the frontend.

## Usage on serverside
 First of all install lib:
 `npm i @gratio/crypt`

 Import and usage:
 ```TS
 import { serverCrypt } from '@gratio/crypt';

 const { encryptMsg } = serverCrypt;

 const cipher = encryptMsg({
   message: { some_serializable: {}, or_just: 'string' }, // Any serializable type (not a function!)
   pass: 'SECRET_PASS'
 }); // Return is a encrypted string
 ```
