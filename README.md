[![npm version](https://img.shields.io/npm/v/@gratio/crypt?color=%23047dec)](https://www.npmjs.org/package/@gratio/crypt)

# @gratio/crypt

Simple AES-128-CTR encryption for server ↔ client exchange.

- **Zero runtime dependencies**
- **Isomorphic**: Server (Node.js `crypto`) and Client (pure JS `lib/cypher`)
- **Dual module**: CommonJS and ESM support
- **Subpath exports**: `@gratio/crypt/server`, `@gratio/crypt/client`, `@gratio/crypt/cypher`

## Install

```shell
npm i @gratio/crypt
```

---

## Server (Node.js)

```ts
import Crypt from '@gratio/crypt';
const { encryptMsg, decryptMsg, generateCommonKey } = Crypt.serverCrypt;

// Or direct subpath import:
// import { encryptMsg, decryptMsg, generateCommonKey } from '@gratio/crypt/server';

const pass = generateCommonKey(); // 16-byte base64 key

const cipher = encryptMsg({ message: { a: 1 }, pass });
// => { data: string, v: string } — both base64

const json = decryptMsg({ message: cipher, pass }); // string
const data = JSON.parse(json); // { a: 1 }
```

- `pass` must decode to a 16-byte AES key (e.g. generated via `generateCommonKey()`).
- `message` may be any JSON-serializable value (objects are automatically JSON-serialized).
- `decryptMsg` returns a string — parse it with `JSON.parse` if you encrypted an object.
- Optional `algorithm` parameter, default `'AES-CTR'`.

---

## Client (Browser & Node.js)

Same AES-128-CTR format as the server, without Node `crypto`.

```ts
import Crypt from '@gratio/crypt';
const { encryptMsg, decryptMsg, generateIV } = Crypt.clientCrypt;

// Or direct subpath import:
// import { encryptMsg, decryptMsg, generateIV } from '@gratio/crypt/client';

const pass = 'MDEyMzQ1Njc4OWFiY2RlZg=='; // 16-byte base64 key

const cipher = encryptMsg({ message: 'Hello', pass }); // { data, v }
const text = decryptMsg({ message: cipher, pass }); // 'Hello'
```

### Low-level Client API

```ts
import { encrypt, decrypt, generateIV } from '@gratio/crypt/client';

const iv = generateIV(); // 16-byte base64 IV
const ciphertext = encrypt('Hello world', pass, iv); // base64
const plaintext = decrypt(ciphertext, pass, iv); // 'Hello world'

// Explicit algorithm (default is 'AES-CTR')
const cipher2 = encrypt('Hello world', pass, iv, 'AES-CTR');
```

> `frontCrypt` is an alias of `clientCrypt`.

---

## Password → key (PBKDF2)

```ts
import Crypt from '@gratio/crypt';
const { pbkdf2, encryptMsg, decryptMsg, generateIV, util } = Crypt.clientCrypt;

const salt = generateIV(); // random salt, store it with the ciphertext
const key = util.encode64(pbkdf2('my-password', salt, 100000, 16));

const cipher = encryptMsg({ message: 'secret', pass: key });
const text = decryptMsg({ message: cipher, pass: key });
```

`pbkdf2(password, salt, iterations?, keyLength?)` returns the derived key as a
binary string; wrap it in `util.encode64` to use it as `pass`. Defaults:
`iterations = 10000`, `keyLength = 16`.

---

## Migrating from forge

Typical forge-based AES-CTR client with a pre-shared base64 key:

```ts
// Old (forge)
const pack = buffer => window.btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)));

const unpack = base64 => {
  if (typeof base64 != 'string') {
    console.warn('Try to unpack not a string! Error.');
    return;
  }
  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
};

const generateIV = () => {
  const iv = forge.random.getBytes(16); // 16 bytes (128 bit)
  return forge.util.encode64(iv); // base64 IV
};

const encrypt = (plaintext, iv) => {
  const cipher = forge.cipher.createCipher('AES-CTR', forge.util.createBuffer(unpack(SOME_KEY)));
  cipher.start({ iv: forge.util.createBuffer(unpack(iv)) });
  const encoder = new TextEncoder('utf-8'); // text -> bytes
  const bytes = encoder.encode(plaintext);
  cipher.update(forge.util.createBuffer(bytes));
  cipher.finish();
  return forge.util.encode64(cipher.output.getBytes()); // base64
};

const decrypt = (ciphertext, iv) => {
  const decipher = forge.cipher.createDecipher('AES-CTR', forge.util.createBuffer(unpack(SOME_KEY)));
  decipher.start({ iv: forge.util.createBuffer(iv) });
  decipher.update(forge.util.createBuffer(ciphertext));
  decipher.finish();
  const bytes = decipher.output.getBytes(); // binary -> UTF-8
  return new TextDecoder('utf-8').decode(new Uint8Array(forge.util.binary.raw.decode(bytes)));
};
```

Same thing with `@gratio/crypt`:

```ts
import Crypt from '@gratio/crypt';
const { packToBase64, unpackBase64, generateIV, encrypt, decrypt } = Crypt.clientCrypt;

// pack(buffer)    -> packToBase64(buffer)   // ArrayBuffer | Uint8Array -> base64
// unpack(base64)  -> unpackBase64(base64)   // base64 -> Uint8Array
// generateIV()    -> generateIV()           // same: 16-byte base64 IV

const iv = generateIV();
const ciphertext = encrypt(plaintext, SOME_KEY, iv); // SOME_KEY — 16-byte base64
const plaintext2 = decrypt(ciphertext, SOME_KEY, iv);
```

Notes:

- `SOME_KEY` stays a base64 string; `encrypt`/`decrypt` take key and IV as base64.
- `unpackBase64` is strict — it throws on invalid base64. If you need the old
  warn-and-return behaviour, keep a thin wrapper around it.

---

## Built-in tools

```ts
import { util, ByteBuffer, baseN } from '@gratio/crypt/cypher';
// or from '@gratio/crypt/client'

// ArrayBuffer / Uint8Array <-> base64
const bytes = new Uint8Array([0, 1, 2, 255]);
const b64 = util.binary.base64.encode(bytes);
const bytes2 = util.binary.base64.decode(b64);

// binary string <-> base64
const bin = util.binary.raw.encode(bytes);
const b64b = util.encode64(bin);
const bin2 = util.decode64(b64b);

// UTF-8
const utf8 = util.encodeUtf8('Привет');
const str = util.decodeUtf8(utf8);

// base58
const b58 = util.binary.base58.encode(bytes);
const bytes3 = util.binary.base58.decode(b58);

// custom alphabet (baseN)
const custom = baseN.encode(bytes, 'abcdefghijklmnopqrstuvwxyz');
const bytes4 = baseN.decode(custom, 'abcdefghijklmnopqrstuvwxyz');

// ByteBuffer
const bb = new ByteBuffer();
bb.putInt32(0x01020304).putBytes('hi');
bb.getInt32(); // 0x01020304
bb.getBytes(2); // 'hi'
bb.toHex(); // hex of the remaining bytes
```

Convenience helpers live on `clientCrypt` (not `cypher`):

```ts
import { packToBase64, unpackBase64 } from '@gratio/crypt/client';

const packed = packToBase64(bytes);   // Uint8Array | ArrayBuffer -> base64
const back = unpackBase64(packed);    // base64 -> Uint8Array
```

More ByteBuffer helpers:

```ts
const bb2 = new ByteBuffer('abc');
bb2.copy();               // independent copy, keeps read position
bb2.isEmpty();            // true when nothing left to read
bb2.fillWithByte(0x41, 3); // append 'AAA'
bb2.truncate(2);          // cut the tail, keep `length - 2` bytes
```

---

## Subpath Exports

| Import Path | Description | Environment |
|-------------|-------------|-------------|
| `@gratio/crypt` | Root export (`serverCrypt`, `clientCrypt`, `frontCrypt`, `cypher`) | Node & Browser |
| `@gratio/crypt/server` | Server encryption methods | Node.js only |
| `@gratio/crypt/client` | Client encryption methods & hashes | Node & Browser |
| `@gratio/crypt/cypher` | Low-level primitives (`aes`, `sha*`, `md5`, `hmac`, `pbkdf2`, `ByteBuffer`, `baseN`) | Node & Browser |
| `@gratio/crypt/dist/*` | Pre-built standalone bundles | Browser |

---

## Hashes / HMAC

The client and cypher modules include hash functions and HMAC:

```ts
import { sha256, sha512, md5, hmac } from '@gratio/crypt/client';
// or from '@gratio/crypt/cypher'

// SHA-256
const hash256 = sha256.create().update('hello').digest().toHex();

// SHA-512 & SHA-384
const hash512 = sha512.create().update('hello').digest().toHex();
const hash384 = sha512.sha384.create().update('hello').digest().toHex();

// MD5
const hashMd5 = md5.create().update('hello').digest().toHex();

// HMAC
const mac = hmac.create();
mac.start('sha256', 'secret-key');
mac.update('hello');
const macHex = mac.digest().toHex();
```

---

## Standalone Bundle (Browsers / `<script>`)

Pre-built bundles in `dist/`:

- `dist/gcrypt.min.js` — minified IIFE (ES5), exposing `window.gCypher` / `window.GratioCypher`.
- `dist/gcrypt.js` — unminified debug IIFE.
- `dist/gcrypt.esm.js` / `dist/gcrypt.esm.mjs` — standalone minified ESM bundle.

```html
<script src="node_modules/@gratio/crypt/dist/gcrypt.min.js"></script>
<script>
  // Global object: window.gCypher (or window.GratioCypher)
  const pass = 'MDEyMzQ1Njc4OWFiY2RlZg==';
  const iv = gCypher.generateIV();
  const cipher = gCypher.encrypt('Hello', pass, iv);
  const text = gCypher.decrypt(cipher, pass, iv);
</script>
```

To rebuild bundles:
```shell
npm run build
```
