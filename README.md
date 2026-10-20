# Crypt
[![npm version](https://img.shields.io/npm/v/@gratio/crypt?color=%23047dec)](https://www.npmjs.org/package/@gratio/crypt)

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
```

> `frontCrypt` is an alias of `clientCrypt`.

---

## Subpath Exports

| Import Path | Description | Environment |
|-------------|-------------|-------------|
| `@gratio/crypt` | Root export (`serverCrypt`, `clientCrypt`, `frontCrypt`, `cypher`) | Node & Browser |
| `@gratio/crypt/server` | Server encryption methods | Node.js only |
| `@gratio/crypt/client` | Client encryption methods & hashes | Node & Browser |
| `@gratio/crypt/cypher` | Low-level primitives (`aes`, `sha*`, `md5`, `hmac`, `ByteBuffer`, `baseN`) | Node & Browser |
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
