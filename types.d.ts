import type { ApiResponse } from '@gratio/api';

export type SerializablePrimitive = string | number | boolean | null;
export type SerializableArray = Serializable[];
export type SerializableObject = { [key: string]: Serializable };
export type Serializable =
  | SerializablePrimitive
  | SerializableArray
  | SerializableObject;

export type CryptedData = { data: string; v: string };

export type EncryptParams = { message: Serializable; pass: string; algorithm?: string };
export type DecryptParams = { message: CryptedData; pass: string; algorithm?: string };

// Типы для шифрованных ответов
export type ApiResponseCrypted = ApiResponse<CryptedData>;

export interface MessageDigest {
  algorithm: string;
  blockLength: number;
  digestLength: number;
  messageLength: number;
  start(): MessageDigest;
  update(msg: string, encoding?: string): MessageDigest;
  digest(): any;
}

export interface Hmac {
  start(md: string | MessageDigest | null, key?: string | number[] | any | null): void;
  update(bytes: string): void;
  getMac(): any;
  digest(): any;
}

export interface Sha512 {
  create(algorithm?: string): MessageDigest;
  sha384: { create(): MessageDigest };
  sha256: { create(): MessageDigest };
  sha224: { create(): MessageDigest };
}

export interface ByteBuffer {
  data: string;
  read: number;
  length(): number;
  isEmpty(): boolean;
  putByte(b: number): ByteBuffer;
  putBytes(bytes: string): ByteBuffer;
  putInt32(i: number): ByteBuffer;
  putInt32Le(i: number): ByteBuffer;
  putBuffer(buffer: ByteBuffer): ByteBuffer;
  getByte(): number;
  getInt32(): number;
  getInt32Le(): number;
  getBytes(count?: number): string;
  bytes(count?: number): string;
  at(i: number): number;
  compact(): ByteBuffer;
  clear(): ByteBuffer;
  copy(): ByteBuffer;
  truncate(count: number): ByteBuffer;
  fillWithByte(b: number, n: number): ByteBuffer;
  toHex(): string;
}

export interface ByteBufferConstructor {
  new (b?: any): ByteBuffer;
}

export interface BinaryUtil {
  raw: {
    encode(bytes: Uint8Array): string;
    decode(str: string, output?: Uint8Array, offset?: number): Uint8Array | number;
  };
  base64: {
    encode(input: Uint8Array, maxline?: number): string;
    decode(input: string, output?: Uint8Array, offset?: number): Uint8Array | number;
  };
  baseN: {
    encode(input: Uint8Array, alphabet: string, maxline?: number): string;
    decode(input: string, alphabet: string): Uint8Array;
  };
  base58: {
    encode(input: Uint8Array, maxline?: number): string;
    decode(input: string): Uint8Array;
  };
}

export interface Util {
  isArray(x: any): boolean;
  isArrayBuffer(x: any): boolean;
  isArrayBufferView(x: any): boolean;
  isNodejs: boolean;
  globalScope: any;
  nextTick(callback: () => void): void;
  setImmediate(callback: () => void): any;
  fillString(c: string, n: number): string;
  encodeUtf8(str: string): string;
  decodeUtf8(str: string): string;
  encode64(input: string, maxline?: number): string;
  decode64(input: string): string;
  ByteBuffer: ByteBufferConstructor;
  binary: BinaryUtil;
}

export interface Cypher {
  util: Util;
  ByteBuffer: ByteBufferConstructor;
  baseN: any;
  sha256: { create(): MessageDigest };
  sha512: Sha512;
  md5: { create(): MessageDigest };
  hmac: { create(): Hmac };
  pbkdf2: (password: string, salt: string, iterations?: number, keyLength?: number) => string;
  prng: { create(plugin: any): any };
  random: any;
  cipher: any;
  createCipher(algorithm: string, key: any): any;
  createDecipher(algorithm: string, key: any): any;
}

export interface ServerCrypt {
  generateCommonKey: () => string;
  encryptMsg: (params: EncryptParams) => CryptedData;
  decryptMsg: (params: DecryptParams) => string;
  unpack: (base64Key: string) => Uint8Array;
  pack: (bufferKey: Uint8Array) => string;
}

export interface ClientCrypt {
  generateCommonKey: () => string;
  generateIV: () => string;
  encrypt: (plaintext: string, key: string, iv: string, algorithm?: string) => string;
  decrypt: (ciphertext: string, key: string, iv: string, algorithm?: string) => string;
  encryptMsg: (params: EncryptParams) => CryptedData;
  decryptMsg: (params: DecryptParams) => string;
  packToBase64: (bufferKey: ArrayBuffer | Uint8Array) => string;
  unpackBase64: (base64: string) => Uint8Array;
  sha256: Cypher['sha256'];
  sha512: Cypher['sha512'];
  md5: Cypher['md5'];
  hmac: Cypher['hmac'];
  pbkdf2: Cypher['pbkdf2'];
  util: Cypher['util'];
  random: Cypher['random'];
  cipher: Cypher['cipher'];
  ByteBuffer: Cypher['ByteBuffer'];
  baseN: Cypher['baseN'];
  prng: Cypher['prng'];
}

// Backward-compatible alias for the previous `frontCrypt` name.
export type FrontCrypt = ClientCrypt;

declare const serverCrypt: ServerCrypt;
declare const clientCrypt: ClientCrypt;
declare const frontCrypt: FrontCrypt;
declare const cypher: Cypher;

declare namespace Crypt {
  const serverCrypt: ServerCrypt;
  const clientCrypt: ClientCrypt;
  const frontCrypt: FrontCrypt;
  const cypher: Cypher;
}

export { serverCrypt, clientCrypt, frontCrypt, cypher };
export default Crypt;
