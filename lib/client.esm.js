// ESM entry point for the standalone client bundle
// (`npm run build:client:esm`).
import clientCrypt from './client.js';

export default clientCrypt;

export const generateIV = clientCrypt.generateIV;
export const generateCommonKey = clientCrypt.generateCommonKey;
export const encrypt = clientCrypt.encrypt;
export const decrypt = clientCrypt.decrypt;
export const encryptMsg = clientCrypt.encryptMsg;
export const decryptMsg = clientCrypt.decryptMsg;
export const packToBase64 = clientCrypt.packToBase64;
export const unpackBase64 = clientCrypt.unpackBase64;
export const sha256 = clientCrypt.sha256;
export const sha512 = clientCrypt.sha512;
export const md5 = clientCrypt.md5;
export const hmac = clientCrypt.hmac;
export const pbkdf2 = clientCrypt.pbkdf2;
export const util = clientCrypt.util;
export const random = clientCrypt.random;
export const cipher = clientCrypt.cipher;
export const ByteBuffer = clientCrypt.ByteBuffer;
export const baseN = clientCrypt.baseN;
export const prng = clientCrypt.prng;
