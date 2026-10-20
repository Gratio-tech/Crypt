const crypto = require('crypto');

const pack = buffer => Buffer.from(buffer).toString('base64'); // Из буфера в base64
const unpack = packed => Buffer.from(packed, 'base64'); // Из base64 в буфер
const generateKey = () => crypto.randomBytes(16); // 128-битный ключ
const generateCommonKey = () => crypto.randomBytes(16).toString('base64'); // Общий 128-битный ключ

// Клиент использует forge-имена алгоритмов, Node хочет, например, 'aes-128-ctr'.
const toNodeAlgorithm = algorithm => {
  if (!algorithm || algorithm === 'AES-CTR') return 'aes-128-ctr';
  if (algorithm === 'AES-CFB') return 'aes-128-cfb';
  return algorithm;
};

// Функция шифрования
const encrypt = (data, key, iv, algorithm) => {
  const cipher = crypto.createCipheriv(toNodeAlgorithm(algorithm), key, iv);
  const bufFromData = Buffer.from(data, 'utf8');
  let encrypted = Buffer.concat([cipher.update(bufFromData), cipher.final()]);
  return encrypted; // Возвращает Buffer
};

// Функция расшифровки
const decrypt = (encryptedData, key, iv, algorithm) => {
  const decipher = crypto.createDecipheriv(toNodeAlgorithm(algorithm), key, iv);
  let decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);
  return decrypted.toString('utf8'); // Возвращает строку
};

const encryptMsg = (params) => {
  if (!params || params.message === undefined || !params.pass) {
    throw new Error(`The function parameter must be an object with fields "message" and "pass": { message: string, pass: string } `);
  }
  const { message, pass } = params; // message - любой сериализуемый объект
  const algorithm = params.algorithm || 'AES-CTR';
  const iv = generateKey();
  const stringToCrypt = typeof message === 'string' ? message : JSON.stringify(message);
  if (typeof stringToCrypt !== 'string') {
    throw new Error(`The "message" must be JSON-serializable.`);
  }
  const encryptedData = encrypt(stringToCrypt, unpack(pass), iv, algorithm);
  return {
    data: pack(encryptedData), // Данные в base64
    v: pack(iv),
  };
};

const decryptMsg = (params) => {
  if (!params || !params.message || !params.pass) {
    throw new Error(`The function parameter must be an object with fields "message" and "pass": { message: string, pass: string } `);
  }
  const { message, pass } = params;
  const algorithm = params.algorithm || 'AES-CTR';
  if (typeof message.data !== 'string' || typeof message.v !== 'string') {
    throw new Error(`Not looks like an encrypted data (message has not "data" or "v" fields).`);
  }
  return decrypt(unpack(message.data), unpack(pass), unpack(message.v), algorithm); // String
};

module.exports = {
  generateCommonKey,
  decryptMsg,
  encryptMsg,
  pack, // Из буфера в base64
  unpack, // Из base64 в буфер
};
